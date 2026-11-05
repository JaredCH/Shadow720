# PLAN_ADDENDUM_v1 — Locked Decisions from Review

> **Superseded.** The GitHub provisioning and PAT decisions below no longer apply:
> the GitHub backend has been removed and Nostr relays are the only storage path.
> Kept for history. See [README.md](./README.md) for the current design.

Supersedes / extends the numbered sections in [PLAN.md](../../../../Shadow720/PLAN.md). Where these conflict with PLAN.md, **this file wins**.

## A1. Repo & PAT Provisioning (extends §2.1)

* **The app provisions the repo.** It calls `POST /user/repos` with `auto_init: true`, then creates the roster issue, the chat issue, and the `vault-v1` release, reading each number/id back from the response rather than assuming 1 and 2.
* **Sign-in, not token pasting.** Fine-grained PATs cannot be created through the API (GitHub has no endpoint, by design), so the app uses the **OAuth 2.0 device authorization grant**: one button, a short code, approval on any device. No client secret is involved, so the `client_id` is compiled in safely.
* **Two-phase tokens**, because a fine-grained PAT scoped to one repository cannot create that repository:
  * *Account token* — from the device flow, used once for provisioning, held only in Rust app state, never persisted, never embedded in an invite.
  * *Repository token* — optional fine-grained token scoped to the created repo. When supplied it is stored in the vault and embedded in the invite; when omitted the account token is used instead, which removes the last manual step at the cost of a broader invite.
* Repository token scopes required:
  * `Contents: Read/Write` — release assets, repo metadata reads.
  * `Issues: Read/Write` — Issue #1/#2 comments.
  * `Administration: Read/Write` — **required** for in-app "Destroy Group" (`DELETE /repos/{owner}/{repo}`).
* PAT is embedded in the invite string, so **every guest can destroy the repo**. Accepted for v1; see A3 for the rotation-based mitigation.
* `InviteCredentialsPayload` gains `repo_created: bool`: `true` when the app provisioned the repo, `false` when it adopted an existing one.
* **Adopt path:** pointing the app at an existing repo runs a repair pass that creates any missing issue or release instead of failing.
* **Provider selector:** the create flow groups hosts by account requirement. GitHub is implemented; GitLab, Codeberg, Radicle, and gitGost are listed as unavailable rather than hidden.
  * GitLab supports device flow (17.1+) and has issues/releases, so it is the next realistic backend.
  * Radicle is accountless (keypair identity) but `radicle-httpd` is read-only and there is no issues or release-asset API, so it cannot back the current schema.
  * gitGost is an anonymous gateway with no issues or release API and no uptime guarantee.

## A1b. Accountless backend: Nostr (extends A1)

GitHub requires an account, and the invite has to carry a token that can destroy the
repository. Nostr removes both problems, so it is now a first-class backend.

* **Identity is a keypair** generated on the device (secp256k1). No email, no signup, no
  OAuth app, no token to paste. Works identically on desktop and Android because the
  Rust core is shared.
* **The invite carries no credential.** Each member signs their own events, so a guest
  can only write their own slot. This closes the "every guest can destroy the repo"
  risk in A1 rather than mitigating it.
* **Schema mapping** (`src/storage.rs`):

  | Logical table | GitHub | Nostr |
  |---|---|---|
  | roster slot | one comment per member on Issue #1 | addressable event, `d` = member pubkey |
  | chat stream | comments on Issue #2 | regular events |
  | blob vault | release assets | Blossom blobs, SHA-256 addressed |

* **Push, not polling.** Relays deliver over WebSocket, so the ETag cache, cadence
  budget, jitter, and adaptive backoff in §6 are not used on this path.
* **Fully wired.** `update_location`, `poll_roster`, `poll_chat`, `send_text`,
  `send_file`, `download_file`, `report_content`, `check_rotation`, `leave_and_wipe`,
  `destroy_group`, `vault_report`, and `refresh_rate_limit` all branch on the backend.
  Verified against a live relay: publish → read back → signature verified.
* **Where Nostr is weaker, and what the app does about it:**
  * *Best-effort event deletion.* Authors can publish NIP-09 deletion requests for
    their own messages. Relays may ignore them or retain copies, and clients validate
    the request's author before hiding an event. `report_content` publishes the flag
    and relies on the local block list.
  * *Cooperative group closure.* The host publishes a pinned-host-signed closure.
    Updated clients wipe their local group vault when they receive and verify it.
    Offline or older clients and relay copies may remain.
  * *Locally owned blob listing and deletion.* The sealed vault records this
    device's uploads and their accepting servers. An uploader can request deletion
    and publish a signed removal notice; other clients mark known pointers
    unavailable. The list is not a complete server inventory and copies may remain.
    New file pointers use a non-replaceable kind; older clients must be updated.
  * *No shared request budget.* `refresh_rate_limit` returns immediately.
* **Crypto is unchanged.** NIP-44 is deliberately *not* used: it is pairwise ECDH, which
  would mean encrypting once per member. The existing `group_master_key` +
  `XChaCha20-Poly1305` envelope stays; Nostr is transport only.
* **Accepted trade-offs:** relays are best-effort and may drop events; deletion is
  advisory (NIP-09 can be ignored); pubkeys and timestamps are public metadata; free
  Blossom tiers are ~20 MiB per file with no retention guarantee. Publishing goes to
  several relays and succeeds if any accepts.
* **Backend selection** is stored in the invite (`backend` field, defaulting to GitHub
  so older invites still parse) and surfaced in the provider picker.

## A2. Background Location (extends §5.1)

* Full background tracking is **in scope**. Manifest additions:

  ```xml
  <uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
  <uses-permission android:name="android.permission.CAMERA" />
  <uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
  ```

* `POST_NOTIFICATIONS` is mandatory on API 33+ for the foreground-service notification to render.
* Required for Play review:
  * Play Console Data Safety: declare location collection; "shared" = no (E2EE to an untrusted blob store, no third-party recipient).
  * Location permissions declaration form + **demo video** showing the in-app disclosure and the runtime permission request in context.
  * The in-app disclosure must be a blocking gate shown **before** the OS prompt.
* Permission request order: disclosure modal → `ACCESS_FINE_LOCATION` + `ACCESS_COARSE_LOCATION` → (only on an explicit user-initiated "enable background tracking") `ACCESS_BACKGROUND_LOCATION`.

## A3. Key Rotation & Member Removal (new)

* In scope. Host-only flows:
  * **Rotate Group Key** — generate a new `group_master_key`, re-build a `GRP1` invite for each member, and record the retired key as a previous epoch in a `rekey` comment on `Issue #1`.
  * **Remove Member** — delete that member's `Issue #1` comment, then force a group-key rotation.
* Multiple key epochs must be supported on read: `EncryptedEnvelope` gains `key_epoch: u8` (default `0`); the client keeps a bounded `DashMap<u8, Zeroizing<[u8; 32]>>` of historical group keys.
* **Re-key Group (PAT expiry path)** — host pastes a freshly generated PAT; the app re-issues all invite strings without touching the group key. Shares the re-invite UI with rotation.
* Documented limitation: a removed member who kept an old invite string retains the old epoch key. Rotation protects only content written after rotation.

## A4. Secret Storage (extends §2.1)

> **Revised during implementation.** This decision was originally
> `tauri-plugin-stronghold`, and the review accepted it. Building it revealed three
> blockers, so the storage *mechanism* changed. The threat model did **not** change.
> See A11 for the swap and the evidence.

* **Keystore-wrapped password, sealed vault file.** The PAT and `group_master_key`
  live in one AEAD-encrypted payload sealed with `XChaCha20-Poly1305` from
  `crypto.rs`, which already carries single-bit tamper tests.
* The vault password is 32 random bytes, generated on first launch, and stored
  **only** wrapped by an Android Keystore AES-GCM key (`setUserAuthenticationRequired(false)`).
* Custom Kotlin plugin (`KeystoreVaultPlugin`) exposes exactly two commands: `wrapSecret(bytes)` and `unwrapSecret(Vec<u8>)`. No general-purpose Keystore surface.
* All Rust secret types derive `Zeroize` + `ZeroizeOnDrop`; invite strings are zeroized immediately after parse.
* If the Keystore key is invalidated (device reset), the app treats the vault as lost and requires a fresh invite paste.

## A5. Rate Limits & Polling (extends §4)

* Cadence while foregrounded: **chat 10s, roster 30s**.
* Mandatory cushion for the 5,000 req/hr shared budget:
  * ±25% random jitter on every interval to prevent thundering-herd alignment.
  * Single-flight + serialized request queue per client.
  * `If-None-Match` ETag on every poll; `304` responses treated as free.
  * Hard **429/403 backoff**: on `429`, or `403` with `x-ratelimit-remaining: 0`, stop all polling until `x-ratelimit-reset` + 60s and surface a non-blocking "sync paused" banner.
  * Adaptive backoff doubles the interval (capped at 5 min) when the last 3 polls returned `304` for a channel.
* Startup burst is **forbidden**: never issue roster + chat + assets fetches in parallel on cold start.
* 10s/30s is a *ceiling*, not a floor — adaptive backoff can only lengthen intervals.

## A6. Build Order (extends §6)

All 7 deliverables in one pass, written in dependency order so each stage compiles before the next:

1. `src-tauri/Cargo.toml` + `src-tauri/src/error.rs`
2. `src-tauri/src/crypto.rs` (unit tests alongside)
3. `src-tauri/src/geo_filter.rs` (unit tests alongside)
4. `src-tauri/src/github_db.rs`
5. `src-tauri/src/lib.rs` (command wiring)
6. `src-tauri/tauri.conf.json` + `gen/android` + `LocationForegroundService.kt` + `KeystoreVaultPlugin.kt`
7. `src/App.tsx` (+ Tailwind, MapLibre, QR)

## A7. Testing Against `jaredch` (new)

* Live integration tests against `jaredch` **run by default**.
* Required mitigations:
  * Default runs need `SHADOWTEST_PAT` and `SHADOWTEST_REPO`; both are required for any live test binary to start.
  * Use a dedicated sandbox repo, not the primary group repo, so destructive coverage can run safely.
  * Live tests must **redact** the PAT and all ciphertext from logged output; `.env` and `*.pat` gitignored from step 0.
  * Rate-limit guard: assert `x-ratelimit-remaining > 500` before starting, abort early if below.
  * Destructive tests are `#[ignore]` by default and require `SHADOWTEST_ALLOW_DESTRUCTIVE=1`.
* CI (if added later) runs the mocked suite only; the live suite is local-only.

## A8. Signature Canonicalization (extends §3)

* Signature input becomes length-prefixed to remove ambiguity:

  ```
  sig_input = u8::to_le_bytes(v)
              || u32::to_le_bytes(sender_pubkey_bytes.len()) || sender_pubkey_bytes
              || u32::to_le_bytes(nonce_bytes.len())         || nonce_bytes
              || u32::to_le_bytes(ciphertext_bytes.len())    || ciphertext_bytes
  ```

* `EncryptedEnvelope` wire order: `v`, `key_epoch`, `sender_pubkey`, `nonce`, `ciphertext`, `signature`.
* Required unit test: flipping any single bit in `ciphertext`, `nonce`, or `key_epoch` must cause `open()` to fail.

## A9. Encoding & Invite Delivery (extends §2.1, §3)

* `EncryptedEnvelope` fields use Base64 **standard with padding** (matches §3).
* The `GRP1-` invite token uses **Base64URL no-pad** (matches §2.1). Keep these deliberately different.
* Invite delivery: copy/paste **and** QR scan.
  * QR generation needs no permission.
  * QR scanning uses **camera** — adds `CAMERA` permission + Play declaration.
  * QR must degrade gracefully to copy/paste when the camera is unavailable or permission is denied.

## A10. Toolchain Baseline (new)

* `minSdk 26`, `targetSdk 35`, `compileSdk 35`.
* Tauri v2 via `tauri android init`; Rust stable; `aarch64-linux-android` target + NDK `r27`.
* Verifying Rust / NDK / JDK / `gh` auth is **step 0** of implementation, not an assumption.
## A11. Implementation Deviations (recorded during the build)

Everything below was discovered by running the code rather than reading it. Each
item lists the deviation, the evidence, and what was done instead.

### A11.1 Stronghold was replaced as the secret store (supersedes A4's mechanism)

Three independent blockers, all verified against `iota_stronghold 2.1`:

1. **Vault records cannot be read back.** `ClientVault::read_secret` is gated behind
   `#[cfg(test)]` upstream. That is correct design for key material that is only ever
   *used*, but the PAT must be handed to an HTTP client, so it has to be readable.
2. **A snapshot commit takes ~100 seconds on Windows.** Stronghold's runtime is built
   on its own hardened shared-memory allocator. Measured: one
   `commit_with_keyprovider` for a 32-byte payload took **103 s**. Every vault test
   therefore took over a minute; the full suite went from 3 s to 232 s.
3. **A client with no records cannot be written at all**, so a freshly created vault
   failed with "error loading client data; no data present" before its first secret
   existed.

**Replacement:** a single AEAD-sealed vault file, with the same two-layer design. The
vault password is still 32 random bytes wrapped by the Android Keystore; the payload
is sealed with `XChaCha20-Poly1305` under an `Argon2id`-derived key, with a versioned
`SHDW720V` header. What changed is the container, not the threat model. The unit tests
assert the same properties Stronghold would have provided: the PAT and group key never
appear in the file, a single flipped bit anywhere fails the open, a foreign file is
rejected, and a lost device key makes the vault unopenable.

Effect: 308 tests run in **3.4 s**.

### A11.2 Invite payload gained `key_epoch`

A03 called for invite re-issue after a rotation, but the original payload had no way
to say which key epoch its `group_master_key` belonged to. The field was added with
`#[serde(default)]`, so an invite written before the field existed still parses as
epoch 0.

### A11.3 Signature input also covers the key epoch

A08's canonical form covered `v ‖ pubkey ‖ nonce ‖ ciphertext`. The implemented form
adds `key_epoch` between `v` and the public key, because the associated data binds the
ciphertext to its epoch and the signature must cover the same bytes. Without this, an
envelope could be replayed under a different epoch label.

### A11.4 `targetSdk` and `compileSdk` are 36, not 35

The baseline in A10 said 35. Only platform 36 is installed locally, and `tauri android
init` generated 37, which is not installed at all and fails the Gradle build. Both were
set to **36**, which is newer than 35 and satisfies Play. Bump to 37 once the SDK is
installed.

### A11.5 The map is rendered on canvas, not with MapLibre

`maplibre-gl` was in the original dependency list. It was removed: tiles require a
third-party provider, which is a privacy leak and a rate-limit liability for an app
whose entire premise is that no third party sees anything. The map is drawn locally on
a `<canvas>` with pan, zoom, and range rings, and works offline. A tile layer can be
re-added behind the same component contract if a self-hosted provider is chosen.

### A11.6 `CAMERA` is declared but not yet used

The permission is present for QR invite scanning. Per `docs/play/PLAY_CONSOLE_ANSWERS.md`
§5, **remove it before release if QR scanning does not ship** — a permission with no
matching feature is a common rejection cause.

### A11.7 Windows cannot create the symlink Tauri's Android build needs

`tauri android build` fails at the symlink step unless Windows Developer Mode is on.
Workaround that works without it: build the Rust library for `aarch64-linux-android`
first, copy `libshadow720_lib.so` into
`gen/android/app/src/main/jniLibs/arm64-v8a/`, then run
`gradlew assembleArm64Debug -x rustBuildArm64Debug`. Confirmed output:
`app-arm64-debug.apk`, 8.8 MB.

### A11.8 Live `jaredch` tests skip rather than fail without credentials

A07 said the live suite runs by default. It does — but when `SHADOWTEST_PAT` or
`SHADOWTEST_REPO` is unset it prints a skip notice instead of failing, so a fresh
clone is not red. The destructive test refuses to run unless
`SHADOWTEST_ALLOW_DESTRUCTIVE=1`, and is intentionally unimplemented rather than
merely ignored, so it cannot delete a repository by accident.
