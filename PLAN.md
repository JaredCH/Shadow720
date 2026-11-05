# PLAN.md — Serverless E2EE Android Group App

> **Superseded.** This is the original design record, kept for history. The GitHub
> backend it describes has been removed: Nostr relays are now the only storage path,
> and there is no account, no token, and no repository. See [README.md](./README.md)
> for how the app actually works today.

Master plan. Original spec lives at [Shadow720/PLAN.md](../../../../Shadow720/PLAN.md); the review decisions are folded in below and also staged separately as [PLAN_ADDENDUM_v1.md](./PLAN_ADDENDUM_v1.md).

**Target:** production-grade, 100% serverless Android app — Tauri v2 (Rust core + TypeScript/Vite UI), GitHub Issues + Release Assets as the database, Google Play Store ready.

**Approach in one line:** The app provisions a private GitHub repo itself, then talks to the GitHub REST v3 API directly with a repo-scoped fine-grained PAT; everything (GPS, chat, profiles, files) is encrypted and signed client-side so GitHub only ever stores ciphertext.

---

## 1. Locked decisions (from review)

| Decision | Choice |
|---|---|
| Repo + PAT provisioning | App **provisions the repo itself** via `POST /user/repos`, after a one-button **OAuth device-flow sign-in**. No token pasting. Optional repo-scoped token for tighter invites |
| Background location | **In scope** — adds `ACCESS_BACKGROUND_LOCATION` + Play declaration + demo video |
| Member removal | **In scope** — host can rotate the group key and re-issue invite strings |
| Secret storage | **Stronghold + Keystore-wrapped vault password** |
| Poll cadence | **Latency-lean**: chat 10 s, roster 30 s, with jitter + adaptive backoff |
| PAT expiry | **In-app host-only "Re-key Group"** flow that re-issues invite strings |
| SDK levels | `minSdk 26`, `targetSdk 35`, `compileSdk 35` |
| Testing | **Live integration tests against `jaredch` on by default** |
| Invite delivery | Copy/paste **+ QR scan** (adds `CAMERA` + declaration) |
| Build order | **All 7 deliverables in one pass**, written in dependency order |

---

## 2. Role & execution directives

* **Strict code quality:** panic-free, memory-safe Rust. No `.unwrap()` / `.expect()` in runtime code. All fallible operations return `Result<T, AppError>` via `thiserror`.
* **Zero server / zero VPS:** client → GitHub REST v3 over HTTPS (`reqwest` + `rustls-tls`). No middleware.
* **Total E2EE:** GitHub is an untrusted ciphertext store. Every coordinate, message, profile, and binary is encrypted client-side with `XChaCha20-Poly1305` and signed with the sender's `Ed25519` key before transmission.

---

## 3. Onboarding, auth & invite token

### 3.1 Provisioning

* **Host:** picks a repository host in-app and presses **Sign in**. The app creates the **private** repo, both schema issues, and the `vault-v1` release. Providers are grouped by account requirement; GitHub is the only one implemented.
* **Sign-in:** OAuth 2.0 device flow. Fine-grained PATs cannot be minted via API, so this is the only way to keep setup inside the app. The `client_id` is public by design for this grant.
* **Two-phase tokens:** the signed-in account token creates the repo and is held only in Rust memory; an optional repo-scoped token is what the vault and invite carry.
* **Host PAT:** fine-grained, scoped to that one repo:
  * `Contents: Read/Write`
  * `Issues: Read/Write`
  * `Administration: Read/Write` (required for in-app Destroy Group — `DELETE /repos/{owner}/{repo}`)
* **Guests:** no GitHub account. They paste a self-contained invite string (`GRP1-…`) and enter the Join Password.
* Accepted risk: the PAT is embedded in the invite, so **every guest can destroy the repo**. Mitigated by rotation (A3) and documented in the Play/privacy copy.

### 3.2 Invite token (`GRP1` format)

1. Host generates a random 256-bit `group_master_key: [u8; 32]`.
2. Payload is packed and compressed (`zstd`):

   ```rust
   #[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
   pub struct InviteCredentialsPayload {
       pub version: u8,                  // 1
       pub repo_owner: String,
       pub repo_name: String,
       pub repo_scoped_pat: String,      // fine-grained PAT, this repo only
       pub group_master_key: [u8; 32],
       pub roster_issue_num: u64,        // Issue #1
       pub chat_issue_num: u64,          // Issue #2
       pub release_id: u64,              // "vault-v1"
       pub repo_created: bool,           // true when the app provisioned it
   }
   ```

3. Wrapping key = `Argon2id(join_password, salt_16B, m_cost = 19456, t_cost = 2, p_cost = 1)`.
4. Compressed payload encrypted with `XChaCha20-Poly1305`, 24-byte random nonce.
5. Output: `GRP1-` + `BASE64URL_NO_PAD(salt_16B ‖ nonce_24B ‖ ciphertext+tag)`.

### 3.3 Invite delivery

* Copy/paste string, **plus** QR:
  * QR **display** needs no permission.
  * QR **scanning** needs `CAMERA` + a Play Data Safety declaration.
  * QR must degrade gracefully to copy/paste if the camera is unavailable or denied.

### 3.4 Secret storage at rest

* Stronghold vault holds the PAT and `group_master_key`.
* Vault password = 32 random bytes from first launch, stored **only** wrapped by an Android Keystore AES-GCM key.
* Custom Kotlin plugin (`KeystoreVaultPlugin`) exposes exactly `wrap_secret(bytes)` / `unwrap_secret(Vec<u8>)`. No broader Keystore surface.
* All secret types derive `Zeroize` + `ZeroizeOnDrop`; invite strings zeroized right after parse.
* Keystore key invalidated (device reset) ⇒ vault is treated as lost, fresh invite required.

---

## 4. Storage engine: GitHub Issues & Release Assets

No commits to the Git tree — this is what avoids `409 Conflict` races and `.git` bloat.

| Table | GitHub primitive | Operation |
|---|---|---|
| Member roster + live location | `Issue #1`, one comment per member | `POST /issues/1/comments` on join, then atomic `PATCH /issues/comments/{my_comment_id}` for every update |
| Group chat + file pointers | `Issue #2` comments | `POST /issues/2/comments` per message |
| Encrypted binary vault | `vault-v1` release assets | `POST https://uploads.github.com/repos/{o}/{r}/releases/{release_id}/assets?name={uuid}.bin` |

* Each member only ever `PATCH`es its **own** comment id, so 50 concurrent phones never collide and produce zero Git commits.
* After a file upload, a `kind: "file_attachment"` envelope is posted to Issue #2.

---

## 5. Cryptographic wire format

```rust
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncryptedEnvelope {
    pub v: u8,                  // protocol version = 1
    pub key_epoch: u8,          // group-key epoch; 0 for the original key
    pub sender_pubkey: String,  // Base64 Ed25519 verifying key (32 B)
    pub nonce: String,          // Base64 XChaCha20 nonce (24 B)
    pub ciphertext: String,     // Base64 XChaCha20-Poly1305 InnerPayload
    pub signature: String,      // Base64 Ed25519 sig over the canonical input below
}
```

**Canonical signature input (length-prefixed, fixed):**

```
sig_input = u8::to_le_bytes(v)
            ‖ u32::to_le_bytes(sender_pubkey.len()) ‖ sender_pubkey
            ‖ u32::to_le_bytes(nonce.len())         ‖ nonce
            ‖ u32::to_le_bytes(ciphertext.len())    ‖ ciphertext
```

**Encoding:** envelope fields = Base64 **standard, padded**; `GRP1-` invite = Base64URL **no-pad**. Deliberately different — do not unify.

**Decrypted `InnerPayload` variants:**

* **Issue #1 (Location State):** `display_name`, `avatar_color`, `lat`, `lon`, `accuracy_m`, `speed_mps`, `heading_deg`, `battery_pct`, `is_charging`, `unix_ms`.
* **Issue #2 (Chat & File Stream):** `ChatEventPayload` enum — `TextMessage`, `FileAttachment`, `ModerationFlag`.

**Required test:** flipping any single bit in `ciphertext`, `nonce`, or `key_epoch` must make `open()` fail.

---

## 6. Rate-limit & quota engineering

Shared 5,000 req/hr PAT budget across the whole group.

1. **ETag conditional polling:** `DashMap<String, (String, Bytes)>` maps URL → `(ETag, cached bytes)`; send `If-None-Match` on every poll. `304` costs no quota.
2. **Cadence (ceiling, not floor):** chat **10 s**, roster **30 s**, foregrounded.
3. **Mandatory cushion:**
   * ±25% random jitter on every interval (anti thundering-herd).
   * Single-flight, serialized request queue per client.
   * `429`, or `403` with `x-ratelimit-remaining: 0` ⇒ halt polling until `x-ratelimit-reset` + 60 s, show a "sync paused" banner.
   * Adaptive backoff: last 3 polls of a channel returned `304` ⇒ double that interval, capped at 5 min.
   * **No cold-start burst:** never fire roster + chat + assets in parallel on launch.
4. **Haversine movement gate:** skip location `PATCH` unless ≥ 30 s elapsed **and** ≥ 15 m moved, or 15 min elapsed (heartbeat).
5. **Quota pruner:** ≤ **15 MB** per file, ≤ **500 MB** total vault. Before upload, list assets and `DELETE /releases/assets/{asset_id}` oldest-first until under budget.

---

## 7. Key rotation, removal & recovery

* **Rotate Group Key** (host): new `group_master_key`, rebuild each member's `GRP1` invite, record the retired key's epoch in a `rekey` comment on Issue #1.
* **Remove Member** (host): delete that member's Issue #1 comment, then force rotation.
* **Re-key Group** (host, PAT expiry): paste a new PAT, re-issue invite strings, group key untouched. Shares UI with rotation.
* Client keeps a bounded `DashMap<u8, Zeroizing<[u8; 32]>>` of historical group keys so old content stays readable.
* Documented limitation: a removed member holding an old invite keeps the old epoch key; rotation only protects content written afterwards.

---

## 8. Google Play compliance

### 8.1 Manifest

```xml
<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_COARSE_LOCATION" />
<uses-permission android:name="android.permission.ACCESS_BACKGROUND_LOCATION" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
<uses-permission android:name="android.permission.FOREGROUND_SERVICE_LOCATION" />
<uses-permission android:name="android.permission.POST_NOTIFICATIONS" />
<uses-permission android:name="android.permission.CAMERA" />

<application ...>
    <service
        android:name=".LocationForegroundService"
        android:foregroundServiceType="location"
        android:exported="false" />
</application>
```

* `POST_NOTIFICATIONS` is required on API 33+ for the foreground-service notification to render.

### 8.2 Required UI & compliance features

1. **First-launch EULA gate:** un-dismissable modal prohibiting illegal content, harassment, copyright infringement.
2. **Prominent location disclosure** — blocking, shown **before** the OS prompt:
   > *"This app collects location data to enable live group sharing with your connected group members, even when the app is in use. All location telemetry is end-to-end encrypted locally before transmission. No location data is ever stored on third-party servers."*
3. **Permission order:** disclosure → fine + coarse → (explicit user action) background.
4. **UGC moderation:**
   * **Block / Mute** — store sender `Ed25519` pubkey locally; hide their chat, files, and map pin.
   * **Report** — flag objectionable messages; host can `DELETE /issues/comments/{id}`.
5. **Data deletion:**
   * **"Leave Group & Wipe My Data"** — delete own Issue #1 comment, zeroize keys, purge local storage.
   * **"Destroy Group"** (host) — `DELETE /repos/{owner}/{repo}`.
6. **Play Console artifacts:** Data Safety declaring location collection with no third-party sharing; location permission declaration form; **demo video** of the in-app disclosure + runtime request.

---

## 9. Deliverables

Dependency-ordered; all produced in one pass, each stage compiling before the next.

1. `src-tauri/Cargo.toml` (pinned) + `src-tauri/src/error.rs` (`AppError`, `serde::Serialize`)
2. `src-tauri/src/crypto.rs` — Ed25519, Argon2id, XChaCha20-Poly1305, invite pack/unpack, envelope seal/open, epoch tags (unit tests alongside)
3. `src-tauri/src/geo_filter.rs` — Haversine 15 m gate, 30 s cooldown, adaptive backoff (unit tests alongside)
4. `src-tauri/src/github_db.rs` — ETag `DashMap` cache, Issue #1/#2 handlers, release asset pruner, rotation, data wiper
5. `src-tauri/src/lib.rs` — `#[tauri::command]` handlers wired to state
6. `src-tauri/tauri.conf.json` + `gen/android` + `LocationForegroundService.kt` + `KeystoreVaultPlugin.kt`
7. `src/App.tsx` — mobile-first TS/Tailwind: onboarding, consent gates, MapLibre map, chat drawer, file vault, QR, moderation controls

---

## 10. Testing

* **Live integration tests against `jaredch` run by default.**
* `SHADOWTEST_PAT` + `SHADOWTEST_REPO` must both be set or a live test binary refuses to start.
* Use a **dedicated sandbox repo**, not the primary group repo.
* Tests **redact** the PAT and all ciphertext from logs; `.env` / `*.pat` gitignored from step 0.
* Guard: assert `x-ratelimit-remaining > 500` before running; abort if lower.
* Destructive cases are `#[ignore]` unless `SHADOWTEST_ALLOW_DESTRUCTIVE=1`.
* Only the mocked suite would run in CI, if CI is added later.

---

## 11. Toolchain baseline

* `minSdk 26`, `targetSdk 35`, `compileSdk 35`.
* Tauri v2 (`tauri android init`), Rust stable, `aarch64-linux-android`, NDK `r27`.
* **Step 0 of implementation:** verify Rust / NDK / JDK / `gh` auth. Not an assumption.

---

## 12. Open questions (to resolve before or during implementation)

1. **Product name / Android applicationId** — placeholder `com.shadow720.app` until confirmed.
2. **Join Password policy** — enforce a minimum strength, or accept anything since Argon2id is expensive?
3. **Map tiles** — MapLibre needs a tile source. OSM public tiles are rate-limited and not intended for production; use a paid/self-hosted provider, or bundled offline style + user-supplied key?
4. **Avatar** — generated colour + initials (no PII, recommended), or an encrypted uploaded image routed through the vault?
5. **Signing / release** — Play upload keystore: generate locally, or via Play App Signing?
6. **`jaredch` details** — is that the GitHub account that will provision the sandbox repo, and is the group repo distinct from it?
