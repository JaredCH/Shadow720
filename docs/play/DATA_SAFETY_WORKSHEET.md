# Shadow720 — Data safety worksheet

A fill-in version of the Play Console **Data safety** form, with the reasoning for
each answer. Cross-check it against the console before submitting, because the form's
wording changes between console versions.

Companion documents: [PRIVACY_POLICY.md](./PRIVACY_POLICY.md) ·
[PLAY_CONSOLE_ANSWERS.md](./PLAY_CONSOLE_ANSWERS.md)

The canonical public privacy policy is
<https://jaredch.github.io/shadow720-legal/PRIVACY.md>.

---

## Section 1 — Data collection and security

| Console question | Answer | Why |
|---|---|---|
| Does your app collect or share any of the required user data types? | **Yes** | Location, messages, files, and a display name are collected. |
| Is all of the user data collected by your app encrypted in transit? | **Yes** | Sealed with `XChaCha20-Poly1305` on-device *before* transmission, then sent over WSS/HTTPS. |
| Does your app provide a way for users to request their data be deleted? | **Yes** | "Leave group and wipe my data"; group creators additionally get "Destroy group". |
| Do you have an independent security review? | **No** | Not performed. |
| Do you commit to Play Families policy? | **Yes** | The app is not directed at children. |

---

## Section 2 — Data types

Answer each row as *collected* / *not collected*, and for collected rows also give
purpose, optionality, and sharing.

| Data type | Collected | Shared | Purpose | Required or optional | Encrypted in transit |
|---|---|---|---|---|---|
| Location → Approximate location | Yes | No | App functionality | Optional | Yes |
| Location → Precise location | Yes | No | App functionality | Optional | Yes |
| Personal info → Name | Yes | No | App functionality | Required (a display name is needed to be identifiable in the group) | Yes |
| Personal info → User IDs | Yes | No | App functionality (the member's public key identifies their roster entry) | Required to participate | Yes |
| Messages → In-app messages | Yes | No | App functionality | Optional | Yes |
| Files and docs | Yes | No | App functionality | Optional | Yes |
| Photos and videos | Yes | No | App functionality | Optional | Yes |
| Audio → Voice or sound recordings | Yes | No | App functionality (shared voice notes) | Optional | Yes |
| Device or other IDs | **No** | — | — | — | — |
| App activity → App interactions | **No** | — | No analytics SDK is present | — | — |
| App info and performance → Crash logs, diagnostics | **No** | — | No crash reporting SDK is present | — | — |
| Financial info | **No** | — | No payments of any kind | — | — |
| Contacts | **No** | — | No contact access is requested | — | — |
| Calendar | **No** | — | Not requested | — | — |
| Web browsing | **No** | — | The app has no browser and no ad SDK | — | — |
| Health and fitness | **No** | — | Not collected | — | — |

### Why "shared" is No for every row

Play counts data as *shared* when it is transferred to a third party. Here the only
external services are the Nostr relays and Blossom file servers named in the group's
invite, and they receive ciphertext they cannot decrypt, cannot interpret, and cannot
correlate to a person. Under Play's definition this is not sharing: the data is not
made available to a third party in usable form.

This is worth being able to defend, so the supporting facts are:

- Payloads are encrypted with a group key that exists only on members' devices.
- A relay receives an opaque signed event whose `content` is a Base64 ciphertext.
- A Blossom server receives an opaque blob whose name is its SHA-256.
- No analytics, advertising, crash-reporting, or social SDK is linked into the app
  (`src-tauri/Cargo.toml` and `package.json` are the full dependency list).
- The only outbound hosts are the relays and Blossom servers in the invite, plus the
  OpenStreetMap tile server for the map. All are in the Tauri content-security policy.

---

## Section 3 — Permission inventory

| Permission | Declared | Console form required |
|---|---|---|
| `ACCESS_FINE_LOCATION` | Yes | Location permissions declaration |
| `ACCESS_COARSE_LOCATION` | Yes | Location permissions declaration |
| `ACCESS_BACKGROUND_LOCATION` | Yes | Location permissions declaration **+ demo video** |
| `FOREGROUND_SERVICE` | Yes | Foreground service declaration |
| `FOREGROUND_SERVICE_LOCATION` | Yes | Foreground service declaration |
| `POST_NOTIFICATIONS` | Yes | No separate form |
| `CAMERA` | **No** | — |

`CAMERA` was removed: the app has no camera feature, and a permission that does not
map to a described feature is a common cause of review rejection.

`RECEIVE_BOOT_COMPLETED` and `WAKE_LOCK` appear in the merged manifest because
`tauri-plugin-notification` declares them. The app registers no boot receiver and
does not start tracking on boot.

---

## Section 4 — Target audience and content

| Question | Answer |
|---|---|
| Target age group | 18 and over |
| Appeals to children? | No |
| Contains ads? | No |
| Uses an advertising ID? | No |
| In-app purchases? | No |

Rationale: the app publishes a user's live location to a group of other adults. That
is inappropriate for a general audience, so the age band is set to 18+ deliberately
rather than opportunistically.

---

## Section 5 — Pre-submission checklist

- [x] Privacy policy URL is public and reachable without sign-in:
      <https://jaredch.github.io/shadow720-legal/PRIVACY.md>
- [x] The URL in the Play listing matches the published policy.
- [x] The policy has a real contact address and provider, not placeholders.
- [x] The privacy policy is linked from inside the app (Settings → About, and both
      consent-gate stages).
- [ ] Demo video is uploaded and its URL is entered in the location declaration.
      *(Recording complete: `demo/Shadow720_demo.mp4`, 3:23, 1080×2400 — upload
      pending.)*
- [x] The disclosure wording in the shipped build matches
      [PLAY_CONSOLE_ANSWERS.md](./PLAY_CONSOLE_ANSWERS.md) §2 and the video.
- [x] Terms and disclosure gates are reachable on a **fresh install** (verified
      during the demo recording: `pm clear` → gates appear in order).
- [x] The persistent foreground-service notification is present whenever background
      location is active (verified on camera in the demo, shot 12).
- [x] `CAMERA` is removed from the manifest.
- [ ] The app collects nothing before the consent gates are cleared (verify by
      watching network traffic on a fresh install with no group joined).
- [x] A `targetSdk` of 35 or newer is in the release build (36).
- [x] The release artifact is a signed `.aab`, not an APK.
- [x] `versionCode` in the bundle is greater than the last uploaded one.
