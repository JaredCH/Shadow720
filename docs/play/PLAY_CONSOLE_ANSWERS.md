# Shadow720 — Play Console declarations

Field-by-field answers for the Google Play Console submissions that this app needs.
Copy each block into the matching Console form.

Companion documents: [PRIVACY_POLICY.md](./PRIVACY_POLICY.md) ·
[DEMO_VIDEO_SCRIPT.md](./DEMO_VIDEO_SCRIPT.md) ·
[DATA_SAFETY_WORKSHEET.md](./DATA_SAFETY_WORKSHEET.md)

The canonical public privacy policy lives at
<https://jaredch.github.io/shadow720-legal/PRIVACY.md> and is what the Play listing
must point at.

---

## 1. App content declarations

### Data safety → Data collection and security

**Does your app collect or share any of the required user data types?** — Yes.

Because data is collected, the following answers apply.

**Is all of the user data collected by your app encrypted in transit?** — Yes.

Every payload is sealed on-device with `XChaCha20-Poly1305` before transmission, so
the data is encrypted *before* it enters the transport as well as during it. The
transport itself is WSS/HTTPS with `rustls`.

**Do you provide a way for users to request that their data is deleted?** — Yes.

In-app: **Leave group and wipe my data** retracts the user's entry from the group and
erases every key on the device. Group creators additionally get **Destroy group**,
which publishes a signed closure notice so every member's device wipes its copy.

**Data safety → Data types**

| Question | Answer |
|---|---|
| Location → Approximate location | Collected (yes), Shared (no) |
| Location → Precise location | Collected (yes), Shared (no) |
| Personal info → Name | Collected (yes), Shared (no) |
| Personal info → User IDs | Collected (yes), Shared (no) |
| Messages → In-app messages | Collected (yes), Shared (no) |
| Files and docs | Collected (yes), Shared (no) |
| Photos and videos | Collected (yes), Shared (no) |
| Audio (voice notes) | Collected (yes), Shared (no) |
| Device or other IDs | **Not collected** |

For every "collected" row:

- **Collected or shared:** Collected. It is **not** shared, because it is never
  transmitted to a third party in a readable form — relays receive only ciphertext
  of which they cannot make use. Under Play's definition, ciphertext sent to a
  service the app developer does not control or read is not "shared".
- **Purpose:** App functionality (and, for location, only live group position
  sharing). Never for advertising, analytics, or personalisation.
- **Optional or required:** Optional. No collection happens before the user
  acknowledges the in-app disclosures and grants permission, and location can be
  withheld while still using the app's other features.
- **Encrypted in transit:** Yes — end-to-end encrypted on device, so yes.

**Data safety → Security practices**

| Question | Answer |
|---|---|
| Data is encrypted in transit | Yes |
| You provide a way for users to request deletion | Yes |
| Data is committed to follow Play Families policy | Yes (app is not directed at children) |
| Independent security review | No |
| Data is encrypted at rest on the device | Yes — the local vault is AEAD-encrypted with a key wrapped by the Android Keystore |

---

## 2. Location permissions declaration

### Why does your app need access to location?

> Shadow720 is a live group-position-sharing app with no server. A user joins a
> private group and shares their location so the other members of that group can see
> where everyone is. Location is the core function of the app: without it there is
> nothing to show on the shared map.

### How is the location data used?

> Exclusively to display each member's position to the other members of the same
> private group, on a map inside the app. Position updates also carry a battery
> level, so members understand why someone's position has stopped updating.
> The app performs no analytics and no advertising.

### Why does your app need **background** location access?

> Group members expect each other's positions to stay current while they are not
> actively looking at the app — the same expectation a messaging app sets for
> messages. With foreground-only access, a member's pin freezes the moment they lock
> their phone, which makes the shared map misleading. Background access is what lets
> the position keep updating while the screen is off.
>
> While background location is active, a persistent foreground-service notification
> is always shown, so the user can see that tracking is running and stop it with one
> tap. Tracking stops if the user revokes the permission or leaves the group.

### What happens if the user does not grant location permission?

> They can still join a group and use encrypted chat and file sharing. Their own
> position is simply not shared, and no network requests containing location are
> made. Every other feature works.

### Play policy compliance notes

- Background location is requested **only after** an explicit in-app disclosure and
  only on a user-initiated action, never on first launch.
- The disclosure text is shown on screen before the OS permission dialog, and the
  demo video captures both in sequence.
- On Android 11+ the background grant is a settings trip, not a dialog. The app
  detects the missing grant and sends the user to the app's permission page rather
  than silently failing.
- The app displays a persistent notification for the entire duration that background
  location is active, and stopping it is a single in-app action.
- `POST_NOTIFICATIONS` is requested before background sharing is enabled, because a
  suppressed notification would violate the "user must always see it" requirement.

---

## 3. Foreground service declaration

### Which foreground service type does your app use?

`location`.

### Why is the foreground service needed?

> To continue publishing the user's encrypted position to their private group while
> the app is not in the foreground. The service is what keeps the update cadence
> alive with the screen off, and its notification is what makes that visible and
> controllable to the user.

### Permissions declared

```
android.permission.INTERNET
android.permission.ACCESS_FINE_LOCATION
android.permission.ACCESS_COARSE_LOCATION
android.permission.ACCESS_BACKGROUND_LOCATION
android.permission.FOREGROUND_SERVICE
android.permission.FOREGROUND_SERVICE_LOCATION
android.permission.POST_NOTIFICATIONS
```

`POST_NOTIFICATIONS` is required on Android 13+ for the foreground-service
notification to be visible, which the location policy requires.

`RECEIVE_BOOT_COMPLETED` and `WAKE_LOCK` appear in the merged manifest because
`tauri-plugin-notification` declares them. The app does not register a boot receiver
and does not start tracking on boot.

There is **no** `CAMERA` permission: the app has no camera feature.

---

## 4. User-generated content

Shadow720 hosts user-generated content, so Play requires moderation controls. All of
these are implemented:

| Requirement | Implementation |
|---|---|
| Terms accepted before use | Un-dismissable first-launch gate prohibiting illegal content, harassment, and copyright infringement. The user must scroll the terms and explicitly accept. |
| Report objectionable content | Any member can report a message. The report is encrypted and published to the group, and the group's creator can act on it. |
| Block a user | Blocking is local and immediate: the blocked member's messages, files, and map pin disappear at once. Nothing is transmitted, so the blocked person is not notified. |
| Delete content | Any member can retract their own events. Leaving the group removes the member's entry. |
| Contact the developer | The Play listing contact address is used for enforcement escalation. |

---

## 5. Sensitive-permission summary

| Permission | Declaration needed | Provided |
|---|---|---|
| `ACCESS_FINE_LOCATION` | Location permissions form | Yes, §2 |
| `ACCESS_BACKGROUND_LOCATION` | Location permissions form + video | Yes, §2 and the video script |
| `FOREGROUND_SERVICE_LOCATION` | Foreground service declaration | Yes, §3 |
| `POST_NOTIFICATIONS` | None (runtime permission) | Yes, §3 |
| `CAMERA` | **Not declared** — the app has no camera feature | — |

---

## 6. Advertising and monetisation

| Question | Answer |
|---|---|
| Does the app contain ads? | No |
| Does the app use an advertising ID? | No |
| In-app purchases | None |
| Target audience | 18+ (live location sharing between adults in a private group) |

---

## 7. Store listing copy

**Short description (≤ 80 characters):**

> End-to-end encrypted group map and chat. No servers, no accounts.

**Full description:**

> Shadow720 shows your private group on a live map and lets you chat and share
> files — with no server anywhere in the middle.
>
> Everything is encrypted on your device before it is stored. Your position,
> messages, and shared files are sealed with XChaCha20-Poly1305 and signed with
> Ed25519, so the relays that hold them see only unreadable ciphertext. Nobody other
> than your group members — not the relay operators, not us — can read any of it.
>
> HOW IT WORKS
> • One person creates a group and shares a single group code with the members.
> • Members do not need any account. Paste the code and join.
> • Your position appears on the others' maps, updating as you move.
> • Chat and file sharing work the same way: encrypted before they leave your phone.
>
> WHY THERE IS NO SERVER
> A server would be a single place where everyone's data could be read or demanded.
> Shadow720 has no such place. There is no company account to breach and no
> operational database of your movements.
>
> WHAT YOU CONTROL
> • An un-dismissable disclosure explains exactly what location sharing does before
>   you ever see a permission prompt.
> • Background sharing is opt-in, shows a permanent notification, and stops with one
>   tap.
> • Block any member instantly and locally; they are never told.
> • Report a message; group creators can act on it.
> • Leave the group and every key is erased from your device.
> • Create a group and you can close it for everyone.
>
> PRIVACY
> No analytics. No advertising. No third-party SDKs. The app talks only to the Nostr
> relays and file servers named in your group's invite, and they see only ciphertext.
>
> Full privacy policy: https://jaredch.github.io/shadow720-legal/PRIVACY.md
