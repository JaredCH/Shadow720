# Shadow720 — Privacy Policy

**Last updated:** 5 November 2026

The canonical, publicly hosted version of this policy is
<https://jaredch.github.io/shadow720-legal/PRIVACY.md>. That URL is what the Play
listing points at. This copy is kept in the repository so a change to the app and a
change to the policy land in the same commit.

Shadow720 is a serverless, end-to-end encrypted group app for sharing your location
and messages with a group you choose. This policy explains exactly what the app does
with your information. It is written to satisfy the Google Play Data Safety
requirements and the Play location-permissions policy.

## Summary

- **No server of ours.** There is no backend operated by the developer. The app talks
  directly to public Nostr relays, which store only encrypted data.
- **No account.** You do not create an account. There is nothing for us to hold about
  you.
- **End-to-end encrypted.** Location, messages, member profiles, and shared files are
  encrypted on your device before transmission. The keys never leave your device
  except inside an invite string you choose to share.
- **No analytics, no advertising, no third-party SDKs.** The app contacts only the
  Nostr relays and Blossom file servers named in your group's invite, plus the map
  tile server.

## What the app collects and where it goes

| Data | Why | Where it is stored | Who can read it |
|---|---|---|---|
| Precise location | To show your position to your group, live | Encrypted, on the group's Nostr relays | Only devices holding the group key — that is, your group members |
| Messages you send | Group chat | Encrypted, on the group's Nostr relays | Only devices holding the group key |
| Files you share | Sharing images, voice notes, documents | Encrypted, uploaded to the group's Blossom servers | Only devices holding the group key |
| Display name and avatar colour | So group members can tell each other apart | Encrypted, alongside your position | Only devices holding the group key |
| Battery level and charging state | So members know why someone stopped updating | Encrypted, alongside your position | Only devices holding the group key |

Every one of these is encrypted on the device with `XChaCha20-Poly1305` and signed
with `Ed25519` before it is transmitted. Relays store ciphertext and cannot read any
of it. The app's developer has no technical means to read it either.

## Data that stays on your device only

- Your group's encryption key and your Nostr signing key. Both are held in a locally
  encrypted vault whose key is wrapped by the Android Keystore, so they are protected
  by the device's hardware security.
- Your block list. Blocking another member is applied locally; nothing is sent
  anywhere, so the blocked person is never told.
- Your location history. The app keeps a local track log so you can see where your
  group has been. It is never published, and it is deleted when you leave the group.
- Your consent choices and display preferences.

## Location

Shadow720 collects precise location **only** to share your position with the group
you have joined, and only after you acknowledge the in-app disclosure and grant the
Android permission.

- Location is collected **even when the app is in the background**, so your group can
  see you while you are not looking at the app. A persistent notification is shown the
  entire time this is active, and it has a Stop button.
- Background location requires the "Allow all the time" permission, which you grant
  yourself in Android settings. The app cannot grant it for you.
- Location is encrypted before it leaves your device.
- You can stop sharing at any time: turn off the location permission in Android
  settings, tap Stop on the notification, or leave the group, which deletes everything
  on the device.
- Location is never sold, never used for advertising, and never shared with anyone
  outside your group.

## Battery

Background location is deliberately conservative. The app asks Android for a fix only
after you have moved a meaningful distance, widens the interval when you are
stationary, and widens it further when the battery is low and the phone is not
charging. A phone sitting on a desk costs almost nothing.

## Nostr relays and Blossom servers

The app stores encrypted data on public Nostr relays and encrypted files on Blossom
servers. These are third-party services, chosen by whoever created your group and
listed in the invite.

- Relays and Blossom servers see ciphertext, your public key, and the timing of your
  updates. They cannot read your location, messages, or files.
- They do not receive your name, email address, phone number, or any account
  identifier, because the app never collects them.
- The app's developer does not operate these services and cannot delete data from them
  on your behalf.

## Retention and deletion

- **Leave group and wipe my data** (in the app): retracts your position entry from the
  group, removes your keys from the device, and erases the local vault and track log.
  The app cannot recover anything afterwards.
- **Destroy group** (group creator only): publishes a signed closure notice so every
  member's device wipes its copy. Relay copies may remain, because relays are
  independent third parties that the app cannot compel.
- Because data is encrypted and no server of ours is involved, we cannot delete
  anything on your behalf: there is nothing for us to delete.

## Children

Shadow720 is not directed at children under 13. It does not knowingly collect
information from children.

## Security notes and limitations

- The group key is shared by all members. Removing someone requires rotating the key;
  after a rotation, a removed member can still read content written *before* the
  rotation, because they already hold that older key.
- Anyone holding a group code can join the group and read everything the group key
  protects. The code is the secret: share it only with people you trust.
- If your device is reset or its hardware key is invalidated, the local vault becomes
  unreadable and you will need a fresh invite. This is intentional: it is what
  prevents a copy of the app's files from yielding your keys.
- Relays are third parties. They may retain copies of ciphertext after a deletion
  request, and they may go offline, taking that copy with them.

## Changes to this policy

Any material change will be published here and in the app's Play listing alongside a
new version. Continuing to use the app after a change means you accept it.

## Contact

Questions about this policy: **jaredch@users.noreply.github.com**

## Provider

Shadow720 is published by JaredCH, an individual developer.
