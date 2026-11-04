# Shadow720 — Privacy Policy

**Last updated:** 3 November 2026

Shadow720 is a serverless, end-to-end encrypted group app. This policy describes
what the app does with your information. It is written to satisfy the Google Play
Data Safety requirements and the Play location-permissions policy.

## Summary

- **No server.** There is no backend operated by anyone. The app talks directly to
  GitHub, which stores only encrypted data.
- **No account.** You do not create an account with us. There is nothing for us to
  hold about you.
- **End-to-end encrypted.** Location, messages, member profiles, and shared files
  are encrypted on your device before transmission. The keys never leave your
  device except inside an invite string you choose to share.
- **No analytics, no advertising, no third-party SDKs.** The app contacts exactly
  one external service: GitHub's API.

## What the app collects and where it goes

| Data | Why | Where it is stored | Who can read it |
|---|---|---|---|
| Precise location | To show your position to your group, live | Encrypted, in your group's private GitHub repository | Only devices holding the group key — that is, your group members |
| Messages you send | Group chat | Encrypted, in your group's private GitHub repository | Only devices holding the group key |
| Files you share | Sharing images, voice notes, documents | Encrypted, uploaded to the group's GitHub release storage | Only devices holding the group key |
| Display name and avatar colour | So group members can tell each other apart | Encrypted, alongside your position | Only devices holding the group key |
| Battery level and charging state | So members know why someone stopped updating | Encrypted, alongside your position | Only devices holding the group key |

Every one of these is encrypted on the device with `XChaCha20-Poly1305` and signed
with `Ed25519` before it is transmitted. GitHub stores ciphertext and cannot read
any of it. The app's authors have no technical means to read it either.

## Data that stays on your device only

- Your group's encryption key and the GitHub token used to reach your group's
  repository. Both are held in a locally encrypted vault whose key is wrapped by the
  Android Keystore, so they are protected by the device's hardware security.
- Your block list. Blocking another member is applied locally; nothing is sent
  anywhere, so the blocked person is never told.
- Your consent choices and display preferences.

## Location

Shadow720 collects precise location **only** to share your position with the group
you have joined, and only after you acknowledge the in-app disclosure and grant the
Android permission.

- Location is collected **even when the app is in the background**, so your group
  can see you while you are not looking at the app. A persistent notification is
  shown the entire time this is active.
- Location is encrypted before it leaves your device.
- You can stop sharing at any time: turn off the location permission in Android
  settings, or leave the group, which deletes everything on the device.
- Location is never sold, never used for advertising, and never shared with anyone
  outside your group.

## The GitHub token

To join a group, the app needs read and write access to one specific private GitHub
repository. That access is provided by a **fine-grained token** scoped to that single
repository, which the group's creator supplies.

This token is included inside the invite string. Anyone you give the invite string
to can read the group's encrypted data store and can delete the repository. Only
share an invite with people you trust, over a channel you trust.

The app never sends your token anywhere except `api.github.com` and
`uploads.github.com`, and it is never logged.

## Retention and deletion

- **Leave group and wipe my data** (in the app): deletes your position entry from
  the group, removes your key and token from the device, and erases the local vault.
  The app cannot recover anything afterwards.
- **Destroy group** (group creator only): deletes the entire GitHub repository,
  including every encrypted message, position, and file.
- Because data is encrypted and no server is involved, we cannot delete anything on
  your behalf: there is nothing for us to delete.

## Children

Shadow720 is not directed at children under 13. It does not knowingly collect
information from children.

## Security notes and limitations

- The group key is shared by all members. Removing someone requires rotating the
  key; after a rotation, a removed member can still read content written *before*
  the rotation, because they already hold that older key.
- Anyone holding an invite string holds the group's token, and can therefore delete
  the group's repository. This is an accepted trade-off of having no server.
- If your device is reset or its hardware key is invalidated, the local vault
  becomes unreadable and you will need a fresh invite. This is intentional: it is
  what prevents a copy of the app's files from yielding your keys.

## Changes to this policy

Any material change will be published in the app's listing alongside a new version.
Continuing to use the app after a change means you accept it.

## Contact

Questions about this policy: *<add a contact address before publishing>*.

## Provider

*<add the legal entity name and address that will publish on Google Play>*