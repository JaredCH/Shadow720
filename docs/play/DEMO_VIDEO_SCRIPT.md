# Shadow720 — Demo video shot list

Play requires a demo video for the **background location** declaration. It must show
the in-app disclosure and the runtime permission request *in context*, so a reviewer
can see that the user is told why before the OS asks.

Keep the recording under 90 seconds. Record on a physical device, portrait, with the
screen recorder's notification hidden, and do not rehearse your way past the
permission dialog — a reviewer needs to see it appear.

Companion documents: [PRIVACY_POLICY.md](./PRIVACY_POLICY.md) ·
[PLAY_CONSOLE_ANSWERS.md](./PLAY_CONSOLE_ANSWERS.md)

---

## Preconditions

- Fresh install, or clear app data, so the first-launch gates appear.
- Location permission **not yet granted** for the app.
- A second device already in the group, so the map shows another member's pin.
- Notification permission **not yet granted**, so that dialog is visible too.
- Background location **not yet granted**, so the settings trip is visible.
- Device language set to English.

---

## Shot list

| # | Time | On screen | Voice-over / caption |
|---|---|---|---|
| 1 | 0:00–0:06 | App launches to the Terms gate. Reviewer sees the app name and that it blocks. | "Shadow720 is a live group map with no server. First launch shows the terms of use." |
| 2 | 0:06–0:14 | Scroll the terms to the end, then tap **I agree**. | "The user must read and accept the terms before anything else, as required for user-generated content." |
| 3 | 0:14–0:26 | The location disclosure sheet appears. Read it slowly enough to be legible. | Read the disclosure aloud: "…collects location data to enable live group sharing with your connected group members, even when the app is in use. All location telemetry is end-to-end encrypted locally before transmission. No location data is ever stored on third-party servers." |
| 4 | 0:26–0:30 | Tap **I understand and agree**. | "The disclosure comes before any permission request." |
| 5 | 0:30–0:36 | Display-name sheet, type a name, continue. | "Only a display name is needed. There is no account." |
| 6 | 0:36–0:44 | Create sheet: name the group, tap **Create group**. | "A group is created with just a name. No account signup, no server." |
| 7 | 0:44–0:56 | **OS permission dialog appears** for location. Grant it. | "Only now does Android ask for location, because the user has just been told why it is needed." |
| 8 | 0:56–1:04 | The map appears with this device plus the second member's pin; this device's pin moves as you walk a few steps. | "Positions are encrypted on the device before they are sent, and the other members' pins update live." |
| 9 | 1:04–1:12 | Open the chat tab, send a message, show it arriving on the second device. | "Chat is encrypted the same way." |
| 10 | 1:12–1:22 | Settings → toggle **Share in the background**. The notification permission dialog appears; grant it. Then the app explains that "Allow all the time" is needed and opens the permission page. Choose **Allow all the time**, return to the app. | "Background sharing asks for notifications first, because Android would otherwise hide the notice that tracking is running. Then it explains that background location is a separate grant and takes the user straight to it." |
| 11 | 1:22–1:30 | Lock the phone. Then, on the second device, show this device's pin still moving. | "This is the background behaviour the permission is for: the position keeps updating while the screen is off." |
| 12 | 1:30–1:36 | Show the persistent foreground-service notification, then pull down and show it is still present. | "A permanent notification is shown for as long as background sharing is running." |
| 13 | 1:36–1:44 | Settings → **Leave group and wipe my data** → confirm. App returns to the join screen; notification is gone. | "Stopping is one action: leaving deletes the user's entry and erases every key from the device, and the tracking notification disappears." |

---

## Narration script (continuous read)

> Shadow720 is a live group map with no server. On first launch the user sees the
> terms of use and must read them before continuing.
>
> Next, before Android is allowed to ask for anything, the app explains exactly what
> location sharing does: it collects location to enable live group sharing with
> connected group members, even while the app is in use, and everything is encrypted
> on the device first, with nothing stored on third-party servers.
>
> Once that is acknowledged, the user picks a display name — there is no account —
> and creates a group with a name and a password.
>
> Only now does Android request location, because the user has just been told why.
>
> On the map, this device's position and another member's position are both live.
> Positions are encrypted before they leave the phone. The same is true for chat.
>
> Turning on background sharing asks for notifications first, because Android would
> otherwise hide the notice that tracking is running. It then explains that
> background location is a separate grant and takes the user straight to the
> permission page, where they choose "Allow all the time".
>
> Here the screen is locked, and the position keeps updating — that is the behaviour
> background location is for. A permanent notification is displayed the whole time it
> is active, so the user always knows.
>
> Leaving the group is a single action: it deletes the user's entry from the group
> and erases every key from the device, and the tracking notification stops.

---

## What the reviewer must be able to see

Tick these off before uploading:

- [x] The in-app disclosure appears **before** the OS permission dialog.
- [x] The disclosure text is legible on screen.
- [x] The OS dialog itself is visible, not cut away.
- [x] The permission is granted on camera.
- [x] The notification permission is requested before background sharing starts.
- [x] The background-location settings trip is shown, and "Allow all the time" is
      chosen on camera.
- [x] The map shows real, moving positions after the grant.
- [x] Background behaviour is demonstrated with the screen locked.
- [x] The foreground-service notification is visible while tracking runs.
- [x] The user can stop tracking, and the notification disappears.

> Captured 2026-05-11 on emulator (Medium_Phone_API_36.1, Android 16, arm64),
> 1080×2400 @ 30fps, H.264 MP4, 3:23. Source segments in `demo/trimmed/`,
> final cut `demo/Shadow720_demo.mp4`. Recorded on an emulator rather than a
> physical device — acceptable for the location declaration, but re-record on a
> physical device if a reviewer asks for real-GPS footage.

---

## Upload checklist

- [x] Record at 1080p or better, portrait, H.264 MP4.
- [ ] Upload to a URL that does not require sign-in (an unlisted video works).
- [ ] Paste that URL into the Play Console location-permissions declaration.
- [x] Confirm the same disclosure wording appears in the app build being reviewed.
