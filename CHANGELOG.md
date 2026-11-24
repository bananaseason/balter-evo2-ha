# Changelog

## 1.1.1 (2026-11-24)

### Changed

- A live view that somebody opened now ends one second after the last viewer closed it
  (was four), so the station is free again practically at once.

### Notes

- Every open MJPEG feed counts as a viewer. If a live view keeps running after you closed
  it, something else is still showing the feed: typically a wall tablet or a second
  dashboard with a `camera_view: live` card. Show the live card only on demand (see the
  README).

## 1.1.0 (2026-11-24)

The first version that was run against a real station for longer than a snapshot. It
replaces the guessed parts of the stream parser with the real frame layout and changes how
the camera uses the station.

### Fixed

- **Live view was a broken slideshow.** Frame boundaries were searched for instead of read,
  and the station's audio packets were handed to the video decoder. The picture showed
  blocks and smears and moved about once every second or two. Frames are now cut exactly
  where the frame head says, and only video reaches the decoder: about 18 frames a second,
  no artefacts.
- **The door opener did nothing for up to a minute and then reported a failure.** Two
  causes: every command waited out a 60-second "recovery" pause after the previous session,
  and the station's acknowledgement was lost because the ~830-byte profile frame the station
  sends after the login was read with a one-byte length. The pause is now two seconds (the
  station needs about one) and the acknowledgement is read. An unlock takes about half a
  second.
- **A refused door command was reported as "not acknowledged".** The station answers a
  wrong door PIN with a refusal; that answer is now read and reported as a wrong PIN, and
  "unlocked" is shown only when the station says it opened.
- A still image took several seconds; it now takes about half a second (the first keyframe
  is used as soon as it is there).
- A session that the station opened without video (reconnected to too quickly, or somebody
  else is watching) is noticed and tried once more instead of delivering nothing.

### Changed

- **The camera no longer contacts the station to keep a dashboard picture fresh.** It shows
  a stored still, the last frame of the latest live view, which also survives a restart. The
  option *Refresh the still image after* brings periodic refreshes back for those who want
  them; its default is 0 = never. Before, an open dashboard reconnected to the station every
  90 seconds, which kept the phone app and the indoor monitor out for part of that time.
- **A live view that somebody opened ends a few seconds after they close it**, and in any
  case after the live view length (90 s by default). The video response ends with it.
- *Keep session open* now defaults to 0: the station is released the moment a command is
  done. (The option was shown before but had no effect; it works now.)
- Opening the door while a live view runs uses the live view's connection: it is immediate
  and the picture keeps running.
- The persistent notification after every successful unlock is gone; the lock entity showing
  "unlocked" for a few seconds is the confirmation.
- A frame type the integration does not know is skipped by its length instead of costing a
  resynchronisation every time it occurs (matters for station models other than the EVO 2).
- The station login uses the entry's stored client id instead of a new random one after
  every restart.

### Added

- Services `balter_evo2.start_live_view` (optional `duration`, `end_when_unwatched`),
  `balter_evo2.stop_live_view` and `balter_evo2.refresh_snapshot`, for example to go live
  when a doorbell automation fires.
- Camera attribute `still_taken`.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): the wire protocol as far as it is known.

### Removed

- The option *Open the audio connection*. It never did anything.

### Upgrading

Update through HACS and restart Home Assistant. No reconfiguration is needed. The options
form of 1.0.0 stored its defaults whenever it was saved (a still refresh every 90 s, a 10 s
session hold); those two values are reset to the new defaults on upgrade, anything else you
chose is kept. To have periodic still refreshes again, set *Refresh the still image after*.
Dashboards keep working; see the README for cards.

## 1.0.0 (2026-11-24)

Initial version: config flow with the phone-app account, camera and door-opener lock over a
direct TCP connection to the station, `record_clip` service, diagnostics.
