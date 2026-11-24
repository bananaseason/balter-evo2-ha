# Balter EVO 2 Door Station

Home Assistant integration for door stations built on the Qualvision / Quvii platform
(Balter EVO, Homaxi and other OEM brands).

- Call card: a tap on the still opens a door-phone call — live picture, two-way audio, open
  the door while you talk, hang up; a ring can open it as an incoming call
- Camera: a stored still image plus an on-demand live view (768x432, ~18 fps) over a direct
  local TCP connection; the live view always ends by itself
- Lock: door opener as a momentary lock entity
- Services: `start_live_view`, `stop_live_view`, `refresh_snapshot`, `record_clip`
- The station is not held between uses, so the phone app keeps working

Sign in with your phone app account, then give the station's local address. Requires ffmpeg.

Unofficial; not affiliated with Balter, Qualvision, Quvii or Homaxi.
