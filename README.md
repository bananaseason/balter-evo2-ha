# Balter EVO 2 Door Station for Home Assistant

[![Validate](https://github.com/bananaseason/balter-evo2-ha/actions/workflows/validate.yml/badge.svg)](https://github.com/bananaseason/balter-evo2-ha/actions/workflows/validate.yml)

Camera and door opener for video door stations built on the **Qualvision / Quvii** platform,
sold under brands such as **Balter EVO** and **Homaxi**.

> **Disclaimer:** this is an unofficial community project. It is not affiliated with,
> endorsed by or supported by Balter, Qualvision, Quvii or Homaxi. Use at your own risk.

## Features

- **Camera** with a stored still image and an on-demand live view (768×432, about 18 frames
  a second) that always ends by itself
- **Lock** entity for each door-release relay (momentary: unlocks, then shows locked again
  after a few seconds). The station's answer is read: "unlocked" means it really opened,
  and a wrong door PIN is reported as such. Opening the door during a live view does not
  interrupt the picture
- Services for automations: `balter_evo2.start_live_view`, `stop_live_view`,
  `refresh_snapshot` and `record_clip` (1 to 30 seconds as MP4)
- Local push: video and door control go straight to the station over TCP port 34567
- The station is never held: nothing is connected to it unless a live view runs or a
  command is being sent, so the phone app and the indoor monitor keep working

## Supported devices

| Status | Devices |
| --- | --- |
| ✅ **Tested** | **Balter EVO 2** (model `IDS94A6FW`) |
| 🧪 **Should work (untested)** | Other **Balter EVO** models; OEM‑identical door stations sold as **Quvii**, **Homaxi**, or built on the **Qualvision** platform, that speak the same application protocol |

> **Honest caveat:** the author owns a single **Balter EVO 2**, so that is the **only device it was
> possible to test on real hardware**. The other models above share the same Qualvision protocol and
> *should* work, but are **unverified**. If you have one, please
> [open an issue](https://github.com/bananaseason/balter-evo2-ha/issues) with the result — reports and
> pull requests are very welcome.

## How it works

1. During setup you sign in **once** with your phone‑app (Quvii) account. That cloud login is used
   **only** to fetch the station's rotating per‑device secrets (keys and door‑open code).
2. After that, the integration talks **directly to the station on your LAN over TCP port 34567** —
   the native application protocol (handshake → AES‑encrypted control → H.264 video). **No cloud is
   in the video path.**
3. Earlier community integrations drove the camera over the station's UDP/P2P transport, which does
   not reliably open a channel on every model and network. This integration uses the station's
   **direct TCP service** instead, which is simpler and fully local.

## How the camera behaves

A door station of this family serves **one client at a time**. A camera entity that keeps
polling it would lock out the phone app, so this one does not:

| Situation | What the entity does | Station contacted |
| --- | --- | --- |
| A dashboard shows the camera | serves the stored still (the last frame of the latest live view) | no (once, right after installing, to get a first still) |
| Somebody opens the camera (more-info, a `camera_view: live` card) | starts a live view, ends it a second after the last viewer left, at the latest after the *live view length* (90 s by default) | yes, for that time |
| `balter_evo2.start_live_view` is called | runs a live view for its full length whether or not anybody watches | yes, for that time |
| `balter_evo2.refresh_snapshot` is called | fetches one fresh still (about half a second) | yes, briefly |
| Home Assistant restarts | brings the stored still back from disk | no |

The camera state is `streaming` while a live view runs and `idle` otherwise; the attribute
`still_taken` says when the stored still was taken.

Keep in mind that every open MJPEG feed counts as a viewer. A card with `camera_view: live`
that is always on screen (a wall tablet, for instance) starts a live view whenever it loads
and keeps one alive for its full length; use the still (`camera_view: auto`) there and show
the live card only on demand, as below.

### Dashboard example

The simplest card is a plain `picture-entity` with `camera_view: auto`: it shows the still,
and a tap opens the camera dialog with the live view. If you prefer the picture to turn into
live video in place when tapped, and back when the live view ends:

```yaml
- type: picture-entity
  entity: camera.front_door
  camera_view: auto
  show_state: false
  tap_action:
    action: perform-action
    perform_action: balter_evo2.start_live_view
    target:
      entity_id: camera.front_door
    data:
      end_when_unwatched: true
  visibility:
    - condition: state
      entity: camera.front_door
      state_not: streaming
- type: picture-entity
  entity: camera.front_door
  camera_view: live
  show_state: false
  visibility:
    - condition: state
      entity: camera.front_door
      state: streaming
```

### Live view when the doorbell rings

The station reports a ring only through the vendor cloud (a push notification to the phone
app), not on the local connection, so the integration has **no doorbell entity**. If the
ring reaches Home Assistant another way (for example an Alexa or Google routine that turns
on a helper), start the live view from that:

```yaml
triggers:
  - trigger: state
    entity_id: input_boolean.doorbell
    to: "on"
actions:
  - action: balter_evo2.start_live_view
    target:
      entity_id: camera.front_door
```

## Options

| Option | Default | Meaning |
| --- | --- | --- |
| Live view length | 90 s | Every live view ends after this time at the latest |
| Refresh the still image after | 0 (never) | Fetch a fresh still by itself once the stored one is older while a dashboard shows it |
| Keep session open | 0 s | Keep the connection after a command so the next one skips the handshake; while it is open the station turns other clients away |
| Door PIN | empty | Only if you want to send a PIN other than the one registered in the cloud |
| Host | from setup | Local address of the station |

## Screenshots

> Screenshots of the setup flow and the camera / lock cards will be added here.

## Requirements

- Home Assistant 2024.12.0 or newer
- The `ffmpeg` integration (a dependency, installed with Home Assistant)
- Your phone-app account (e-mail and password). The cloud account is only used to fetch the
  station's rotating access secrets; everything else is local.
- The station must be reachable from Home Assistant on **TCP port 34567**.

## Installation (HACS custom repository)

1. In HACS open the menu (three dots), choose **Custom repositories**.
2. Add `https://github.com/bananaseason/balter-evo2-ha` with category **Integration**.
3. Install **Balter EVO 2 Door Station** and restart Home Assistant.
4. Go to **Settings > Devices & services > Add integration** and pick *Balter EVO 2 Door Station*.
5. Sign in with your cloud account, select the station and enter its local IP address.

### Manual install

Copy `custom_components/balter_evo2` into your Home Assistant `config/custom_components/`
directory and restart Home Assistant, then continue from step 4 above.

## Notes

- **Give the station a DHCP reservation** in your router. The integration connects by the
  address you enter; if it changes, use *Reconfigure* on the entry.
- **Direct TCP, not UDP:** the station's UDP/P2P transport used by earlier community integrations
  proved unreliable, so this integration speaks the application protocol directly over TCP.
- The station has a single session slot and needs about a second between two sessions;
  the integration takes care of both. If the phone app or the indoor monitor is showing
  the picture, a live view from Home Assistant may come up without video until they are
  done.
- Audio is not supported: the station's audio packets are skipped.
- The wire protocol is documented in [docs/PROTOCOL.md](docs/PROTOCOL.md).

## Security: do not expose the lock to voice assistants

The door opener is a real lock. **Do not expose it to Assist, Alexa, Google Home or any other
voice assistant**, and do not automate it from presence detection that can be spoofed. A spoken
or accidental command could open your front door.

Home Assistant exposes `lock` entities to the conversation agent **by default**, and an
integration cannot opt its entity out from code. After setup, remove it yourself under
**Settings > Voice assistants > Expose** (toggle the lock off), or with the
`homeassistant.expose_entity` service. The integration diagnostics report the current exposure
under `lock_exposed_to_assist`, but that is advisory only — it does not enforce anything.

## Credits

Protocol groundwork (cloud REST protocol, frame formats) comes from
[LucaHerrero/balter-evo-ha](https://github.com/LucaHerrero/balter-evo-ha) (MIT).
Parts of this code are adapted from it; see [LICENSE](LICENSE).

## License

MIT
