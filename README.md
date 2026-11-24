# Balter EVO 2 Door Station for Home Assistant

[![Validate](https://github.com/bananaseason/balter-evo2-ha/actions/workflows/validate.yml/badge.svg)](https://github.com/bananaseason/balter-evo2-ha/actions/workflows/validate.yml)

Camera and door opener for video door stations built on the **Qualvision / Quvii** platform,
sold under brands such as **Balter EVO** and **Homaxi**.

> **Disclaimer:** this is an unofficial community project. It is not affiliated with,
> endorsed by or supported by Balter, Qualvision, Quvii or Homaxi. Use at your own risk.

## Features

- Camera entity with live view (bounded MJPEG) and cached snapshots
- Lock entity for each door-release relay (momentary: unlocks, then re-locks after a few seconds)
- `balter_evo2.record_clip` entity service: record 1 to 30 seconds to an MP4 file
- Local push: video and door control go straight to the station over TCP port 34567

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

## Screenshots

> Screenshots of the setup flow and the camera / lock cards will be added here once the integration
> is validated on real hardware.

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
- The station has a single session slot. Live streams are time-limited so the doorbell and
  the phone app are not blocked; the connection used for unlocking is kept open only for the
  configurable "keep session open" time.
- The optional audio connection is off by default and not needed for camera and lock.

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
