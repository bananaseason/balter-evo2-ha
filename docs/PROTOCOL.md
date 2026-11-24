# Wire protocol (TCP port 34567)

What this integration speaks to the door station, as observed on a **Balter EVO 2
(`IDS94A6FW`)**. It was worked out from captures of the official app and from the
integration's own sessions with the station; nothing here comes from vendor
documentation, so treat every field marked *unknown* as exactly that.

The same application frames travel inside the UDP/P2P tunnel that earlier community
integrations used. On TCP they arrive bare: no transport header, no retransmission
layer, no outer frame.

## Keys

The cloud account (the one of the phone app) returns two per-device secrets that rotate
about once a week:

| Secret | Used for |
| --- | --- |
| `data_encode_key` | AES-256 key of every frame on the connection |
| dynamic password | the LOGIN payload |

All encryption is **AES-256-CBC with a constant IV of sixteen ASCII `0` characters**
(`0x30`), restarted for every encrypted block run: the head is one run, the encrypted
part of the body is another.

## Connection

1. The client connects and writes a 32-byte **plaintext** setup body: `a9` followed by
   zeros (byte 9 is the channel: `0` video and control, `2` audio).
2. The station echoes 32 bytes: byte 0 `a9`, byte 10 `02`, byte 11 `01` (accepted).
3. The client writes the LOGIN frame (type `0x01`, `msg13 = 1`).
4. The client writes its setup frames (`0xFE`, `msg13` 5, 6 and 2, payload `00`).
5. The station answers and starts sending video **on its own**. There is no play
   command.
6. Both sides send a keepalive (type `0x00`, empty payload) every ~10 s. The client
   says goodbye with type `0x07`.

A typical start, with times from the connect:

| Time | Direction | Frame |
| --- | --- | --- |
| 0.03 s | station | `0xFE msg13=14`, 16 bytes `00 01 07 00 …`: video will follow |
| 0.03 s | station | `0x01`: LOGIN answer |
| 0.06 s | station | `0xFE msg13=5`, `00 05` |
| 0.07 s | station | `0xFE msg13=18`, `00 01` + JSON profile (~800 bytes) |
| 0.10 s | station | `0xFE msg13=2`, `01 01`: session ready |
| 0.45 s | station | first keyframe |

## Frames

Every frame starts with a 32-byte encrypted **head**:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 1 | type: `0x00` keepalive, `0x01` login, `0x07` close, `0xA0` media, `0xFE` control |
| 1 | 4 | timestamp / tick (station: a running counter; the client may send 0) |
| 5 | 4 | zero |
| 9 | 2 | `encrypted_len`, u16 LE: encrypted bytes that follow the head |
| 11 | 2 or 4 | `content_len`: u16 LE in control frames, u32 LE in media frames |
| 13 | 1 | `msg13`, the message id (control frames) |
| 14 | 3 | flags (the client's LOGIN sets bytes 15 and 16 to 1) |
| 17 | 15 | zero |

The head alone tells where the frame ends, which is the only way to find frame
boundaries: nothing on the stream is delimited in plaintext.

### Control frames

`head` + `encrypted_len` bytes. The body is `payload || SHA-256(head || payload)`,
zero padded to a block and encrypted; `content_len` is the payload length. (The LOGIN
answer carries a status word in that field instead.)

Note the 16-bit length: the profile the station sends right after the login is about
830 bytes long. Reading the length as a single byte loses the stream at that frame.

| `msg13` | Direction | Meaning |
| --- | --- | --- |
| 2 | both | session setup / session ready |
| 4 | client | **open door**: payload 16 bytes (`lock number`, 0, `door station`, 1, zeros) + 64 ASCII hex characters, the SHA-256 of the door PIN |
| 4 | station | open-door answer, two bytes, see below |
| 5, 6 | client | setup frames the app sends after its LOGIN |
| 8 | station | heartbeat with a counter, about once a second |
| 14 | station | sent first in a session that will carry video |
| 18 | station | JSON profile: channels, locks and their names |

The station answers the client's setup frames: `msg13=5` with `00 05` at once, and
`msg13=2` with the profile (`msg13=18`) followed by "session ready" (`msg13=2`, `01 01`).
An open-door command that is sent before that answer can be dropped without any reply
(seen with the command sent 230 ms before the answers arrived). The phone app sends the
command only while its picture runs.

The two buttons of the phone app on an EVO 2 (a padlock and a door) are lock 1 and
lock 2 of door station 1. The door button sends `02 00 01 01`: the lock number comes
first, the door station third. (With one lock and one door station both are 1, which is
why the order cannot be read from a capture of such a unit.)

Answers to the open-door command, as seen on an EVO 2 (`IDS94A6FW`):

| Answer | When |
| --- | --- |
| `00 00` | the phone app, lock 2, right PIN, 120 ms after the command |
| `00 01` | this integration, lock 1 or lock 2, right PIN, 60 to 90 ms after the command |
| `01 00` | wrong PIN (the app and this integration) |
| `01 01` | door station 2, which this unit does not have (the result of sending the two numbers the other way round) |

The first byte is the result (0 = accepted). What the second byte says is not known.

Locks are named by the cloud's sub-device list and by the station's profile with codes
such as `Channel_1 lock1`, `Channel_1 lock2` (EVO 2), `lock_chn1 1` or `door1-lock1`:
door station and lock number, both 1-based, the values the open-door payload carries.

### Media frames (type `0xA0`)

`head` + `content_len` bytes. Only the first `encrypted_len` bytes (32 on the EVO 2)
are encrypted, the rest is plaintext. The decrypted payload starts with a 20-byte
packet header:

| Offset | Size | Field |
| --- | --- | --- |
| 0 | 3 | `00 00 01` |
| 3 | 1 | kind: `0xE0` video delta frame, `0xE1` video keyframe, `0xE3` audio |
| 4 | 4 | data length, u32 LE (`content_len - 20`) |
| 8 | 4 | station wall clock, seconds since the epoch, u32 LE |
| 12 | 2 | milliseconds, u16 LE |
| 14 | 6 | video: `01 64`, width u16 LE, height u16 LE; audio: format byte, `01`, sample rate u16 LE, `00 00` |

followed by the data:

- **video**: H.264 Annex B, Main profile, 768×432 at about 18 frames a second. A
  keyframe packet holds SPS, PPS and the IDR picture together and comes every one to
  three seconds.
- **audio**: G.711 A-law, 8 kHz, mono, 320 bytes (40 ms) per packet. The integration
  skips these packets.

Audio and video packets are interleaved on the one connection. Feeding everything to
an H.264 decoder, or cutting frames anywhere but at the head's length, produces the
blocky, slow picture that an unpinned parser shows.

## Session rules of the station

- It serves **one session at a time**. While a client is connected, the phone app and
  any other client are turned away.
- After a session closes it needs a moment. A reconnect within about half a second is
  accepted and logged in, but that session carries **no video** (the `msg13=14` frame
  is missing). From about one second on everything is normal. The integration keeps
  two seconds between sessions and retries once if a session comes up without video.
- A door command is accepted on a session that is streaming video, and the stream
  keeps running.
- It writes every frame separately and waits for the acknowledgement of a small write
  before sending the next (Nagle). A client that delays its ACKs gets small frames, a
  dark or motionless picture, in clumps a few times a second; acknowledge at once
  (`TCP_QUICKACK` on Linux, set again after every read).
- The frame rate follows the light: about 18 frames a second by day, about 15 in the dark.

## The audio channel and talk-back

Seen in a capture of the phone app (there over its UDP transport, where both channels
share one connection; the frames are the same). **Not implemented by this integration.**

The audio channel is a second channel opened with the setup body `a9 … [9] = 02`:

| Step | Direction | Frame |
| --- | --- | --- |
| 1 | client | LOGIN with type `0x0B`, `msg13 = 0xFF`, head byte 14 `0xFF`, the same payload as the video LOGIN |
| 2 | station | type `0x0B`, no payload |
| 3 | client | type `0x0C` (audio format): `msg13 = 1`, head bytes 15..16 = sample rate (`40 1f` = 8000), then type `0x0D` with `msg13 = 1` (not talking) |
| 4 | station | type `0x0C`, then `0x0D` |
| talk | client | type `0x0D`, `msg13 = 0`: talking starts; the station answers `0x0D` |
| talk | client | type `0xA2` every 40 ms: the microphone audio |
| end | client | type `0x0D`, `msg13 = 1`: talking ends; the station answers `0x0D` |

The frames of types `0x0B` (answer), `0x0C` and `0x0D` carry no payload: the head is
followed by 32 encrypted bytes, the SHA-256 of the decrypted head, and the client puts
`ff ff` into the content length.

A talk frame (`0xA2`) is laid out like a media frame (32 encrypted bytes, u32 content
length) and holds `00 00 01 f0 0e 02`, the data length as u16 LE (`40 01` = 320) and
320 bytes of G.711 A-law, 8 kHz: 40 ms.

While the app shows the picture, the station's own audio (kind `0xE3`) arrives on the
video channel, not on the audio channel.

## Not known

- Whether a higher-resolution stream can be requested. The station sends 768×432
  unasked; no command that selects another stream has been identified.
- The meaning of the two-byte answers to the setup frames (`00 05`, `01 01`).
- Whether the audio channel and talk-back work on a second TCP connection the way they do
  on the app's UDP transport.
- The second byte of the open-door answer.
- How a doorbell press is signalled locally, if it is at all: the station reports rings
  through the vendor cloud as push notifications.
