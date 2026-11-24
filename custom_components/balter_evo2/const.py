"""Constants for the Balter EVO 2 Door Station integration.

Supports door stations built on the Qualvision / Quvii platform and sold under
several OEM brands (Balter EVO, Homaxi, ...). The cloud REST protocol and the
application-layer frame formats were reverse-engineered by the community
integration balter-evo-ha (MIT licensed, https://github.com/LucaHerrero/balter-evo-ha);
the constants below are adapted from its ``const.py``. The local transport of
this integration is a plain TCP connection to the station (port 34567).

This integration is unofficial and not affiliated with Qualvision, Quvii,
Balter or Homaxi.
"""

from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "balter_evo2"

PLATFORMS: list[Platform] = [Platform.CAMERA, Platform.LOCK]

# --- Local station transport -------------------------------------------------

# The station serves its video + control channel on this TCP port.
STATION_PORT = 34567

# --- Config entry data / options keys ----------------------------------------

# Account e-mail and password use homeassistant.const.CONF_EMAIL / CONF_PASSWORD.
# Entry data additionally holds the self-generated 16-hex installation id.
CONF_CLIENT_ID = "client_id"
# LAN address of the station (per device; also an options override).
CONF_HOST = "host"
CONF_DOOR_PIN = "door_pin"
CONF_WARM_IDLE = "warm_idle"
CONF_STREAM_DURATION = "stream_duration"
CONF_SNAPSHOT_TTL = "snapshot_ttl"
# The audio connection (CH1) is not needed for camera + lock and defaults to off.
CONF_ENABLE_AUDIO = "enable_audio"
DEFAULT_ENABLE_AUDIO = False

# --- Timeouts (seconds) -------------------------------------------------------

# Waiting for the station's setup echo / first valid control frame after connect.
LOGIN_TIMEOUT = 8.0
# Generic timeout for one cloud REST request.
REQUEST_TIMEOUT = 15
# Application keepalive interval, both directions, on every open connection.
KEEPALIVE_INTERVAL = 10.0

# --- Lock ----------------------------------------------------------------------

# A door-release relay is momentary: after unlocking it buzzes open and re-locks on
# its own. We surface it as a lock and optimistically flip back to "locked" after
# this delay. Kept comfortably long so the "unlocked" state stays visible in the UI
# -- important for remote users who cannot hear the relay.
RELOCK_DELAY = 8

# Lock created when the cloud reports no sub-devices for a station.
# door=1 / lock=1 is the door opener of every EVO 2 station (verified live).
DEFAULT_LOCK = {"code": "door1-lock1", "name": "Door opener", "door": 1, "locknumber": 1}

# --- Camera --------------------------------------------------------------------

# Entity service of the camera: record a short MP4 clip and write it to disk.
SERVICE_RECORD_CLIP = "record_clip"
ATTR_FILENAME = "filename"
ATTR_SECONDS = "seconds"
RECORD_CLIP_MIN_SECONDS = 1
RECORD_CLIP_MAX_SECONDS = 30

# Maximum duration of one live stream. The station cannot tolerate a permanently
# open session (it would block the doorbell and other residents), so every live
# stream is bounded and the station slot is released afterwards.
STREAM_DURATION = 90.0
DEFAULT_STREAM_DURATION = STREAM_DURATION

# How long to wait for a live stream to end cleanly on entity removal before it
# is aborted.
STREAM_STOP_TIMEOUT = 5.0

# Minimum age before a new still image is fetched. Must exceed the slot cycle
# (SESSION_MIN_GAP + one snapshot, roughly 70 s): a shorter value lets an open
# dashboard hold the station permanently, starving the doorbell, the app and the
# door opener.
SNAPSHOT_CACHE_TTL = 90.0
DEFAULT_SNAPSHOT_TTL = SNAPSHOT_CACHE_TTL

# --- Session slot management ----------------------------------------------------

# The station serves only ONE app session at a time and needs recovery time after
# it: an attempt that starts while it is still busy extends the busy period.
# Snapshot, live stream and door opening therefore share one slot and keep this
# minimum gap (observed 60-90 s; 30 s was too short -- an open exactly 30 s after
# the previous session stalled at LOGIN). Applies only after a session that
# actually occupied the station.
SESSION_MIN_GAP = 60.0

# How long a session is kept open after a command. Re-establishing it costs
# several seconds, which is why the official app opens instantly on a second
# press: it keeps the session and only sends the command. The value trades
# "second open immediately" against "station free again quickly" and is
# therefore configurable in the options. 0 disables keeping sessions warm.
DEFAULT_WARM_IDLE = 10.0
WARM_IDLE_MAX = 60.0

# --- Cloud credentials cache ------------------------------------------------------

# The per-device secrets (dynamic password, data-encode key) rotate weekly; polling
# more often only loads the cloud without benefit.
CREDENTIAL_MAX_AGE = 900.0

# Age up to which a cached pair is used without asking the cloud. On the way to
# opening the door a slow or disturbed cloud connection must not hold up the
# command: the secrets rotate weekly, a pair from this morning is practically
# always still valid. It is refreshed in the background.
CREDENTIAL_STALE_AGE = 12 * 3600.0

# How long an unlock waits at most for fresh secrets before proceeding with the
# cached pair. The cloud normally answers in ~300 ms.
CREDENTIAL_REFRESH_WAIT = 1.5

# Coordinator poll interval for the cloud device list (seconds).
UPDATE_INTERVAL = 15 * 60

# --- Cloud client identity ----------------------------------------------------------

# Fixed client identity constants captured from the real app's login request. They
# identify the app/OEM to the backend, not the individual user.
APP_ID = "4028"
OEM_ID = "G0028,G0126"
# The station LOGIN carries the same OEM id without the comma (byte-exact against
# captures) -- derive it in exactly one place.
OEM_ID_COMPACT = OEM_ID.replace(",", "")
CLIENT_TYPE = "3"
CLIENT_VERSION = "v1.13"
IP_REGION_ID = "1"

# The userapp REST host is not fixed: it is announced per account by the discovery
# service (mst/query -> server-type "userapp") and resolved at login time by the
# cloud client. HOST / BASE_PATH are only a fallback if discovery fails.
DISCOVERY_HOST = "global.qvcloud.net"
DISCOVERY_PATH = "/mst/query"
HOST = "r1-2.qvcloud.net"
BASE_PATH = "/auth/user"

# The real app presents an OkHttp User-Agent; sent for parity.
USER_AGENT = "okhttp/4.9.0"

# Manufacturer string shown in the device registry.
MANUFACTURER = "Qualvision (Balter/Quvii/Homaxi)"
