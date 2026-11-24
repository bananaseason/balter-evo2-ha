"""FFmpeg helpers: decrypted H.264 -> JPEG stills and short MP4 clips.

Pure subprocess work, executor-only -- never call these from the event loop.
``ffmpeg`` is a host binary (not a pip dependency), so every entry point
degrades gracefully: it returns ``None`` with a single clear log line when
ffmpeg is missing or no decodable keyframe is present, and never raises.

The codec itself (AES, frame and packet parsing) lives in :mod:`protocol`; this
module only shells out to ffmpeg with ready-made H.264.

Attribution: the still/clip ffmpeg invocations are ported from ``p2p.py`` of
balter-evo-ha (https://github.com/LucaHerrero/balter-evo-ha, MIT licensed).
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile

_LOGGER = logging.getLogger(__name__)

# ffmpeg timeouts (seconds). A still is one frame; a clip is re-encoded.
_STILL_TIMEOUT = 15.0
_CLIP_TIMEOUT = 120.0

# Clip frame-rate bounds. The station runs ~18 fps; clamp the estimate so a
# miscount cannot produce a comically fast or slow clip.
_FPS_MIN = 5.0
_FPS_MAX = 30.0


def run_ffmpeg(args: list[str], timeout: float) -> bool:
    """Run ffmpeg, reporting whether it could be started at all.

    Returns ``False`` (never raises) when ffmpeg is absent or fails, so callers
    on a minimal install degrade instead of crashing.
    """
    try:
        subprocess.run(
            ["ffmpeg", "-hide_banner", "-loglevel", "error", *args],
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError:
        _LOGGER.error(
            "ffmpeg not found -- it is required on the Home Assistant host for "
            "snapshots, clips and the live stream"
        )
        return False
    except (OSError, subprocess.SubprocessError) as err:
        _LOGGER.warning("ffmpeg failed: %s", err)
        return False
    return True


def h264_to_jpeg(h264: bytes) -> bytes | None:
    """Decode the first frame of an H.264 stream into a JPEG, or ``None``."""
    if not h264:
        return None
    with tempfile.TemporaryDirectory(prefix="balter_evo2_snapshot_") as tmp_dir:
        raw = os.path.join(tmp_dir, "frame.h264")
        jpg = os.path.join(tmp_dir, "frame.jpg")
        with open(raw, "wb") as handle:
            handle.write(h264)
        if not run_ffmpeg(
            ["-y", "-f", "h264", "-i", raw, "-frames:v", "1", "-q:v", "2", jpg],
            _STILL_TIMEOUT,
        ):
            return None
        if not os.path.exists(jpg) or os.path.getsize(jpg) == 0:
            _LOGGER.debug("ffmpeg produced no still image")
            return None
        with open(jpg, "rb") as handle:
            return handle.read()


def h264_to_mp4(h264: bytes, seconds: float) -> bytes | None:
    """Re-encode an H.264 stream into a playable ``seconds``-long MP4, or ``None``.

    The playback frame rate is estimated from the number of coded pictures so
    the clip runs close to real time; the output is trimmed to ``seconds``.
    """
    if not h264:
        return None
    seconds = max(1.0, float(seconds))
    pictures = _count_pictures(h264)
    fps = max(_FPS_MIN, min(_FPS_MAX, pictures / seconds)) if pictures else _FPS_MIN
    with tempfile.TemporaryDirectory(prefix="balter_evo2_clip_") as tmp_dir:
        raw = os.path.join(tmp_dir, "clip.h264")
        mp4 = os.path.join(tmp_dir, "clip.mp4")
        with open(raw, "wb") as handle:
            handle.write(h264)
        ok = run_ffmpeg(
            [
                "-y",
                "-f",
                "h264",
                "-r",
                f"{fps:.2f}",
                "-i",
                raw,
                "-t",
                f"{seconds:.2f}",
                "-c:v",
                "libx264",
                "-pix_fmt",
                "yuv420p",
                mp4,
            ],
            _CLIP_TIMEOUT,
        )
        if ok and os.path.exists(mp4) and os.path.getsize(mp4) > 0:
            with open(mp4, "rb") as handle:
                return handle.read()
    _LOGGER.warning("ffmpeg produced no clip")
    return None


def _count_pictures(h264: bytes) -> int:
    """Count the coded-picture NAL units (types 1 and 5) in a stream."""
    count = 0
    pos = h264.find(b"\x00\x00\x00\x01")
    while pos >= 0:
        if pos + 4 < len(h264) and (h264[pos + 4] & 0x1F) in (1, 5):
            count += 1
        pos = h264.find(b"\x00\x00\x00\x01", pos + 4)
    return count
