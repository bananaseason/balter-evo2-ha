/*
 * balter-evo2-call-card: a doorbell call screen for the balter_evo2 integration.
 *
 * Idle: the stored still, nothing connected. Tap: a full-screen call overlay (video, the
 * visitor's voice, talk-back, door button, hang up). The backend keeps the station only while
 * this page heartbeats; leaving the app ends the call at once (see call/end, pagehide).
 *
 * Plain HTMLElement + shadow DOM, no imports, no build step. Spec: PRODUCT.md / DESIGN.md.
 */
const CARD_VERSION = "1.0.0";
const WS = {
  start: "balter_evo2/call/start",
  heartbeat: "balter_evo2/call/heartbeat",
  talk: "balter_evo2/call/talk",
  audio: "balter_evo2/call/audio",
  end: "balter_evo2/call/end",
  extend: "balter_evo2/call/extend",
};
const HEARTBEAT_MS = 1000;
const MAX_EXTENSIONS = 2;
const RING_STALE_MS = 90000;
const PENDING_MIC_MS = 12000; // the backend's first-talk budget is ~11 s (login 8 s + answer 2 s)
const VIDEO_LOST_MS = 3000;
const ENDED_AUTOCLOSE_MS = 30000;
const SILENT_HINT_MS = 3000;
const JITTER_S = 0.16;
const MAX_BUFFER_S = 0.4;
const CHUNK = 320; // 40 ms of 8 kHz audio

/* ---------------------------------------------------------------- strings */

const S = {
  tap: "Tap to look",
  ariaLook: (n) => `Look at ${n} live`,
  liveNow: "Live now",
  ageToday: (t) => `Picture from ${t}`,
  ageYesterday: (t) => `Picture from yesterday, ${t}`,
  ageOlder: (d, t) => `Picture from ${d}, ${t}`,
  noStill: "No picture yet",
  notLive: "not live",
  doorShort: "Open",
  doorLabel: "Open door",
  doorOpening: "Opening…",
  doorOpened: "Door opened",
  doorOpenedShort: "Opened",
  doorFailed: (m) => `Door did not open: ${m}`,
  doorUnavailable: "Door unavailable",
  doorUnavailableShort: "Unavailable",
  ringBand: "Someone is ringing",
  ringAnnounce: (n) => `Someone is ringing at ${n}`,
  ringHint: "Answer to see and hear them.",
  answer: "Answer",
  decline: "Decline",
  chipConnecting: "Connecting…",
  chipLive: "Live",
  chipTalking: "Talking",
  chipBusy: "Station busy",
  chipEnded: "Ended",
  midConnecting: "Connecting…",
  midConnectingSub: "Live in a few seconds",
  midListening: "Listening",
  midListeningSub: "Tap Mic to talk",
  midTalking: "You are talking",
  midTalkingSub: "They can hear you",
  midSoundOff: "Sound is off",
  midSoundOffSub: "Tap Sound to hear them",
  midVideoLost: "Video lost",
  midVideoLostSub: "Sound and the door still work",
  meterDoor: "Door",
  meterYou: "You",
  micAria: "Microphone",
  micDisabled: "Mic",
  micOff: "Mic off",
  micPending: "Starting…",
  micOn: "Mic on",
  micBlocked: "Mic blocked",
  micNone: "No mic",
  micTag: "MIC ON",
  micCoach: "Tap Mic to talk",
  soundOn: "Sound",
  soundOff: "Sound off",
  hangup: "Hang up",
  noticeInsecureUrl: (u) => `Talking needs a secure connection. Open Home Assistant via ${u}`,
  noticeInsecure: "Talking needs a secure connection. Open Home Assistant via an https address.",
  noticeInsecureApp: "Talking needs https. In the Home Assistant app: Settings > Companion App > Server > Internal URL: use the https address (or clear it).",
  videoLostTitle: "Video lost",
  videoLostBody: "The picture stopped, so the call ended.",
  noticeOpen: "Open",
  noticeDenied: "Microphone blocked. Allow it in the browser or app settings.",
  noticeDeniedIos: "iPhone: Settings > Home Assistant > Microphone.",
  noticeNoDevice: "No microphone found on this device.",
  noticeEcho: "Use headphones or hold the phone to your ear to avoid echo.",
  noticeEchoOk: "Got it",
  noticeSilent: "No sound? Check the silent switch.",
  toastTalkFailed: "Couldn't open the talk channel",
  toastNotLive: "Wait until the picture is live",
  endingBanner: (s) => `Call ends in ${s} s`,
  extend: "Extend",
  busyTitle: "Station in use",
  busyBody: "The station is in use (phone app or indoor monitor). Try again in a moment.",
  busyAction: "Try again",
  errorTitle: "Couldn't connect",
  errorBody: (m) => m || "The door station did not answer.",
  limitTitle: "Call ended (time limit)",
  limitBody: "The call reached its time limit.",
  lostTitle: "Connection lost",
  lostBody: "Home Assistant could not be reached. The call has ended.",
  timeoutTitle: "Call ended",
  timeoutBody: "The live view stopped.",
  again: "Call again",
  close: "Close",
  configNotFound: (e) => `Camera not found: ${e}`,
  configNotFoundSub: "Check the card's camera_entity.",
  keys: "Space: mic · Esc: hang up",
  dismiss: "Dismiss",
  announce: {
    connecting: "Connecting",
    live: "Live",
    talking: "You are talking",
    micOff: "Microphone off",
    soundOff: "Sound off",
    soundOn: "Sound on",
    opening: "Opening the door",
    opened: "Door opened",
    doorFailed: "Door did not open",
    ending: "Call ends in 20 seconds",
    extended: "Call extended",
    ended: "Call ended",
  },
};

/* ------------------------------------------------------------ pure audio */

/** Decode one G.711 A-law byte to a 16-bit linear sample. */
function alawDecodeByte(a) {
  a ^= 0x55;
  let t = (a & 0x0f) << 4;
  const seg = (a & 0x70) >> 4;
  if (seg === 0) t += 8;
  else if (seg === 1) t += 0x108;
  else {
    t += 0x108;
    t <<= seg - 1;
  }
  return a & 0x80 ? t : -t;
}

const SEG_END = [0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff];

/** Encode one 16-bit linear sample to a G.711 A-law byte. */
function alawEncodeSample(sample) {
  let pcm = sample >> 3;
  let mask;
  if (pcm >= 0) mask = 0xd5;
  else {
    mask = 0x55;
    pcm = -pcm - 1;
  }
  let seg = 8;
  for (let i = 0; i < 8; i++) {
    if (pcm <= SEG_END[i]) {
      seg = i;
      break;
    }
  }
  if (seg >= 8) return 0x7f ^ mask;
  let aval = seg << 4;
  aval |= seg < 2 ? (pcm >> 1) & 0x0f : (pcm >> seg) & 0x0f;
  return aval ^ mask;
}

const ALAW_TABLE = (() => {
  const t = new Float32Array(256);
  for (let i = 0; i < 256; i++) t[i] = alawDecodeByte(i) / 32768;
  return t;
})();

/** A-law bytes -> Float32 in [-1, 1). */
function alawDecode(bytes) {
  const out = new Float32Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = ALAW_TABLE[bytes[i]];
  return out;
}

/** Float32 [-1, 1] -> A-law bytes (clipped). */
function alawEncode(floats) {
  const out = new Uint8Array(floats.length);
  for (let i = 0; i < floats.length; i++) {
    let v = Math.round(floats[i] * 32768);
    if (v > 32767) v = 32767;
    else if (v < -32768) v = -32768;
    out[i] = alawEncodeSample(v);
  }
  return out;
}

/**
 * Streaming windowed-sinc resampler (low-pass + rate conversion) to 8 kHz.
 * push(Float32Array) returns the new output samples.
 */
class Resampler {
  constructor(inRate, outRate = 8000, zeros = 6) {
    this.ratio = inRate / outRate;
    // cutoff as a fraction of the input Nyquist-normalised sinc: 90 % of the output Nyquist
    this.fc = Math.min(1, outRate / inRate) * 0.9;
    this.half = zeros / this.fc; // half width in input samples
    this.buf = new Float32Array(0);
    this.pos = 0; // fractional index of the next output centre in buf
  }

  push(input) {
    const merged = new Float32Array(this.buf.length + input.length);
    merged.set(this.buf, 0);
    merged.set(input, this.buf.length);
    const buf = merged;
    const out = [];
    const { half, fc, ratio } = this;
    let pos = this.pos;
    while (pos + half < buf.length) {
      const lo = Math.max(0, Math.ceil(pos - half));
      const hi = Math.floor(pos + half);
      let acc = 0;
      let norm = 0;
      for (let i = lo; i <= hi; i++) {
        const x = i - pos;
        const px = Math.PI * fc * x;
        const sinc = x === 0 ? 1 : Math.sin(px) / px;
        const w = 0.5 * (1 + Math.cos((Math.PI * x) / half));
        const k = fc * sinc * w;
        acc += buf[i] * k;
        norm += k;
      }
      out.push(norm > 0.5 ? acc / norm : acc);
      pos += ratio;
    }
    const drop = Math.max(0, Math.floor(pos - half));
    this.buf = buf.slice(drop);
    this.pos = pos - drop;
    return Float32Array.from(out);
  }
}

function b64encode(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i += 0x2000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x2000));
  }
  return btoa(s);
}

function b64decode(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

function rms(f) {
  if (!f.length) return 0;
  let a = 0;
  for (let i = 0; i < f.length; i++) a += f[i] * f[i];
  return Math.sqrt(a / f.length);
}

/** RMS -> 0..5 lit bars (dB scale, -50 dBFS = nothing, -10 dBFS = full). */
function levelToBars(r) {
  if (r <= 0) return 0;
  const db = 20 * Math.log10(r);
  const x = Math.min(1, Math.max(0, (db + 50) / 40));
  return Math.ceil(x * 5);
}

/* ---------------------------------------------------------------- helpers */

const THEME_VARS = [
  "--primary-background-color",
  "--secondary-background-color",
  "--card-background-color",
  "--primary-text-color",
  "--secondary-text-color",
  "--primary-color",
  "--text-primary-color",
  "--success-color",
  "--error-color",
  "--warning-color",
  "--ha-card-border-radius",
  "--ha-dialog-border-radius",
  "--ha-font-family-body",
  "--paper-font-body1_-_font-family",
  "--mdc-dialog-scrim-color",
];

function haptic(type) {
  try {
    window.dispatchEvent(new CustomEvent("haptic", { detail: type }));
  } catch (_e) {
    /* no bridge */
  }
}

function setText(el, text) {
  if (el && el.textContent !== text) el.textContent = text;
}

function setIcon(el, icon) {
  if (el && el.getAttribute("icon") !== icon) el.setAttribute("icon", icon);
}

function isIOS() {
  const ua = navigator.userAgent || "";
  return /iPad|iPhone|iPod/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1);
}

function isCompanionApp() {
  return /Home Assistant/i.test(navigator.userAgent || "");
}

function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch (_e) {
    return null;
  }
}

function storageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch (_e) {
    /* private mode */
  }
}

function ic(name, cls = "") {
  return `<ha-icon class="${cls}" icon="mdi:${name}"></ha-icon>`;
}

function secureUrl(config, hass) {
  const raw =
    (config && (config.secure_url || config.https_url)) ||
    (hass && hass.config && hass.config.external_url) ||
    "";
  return /^https:\/\//i.test(raw) ? raw : "";
}

function secureTarget(base) {
  try {
    const u = new URL(base);
    return new URL(location.pathname + location.search + location.hash, u.origin).href;
  } catch (_e) {
    return base;
  }
}

function errMessage(e) {
  if (!e) return "unknown error";
  if (typeof e === "string") return e;
  return e.message || e.code || "unknown error";
}

function isSecureCtx() {
  return window.isSecureContext !== false;
}

function micAvailable() {
  return !!(navigator.mediaDevices && navigator.mediaDevices.getUserMedia);
}

/* ------------------------------------------------------------------ door */

/** The Open-door button logic shared by the idle card and the overlay. */
class Door {
  constructor(card) {
    this.card = card;
    this.state = "ready"; // ready | opening | opened
    this._timer = 0;
  }

  async press() {
    if (this.state === "opening") return;
    const entity = this.card._config.lock_entity;
    if (!entity) return;
    clearTimeout(this._timer);
    this.state = "opening";
    haptic("light");
    this.card._doorChanged(S.announce.opening);
    try {
      await this.card._hass.callService("lock", "unlock", { entity_id: entity });
      this.state = "opened";
      haptic("success");
      this.card._notify(S.doorOpened, false);
      this.card._doorChanged(S.announce.opened);
      this._timer = setTimeout(() => {
        this.state = "ready";
        this.card._doorChanged();
      }, 3000);
    } catch (e) {
      this.state = "ready";
      haptic("failure");
      this.card._notify(S.doorFailed(errMessage(e)), true);
      this.card._doorChanged(S.announce.doorFailed);
    }
  }

  dispose() {
    clearTimeout(this._timer);
  }
}

/* ---------------------------------------------------------------- player */

/** Plays the station's A-law audio through one AudioContext with a small jitter buffer. */
class Player {
  constructor(ctx) {
    this.ctx = ctx;
    this.gain = ctx.createGain();
    this.gain.connect(ctx.destination);
    this.next = 0;
    this.frames = 0;
    this.level = 0;
    this.lastLoud = 0;
  }

  setMuted(muted) {
    this.gain.gain.value = muted ? 0 : 1;
  }

  push(bytes) {
    const f = alawDecode(bytes);
    this.frames += 1;
    const r = rms(f);
    this.level = Math.max(r, this.level * 0.85);
    if (r > 0.03) this.lastLoud = performance.now();
    const ctx = this.ctx;
    const now = ctx.currentTime;
    if (this.next < now + 0.02) this.next = now + JITTER_S; // underrun: re-prime
    if (this.next - now > MAX_BUFFER_S) return; // too far behind: drop
    const buf = ctx.createBuffer(1, f.length, 8000);
    buf.getChannelData(0).set(f);
    const src = ctx.createBufferSource();
    src.buffer = buf;
    src.connect(this.gain);
    src.start(this.next);
    this.next += f.length / 8000;
  }

  /** True while the visitor was loud in the last 300 ms (drives the outgoing duck). */
  get loud() {
    return performance.now() - this.lastLoud < 300;
  }

  stop() {
    try {
      this.gain.disconnect();
    } catch (_e) {
      /* already gone */
    }
  }
}

/* ------------------------------------------------------------------- mic */

const WORKLET_SRC = `
class BevCapture extends AudioWorkletProcessor {
  constructor() { super(); this.buf = new Float32Array(1024); this.n = 0; }
  process(inputs) {
    const c = inputs[0] && inputs[0][0];
    if (c) {
      for (let i = 0; i < c.length; i++) {
        this.buf[this.n++] = c[i];
        if (this.n === this.buf.length) { this.port.postMessage(this.buf.slice(0)); this.n = 0; }
      }
    }
    return true;
  }
}
registerProcessor("bev-capture", BevCapture);
`;

/** Microphone capture -> 8 kHz A-law chunks of 320 bytes. Opened only by a user action. */
class Mic {
  constructor(ctx, onChunk) {
    this.ctx = ctx;
    this.onChunk = onChunk;
    this.stream = null;
    this.node = null;
    this.rs = new Resampler(ctx.sampleRate);
    this.queue = new Float32Array(0);
    this.open = false;
  }

  async start() {
    const stream = await navigator.mediaDevices.getUserMedia({
      audio: {
        echoCancellation: true,
        noiseSuppression: true,
        autoGainControl: true,
        channelCount: 1,
      },
    });
    this.stream = stream;
    const ctx = this.ctx;
    try {
      await ctx.resume();
    } catch (_e) {
      /* gesture rules; the tap already resumed it */
    }
    const src = ctx.createMediaStreamSource(stream);
    const sink = ctx.createGain();
    sink.gain.value = 0;
    sink.connect(ctx.destination);
    this.src = src;
    this.sink = sink;
    let node = null;
    if (ctx.audioWorklet && typeof AudioWorkletNode !== "undefined") {
      let url = "";
      try {
        url = URL.createObjectURL(new Blob([WORKLET_SRC], { type: "text/javascript" }));
        await ctx.audioWorklet.addModule(url);
        node = new AudioWorkletNode(ctx, "bev-capture", {
          numberOfInputs: 1,
          numberOfOutputs: 1,
          channelCount: 1,
          outputChannelCount: [1],
        });
        node.port.onmessage = (e) => this._samples(e.data);
      } catch (_e) {
        node = null;
      } finally {
        if (url) URL.revokeObjectURL(url);
      }
    }
    if (!node) {
      node = ctx.createScriptProcessor(2048, 1, 1);
      node.onaudioprocess = (e) => this._samples(new Float32Array(e.inputBuffer.getChannelData(0)));
    }
    this.node = node;
    src.connect(node);
    node.connect(sink);
    this.open = true;
  }

  /** Drop what was captured while the mic was gated, so no stale audio is sent. */
  flush() {
    this.queue = new Float32Array(0);
    this.rs = new Resampler(this.ctx.sampleRate);
  }

  _samples(frame) {
    const out = this.rs.push(frame);
    if (!out.length) return;
    const q = new Float32Array(this.queue.length + out.length);
    q.set(this.queue, 0);
    q.set(out, this.queue.length);
    let off = 0;
    while (q.length - off >= CHUNK) {
      this.onChunk(q.subarray(off, off + CHUNK));
      off += CHUNK;
    }
    this.queue = q.slice(off);
  }

  stop() {
    this.open = false;
    try {
      if (this.node) {
        if (this.node.port) this.node.port.onmessage = null;
        this.node.onaudioprocess = null;
        this.node.disconnect();
      }
      if (this.src) this.src.disconnect();
      if (this.sink) this.sink.disconnect();
    } catch (_e) {
      /* graph already torn down */
    }
    if (this.stream) {
      for (const t of this.stream.getTracks()) t.stop();
      this.stream = null;
    }
  }
}

/* ------------------------------------------------------------- call logic */

const registry = new Map(); // camera entity -> Call (one overlay per camera)

class Call {
  constructor(card) {
    this.card = card;
    this.entity = card._config.camera_entity;
    this.phase = "idle"; // incoming | connecting | live | ended
    this.view = null;
    this.reset();
    this._onVis = () => {
      if (document.visibilityState === "hidden") this._leave();
    };
    this._onHide = () => this._leave();
    this._onKey = null;
  }

  reset() {
    this.callId = null;
    this.unsub = null;
    this.ended = false;
    this.ending = null; // {kind, message}
    this.backend = { state: "connecting", talking: false, talk_ready: false, ends_at: null };
    this.talking = false;
    this.micPending = false;
    this.micErr = null; // denied | none
    this.noticeInsecure = false;
    this.noticeEcho = false;
    this.noticeSilent = false;
    this.micDeadline = 0;
    this.micTicket = 0;
    this.sound = true;
    this.videoLost = 0; // timestamp
    this.extensions = 0;
    this.extendBusy = false;
    this.hbFails = 0;
    this.liveAt = 0;
    this.coachUntil = 0;
    this.outLevel = 0;
    this.mode = "peek";
    this._endingAnnounced = false;
    this._silentShown = false;
  }

  get hass() {
    return this.card._hass;
  }

  get name() {
    return this.card._name();
  }

  /* ---- lifecycle ---- */

  mount() {
    if (this.view) return;
    registry.set(this.entity, this);
    const view = document.createElement("balter-evo2-call-screen");
    this.view = view;
    view.attach(this);
    document.body.appendChild(view);
    this._prevOverflow = document.documentElement.style.overflow;
    document.documentElement.style.overflow = "hidden";
    document.addEventListener("visibilitychange", this._onVis);
    window.addEventListener("pagehide", this._onHide);
    document.addEventListener("freeze", this._onHide);
    this._timer = setInterval(() => this._tick(), 250);
    this._meterTimer = setInterval(() => this.view && this.view.meters(), 66);
  }

  openIncoming() {
    this.phase = "incoming";
    this.mount();
    this._render();
  }

  /** Start a call. Must run inside the user's tap (audio unlock). */
  begin(mode) {
    this.mode = mode;
    if (mode === "answer") this.card._ringDismissed = true; // handled: no second Answer while the helper stays on
    this._unlockAudio();
    this.reset_for_begin();
    this.phase = "connecting";
    this.mount();
    this._render();
    this._focus();
    this._announce(S.announce.connecting);
    this._connect();
  }

  reset_for_begin() {
    const mode = this.mode;
    this.reset();
    this.mode = mode;
    if (!isSecureCtx() || !micAvailable()) this.noticeInsecure = true;
  }

  _unlockAudio() {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (!AC) return;
    try {
      if (!this.ctx || this.ctx.state === "closed") this.ctx = new AC({ latencyHint: "interactive" });
      const p = this.ctx.resume();
      if (p && p.catch) p.catch(() => {});
      const b = this.ctx.createBuffer(1, 1, 22050);
      const s = this.ctx.createBufferSource();
      s.buffer = b;
      s.connect(this.ctx.destination);
      s.start(0);
      if (!this.player) {
        this.player = new Player(this.ctx);
      }
      this.player.setMuted(!this.sound);
    } catch (_e) {
      this.ctx = null;
    }
    try {
      if (navigator.audioSession) navigator.audioSession.type = "playback";
    } catch (_e) {
      /* unsupported */
    }
  }

  async _connect() {
    const conn = this.hass.connection;
    const cb = (ev) => this._onEvent(ev);
    this._cb = cb;
    this._conn = conn;
    try {
      const unsub = await conn.subscribeMessage(cb, { type: WS.start, entity_id: this.entity }, { resubscribe: false });
      if (this.ended) {
        // Left while the start was in flight: release it right away.
        try {
          unsub();
        } catch (_e) {
          /* ignore */
        }
        return;
      }
      this.unsub = unsub;
      this._watchConnection();
    } catch (e) {
      if (this.ended) return;
      const code = e && e.code;
      if (code === "not_found") {
        this.card._configError = true;
        this.card._renderIdle();
        this.close(true);
        return;
      }
      if (code === "station_busy") return this._finish({ kind: "busy" });
      this._finish({ kind: "error", message: errMessage(e) });
    }
  }

  _watchConnection() {
    const conn = this._conn;
    if (!conn || !conn.addEventListener) return;
    this._onDisc = () => {
      if (!this.ended) this._finish({ kind: "lost" }, true);
    };
    conn.addEventListener("disconnected", this._onDisc);
  }

  _setCallId(id) {
    if (this.callId || !id) return;
    this.callId = id;
    this._hbTimer = setInterval(() => this._heartbeat(), HEARTBEAT_MS);
  }

  _heartbeat() {
    if (this.ended || !this.callId || document.visibilityState !== "visible") return;
    this.hass.callWS({ type: WS.heartbeat, call_id: this.callId }).then(
      () => {
        this.hbFails = 0;
      },
      () => {
        this.hbFails += 1;
        if (this.hbFails >= 2 && !this.ended) this._finish({ kind: "lost" }, true);
      },
    );
  }

  _onEvent(ev) {
    if (this.ended || !ev) return;
    if (ev.call_id) this._setCallId(ev.call_id);
    if (ev.type === "audio") {
      if (this.player && ev.data) {
        try {
          this.player.push(b64decode(ev.data));
        } catch (_e) {
          /* bad chunk */
        }
      }
      return;
    }
    if (ev.type !== "state") return;
    const wasTalking = this.talking;
    this.backend = { ...this.backend, ...ev };
    if (ev.state === "live" && this.phase !== "live") {
      this.phase = "live";
      this.liveAt = performance.now();
      this._announce(S.announce.live);
      if (this.mode === "answer") this.coachUntil = performance.now() + 4000;
      this.card._refreshStill();
    }
    if (ev.state === "ended") {
      this._onEnded(ev);
      return;
    }
    this.talking = !!ev.talking;
    if (this.talking && !wasTalking) {
      this.micPending = false;
      haptic("medium");
      this._announce(S.announce.talking);
      if (this.mic) this.mic.flush();
    } else if (!this.talking && wasTalking) {
      haptic("light");
      this._announce(S.announce.micOff);
    }
    this._render();
  }

  _onEnded(ev) {
    const r = ev.reason;
    if (r === "hangup" || r === "heartbeat") {
      this._release(true);
      return this.close(true);
    }
    if (r === "station_busy") return this._finish({ kind: "busy" }, false, true);
    if (r === "max_duration") return this._finish({ kind: "limit" }, false, true);
    if (r === "timeout") return this._finish({ kind: "timeout" }, false, true);
    return this._finish({ kind: "error", message: ev.message || "" }, false, true);
  }

  /**
   * Release everything and show the ended screen. `silentWS`: the websocket is gone, so no
   * call/end can be sent. `serverEnded`: the backend already ended it.
   */
  _finish(info, silentWS = false, serverEnded = false) {
    if (this.ended) return;
    this._release(serverEnded || silentWS);
    this.ending = info;
    this.phase = "ended";
    this.endedAt = performance.now();
    haptic(info.kind === "limit" || info.kind === "timeout" ? "light" : "failure");
    this._announce(S.announce.ended);
    if (this.view) {
      this._render();
      this._focus();
    }
  }

  /** Stop the session, the mic, the audio and the video; send call/end unless told not to. */
  _release(skipEnd) {
    if (this.ended) return;
    this.ended = true;
    clearInterval(this._hbTimer);
    if (this._conn && this._onDisc) {
      try {
        this._conn.removeEventListener("disconnected", this._onDisc);
      } catch (_e) {
        /* ignore */
      }
    }
    if (!skipEnd && this.callId) this._sendEnd();
    if (this.unsub) {
      try {
        const r = this.unsub();
        if (r && r.catch) r.catch(() => {});
      } catch (_e) {
        /* ignore */
      }
      this.unsub = null;
    }
    this.talking = false;
    this.micPending = false;
    if (this.mic) {
      this.mic.stop();
      this.mic = null;
    }
    if (this.player) {
      this.player.stop();
      this.player = null;
    }
    if (this.ctx) {
      try {
        this.ctx.close();
      } catch (_e) {
        /* ignore */
      }
      this.ctx = null;
    }
    try {
      if (navigator.audioSession) navigator.audioSession.type = "auto";
    } catch (_e) {
      /* ignore */
    }
    if (this.view) this.view.dropVideo();
  }

  _sendEnd() {
    const msg = { type: WS.end, call_id: this.callId };
    try {
      const c = this._conn || this.hass.connection;
      if (c && c.sendMessage) {
        c.sendMessage(msg);
        return;
      }
    } catch (_e) {
      /* fall through */
    }
    try {
      this.hass.callWS(msg).catch(() => {});
    } catch (_e) {
      /* ignore */
    }
  }

  /** The user left (tab hidden, page hide): end at once, close without animation. */
  _leave() {
    if (this.phase === "incoming") return;
    this.close(true);
  }

  /** Close the overlay (and end the call if one runs). */
  close(instant = false) {
    this._release(false);
    clearInterval(this._timer);
    clearInterval(this._meterTimer);
    document.removeEventListener("visibilitychange", this._onVis);
    window.removeEventListener("pagehide", this._onHide);
    document.removeEventListener("freeze", this._onHide);
    if (registry.get(this.entity) === this) registry.delete(this.entity);
    this.phase = "idle";
    const view = this.view;
    this.view = null;
    if (view) {
      document.documentElement.style.overflow = this._prevOverflow || "";
      view.dispose(instant);
    }
    this.card._callClosed(this);
  }

  /* ---- user actions ---- */

  hangup() {
    haptic("medium");
    this.close(false);
  }

  decline() {
    this.card._ringDismissed = true;
    this.close(false);
    this.card._renderIdle();
  }

  answer() {
    this.begin("answer");
  }

  again() {
    this.begin("peek");
  }

  toggleSound() {
    this.sound = !this.sound;
    if (this.player) this.player.setMuted(!this.sound);
    this._announce(this.sound ? S.announce.soundOn : S.announce.soundOff);
    this._render();
  }

  async toggleMic() {
    if (this.phase === "connecting") return this._toast(S.toastNotLive, false);
    if (this.phase !== "live") return;
    if (!isSecureCtx() || !micAvailable()) {
      this.noticeInsecure = true;
      this._render();
      return;
    }
    if (this.talking || this.micPending) return this._talkOff();
    const ticket = ++this.micTicket;
    this.micPending = true;
    this.micErr = null;
    this._render();
    try {
      if (!this.mic) {
        if (!this.ctx) this._unlockAudio();
        // iOS 17+ uses the explicit type as the AVAudioSession category: 'playback' has no input,
        // so switch to play-and-record inside the tap, before capture starts.
        try {
          if (navigator.audioSession) navigator.audioSession.type = "play-and-record";
        } catch (_e) {
          /* unsupported */
        }
        const mic = new Mic(this.ctx, (chunk) => this._micChunk(chunk));
        await mic.start();
        if (this.ended) {
          mic.stop();
          return;
        }
        this.mic = mic;
        if (!storageGet("balter_evo2_echo_seen")) this.noticeEcho = true;
      }
    } catch (e) {
      try {
        if (navigator.audioSession && !this.mic) navigator.audioSession.type = "playback";
      } catch (_e) {
        /* unsupported */
      }
      if (ticket !== this.micTicket) return;
      this.micPending = false;
      const n = e && e.name;
      this.micErr = n === "NotFoundError" || n === "OverconstrainedError" || n === "NotReadableError" ? "none" : "denied";
      this._render();
      return;
    }
    if (ticket !== this.micTicket || this.ended) return;
    this.micDeadline = performance.now() + PENDING_MIC_MS;
    try {
      const r = await this.hass.callWS({ type: WS.talk, call_id: this.callId, talking: true });
      if (ticket !== this.micTicket || this.ended) return;
      if (r && r.talking === false) throw new Error("refused");
      if (r && r.talking === true && !this.talking) {
        this.talking = true;
        this.micPending = false;
        haptic("medium");
        this._announce(S.announce.talking);
        this.mic.flush();
        this._render();
      }
    } catch (e) {
      if (ticket !== this.micTicket || this.ended) return;
      this._micFailed(e && e.code === "not_live" ? S.toastNotLive : S.toastTalkFailed);
    }
  }

  _micFailed(text) {
    this.micPending = false;
    this.talking = false;
    this.micTicket += 1;
    if (this.callId && !this.ended) {
      this.hass.callWS({ type: WS.talk, call_id: this.callId, talking: false }).catch(() => {});
    }
    this._toast(text, true);
    this._render();
  }

  async _talkOff() {
    this.micTicket += 1;
    const was = this.talking;
    this.talking = false;
    this.micPending = false;
    this._render();
    if (was) {
      haptic("light");
      this._announce(S.announce.micOff);
    }
    try {
      await this.hass.callWS({ type: WS.talk, call_id: this.callId, talking: false });
    } catch (_e) {
      /* the backend ends the talk with the call anyway */
    }
  }

  /** One 40 ms chunk of float mic samples at 8 kHz. Sent only while the backend says talking. */
  _micChunk(f) {
    if (!this.talking || this.ended || !this.callId) return;
    let gain = 1;
    if (this.player && this.player.loud) gain = 0.25; // soft half-duplex gate, -12 dB
    const g = new Float32Array(f.length);
    for (let i = 0; i < f.length; i++) g[i] = f[i] * gain;
    this.outLevel = Math.max(rms(g), this.outLevel * 0.85);
    const data = b64encode(alawEncode(g));
    const msg = { type: WS.audio, call_id: this.callId, data };
    try {
      const c = this._conn || this.hass.connection;
      if (c && c.sendMessage) c.sendMessage(msg);
      else this.hass.callWS(msg).catch(() => {});
    } catch (_e) {
      /* dropped */
    }
  }

  async extend() {
    if (this.extendBusy || this.extensions >= MAX_EXTENSIONS) return;
    this.extendBusy = true;
    try {
      const r = await this.hass.callWS({ type: WS.extend, call_id: this.callId });
      this.extensions += 1;
      if (r && r.ends_at) this.backend.ends_at = r.ends_at;
      this._announce(S.announce.extended);
    } catch (_e) {
      this.extensions = MAX_EXTENSIONS; // refused: no more
    }
    this.extendBusy = false;
    if (this.view) this._render();
  }

  videoError() {
    if (this.phase === "live" && !this.videoLost) {
      this.videoLost = performance.now();
      this._render();
    }
  }

  videoLoaded() {
    if (this.videoLost) {
      this.videoLost = 0;
      if (this.view) this._render();
    }
  }

  _tick() {
    if (!this.view) return;
    const now = performance.now();
    if (this.micPending && this.micDeadline && now > this.micDeadline && !this.talking) {
      this.micDeadline = 0;
      this._micFailed(S.toastTalkFailed);
    }
    if (this.phase === "live" && this.videoLost && now - this.videoLost > VIDEO_LOST_MS) {
      this._finish({ kind: "videolost" });
      return;
    }
    if (this.phase === "live" && this.sound && !this.noticeSilent && this.liveAt && now - this.liveAt > SILENT_HINT_MS) {
      const silent = !this.player || !this.ctx || this.ctx.state !== "running" || this.player.frames === 0;
      if (silent && !this._silentShown) {
        this._silentShown = true;
        this.noticeSilent = true;
      }
    }
    if (this.phase === "ended" && now - (this.lastInteraction || this.endedAt) > ENDED_AUTOCLOSE_MS) {
      this.close(false);
      return;
    }
    this._render();
  }

  remaining() {
    const e = this.backend.ends_at;
    if (!e || this.phase !== "live") return null;
    return Math.max(0, Math.ceil(e - Date.now() / 1000));
  }

  _announce(text) {
    if (this.view) this.view.announce(text);
  }

  _render() {
    if (this.view) this.view.render();
  }

  _toast(text, error) {
    if (this.view) this.view.toast(text, error);
  }

  _focus() {
    if (this.view) this.view.focusPrimary();
  }

  onHass() {
    if (this.view) this._render();
  }
}

/* ------------------------------------------------------------ call screen */

const SCREEN_CSS = `
:host{--bev-surface:var(--primary-background-color,#fafafa);--bev-card:var(--card-background-color,#fff);
  --bev-text:var(--primary-text-color,#212121);--bev-text-2:var(--secondary-text-color,#727272);
  --bev-primary:var(--primary-color,#03a9f4);--bev-on-primary:var(--text-primary-color,#fff);
  --bev-success:var(--success-color,#4caf50);--bev-error:var(--error-color,#db4437);--bev-warning:var(--warning-color,#ffa600);
  --bev-neutral:color-mix(in srgb,var(--bev-text) 10%,transparent);--bev-neutral-strong:color-mix(in srgb,var(--bev-text) 18%,transparent);
  --bev-primary-d:color-mix(in srgb,var(--bev-primary) 80%,#000);--bev-success-d:color-mix(in srgb,var(--bev-success) 80%,#000);
  --bev-warning-t:color-mix(in srgb,var(--bev-warning) 55%,var(--bev-text));
  --bev-scrim:color-mix(in srgb,var(--bev-card) 72%,transparent);--bev-video-bg:var(--secondary-background-color,#e5e5e5);
  --bev-radius:var(--ha-card-border-radius,12px);--bev-dialog-radius:var(--ha-dialog-border-radius,24px);
  --bev-font:var(--ha-font-family-body,var(--paper-font-body1_-_font-family,Roboto,sans-serif))}
:host{position:fixed;inset:0;z-index:1000;display:block;font-family:var(--bev-font);color:var(--bev-text);
  background:var(--bev-surface);overscroll-behavior:contain;backdrop-filter:none;-webkit-backdrop-filter:none;
  -webkit-text-size-adjust:100%;animation:fade 160ms ease-out}
:host(.closing){animation:fadeout 120ms ease-in forwards}
*{box-sizing:border-box}
[hidden]{display:none!important}
button{font:inherit;color:inherit;border:0;background:none;padding:0;cursor:pointer;min-width:56px;min-height:56px;
  touch-action:manipulation;-webkit-tap-highlight-color:transparent;transition:transform 80ms}
button:focus-visible{outline:2px solid var(--bev-primary);outline-offset:3px}
button:active:not([aria-disabled=true]){transform:scale(.96)}
button[aria-disabled=true]{cursor:default}
ha-icon{--mdc-icon-size:24px;display:inline-flex;flex:none}
.panel{height:100%;display:flex;flex-direction:column;padding:env(safe-area-inset-top) env(safe-area-inset-right) 0 env(safe-area-inset-left)}
.topbar{flex:none;display:flex;align-items:center;gap:8px;height:56px;padding:0 20px}
.title{margin:0;font-size:20px;line-height:26px;font-weight:600;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;min-width:0}
.chip{flex:none;display:inline-flex;align-items:center;gap:6px;height:28px;padding:0 10px;border-radius:14px;
  font-size:13px;line-height:16px;font-weight:500;background:var(--bev-neutral);color:var(--bev-text)}
.chip .dot{width:8px;height:8px;border-radius:50%;background:var(--bev-success)}
.chip.talking{background:var(--bev-error);color:var(--bev-on-primary)}
.chip.talking .dot{background:var(--bev-on-primary);animation:blink 1s infinite}
.chip.ended{color:var(--bev-text-2)}
.chip.busy{color:var(--bev-warning-t)}
.chip.busy .dot{background:var(--bev-warning)}
.chip .sp{width:12px;height:12px;border-width:2px}
.timer{margin-left:auto;font-size:15px;line-height:20px;font-weight:500;color:var(--bev-text-2);font-variant-numeric:tabular-nums}
.timer.warn{color:var(--bev-warning-t);font-weight:600}
.band{flex:none;display:flex;align-items:center;justify-content:center;gap:10px;min-height:56px;padding:0 20px;
  background:var(--bev-success-d);color:var(--bev-on-primary);font-size:18px;font-weight:600}
.band ha-icon{animation:wiggle 1.6s infinite}
.video{position:relative;flex:none;width:100%;aspect-ratio:16/9;background:var(--bev-video-bg);overflow:hidden}
.video img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block}
.video .live{opacity:0;transition:opacity 200ms}
.video .live.on{opacity:1}
.video .dim{position:absolute;inset:0;background:var(--bev-scrim);display:flex;align-items:center;justify-content:center;flex-direction:column;gap:8px}
.video.talking::after{content:"";position:absolute;inset:0;box-shadow:inset 0 0 0 4px var(--bev-error);pointer-events:none}
.tag{position:absolute;left:8px;top:8px;background:var(--bev-error);color:var(--bev-on-primary);font-size:12px;font-weight:700;
  letter-spacing:.06em;padding:4px 8px;border-radius:6px}
.age{position:absolute;left:8px;bottom:8px;font-size:13px;line-height:16px;font-weight:500;padding:4px 10px;border-radius:999px;background:var(--bev-scrim)}
.vlost{font-size:15px;font-weight:600}
.vlost ha-icon{--mdc-icon-size:32px}
.sp{width:32px;height:32px;border:2.5px solid var(--bev-neutral);border-top-color:var(--bev-primary);border-radius:50%;animation:spin .9s linear infinite}
.middle{flex:1 1 auto;min-height:0;overflow:auto;display:flex;flex-direction:column;align-items:center;justify-content:safe center;
  gap:12px;padding:12px 20px;text-align:center}
.middle>*{max-width:360px;width:100%}
.middle>.sp,.middle>.bigicon{width:auto;max-width:none;flex:none;align-self:center}
.middle>.sp{width:32px;height:32px}
.headline{margin:0;font-size:22px;line-height:28px;font-weight:600}
.headline.err{color:var(--bev-error)}
.sub{margin:0;font-size:15px;line-height:21px;color:var(--bev-text-2)}
.bigicon{--mdc-icon-size:40px;color:var(--bev-text-2)}
.meter{display:flex;align-items:flex-end;justify-content:center;gap:4px;height:28px}
.meter .lbl{font-size:13px;line-height:16px;font-weight:500;color:var(--bev-text-2);width:36px;text-align:right;margin-right:6px;align-self:center}
.meter i{display:block;width:6px;border-radius:3px;background:var(--bev-neutral)}
.meter i:nth-of-type(1){height:8px}.meter i:nth-of-type(2){height:12px}.meter i:nth-of-type(3){height:16px}
.meter i:nth-of-type(4){height:20px}.meter i:nth-of-type(5){height:24px}
.meter.in i.on{background:var(--bev-text)}
.meter.out i.on{background:var(--bev-error)}
.meters{display:flex;flex-direction:column;gap:6px;align-items:center}
.note{display:flex;align-items:center;gap:12px;text-align:left;padding:12px 16px;border-radius:12px;background:var(--bev-neutral);font-size:15px;line-height:21px}
.note.warn{border-left:2px solid var(--bev-warning);border-radius:4px 12px 12px 4px}
.note .txt{flex:1;min-width:0}
.note button{min-height:56px;padding:0 8px;color:var(--bev-primary);font-size:15px;font-weight:600}
.controls{position:relative;flex:none;display:flex;flex-direction:column;gap:20px;padding:0 20px calc(16px + env(safe-area-inset-bottom))}
.door{display:flex;align-items:center;justify-content:center;gap:10px;width:100%;height:64px;border-radius:32px;font-size:18px;line-height:24px;font-weight:600;
  background:var(--bev-primary-d);color:var(--bev-on-primary);transition:background 200ms}
.door.opening{opacity:.85}
.door.opened{background:var(--bev-success-d)}
.door.opened ha-icon{animation:pop 180ms ease-out}
.door.unavail,.door.secondary{background:var(--bev-neutral);color:var(--bev-text)}
.door.unavail{color:var(--bev-text-2)}
.door .sp{width:20px;height:20px;border-width:2.5px;border-color:rgba(255,255,255,.35);border-top-color:var(--bev-on-primary)}
.row{display:grid;grid-template-columns:repeat(3,1fr);justify-items:center;align-items:start}
.row.two{grid-template-columns:1fr 1fr}
.rb{position:relative;display:flex;flex-direction:column;align-items:center;gap:6px}
.rb .lbl{font-size:13px;line-height:16px;font-weight:500}
.round{position:relative;width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;background:var(--bev-neutral);color:var(--bev-text)}
.round ha-icon{--mdc-icon-size:28px}
.round:active:not([aria-disabled=true]){background:var(--bev-neutral-strong)}
.round.big{width:80px;height:80px}
.round.red{background:var(--bev-error);color:var(--bev-on-primary)}
.round.green{background:var(--bev-success);color:var(--bev-on-primary)}
.round.green.halo{animation:halo 1.6s ease-out infinite}
.round.dis{opacity:.5}
.round.lock{opacity:.6}
.round.inv{background:var(--bev-text);color:var(--bev-card)}
.round.on::after{content:"";position:absolute;inset:0;border-radius:50%;border:3px solid color-mix(in srgb,var(--bev-error) 40%,transparent);animation:ring 1.2s ease-out infinite;pointer-events:none}
.round.pending::before{content:"";position:absolute;inset:-4px;border-radius:50%;border:3px solid transparent;border-top-color:var(--bev-primary);animation:spin .9s linear infinite}
.badge{position:absolute;top:-4px;right:-4px;width:22px;height:22px;border-radius:50%;background:var(--bev-surface);display:flex;align-items:center;justify-content:center;color:var(--bev-warning)}
.badge ha-icon{--mdc-icon-size:20px}
.badge.lockb{color:var(--bev-text-2)}
.pills{display:flex;gap:12px}
.pill{flex:1;height:56px;border-radius:28px;font-size:16px;font-weight:600;background:var(--bev-neutral);color:var(--bev-text)}
.pill.primary{background:var(--bev-primary-d);color:var(--bev-on-primary)}
.toast{position:absolute;left:20px;right:20px;bottom:calc(100% + 16px);z-index:3;padding:12px 16px;border-radius:12px;background:var(--bev-text);color:var(--bev-card);
  font-size:15px;line-height:21px;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical;overflow:hidden;animation:rise 160ms ease-out;cursor:pointer}
.toast.error{border-left:4px solid var(--bev-error)}
.coach{position:absolute;left:calc(100% - 4px);top:20px;white-space:nowrap;background:var(--bev-text);color:var(--bev-card);
  padding:8px 12px;border-radius:10px;font-size:13px;font-weight:500;pointer-events:none;z-index:2}
.coach::after{content:"";position:absolute;top:50%;right:100%;margin-top:-6px;border:6px solid transparent;border-right-color:var(--bev-text)}
.hint{display:none;text-align:center;font-size:13px;line-height:16px;color:var(--bev-text-2)}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.panel[data-phase=incoming] .only-call,.panel[data-phase=ended] .only-live,.panel[data-phase=incoming] .only-live{display:none!important}
.panel:not([data-phase=incoming]) .only-incoming{display:none!important}
.panel:not([data-phase=ended]) .only-ended{display:none!important}
.panel[data-phase=ended] .only-notended,.panel[data-phase=incoming] .only-notended{display:none!important}
@media (max-height:700px) and (orientation:portrait){.panel.talking .meter.in{display:none}}
@media (max-width:359px){.round{width:64px;height:64px}.door{height:56px}.controls,.middle,.topbar{padding-left:16px;padding-right:16px}}
@media (orientation:landscape) and (max-height:500px){
  .panel{display:grid;grid-template-columns:auto minmax(280px,1fr);grid-template-rows:auto 1fr auto}
  .video{grid-column:1;grid-row:1/4;align-self:center;width:min(62vw,calc((100dvh - env(safe-area-inset-top) - env(safe-area-inset-bottom))*16/9))}
  .topbar,.band{grid-column:2;grid-row:1}
  .middle{grid-column:2;grid-row:2}
  .controls{grid-column:2;grid-row:3;gap:12px}
  .round{width:64px;height:64px}.door{height:56px}
  .middle .sub,.middle .meters,.middle .note{display:none}
}
@media (min-width:900px) and (pointer:fine){
  :host{background:var(--mdc-dialog-scrim-color,rgba(0,0,0,.32));display:flex;align-items:center;justify-content:center}
  .panel{height:auto;max-height:calc(100vh - 48px);width:min(720px,calc(100vw - 48px));background:var(--bev-card);border-radius:var(--bev-dialog-radius);overflow:hidden;padding:0}
  .video{width:min(100%,calc(44vh*16/9));margin:0 auto}
  .middle{min-height:0}
  .door{max-width:360px;align-self:center}
  .hint{display:block}
  .controls{padding-top:8px}
}
@supports not (color:color-mix(in srgb,red,blue)){
  :host{--bev-primary-d:var(--bev-primary);--bev-success-d:var(--bev-success);--bev-warning-t:var(--bev-text);--bev-neutral:var(--secondary-background-color,#e5e5e5);--bev-neutral-strong:var(--divider-color,#ccc);--bev-scrim:var(--card-background-color,#fff)}
  .video .dim,.age{opacity:.85}
}
@media (prefers-reduced-motion:reduce){
  :host,:host(.closing){animation-duration:100ms}
  .band ha-icon,.chip.talking .dot,.round.green.halo,.round.on::after,.door.opened ha-icon,.toast{animation:none}
  .round.on::after{inset:-6px;border-color:var(--bev-error);border-width:3px;opacity:1;transform:none}
}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes fade{from{opacity:0}to{opacity:1}}
@keyframes fadeout{to{opacity:0}}
@keyframes blink{50%{opacity:.35}}
@keyframes pop{from{transform:scale(.6)}to{transform:scale(1)}}
@keyframes rise{from{transform:translateY(8px);opacity:0}to{transform:none;opacity:1}}
@keyframes ring{from{transform:scale(1);opacity:1}to{transform:scale(1.25);opacity:0}}
@keyframes halo{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--bev-success) 55%,transparent)}100%{box-shadow:0 0 0 14px transparent}}
@keyframes wiggle{0%,40%,100%{transform:rotate(0)}10%{transform:rotate(12deg)}20%{transform:rotate(-12deg)}30%{transform:rotate(8deg)}}
`;

const SCREEN_HTML = `
<div class="panel" part="panel" data-phase="connecting">
  <div class="band only-incoming" aria-hidden="true">${ic("bell-ring")}<span class="bandtxt"></span></div>
  <div class="topbar only-call">
    <h2 class="title" id="title"></h2>
    <span class="chip" aria-hidden="true"><span class="sp"></span><span class="dot"></span><span class="t"></span></span>
    <span class="timer" aria-hidden="true"></span>
  </div>
  <div class="video">
    <img class="still" alt="" draggable="false">
    <img class="live" alt="" draggable="false">
    <div class="dim spin-layer"><div class="sp"></div></div>
    <div class="dim vlost" hidden>${ic("video-off-outline")}<span></span></div>
    <span class="tag" hidden></span>
    <span class="age" hidden></span>
  </div>
  <div class="middle">
    <div class="sp only-notcalling mspin" hidden></div>
    <ha-icon class="bigicon" hidden></ha-icon>
    <h3 class="headline"></h3>
    <p class="sub"></p>
    <div class="meters only-live" hidden>
      <div class="meter in"><span class="lbl"></span><i></i><i></i><i></i><i></i><i></i></div>
      <div class="meter out" hidden><span class="lbl"></span><i></i><i></i><i></i><i></i><i></i></div>
    </div>
    <div class="note" hidden>
      <ha-icon></ha-icon><span class="txt"></span><button type="button" class="noteact" hidden></button>
    </div>
  </div>
  <div class="controls">
    <div class="toast" role="status" hidden></div>
    <button type="button" class="door" data-act="door" aria-label="Open door"><span class="doorinner"></span></button>
    <div class="row only-live">
      <div class="rb micwrap">
        <span class="coach" hidden></span>
        <button type="button" class="round" data-act="mic" aria-label="Microphone">
          <ha-icon></ha-icon><span class="badge" hidden><ha-icon></ha-icon></span>
        </button>
        <span class="lbl"></span>
      </div>
      <div class="rb">
        <button type="button" class="round" data-act="sound" aria-label="Sound"><ha-icon></ha-icon></button>
        <span class="lbl"></span>
      </div>
      <div class="rb">
        <button type="button" class="round red" data-act="hangup" aria-label="Hang up">${ic("phone-hangup")}</button>
        <span class="lbl"></span>
      </div>
    </div>
    <div class="row two only-incoming">
      <div class="rb">
        <button type="button" class="round big red" data-act="decline" aria-label="Decline">${ic("phone-hangup")}</button>
        <span class="lbl"></span>
      </div>
      <div class="rb">
        <button type="button" class="round big green halo" data-act="answer" aria-label="Answer">${ic("phone")}</button>
        <span class="lbl"></span>
      </div>
    </div>
    <div class="pills only-ended">
      <button type="button" class="pill" data-act="close"></button>
      <button type="button" class="pill primary" data-act="again"></button>
    </div>
    <div class="hint only-live"></div>
  </div>
  <div class="sr" aria-live="polite" role="status"></div>
</div>
`;

class BalterEvo2CallScreen extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this.shadowRoot.innerHTML = `<style>${SCREEN_CSS}</style>${SCREEN_HTML}`;
    this._q = (s) => this.shadowRoot.querySelector(s);
    this._toastTimer = 0;
    this._shownLive = false;
  }

  attach(call) {
    this.call = call;
    const host = call.card;
    // Copy the theme variables of the card onto the portal (per-view themes).
    try {
      const cs = getComputedStyle(host);
      for (const v of THEME_VARS) {
        const val = cs.getPropertyValue(v).trim();
        if (val) this.style.setProperty(v, val);
      }
    } catch (_e) {
      /* no theme copy */
    }
    this._opener = host._pictureButton ? host._pictureButton() : null;
    const panelEl = this._q(".panel");
    panelEl.setAttribute("role", "dialog");
    panelEl.setAttribute("aria-modal", "true");
    panelEl.setAttribute("aria-labelledby", "title");
    this.shadowRoot.querySelector(".panel").addEventListener("click", (e) => this._click(e));
    this.addEventListener("keydown", (e) => this._key(e));
    this.addEventListener("keyup", (e) => {
      if (e.key === " ") e.preventDefault(); // Space is the mic key, never a button press
    });
    this.addEventListener("pointerdown", () => {
      call.lastInteraction = performance.now();
    });
    this._q(".noteact").addEventListener("click", () => this._noteAction());
    this._q(".toast").addEventListener("click", () => {
      this._q(".toast").hidden = true;
    });
    const live = this._q(".live");
    live.addEventListener("error", () => {
      if (live.getAttribute("src")) call.videoError();
    });
    live.addEventListener("load", () => {
      if (live.getAttribute("src")) {
        live.classList.add("on");
        call.videoLoaded();
      }
    });
    this._lbl();
  }

  _lbl() {
    const labels = this.shadowRoot.querySelectorAll(".rb .lbl");
    // order in DOM: mic, sound, hangup, decline, answer
    this._micLbl = labels[0];
    this._soundLbl = labels[1];
    setText(labels[2], S.hangup);
    setText(labels[3], S.decline);
    setText(labels[4], S.answer);
    setText(this._q(".meter.in .lbl"), S.meterDoor);
    setText(this._q(".meter.out .lbl"), S.meterYou);
    setText(this._q(".hint"), S.keys);
    setText(this._q(".tag"), S.micTag);
    setText(this._q(".vlost span"), S.midVideoLost);
    setText(this._q(".coach"), S.micCoach);
  }

  /* ---- events ---- */

  _click(e) {
    const b = e.target.closest("button[data-act]");
    if (!b) return;
    const c = this.call;
    c.lastInteraction = performance.now();
    switch (b.dataset.act) {
      case "door":
        if (b.getAttribute("aria-disabled") !== "true") c.card._door.press();
        break;
      case "mic":
        c.toggleMic();
        break;
      case "sound":
        c.toggleSound();
        break;
      case "hangup":
        c.hangup();
        break;
      case "decline":
        c.decline();
        break;
      case "answer":
        c.answer();
        break;
      case "close":
        haptic("light");
        c.close(false);
        break;
      case "again":
        c.again();
        break;
      default:
    }
  }

  _noteAction() {
    const c = this.call;
    const act = this._noteActName;
    if (act === "echo") {
      storageSet("balter_evo2_echo_seen", "1");
      c.noticeEcho = false;
    } else if (act === "silent") {
      c.noticeSilent = false;
    } else if (act === "extend") {
      c.extend();
    } else if (act === "secure") {
      const url = secureUrl(c.card._config, c.hass);
      if (url) {
        const target = secureTarget(url);
        if (!window.open(target, "_blank", "noopener")) location.href = target;
      }
    }
    this.render();
  }

  _key(e) {
    const c = this.call;
    if (!c) return;
    if (e.key === "Escape") {
      e.preventDefault();
      if (c.phase === "incoming") c.decline();
      else if (c.phase === "ended") c.close(false);
      else c.hangup();
      return;
    }
    if (e.key === " " && (c.phase === "live" || c.phase === "connecting")) {
      e.preventDefault();
      c.toggleMic();
      return;
    }
    if (e.key === "Tab") {
      const list = [...this.shadowRoot.querySelectorAll("button")].filter(
        (b) => !b.disabled && b.getAttribute("aria-disabled") !== "true" && b.offsetParent !== null,
      );
      if (!list.length) return;
      const active = this.shadowRoot.activeElement;
      const i = list.indexOf(active);
      let n = i + (e.shiftKey ? -1 : 1);
      if (n < 0) n = list.length - 1;
      if (n >= list.length) n = 0;
      e.preventDefault();
      list[n].focus();
    }
  }

  focusPrimary() {
    requestAnimationFrame(() => {
      const c = this.call;
      if (!c) return;
      const sel =
        c.phase === "ended"
          ? ".pill.primary"
          : c.phase === "incoming"
            ? "[data-act=answer]"
            : "[data-act=hangup]";
      const el = this._q(sel);
      if (el) el.focus();
    });
  }

  announce(text) {
    const sr = this._q(".sr");
    sr.textContent = "";
    setTimeout(() => {
      sr.textContent = text;
    }, 30);
  }

  toast(text, error) {
    const t = this._q(".toast");
    t.textContent = text;
    t.className = `toast${error ? " error" : ""}`;
    t.setAttribute("role", error ? "alert" : "status");
    t.hidden = false;
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => {
      t.hidden = true;
    }, error ? 6000 : 4000);
  }

  /* ---- render ---- */

  render() {
    const c = this.call;
    if (!c) return;
    const hass = c.hass;
    const phase = c.phase;
    const panel = this._q(".panel");
    panel.dataset.phase = phase === "connecting" || phase === "live" ? phase : phase;
    const b = c.backend;
    const talking = c.talking;
    panel.classList.toggle("talking", !!talking);
    const live = phase === "live";
    const card = c.card;

    setText(this._q("#title"), c.name);
    setText(this._q(".bandtxt"), S.ringBand);

    // still
    const still = this._q(".still");
    const stillUrl = card._stillUrl || "";
    if (stillUrl && still.getAttribute("src") !== stillUrl) still.setAttribute("src", stillUrl);
    const ageEl = this._q(".age");
    ageEl.hidden = phase !== "incoming";
    if (phase === "incoming") setText(ageEl, `${card._ageText()} · ${S.notLive}`);

    // live video
    const liveImg = this._q(".live");
    if (live && !liveImg.getAttribute("src")) {
      const st = hass.states[c.entity];
      const tok = st && st.attributes && st.attributes.access_token;
      let url = `/api/camera_proxy_stream/${c.entity}${tok ? `?token=${tok}` : ""}`;
      if (hass.hassUrl) url = hass.hassUrl(url);
      liveImg.classList.remove("on");
      liveImg.setAttribute("src", url);
    }
    const video = this._q(".video");
    video.classList.toggle("talking", talking);
    this._q(".tag").hidden = !talking;
    this._q(".spin-layer").hidden = phase !== "connecting";
    const lost = live && !!c.videoLost;
    this._q(".vlost").hidden = !lost;

    // chip + timer
    const chip = this._q(".chip");
    const busy = phase === "ended" && c.ending && c.ending.kind === "busy";
    chip.className = "chip";
    if (talking && live) chip.classList.add("talking");
    if (phase === "ended") chip.classList.add(busy ? "busy" : "ended");
    chip.querySelector(".sp").hidden = phase !== "connecting";
    chip.querySelector(".dot").hidden = phase !== "live";
    setText(
      chip.querySelector(".t"),
      phase === "connecting" ? S.chipConnecting
        : phase === "live" ? (talking ? S.chipTalking : S.chipLive)
          : busy ? S.chipBusy : S.chipEnded,
    );
    chip.hidden = phase === "incoming";
    const rem = c.remaining();
    const timer = this._q(".timer");
    timer.hidden = rem === null;
    if (rem !== null) {
      setText(timer, `${Math.floor(rem / 60)}:${String(rem % 60).padStart(2, "0")}`);
      timer.classList.toggle("warn", rem <= 30);
    }

    this._renderMiddle(c, rem);
    this._renderControls(c);
    this.meters();
  }

  _renderMiddle(c, rem) {
    const phase = c.phase;
    const q = this._q.bind(this);
    const spin = q(".mspin");
    const big = q(".bigicon");
    const head = q(".headline");
    const sub = q(".sub");
    const meters = q(".meters");
    head.classList.remove("err");
    spin.hidden = true;
    big.hidden = true;
    meters.hidden = true;
    q(".meter.out").hidden = !c.talking;
    let h = "";
    let s = "";
    if (phase === "incoming") {
      h = c.name;
      s = S.ringHint;
    } else if (phase === "connecting") {
      spin.hidden = false;
      spin.className = "sp mspin";
      h = S.midConnecting;
      s = S.midConnectingSub;
    } else if (phase === "live") {
      meters.hidden = false;
      if (c.videoLost) {
        h = S.midVideoLost;
        s = S.midVideoLostSub;
      } else if (c.talking) {
        h = S.midTalking;
        s = S.midTalkingSub;
        head.classList.add("err");
      } else if (!c.sound) {
        h = S.midSoundOff;
        s = S.midSoundOffSub;
      } else {
        h = S.midListening;
        s = c.micErr || !isSecureCtx() || !micAvailable() ? S.midVideoLostSub : S.midListeningSub;
      }
    } else if (phase === "ended") {
      const e = c.ending || { kind: "error" };
      const map = {
        busy: ["account-clock", S.busyTitle, S.busyBody, S.busyAction],
        error: ["lan-disconnect", S.errorTitle, S.errorBody(e.message), S.again],
        limit: ["timer-outline", S.limitTitle, S.limitBody, S.again],
        lost: ["wifi-off", S.lostTitle, S.lostBody, S.again],
        timeout: ["timer-outline", S.timeoutTitle, S.timeoutBody, S.again],
        videolost: ["video-off-outline", S.videoLostTitle, S.videoLostBody, S.again],
      };
      const m = map[e.kind] || map.error;
      big.hidden = false;
      setIcon(big, `mdi:${m[0]}`);
      h = m[1];
      s = m[2];
      setText(q("[data-act=again]"), m[3]);
      setText(q("[data-act=close]"), S.close);
    }
    setText(head, h);
    setText(sub, s);

    // note slot: ending banner > notices
    const note = q(".note");
    const act = q(".noteact");
    let n = null;
    if (phase === "live" && rem !== null && rem <= 20 && rem > 0) {
      n = {
        warn: true,
        icon: "timer-outline",
        text: S.endingBanner(rem),
        act: (c.backend.can_extend !== false && c.extensions < MAX_EXTENSIONS) ? ["extend", S.extend] : null,
      };
      if (!c._endingAnnounced) {
        c._endingAnnounced = true;
        this.announce(S.announce.ending);
      }
    } else if (phase === "live") {
      const url = secureUrl(c.card._config, c.hass);
      // A link out would leave the app (Safari, new login, call ended): inside the Companion app and
      // on iOS the fix is the app's own server URL.
      const inApp = isCompanionApp() || isIOS();
      if (c.noticeInsecure) {
        n = {
          icon: "lock",
          text: inApp ? S.noticeInsecureApp : url ? S.noticeInsecureUrl(new URL(url).origin) : S.noticeInsecure,
          act: url && !inApp ? ["secure", S.noticeOpen] : null,
        };
      } else if (c.micErr === "denied") {
        n = { icon: "alert-circle", text: S.noticeDenied + (isIOS() ? ` ${S.noticeDeniedIos}` : "") };
      } else if (c.micErr === "none") {
        n = { icon: "microphone-off", text: S.noticeNoDevice };
      } else if (c.noticeEcho) {
        n = { icon: "headphones", text: S.noticeEcho, act: ["echo", S.noticeEchoOk] };
      } else if (c.noticeSilent) {
        n = { icon: "bell-off-outline", text: S.noticeSilent, act: ["silent", S.dismiss + " ×"] };
      }
    }
    note.hidden = !n;
    // landscape hides the note slot (DESIGN 4.0b): say a new notice once as a toast instead
    const nText = n && !n.warn ? n.text : null;
    if (nText && nText !== this._lastNoteToast && window.matchMedia && window.matchMedia("(orientation:landscape) and (max-height:500px)").matches) {
      this.toast(nText, false);
    }
    this._lastNoteToast = nText;
    if (n) {
      note.classList.toggle("warn", !!n.warn);
      setIcon(note.querySelector("ha-icon"), `mdi:${n.icon}`);
      setText(note.querySelector(".txt"), n.text);
      act.hidden = !n.act;
      this._noteActName = n.act ? n.act[0] : null;
      if (n.act) setText(act, n.act[1]);
    }
  }

  _renderControls(c) {
    const q = this._q.bind(this);
    const phase = c.phase;
    const card = c.card;
    const cfg = card._config;

    // door
    const door = q(".door");
    door.hidden = !cfg.lock_entity;
    if (cfg.lock_entity) {
      const lockSt = c.hass.states[cfg.lock_entity];
      const unavailable = !lockSt || lockSt.state === "unavailable";
      const ds = card._door.state;
      door.className = "door";
      door.setAttribute("aria-busy", ds === "opening" ? "true" : "false");
      door.setAttribute("aria-disabled", unavailable ? "true" : "false");
      let html;
      if (unavailable) {
        door.classList.add("unavail");
        html = `${ic("key-variant")}<span>${S.doorUnavailable}</span>`;
      } else if (ds === "opening") {
        door.classList.add("opening");
        html = `<span class="sp"></span><span>${S.doorOpening}</span>`;
      } else if (ds === "opened") {
        door.classList.add("opened");
        html = `${ic("check-bold")}<span>${S.doorOpened}</span>`;
      } else {
        if (phase === "incoming") door.classList.add("secondary");
        html = `${ic("key-variant")}<span>${S.doorLabel}</span>`;
      }
      const inner = q(".doorinner");
      if (inner.dataset.k !== html) {
        inner.dataset.k = html;
        inner.innerHTML = html;
        inner.style.display = "contents";
      }
    }

    if (phase === "incoming" || phase === "ended") return;

    // mic
    const mic = q("[data-act=mic]");
    const badge = mic.querySelector(".badge");
    const micIcon = mic.querySelector("ha-icon");
    mic.className = "round";
    badge.hidden = true;
    badge.classList.remove("lockb");
    let label = S.micOff;
    let pressed = "false";
    let aDisabled = "false";
    let icon = "microphone-off";
    if (phase !== "live") {
      mic.classList.add("dis");
      label = S.micDisabled;
      aDisabled = "true";
    } else if (!isSecureCtx() || !micAvailable()) {
      mic.classList.add("lock");
      badge.hidden = false;
      badge.classList.add("lockb");
      setIcon(badge.querySelector("ha-icon"), "mdi:lock");
      label = S.micNone;
      aDisabled = "true";
    } else if (c.micErr) {
      badge.hidden = false;
      setIcon(badge.querySelector("ha-icon"), "mdi:alert-circle");
      label = c.micErr === "none" ? S.micNone : S.micBlocked;
    } else if (c.talking) {
      mic.classList.add("red", "on");
      label = S.micOn;
      pressed = "true";
      icon = "microphone";
    } else if (c.micPending) {
      mic.classList.add("pending");
      label = S.micPending;
      icon = "microphone";
    }
    setIcon(micIcon, `mdi:${icon}`);
    mic.setAttribute("aria-pressed", pressed);
    mic.setAttribute("aria-disabled", aDisabled);
    mic.setAttribute("aria-busy", c.micPending ? "true" : "false");
    setText(this._micLbl, label);
    const coach = q(".coach");
    coach.hidden = !(c.coachUntil && performance.now() < c.coachUntil && !c.talking && !c.micPending);

    // sound
    const snd = q("[data-act=sound]");
    snd.className = c.sound ? "round" : "round inv";
    setIcon(snd.querySelector("ha-icon"), c.sound ? "mdi:volume-high" : "mdi:volume-off");
    snd.setAttribute("aria-pressed", c.sound ? "true" : "false");
    setText(this._soundLbl, c.sound ? S.soundOn : S.soundOff);
  }

  /** Fast path: the level meters (15 Hz). */
  meters() {
    const c = this.call;
    if (!c || c.phase !== "live") return;
    const set = (sel, bars) => {
      const els = this.shadowRoot.querySelectorAll(`${sel} i`);
      els.forEach((el, i) => el.classList.toggle("on", i < bars));
    };
    if (c.player) {
      c.player.level *= 0.9;
      set(".meter.in", c.sound ? levelToBars(c.player.level) : 0);
    }
    c.outLevel *= 0.9;
    set(".meter.out", c.talking ? levelToBars(c.outLevel) : 0);
  }

  dropVideo() {
    // WebKit keeps a multipart MJPEG load alive unless src is cleared first.
    const live = this._q(".live");
    if (live) {
      live.classList.remove("on");
      live.removeAttribute("src");
      live.src = "";
    }
  }

  dispose(instant) {
    this.dropVideo();
    clearTimeout(this._toastTimer);
    const opener = this._opener;
    const done = () => {
      const live = this._q(".live");
      if (live) live.remove();
      this.remove();
      if (opener && opener.isConnected !== false && opener.focus) {
        try {
          opener.focus({ preventScroll: true });
        } catch (_e) {
          /* ignore */
        }
      }
    };
    this.call = null;
    if (instant) done();
    else {
      this.classList.add("closing");
      setTimeout(done, 130);
    }
  }
}

/* ---------------------------------------------------------------- the card */

const CARD_CSS = `
:host{display:block}
ha-card{overflow:hidden;position:relative;--ha-card-backdrop-filter:none;-webkit-backdrop-filter:none;backdrop-filter:none;
  font-family:var(--bev-font)}
*{box-sizing:border-box}
[hidden]{display:none!important}
.root{--bev-primary-d:color-mix(in srgb,var(--bev-primary) 80%,#000);--bev-success-d:color-mix(in srgb,var(--bev-success) 80%,#000);--bev-card:var(--card-background-color,#fff);--bev-text:var(--primary-text-color,#212121);--bev-text-2:var(--secondary-text-color,#727272);
  --bev-primary:var(--primary-color,#03a9f4);--bev-on-primary:var(--text-primary-color,#fff);--bev-success:var(--success-color,#4caf50);
  --bev-error:var(--error-color,#db4437);--bev-neutral:color-mix(in srgb,var(--bev-text) 10%,transparent);
  --bev-neutral-strong:color-mix(in srgb,var(--bev-text) 18%,transparent);--bev-scrim:color-mix(in srgb,var(--bev-card) 72%,transparent);
  --bev-video-bg:var(--secondary-background-color,#e5e5e5);
  --bev-font:var(--ha-font-family-body,var(--paper-font-body1_-_font-family,Roboto,sans-serif));font-family:var(--bev-font);color:var(--bev-text)}
@supports not (color:color-mix(in srgb,red,blue)){.root{--bev-primary-d:var(--bev-primary);--bev-success-d:var(--bev-success);--bev-neutral:var(--secondary-background-color,#e5e5e5);--bev-neutral-strong:var(--divider-color,#ccc);--bev-scrim:var(--card-background-color,#fff)}}
button{font:inherit;color:inherit;border:0;background:none;padding:0;cursor:pointer;touch-action:manipulation;-webkit-tap-highlight-color:transparent;transition:transform 120ms}
button:focus-visible{outline:2px solid var(--bev-primary);outline-offset:-2px}
ha-icon{--mdc-icon-size:24px;display:inline-flex}
.band{display:flex;align-items:center;gap:10px;min-height:48px;padding:0 16px;background:var(--bev-success-d);color:var(--bev-on-primary);font-size:16px;font-weight:600}
.band ha-icon{animation:wiggle 1.6s infinite}
.pic{position:relative;display:block;width:100%;aspect-ratio:16/9;background:var(--bev-video-bg);overflow:hidden}
.pic:active{transform:scale(.98)}
.pic img{position:absolute;inset:0;width:100%;height:100%;object-fit:cover;display:block}
.center{position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px}
.badge{width:64px;height:64px;border-radius:50%;background:var(--bev-scrim);display:flex;align-items:center;justify-content:center}
.badge ha-icon{--mdc-icon-size:32px}
.lblpill{font-size:13px;line-height:16px;font-weight:500;padding:6px 12px;border-radius:999px;background:var(--bev-scrim)}
.liveNow{position:absolute;left:12px;top:12px;display:flex;align-items:center;gap:6px;font-size:13px;font-weight:500;padding:4px 10px;border-radius:999px;background:var(--bev-scrim)}
.liveNow i{width:8px;height:8px;border-radius:50%;background:var(--bev-success)}
.agechip{position:absolute;left:12px;bottom:12px;font-size:13px;font-weight:500;padding:4px 10px;border-radius:999px;background:var(--bev-scrim)}
.foot{display:flex;align-items:center;gap:12px;padding:12px 16px;min-height:80px}
.meta{flex:1;min-width:0}
.name{font-size:16px;line-height:22px;font-weight:500;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.age{font-size:13px;line-height:16px;font-weight:500;color:var(--bev-text-2)}
.door{display:inline-flex;align-items:center;justify-content:center;gap:8px;height:56px;min-width:56px;padding:0 20px;border-radius:28px;
  background:var(--bev-primary-d);color:var(--bev-on-primary);font-size:16px;font-weight:600}
.door.opening{opacity:.85}
.door.opened{background:var(--bev-success-d)}
.door.unavail,.door.secondary{background:var(--bev-neutral);color:var(--bev-text)}
.door.unavail{color:var(--bev-text-2)}
.sp{width:20px;height:20px;border:2.5px solid rgba(255,255,255,.35);border-top-color:var(--bev-on-primary);border-radius:50%;animation:spin .9s linear infinite}
.ringfoot{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px}
.rb{display:flex;flex-direction:column;align-items:center;gap:4px;font-size:13px;font-weight:500}
.round{width:64px;height:64px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:var(--bev-on-primary)}
.round.red{background:var(--bev-error)}
.round.green{background:var(--bev-success)}
.round.halo{animation:halo 1.6s ease-out infinite}
ha-card.ringing{border:2px solid var(--bev-success)}
ha-card.ringing.pulse{animation:halo 1.6s ease-out infinite}
.err{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;aspect-ratio:16/9;padding:16px;text-align:center;background:var(--bev-video-bg);font-size:15px;line-height:21px}
.err ha-icon{--mdc-icon-size:32px;color:var(--bev-error)}
.err small{color:var(--bev-text-2);font-size:15px}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
@media (prefers-reduced-motion:reduce){.band ha-icon,.round.halo,ha-card.ringing.pulse{animation:none}ha-card.ringing.pulse{box-shadow:0 0 0 4px var(--bev-success)}}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes wiggle{0%,40%,100%{transform:rotate(0)}10%{transform:rotate(12deg)}20%{transform:rotate(-12deg)}30%{transform:rotate(8deg)}}
@keyframes halo{0%{box-shadow:0 0 0 0 color-mix(in srgb,var(--bev-success) 55%,transparent)}100%{box-shadow:0 0 0 12px transparent}}
`;

const CARD_HTML = `
<ha-card>
  <div class="root">
    <div class="err" hidden>${ic("alert-outline")}<div class="errmsg"></div><small class="errsub"></small></div>
    <div class="main">
      <div class="band" hidden>${ic("bell-ring")}<span></span></div>
      <button type="button" class="pic">
        <img alt="" draggable="false">
        <div class="center idlec"><span class="badge">${ic("play")}</span><span class="lblpill"></span></div>
        <span class="liveNow" hidden><i></i><span></span></span>
        <span class="agechip" hidden></span>
      </button>
      <div class="foot">
        <div class="meta"><div class="name"></div><div class="age"></div></div>
        <button type="button" class="door" data-act="door" hidden></button>
      </div>
      <div class="ringfoot" hidden>
        <div class="rb"><button type="button" class="round red" data-act="decline" aria-label="Decline">${ic("phone-hangup")}</button><span class="dl"></span></div>
        <button type="button" class="door secondary" data-act="door" hidden></button>
        <div class="rb"><button type="button" class="round green halo" data-act="answer" aria-label="Answer">${ic("phone")}</button><span class="al"></span></div>
      </div>
    </div>
    <div class="sr" aria-live="polite"></div>
    <div class="sr" aria-live="assertive" data-r></div>
  </div>
</ha-card>
`;

class BalterEvo2CallCard extends HTMLElement {
  static getStubConfig(hass) {
    const ids = hass && hass.states ? Object.keys(hass.states) : [];
    const cam = ids.find((i) => i.startsWith("camera.") && /entrance|door|balter/i.test(i)) || ids.find((i) => i.startsWith("camera.")) || "camera.entrance_front_door";
    const lock = ids.find((i) => i.startsWith("lock.") && /door|opener/i.test(i)) || ids.find((i) => i.startsWith("lock."));
    const cfg = { camera_entity: cam };
    if (lock) cfg.lock_entity = lock;
    return cfg;
  }

  static getConfigElement() {
    return document.createElement("balter-evo2-call-card-editor");
  }

  constructor() {
    super();
    this.attachShadow({ mode: "open" });
    this._config = null;
    this._hass = null;
    this._built = false;
    this._door = new Door(this);
    this._stillKey = null;
    this._stillUrl = "";
    this._ringState = null;
    this._ringDismissed = false;
    this._call = null;
    this._configError = false;
  }

  setConfig(config) {
    if (!config || !config.camera_entity) throw new Error("camera_entity is required");
    this._config = { ring_takeover: true, ...config };
    this._configError = false;
    this._build();
    this._renderIdle();
  }

  getCardSize() {
    // 16:9 picture + footer: about 7 rows of 50 px at full width.
    return 7;
  }

  getGridOptions() {
    // The height follows the width (16:9 picture), so the section sizes it.
    return { columns: 12, rows: "auto", min_columns: 6 };
  }

  set hass(h) {
    this._hass = h;
    if (!this._config) return;
    this._updateRing();
    this._renderIdle();
    if (this._call) this._call.onHass();
  }

  connectedCallback() {
    this._connected = true;
    clearTimeout(this._dcTimer);
    if (this._config && this._hass) this._updateRing();
  }

  disconnectedCallback() {
    this._connected = false;
    // Lovelace re-parents cards when the column count changes (rotation, edit mode): detach and
    // re-attach in one go. Release only if the element did not come back; the heartbeat, visibility
    // and pagehide paths still cover a real exit within the 1-2 s budget.
    clearTimeout(this._dcTimer);
    this._dcTimer = setTimeout(() => {
      if (this.isConnected) return;
      if (this._call) this._call.close(true);
      this._door.dispose();
    }, 300);
  }

  /* ---- build / render ---- */

  _build() {
    if (this._built) return;
    this._built = true;
    const root = this.shadowRoot;
    root.innerHTML = `<style>${CARD_CSS}</style>${CARD_HTML}`;
    this._r = (s) => root.querySelector(s);
    root.querySelector(".pic").addEventListener("click", () => this._picTap());
    root.addEventListener("click", (e) => {
      const b = e.target.closest("button[data-act]");
      if (!b) return;
      if (b.dataset.act === "door") {
        if (b.getAttribute("aria-disabled") !== "true") this._door.press();
      } else if (b.dataset.act === "answer") this._startCall("answer");
      else if (b.dataset.act === "decline") {
        this._ringDismissed = true;
        this._renderIdle();
      }
    });
    setText(root.querySelector(".lblpill"), S.tap);
    setText(root.querySelector(".dl"), S.decline);
    setText(root.querySelector(".al"), S.answer);
    setText(root.querySelector(".liveNow span:last-child"), S.liveNow);
  }

  _pictureButton() {
    return this._r ? this._r(".pic") : null;
  }

  _camState() {
    return this._hass && this._hass.states ? this._hass.states[this._config.camera_entity] : undefined;
  }

  _name() {
    if (this._config.name) return this._config.name;
    const st = this._camState();
    return (st && st.attributes && st.attributes.friendly_name) || this._config.camera_entity;
  }

  _stillTaken() {
    const st = this._camState();
    const v = st && st.attributes && st.attributes.still_taken;
    if (!v) return null;
    const d = typeof v === "number" ? new Date(v * 1000) : new Date(v);
    return Number.isNaN(d.getTime()) ? null : d;
  }

  _ageText() {
    const d = this._stillTaken();
    if (!d) return S.noStill;
    const lang = (this._hass && this._hass.locale && this._hass.locale.language) || undefined;
    const t = new Intl.DateTimeFormat(lang, { hour: "2-digit", minute: "2-digit" }).format(d);
    const now = new Date();
    const dayStart = (x) => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((dayStart(now) - dayStart(d)) / 86400000);
    if (diff <= 0) return S.ageToday(t);
    if (diff === 1) return S.ageYesterday(t);
    return S.ageOlder(new Intl.DateTimeFormat(lang, { day: "numeric", month: "short" }).format(d), t);
  }

  /** The stored still: changes only when the still changes, never polls. */
  _refreshStill() {
    const st = this._camState();
    if (!st) return;
    const pic = st.attributes && st.attributes.entity_picture;
    if (!pic) return;
    const taken = st.attributes.still_taken || "";
    const base = pic.split("?")[0];
    const key = `${base}|${taken}`;
    if (key === this._stillKey && this._stillUrl) return;
    this._stillKey = key;
    this._stillUrl = pic + (pic.includes("?") ? "&" : "?") + `t=${encodeURIComponent(taken)}`;
    if (this._hass && this._hass.hassUrl) this._stillUrl = this._hass.hassUrl(this._stillUrl);
  }

  _ringing() {
    const ent = this._config.ring_entity;
    if (!ent || !this._hass) return false;
    const st = this._hass.states[ent];
    if (!st || st.state !== "on") return false;
    // a helper nobody switches off must not ring forever
    const since = Date.parse(st.last_changed);
    return !(since && Date.now() - since > RING_STALE_MS);
  }

  _renderIdle() {
    if (!this._built || !this._config) return;
    const r = this._r;
    const cfg = this._config;
    const st = this._camState();
    const err = r(".err");
    const main = r(".main");
    if (this._configError || (this._hass && !st)) {
      err.hidden = false;
      main.hidden = true;
      setText(r(".errmsg"), S.configNotFound(cfg.camera_entity));
      setText(r(".errsub"), S.configNotFoundSub);
      return;
    }
    err.hidden = true;
    main.hidden = false;
    if (!st) return;
    this._refreshStill();
    const img = r(".pic img");
    if (this._stillUrl && img.getAttribute("src") !== this._stillUrl) img.setAttribute("src", this._stillUrl);
    const ringing = this._ringing() && !this._ringDismissed && !this._call;
    const ha = r("ha-card");
    ha.classList.toggle("ringing", ringing);
    ha.classList.toggle("pulse", ringing);
    r(".band").hidden = !ringing;
    setText(r(".band span"), S.ringBand);
    r(".foot").hidden = ringing;
    r(".ringfoot").hidden = !ringing;
    r(".idlec").hidden = ringing;
    const live = st.state === "streaming";
    r(".liveNow").hidden = !live || ringing;
    const chip = r(".agechip");
    chip.hidden = !ringing;
    if (ringing) setText(chip, `${this._ageText()} · ${S.notLive}`);
    r(".pic").setAttribute("aria-label", ringing ? S.answer : S.ariaLook(this._name()));
    setText(r(".name"), this._name());
    setText(r(".age"), this._ageText());
    this._renderDoorButtons();
    if (ringing && !this._ringAnnounced) {
      this._ringAnnounced = true;
      const a = r("[data-r]");
      a.textContent = S.ringAnnounce(this._name());
      haptic("warning");
    }
    if (!ringing && !this._ringing()) this._ringAnnounced = false;
  }

  _renderDoorButtons() {
    const lockId = this._config.lock_entity;
    this.shadowRoot.querySelectorAll(".door").forEach((b) => {
      b.hidden = !lockId;
      if (!lockId) return;
      const ls = this._hass && this._hass.states[lockId];
      const unavailable = !ls || ls.state === "unavailable";
      const ds = this._door.state;
      const secondary = b.classList.contains("secondary");
      b.className = `door${secondary ? " secondary" : ""}`;
      b.setAttribute("aria-label", S.doorLabel);
      b.setAttribute("aria-disabled", unavailable ? "true" : "false");
      b.setAttribute("aria-busy", ds === "opening" ? "true" : "false");
      let html;
      if (unavailable) {
        b.classList.add("unavail");
        html = `${ic("key-variant")}<span>${S.doorUnavailableShort}</span>`;
      } else if (ds === "opening") {
        b.classList.add("opening");
        html = `<span class="sp"></span><span>${S.doorOpening}</span>`;
      } else if (ds === "opened") {
        b.classList.add("opened");
        html = `${ic("check-bold")}<span>${S.doorOpenedShort}</span>`;
      } else {
        html = `${ic("key-variant")}<span>${S.doorShort}</span>`;
      }
      if (b.dataset.k !== html) {
        b.dataset.k = html;
        b.innerHTML = html;
      }
    });
  }

  /** Called by the Door helper when its state changed. */
  _doorChanged(announce) {
    this._renderDoorButtons();
    if (this._call && this._call.view) {
      this._call.view.render();
      if (announce) this._call.view.announce(announce);
    } else if (announce && this._r) {
      this._r(".sr").textContent = announce;
    }
  }

  _notify(message, error) {
    if (this._call && this._call.view) {
      this._call.view.toast(message, error);
      return;
    }
    try {
      this.dispatchEvent(new CustomEvent("hass-notification", { detail: { message }, bubbles: true, composed: true }));
    } catch (_e) {
      /* no snackbar */
    }
  }

  /* ---- ring ---- */

  _updateRing() {
    const on = this._ringing();
    if (!on) {
      this._ringDismissed = false;
      this._takeoverDone = false;
      if (this._call && this._call.phase === "incoming") this._call.close(false);
      return;
    }
    // off -> on, or the page loaded while someone is ringing (a notification opened it)
    if (
      this._config.ring_takeover !== false &&
      !this._call &&
      !this._ringDismissed &&
      !this._takeoverDone &&
      !registry.has(this._config.camera_entity) &&
      document.visibilityState === "visible" &&
      this._connected
    ) {
      this._takeoverDone = true;
      this._call = new Call(this);
      this._call.openIncoming();
      haptic("warning");
    }
  }

  /* ---- call ---- */

  _picTap() {
    if (this._ringing() && !this._ringDismissed && !this._call) return this._startCall("answer");
    this._startCall("peek");
  }

  _startCall(mode) {
    const existing = registry.get(this._config.camera_entity);
    if (existing && existing !== this._call) {
      // Same camera in another card: its overlay is already up.
      if (existing.view) existing.view.focusPrimary();
      return;
    }
    if (!this._call) this._call = new Call(this);
    this._call.begin(mode);
  }

  _callClosed(call) {
    if (this._call === call) this._call = null;
    this._renderIdle();
  }
}

/* ----------------------------------------------------------------- editor */

class BalterEvo2CallCardEditor extends HTMLElement {
  constructor() {
    super();
    this._config = {};
    this._hass = null;
  }

  setConfig(config) {
    this._config = config || {};
    this._render();
  }

  set hass(h) {
    this._hass = h;
    if (this._form) this._form.hass = h;
  }

  _render() {
    if (!this._form) {
      this._form = document.createElement("ha-form");
      this._form.computeLabel = (s) => s.label || s.name;
      this._form.addEventListener("value-changed", (e) => {
        e.stopPropagation();
        const config = { ...e.detail.value };
        for (const k of Object.keys(config)) if (config[k] === "" || config[k] === undefined) delete config[k];
        this.dispatchEvent(new CustomEvent("config-changed", { detail: { config }, bubbles: true, composed: true }));
      });
      this.appendChild(this._form);
    }
    this._form.hass = this._hass;
    this._form.schema = [
      { name: "camera_entity", label: "Camera (required)", required: true, selector: { entity: { domain: "camera", integration: "balter_evo2" } } },
      { name: "lock_entity", label: "Door opener", selector: { entity: { domain: "lock", integration: "balter_evo2" } } },
      { name: "ring_entity", label: "Doorbell entity (on = ringing)", selector: { entity: { domain: ["input_boolean", "binary_sensor"] } } },
      { name: "name", label: "Name", selector: { text: {} } },
      { name: "secure_url", label: "https address for talking (optional)", selector: { text: {} } },
      { name: "ring_takeover", label: "Open the call screen when it rings", selector: { boolean: {} } },
    ];
    this._form.data = { ring_takeover: true, ...this._config };
  }
}

/* ----------------------------------------------------------- registration */

if (typeof HTMLElement !== "undefined" && typeof customElements !== "undefined") {
  const define = (name, cls) => {
    if (!customElements.get(name)) customElements.define(name, cls);
  };
  define("balter-evo2-call-screen", BalterEvo2CallScreen);
  define("balter-evo2-call-card-editor", BalterEvo2CallCardEditor);
  define("balter-evo2-call-card", BalterEvo2CallCard);
  BalterEvo2CallCard.internals = {
    alawDecodeByte,
    alawEncodeSample,
    alawDecode,
    alawEncode,
    Resampler,
    b64encode,
    b64decode,
    rms,
    levelToBars,
    version: CARD_VERSION,
  };
  window.customCards = window.customCards || [];
  if (!window.customCards.some((c) => c.type === "balter-evo2-call-card")) {
    window.customCards.push({
      type: "balter-evo2-call-card",
      name: "Balter EVO 2 call card",
      description: "Door station call screen: still, live video, two-way audio, door opener.",
      preview: false,
      documentationURL: "https://github.com/bananaseason/qualvision-ha",
    });
  }
}
