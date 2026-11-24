// Mock harness: renders the call card with a fake hass. Open demo.html over http://localhost
// (a secure context, so the real microphone works) or file:// for layout only.
import "../balter-evo2-call-card.js";

const I = customElements.get("balter-evo2-call-card").internals;
const params = new URLSearchParams(location.search);

// --- ha-icon stub (real HA ships the real one) ---
const GLYPHS = {
  play: "▶", "volume-high": "🔊", "volume-off": "🔇", microphone: "🎙", "microphone-off": "🎙̸",
  "key-variant": "🔑", "check-bold": "✔", "phone-hangup": "☎", phone: "📞", "bell-ring": "🔔",
  "account-clock": "⏳", "lan-disconnect": "⚠", "wifi-off": "📵", "timer-outline": "⏱", "video-off-outline": "🚫",
  "bell-off-outline": "🔕", headphones: "🎧", "alert-outline": "⚠", "alert-circle": "❗", lock: "🔒",
};
class HaIconStub extends HTMLElement {
  static get observedAttributes() { return ["icon"]; }
  connectedCallback() { this.attributeChangedCallback(); }
  attributeChangedCallback() {
    const n = (this.getAttribute("icon") || "").replace("mdi:", "");
    this.textContent = GLYPHS[n] || n;
    this.style.cssText = "display:inline-flex;align-items:center;justify-content:center;width:var(--mdc-icon-size,24px);height:var(--mdc-icon-size,24px);font-size:calc(var(--mdc-icon-size,24px)*.8)";
  }
}
customElements.define("ha-icon", HaIconStub);

// --- fake hass ---
const logEl = document.getElementById("log");
const log = (m) => { logEl.textContent = `${new Date().toLocaleTimeString()} ${m}\n${logEl.textContent}`.slice(0, 4000); };

const svg = (bg, txt) => `data:image/svg+xml;utf8,${encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360"><rect width="640" height="360" fill="${bg}"/>` +
  `<circle cx="320" cy="150" r="60" fill="#ffffff55"/><rect x="230" y="220" width="180" height="140" rx="60" fill="#ffffff55"/>` +
  `<text x="20" y="40" font-size="24" fill="#fff" font-family="sans-serif">${txt}</text></svg>`)}`;
const stillSvg = svg("#455a64", "stored still");
const liveSvg = `data:image/svg+xml;utf8,${encodeURIComponent(
  `<svg xmlns="http://www.w3.org/2000/svg" width="640" height="360"><rect width="640" height="360" fill="#2e7d32"/>` +
  `<circle cx="320" cy="150" r="60" fill="#ffffff66"><animate attributeName="cx" values="260;380;260" dur="3s" repeatCount="indefinite"/></circle>` +
  `<text x="20" y="40" font-size="24" fill="#fff" font-family="sans-serif">LIVE (mock MJPEG)</text></svg>`)}`;

const listeners = new Set();
const cam = "camera.entrance_front_door";
const lockId = "lock.entrance_front_door_door_opener_2";
const ringId = "input_boolean.doorbell";
const still = new Date(Date.now() - 20 * 60000).toISOString();
const states = {
  [cam]: { entity_id: cam, state: "idle", attributes: { friendly_name: "Front door", access_token: "tok", entity_picture: "/api/camera_proxy/camera.entrance_front_door?token=tok", still_taken: still } },
  [lockId]: { entity_id: lockId, state: "locked", attributes: { friendly_name: "Door opener 2" } },
  [ringId]: { entity_id: ringId, state: params.get("ring") ? "on" : "off", attributes: {} },
};

let call = null; // {id, cb, hb, endsAt, tone, talking, watchdog}
let doorFails = false;

function emit(ev) { if (call) call.cb({ call_id: call.id, ...ev }); }
function stateEv(extra) {
  return { type: "state", state: "live", talking: call.talking, talk_ready: call.talkReady, ends_at: call.endsAt, reason: null, message: null, ...extra };
}
function stopCall(why) {
  if (!call) return;
  clearInterval(call.tone); clearInterval(call.watchdog);
  log(`station released (${why})`);
  call = null;
}

function handle(msg) {
  if (msg.type === "balter_evo2/call/audio") { if (call) call.audioIn = (call.audioIn || 0) + 1; return {}; }
  if (!call || msg.call_id !== call.id) { log(`${msg.type} for unknown call`); return {}; }
  switch (msg.type) {
    case "balter_evo2/call/heartbeat": call.hb = Date.now(); return {};
    case "balter_evo2/call/talk":
      if (scenario() === "nomic" && msg.talking) return new Promise(() => {}); // never confirms
      call.talking = msg.talking; call.talkReady = call.talkReady || msg.talking;
      log(`talk ${msg.talking}`);
      setTimeout(() => emit(stateEv()), 250);
      return { talking: msg.talking };
    case "balter_evo2/call/extend": call.endsAt += 180; log("extend"); emit(stateEv()); return { ends_at: call.endsAt };
    case "balter_evo2/call/end": log(`mic chunks received: ${call.audioIn || 0}`); stopCall("hangup"); return {};
    default: return {};
  }
}

const scenario = () => document.getElementById("scenario").value;

const hass = {
  states, locale: { language: "en" }, config: { external_url: "https://example.ts.net" },
  hassUrl: (p) => (p.startsWith("/api/camera_proxy_stream/") ? liveSvg : p.startsWith("/api/camera_proxy/") ? stillSvg : p),
  async callService(domain, service, data) {
    log(`${domain}.${service} ${data.entity_id}`);
    await new Promise((r) => setTimeout(r, 700));
    if (doorFails) throw new Error("The door station is busy with another action.");
    states[lockId] = { ...states[lockId], state: "unlocked" };
  },
  callWS: async (msg) => handle(msg),
  connection: {
    sendMessage: (msg) => { handle(msg); },
    addEventListener() {}, removeEventListener() {},
    async subscribeMessage(cb, msg) {
      const sc = scenario();
      log(`call/start (${sc})`);
      await new Promise((r) => setTimeout(r, sc === "slow" ? 4000 : 400));
      if (sc === "busy") throw { code: "station_busy", message: "Station busy" };
      if (sc === "notfound") throw { code: "not_found", message: "no such camera" };
      if (call) stopCall("replaced");
      call = { id: `c${Date.now()}`, cb, hb: Date.now(), endsAt: Math.floor(Date.now() / 1000) + (sc === "short" ? 35 : 180), talking: false, talkReady: false };
      call.watchdog = setInterval(() => {
        if (Date.now() - call.hb > 3000) { emit({ type: "state", state: "ended", reason: "heartbeat" }); stopCall("heartbeat timeout"); }
      }, 500);
      setTimeout(() => {
        if (!call) return;
        if (sc === "busyev") { emit({ type: "state", state: "ended", reason: "station_busy" }); stopCall("busy"); return; }
        if (sc === "error") { emit({ type: "state", state: "ended", reason: "error", message: "The station refused the session." }); stopCall("error"); return; }
        emit(stateEv({ state: "connecting" }));
        setTimeout(() => {
          if (!call) return;
          states[cam] = { ...states[cam], state: "streaming" };
          emit(stateEv());
          // 440 Hz test tone, 40 ms packets, like the station's 0xE3 audio
          let phase = 0, seq = 0;
          call.tone = setInterval(() => {
            const f = new Float32Array(320);
            for (let i = 0; i < 320; i++) { f[i] = 0.3 * Math.sin(phase) * (Math.sin(Date.now() / 700) > 0 ? 1 : 0.05); phase += (2 * Math.PI * 440) / 8000; }
            emit({ type: "audio", data: I.b64encode(I.alawEncode(f)), seq: seq++ });
          }, 40);
        }, 300);
      }, 20);
      return () => { log("unsubscribed"); states[cam] = { ...states[cam], state: "idle" }; push(); stopCall("unsubscribe"); };
    },
  },
};

const card = document.createElement("balter-evo2-call-card");
card.setConfig({ camera_entity: cam, lock_entity: lockId, ring_entity: ringId, secure_url: params.get("secure") || undefined });
document.getElementById("slot").appendChild(card);
const push = () => { hass.states = { ...states }; card.hass = hass; };
push();
setInterval(push, 1000);

document.getElementById("ring").onclick = () => { states[ringId] = { ...states[ringId], state: states[ringId].state === "on" ? "off" : "on" }; push(); };
document.getElementById("dark").onclick = () => document.body.classList.toggle("dark");
document.getElementById("lock").onclick = () => { states[lockId] = { ...states[lockId], state: states[lockId].state === "unavailable" ? "locked" : "unavailable" }; push(); };
document.getElementById("lockfail").onclick = () => { doorFails = !doorFails; log(`door fails: ${doorFails}`); };
if (params.get("dark")) document.body.classList.add("dark");
if (params.get("scenario")) document.getElementById("scenario").value = params.get("scenario");
