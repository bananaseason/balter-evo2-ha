// Unit tests for the pure audio functions of the call card. Run: node test.mjs
import assert from "node:assert/strict";
import { pathToFileURL, fileURLToPath } from "node:url";
import path from "node:path";

const registry = new Map();
globalThis.HTMLElement = class {};
globalThis.customElements = { define: (n, c) => registry.set(n, c), get: (n) => registry.get(n) };
globalThis.window = globalThis;

const here = path.dirname(fileURLToPath(import.meta.url));
await import(pathToFileURL(path.join(here, "..", "balter-evo2-call-card.js")).href);
const I = registry.get("balter-evo2-call-card").internals;
assert.ok(I, "internals exposed");

let n = 0;
const t = (name, fn) => {
  fn();
  n += 1;
  console.log("ok -", name);
};

t("A-law known vectors (G.711)", () => {
  // silence and full scale
  assert.equal(I.alawEncodeSample(0), 0xd5);
  assert.equal(I.alawEncodeSample(-1), 0x55);
  assert.equal(I.alawDecodeByte(0xd5), 8);
  assert.equal(I.alawDecodeByte(0x55), -8);
  assert.equal(I.alawDecodeByte(0xaa), 32256);
  assert.equal(I.alawDecodeByte(0x2a), -32256);
  assert.equal(I.alawEncodeSample(32767), 0xaa);
  assert.equal(I.alawEncodeSample(-32768), 0x2a);
});

t("every A-law byte survives decode -> encode", () => {
  for (let b = 0; b < 256; b++) {
    assert.equal(I.alawEncodeSample(I.alawDecodeByte(b)), b, `byte ${b}`);
  }
});

t("linear -> A-law -> linear stays within quantisation error", () => {
  for (let v = -32768; v <= 32767; v += 7) {
    const back = I.alawDecodeByte(I.alawEncodeSample(v));
    const tol = Math.max(16, Math.abs(v) * 0.04);
    assert.ok(Math.abs(back - v) <= tol, `${v} -> ${back}`);
  }
});

t("float encode/decode round trip and clipping", () => {
  const f = Float32Array.from([0, 0.25, -0.25, 0.9, -0.9, 1.5, -1.5]);
  const back = I.alawDecode(I.alawEncode(f));
  for (let i = 0; i < 5; i++) assert.ok(Math.abs(back[i] - f[i]) < 0.04, `${f[i]} -> ${back[i]}`);
  assert.ok(back[5] > 0.9 && back[6] < -0.9);
});

t("base64 round trip", () => {
  const b = new Uint8Array(320).map((_, i) => (i * 7) & 255);
  assert.deepEqual(I.b64decode(I.b64encode(b)), b);
});

const sine = (freq, rate, secs, amp = 0.5) =>
  Float32Array.from({ length: Math.round(rate * secs) }, (_, i) => amp * Math.sin((2 * Math.PI * freq * i) / rate));

const peak = (a, from = 0) => {
  let m = 0;
  for (let i = from; i < a.length; i++) m = Math.max(m, Math.abs(a[i]));
  return m;
};

t("resampler 48k -> 8k: length and 440 Hz amplitude kept", () => {
  const rs = new I.Resampler(48000);
  const out = rs.push(sine(440, 48000, 1));
  assert.ok(Math.abs(out.length - 8000) < 80, `len ${out.length}`);
  const p = peak(out, 200);
  assert.ok(p > 0.47 && p < 0.53, `peak ${p}`);
});

t("resampler 44.1k -> 8k: non-integer ratio", () => {
  const rs = new I.Resampler(44100);
  const out = rs.push(sine(1000, 44100, 1));
  assert.ok(Math.abs(out.length - 8000) < 80, `len ${out.length}`);
  const p = peak(out, 200);
  assert.ok(p > 0.46 && p < 0.54, `peak ${p}`);
});

t("resampler low-passes: 6 kHz (above 4 kHz Nyquist) is removed", () => {
  const rs = new I.Resampler(48000);
  const out = rs.push(sine(6000, 48000, 1, 0.8));
  assert.ok(peak(out, 200) < 0.05, `alias ${peak(out, 200)}`);
});

t("resampler is streaming: chunked input equals one-shot", () => {
  const x = sine(300, 48000, 0.5);
  const whole = new I.Resampler(48000).push(x);
  const rs = new I.Resampler(48000);
  const parts = [];
  for (let i = 0; i < x.length; i += 1000) parts.push(rs.push(x.subarray(i, i + 1000)));
  const joined = Float32Array.from(parts.flatMap((p) => [...p]));
  assert.equal(joined.length, whole.length);
  for (let i = 0; i < whole.length; i++) assert.ok(Math.abs(joined[i] - whole[i]) < 1e-5);
});

t("DC passes at unity gain", () => {
  const out = new I.Resampler(48000).push(new Float32Array(48000).fill(0.5));
  assert.ok(Math.abs(out[4000] - 0.5) < 0.01);
});

t("rms and level bars", () => {
  assert.equal(I.rms(new Float32Array(0)), 0);
  assert.ok(Math.abs(I.rms(sine(440, 8000, 1, 1)) - Math.SQRT1_2) < 0.01);
  assert.equal(I.levelToBars(0), 0);
  assert.equal(I.levelToBars(0.0001), 0);
  assert.equal(I.levelToBars(0.5), 5);
  assert.ok(I.levelToBars(0.01) >= 1 && I.levelToBars(0.01) <= 4);
});

console.log(`${n} tests passed`);
