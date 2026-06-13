// UYAP Tarayıcı İstemcisi — "ev istemcisi"nin (home_client.py) tarayıcı içi karşılığı.
//
// Bu sayfa (ana/üst pencere) WebRTC tünelini AÇIK TUTAR ve hiç gezinmez. UYAP içeriği
// alttaki tam ekran <iframe> içinde yüklenir; iframe'in tüm istekleri Service Worker
// tarafından yakalanıp bu sayfadaki DataChannel üzerinden DOĞRUDAN ofise tünellenir.
// Böylece gezinme iframe içinde olur, üst sayfa (ve WebRTC) yaşamaya devam eder.
//
// Satıcı sunucusu yalnızca bu statik dosyaları + SDP'yi taşır; UYAP verisi P2P akar.

import { encodeFrames, Reassembler, finalize } from "./wire.js";

const REQUEST_TIMEOUT = 120000; // ms — büyük UDF/PDF indirmeleri
const READY_TIMEOUT = 30000;    // ms — kanal açılması için bekleme

// ---- Yapılandırma (config.js -> window.UYAP_CONFIG, ?room/?signaling ile ezilebilir) ----
const cfg = window.UYAP_CONFIG || {};
const params = new URLSearchParams(location.search);
const ROOM = params.get("room") || cfg.room || "";
// signaling verilmemişse AYNI origin'in /ws'inden türet (birleşik vendor_server).
function defaultSignaling() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  return proto + "//" + location.host + "/ws";
}
let SIGNALING = params.get("signaling") || cfg.signaling || defaultSignaling();
const ICE = cfg.ice || [];

function status(text, level) {
  if (typeof window.__uyapStatus === "function") window.__uyapStatus(text, level);
  console.log("[tünel]", text);
}

// --------------------------------------------------------------------------------------
// Tünel durumu
// --------------------------------------------------------------------------------------
let channel = null;
const reasm = new Reassembler();
const pending = new Map();      // id -> {resolve, reject}
let readyWaiters = [];

function flushReady() {
  const ws = readyWaiters;
  readyWaiters = [];
  for (const w of ws) w();
}

function failAll(reason) {
  for (const { reject } of pending.values()) reject(new Error(reason));
  pending.clear();
}

function ensureReady() {
  if (channel && channel.readyState === "open") return Promise.resolve();
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => {
      readyWaiters = readyWaiters.filter((w) => w !== onReady);
      reject(new Error("Ofis bağlantısı kurulamadı (kanal hazır değil)."));
    }, READY_TIMEOUT);
    function onReady() { clearTimeout(t); resolve(); }
    readyWaiters.push(onReady);
  });
}

async function drain(ch, threshold = 1_000_000) {
  while (ch.bufferedAmount > threshold) {
    await new Promise((r) => setTimeout(r, 10));
  }
}

async function sendMessage(ch, id, kind, meta, body) {
  for (const frame of encodeFrames(id, kind, meta, body)) {
    await drain(ch);
    ch.send(frame);
  }
}

function randomId() {
  if (crypto.randomUUID) return crypto.randomUUID().replace(/-/g, "");
  return Math.random().toString(16).slice(2) + Date.now().toString(16);
}

function headersToObject(pairs) {
  const o = {};
  for (const [k, v] of pairs) o[k] = v;
  return o;
}

// SW'den gelen mantıksal isteği ofise tüneller; {status, headers, body(Uint8Array)} döner.
async function tunnelRequest(req) {
  await ensureReady();
  const id = randomId();
  const meta = {
    method: req.method,
    path: req.path,                 // başında "/" var; ofis lstrip yapıyor
    query: req.query || "",
    headers: headersToObject(req.headers || []),
    proxy_base: location.origin,    // ofis UYAP URL'lerini bu origin'e yeniden yazar
    client: "sw",                   // ofis: enjekte script GÖMME (SW zaten yakalıyor)
  };
  const body = req.body ? new Uint8Array(req.body) : new Uint8Array(0);

  const result = new Promise((resolve, reject) => {
    pending.set(id, { resolve, reject });
  });
  const timer = setTimeout(() => {
    const p = pending.get(id);
    if (p) { pending.delete(id); p.reject(new Error("Ofis zamanında yanıt vermedi.")); }
  }, REQUEST_TIMEOUT);

  try {
    await sendMessage(channel, id, "req", meta, body);
    const rec = await result;
    return {
      status: (rec.meta && rec.meta.status) || 502,
      headers: (rec.meta && rec.meta.headers) || {},
      body: rec.body,
    };
  } finally {
    clearTimeout(timer);
    pending.delete(id);
  }
}

// --------------------------------------------------------------------------------------
// WebRTC (offerer) + signaling
// --------------------------------------------------------------------------------------
function attachChannel(ch) {
  channel = ch;
  ch.binaryType = "arraybuffer";
  ch.onopen = () => {
    status("Ofis bağlantısı kuruldu — UYAP açılıyor.", "ok");
    flushReady();
    if (typeof window.__uyapTunnelOpen === "function") window.__uyapTunnelOpen();
  };
  ch.onclose = () => {
    failAll("Kanal kapandı.");
    status("Bağlantı koptu, yeniden bağlanılıyor…", "warn");
  };
  ch.onmessage = async (ev) => {
    let rec;
    try {
      rec = reasm.feed(ev.data);
    } catch (e) {
      console.error("[tünel] çerçeve çözme hatası", e);
      return;
    }
    if (!rec || rec.kind !== "res") return;
    const p = pending.get(rec.id);
    if (!p) return;
    pending.delete(rec.id);
    try {
      await finalize(rec);             // gerekiyorsa zlib aç
      p.resolve(rec);
    } catch (e) {
      p.reject(e);
    }
  };
}

function waitIceComplete(pc) {
  if (pc.iceGatheringState === "complete") return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { pc.removeEventListener("icegatheringstatechange", check); resolve(); };
    function check() { if (pc.iceGatheringState === "complete") done(); }
    pc.addEventListener("icegatheringstatechange", check);
    setTimeout(resolve, 3000); // bir aday takılırsa elde olanla devam et
  });
}

let pc = null;
let ws = null;
let backoff = 1000;

async function startOffer() {
  if (pc && pc.connectionState === "connected") return;
  if (pc) { try { await pc.close(); } catch (_) {} }
  pc = new RTCPeerConnection({ iceServers: ICE });

  // ordered:false -> büyük PDF/UDF inerken arkasındaki küçük AJAX'lar SCTP sırasında
  // beklemesin (head-of-line yok); kanal yine güvenilir, Reassembler seq ile birleştirir.
  const ch = pc.createDataChannel("uyap", { ordered: false });
  attachChannel(ch);

  pc.onconnectionstatechange = () => {
    status("P2P durumu: " + pc.connectionState, pc.connectionState === "connected" ? "ok" : "warn");
    if (["failed", "closed", "disconnected"].includes(pc.connectionState)) failAll("Bağlantı sıfırlandı.");
  };

  const offer = await pc.createOffer();
  await pc.setLocalDescription(offer);
  await waitIceComplete(pc);          // SDP "tam" olsun (aiortc gibi trickle yok)
  ws.send(JSON.stringify({ type: "offer", sdp: pc.localDescription.sdp, sdptype: pc.localDescription.type }));
  status("Ofise teklif gönderildi, yanıt bekleniyor…", "warn");
}

function connectSignaling() {
  status("Buluşturma sunucusuna bağlanılıyor…", "warn");
  ws = new WebSocket(SIGNALING);

  ws.onopen = () => {
    backoff = 1000;
    ws.send(JSON.stringify({ role: "home", room: ROOM }));
    status("Odaya katıldı, ofis bekleniyor…", "warn");
  };

  ws.onmessage = async (ev) => {
    let msg;
    try { msg = JSON.parse(ev.data); } catch (_) { return; }
    try {
      if (msg.type === "start") {
        await startOffer();
      } else if (msg.type === "joined") {
        status("Odaya katıldı (ofis hazır: " + msg.peer_present + ").", "warn");
      } else if (msg.type === "answer") {
        if (pc && pc.signalingState === "have-local-offer") {
          await pc.setRemoteDescription({ sdp: msg.sdp, type: msg.sdptype || "answer" });
        }
      } else if (msg.type === "peer_left") {
        status("Ofis ayrıldı, bekleniyor…", "warn");
        failAll("Ofis ayrıldı.");
        if (pc) { try { await pc.close(); } catch (_) {} pc = null; }
      } else if (msg.type === "error") {
        status("Buluşturma reddetti: " + msg.error, "err");
        ws.close();
      }
    } catch (e) {
      console.error("[tünel] signaling mesaj hatası", e);
    }
  };

  ws.onclose = () => {
    status("Buluşturma bağlantısı koptu, " + (backoff / 1000) + "s sonra yeniden…", "warn");
    failAll("Signaling koptu.");
    setTimeout(connectSignaling, backoff);
    backoff = Math.min(backoff * 2, 30000);
  };

  ws.onerror = () => { try { ws.close(); } catch (_) {} };
}

// --------------------------------------------------------------------------------------
// Service Worker köprüsü: SW her yakaladığı isteği bize yollar, biz tünelleyip cevaplarız.
// --------------------------------------------------------------------------------------
function wireServiceWorkerBridge() {
  navigator.serviceWorker.addEventListener("message", async (event) => {
    const msg = event.data;
    if (!msg || msg.type !== "uyap-req") return;
    const port = event.ports[0];
    try {
      const res = await tunnelRequest(msg);
      const transfer = res.body && res.body.buffer ? [res.body.buffer] : [];
      port.postMessage(res, transfer);
    } catch (e) {
      port.postMessage({ error: String((e && e.message) || e) });
    }
  });
}

async function registerServiceWorker() {
  if (!("serviceWorker" in navigator)) {
    status("Tarayıcı Service Worker desteklemiyor.", "err");
    throw new Error("no-sw");
  }
  const reg = await navigator.serviceWorker.register("/__app__/sw.js", { scope: "/" });
  await navigator.serviceWorker.ready;
  if (!navigator.serviceWorker.controller) {
    await new Promise((resolve) => {
      navigator.serviceWorker.addEventListener("controllerchange", () => resolve(), { once: true });
      setTimeout(resolve, 2000); // güvenlik ağı
    });
  }
  return reg;
}

// --------------------------------------------------------------------------------------
// Başlat
// --------------------------------------------------------------------------------------
export async function boot() {
  if (!ROOM || !SIGNALING) {
    status("Yapılandırma eksik (room/signaling). URL'ye ?room=... ekleyin.", "err");
    return;
  }
  // Yerel test için signaling ws:// ise ICE'ı boş bırak (127.0.0.1 host adayları yeter).
  try {
    await registerServiceWorker();
    wireServiceWorkerBridge();
  } catch (e) {
    return; // SW yoksa devam edemeyiz
  }
  connectSignaling();
}

boot();
