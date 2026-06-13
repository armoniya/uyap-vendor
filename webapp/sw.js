// UYAP Service Worker — yerel aiohttp sunucusunun (home_client) tarayıcı içi karşılığı.
//
// Üst sayfanın iframe'inden çıkan TÜM istekleri (gezinme, XHR, fetch, img, css, js…) ağ
// katmanında yakalar; uygulama kabuğu (/__app__/*, /, /index.html) dışındakileri tünel
// sayfasına (üst pencere) postMessage ile yollayıp dönen cevaptan bir Response kurar.
//
// Böylece UYAP'ın kendi JS'ini değiştirmeye gerek kalmaz: her istek şeffafça ofise gider.

const APP_SHELL_PREFIX = "/__app__/";
const REDIRECT_STATUSES = [301, 302, 303, 307, 308];
const NO_BODY_STATUSES = [204, 205, 304];

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) =>
  e.waitUntil((async () => {
    // Eski sürüm önbelleklerini temizle, sonra kontrolü devral.
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== STATIC_CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })())
);

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Başka origin'lere (varsa) karışma.
  if (url.origin !== self.location.origin) return;

  const p = url.pathname;
  // Uygulama kabuğu ve kök sayfa: doğrudan ağ/önbellek (tünelleme).
  if (p === "/" || p === "/index.html" || p.startsWith(APP_SHELL_PREFIX)) return;
  if (p === "/favicon.ico") {
    event.respondWith(new Response(null, { status: 204 }));
    return;
  }

  event.respondWith(handle(event));
});

const STATIC_CACHE = "uyap-static-v1";
const STATIC_EXT = /\.(?:js|css|mjs|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp)$/i;

// Statik (değişmeyen) varlık mı? Bunlar tarayıcı önbelleğinden servis edilip tünel
// round-trip'inden kurtarılır. Dinamik uçlar (.ajx, sorgular, gezinme HTML'i) hariç.
function isCacheableStatic(url, method) {
  if (method !== "GET") return false;
  const p = url.pathname.toLowerCase();
  return p.includes("/static/") || STATIC_EXT.test(p);
}

// Statik için "önce önbellek": varsa anında döndür (tünele hiç gitmez). Yoksa tünelle
// çek ve 200 ise önbelleğe koy — bir sonraki açılışta artık yereldir. Statik dışı her
// istek doğrudan tünellenir (dinamik veri hep tazedir).
async function handle(event) {
  const req = event.request;
  const url = new URL(req.url);
  if (isCacheableStatic(url, req.method)) {
    try {
      const cache = await caches.open(STATIC_CACHE);
      const hit = await cache.match(req);
      if (hit) return hit;
      const resp = await tunnelFetch(event);
      if (resp && resp.status === 200) {
        try { await cache.put(req, resp.clone()); } catch (_) {}
      }
      return resp;
    } catch (_) {
      return tunnelFetch(event);
    }
  }
  return tunnelFetch(event);
}

async function tunnelFetch(event) {
  const req = event.request;
  const url = new URL(req.url);
  try {
    const client = await pickClient();
    if (!client) {
      return text(503, "Tünel sayfası bulunamadı. Ana sekmeyi yenileyin.");
    }

    const bodyBuf =
      req.method === "GET" || req.method === "HEAD" ? null : await req.arrayBuffer();

    const headers = [];
    for (const pair of req.headers) headers.push(pair);

    const message = {
      type: "uyap-req",
      method: req.method,
      path: url.pathname,
      query: url.search.replace(/^\?/, ""),
      headers,
      body: bodyBuf,
    };

    const res = await postRequest(client, message, bodyBuf ? [bodyBuf] : []);
    if (!res || res.error) {
      return text(502, "Tünel hatası: " + ((res && res.error) || "bilinmiyor"));
    }

    // 3xx yönlendirme: SW ham redirect döndüremez (navigasyon ağ hatası verir);
    // Location'ı çözüp tarayıcının takip edeceği bir redirect üret.
    if (REDIRECT_STATUSES.includes(res.status)) {
      const loc = headerValue(res.headers, "location");
      if (loc) {
        return Response.redirect(new URL(loc, req.url).href, res.status);
      }
    }

    const h = new Headers();
    for (const k in res.headers) {
      const lk = k.toLowerCase();
      if (lk === "content-length" || lk === "transfer-encoding" || lk === "content-encoding") continue;
      try { h.set(k, res.headers[k]); } catch (_) {}
    }

    const body = NO_BODY_STATUSES.includes(res.status) ? null : res.body;
    return new Response(body, { status: res.status, headers: h });
  } catch (e) {
    return text(502, "Tünel istisnası: " + ((e && e.message) || e));
  }
}

// WebRTC tünelini taşıyan ÜST sayfayı bul (iframe değil). index.html kökte ("/").
async function pickClient() {
  const list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
  for (const c of list) {
    const u = new URL(c.url);
    if (u.pathname === "/" || u.pathname === "/index.html") return c;
  }
  return list[0] || null;
}

function postRequest(client, message, transfer) {
  return new Promise((resolve) => {
    const mc = new MessageChannel();
    mc.port1.onmessage = (e) => resolve(e.data);
    client.postMessage(message, [mc.port2, ...transfer]);
  });
}

function headerValue(obj, name) {
  for (const k in obj) if (k.toLowerCase() === name) return obj[k];
  return null;
}

function text(status, msg) {
  return new Response(msg, {
    status,
    headers: { "content-type": "text/plain; charset=utf-8" },
  });
}
