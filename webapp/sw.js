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

// VENDOR (satıcı sunucusu) uçları: admin/ofis panelleri, JSON API, signaling, ICE. Bunlar
// UYAP içeriği DEĞİLDİR; tünele sokulmamalı, doğrudan ağa gitmeli. SW kapsamı "/" olduğundan
// bu yolları AÇIKÇA es geçmezsek yanlışlıkla tünelleyip "tünel yok" 503'ü üretir.
function isVendorRoute(p) {
  return (
    p === "/ws" ||
    p === "/ice" ||
    p === "/admin" || p.startsWith("/admin/") ||
    p === "/ofis" || p.startsWith("/ofis/") ||
    p.startsWith("/api/")
  );
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) =>
  e.waitUntil((async () => {
    // Eski sürüm önbelleklerini temizle (güncel olanları KORU), sonra kontrolü devral.
    const KEEP = [STATIC_CACHE, PAGE_CACHE];
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => !KEEP.includes(k)).map((k) => caches.delete(k)));
    await self.clients.claim();
  })())
);

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);

  // Başka origin'lere (varsa) karışma.
  if (url.origin !== self.location.origin) return;

  const p = url.pathname;
  // Uygulama kabuğu, kök sayfa ve VENDOR uçları: doğrudan ağa bırak (tünelleme YOK).
  if (p === "/" || p === "/index.html" || p.startsWith(APP_SHELL_PREFIX)) return;
  if (isVendorRoute(p)) return;
  if (p === "/favicon.ico") {
    event.respondWith(new Response(null, { status: 204 }));
    return;
  }

  event.respondWith(handle(event));
});

const STATIC_CACHE = "uyap-static-v2";
const PAGE_CACHE = "uyap-pages-v2";
const STATIC_EXT = /\.(?:js|css|mjs|woff2?|ttf|otf|eot|png|jpe?g|gif|svg|ico|webp)$/i;

// Statik (değişmeyen) varlık mı? Bunlar tarayıcı önbelleğinden servis edilip tünel
// round-trip'inden kurtarılır. Dinamik uçlar (.ajx, sorgular) hariç.
function isCacheableStatic(url, method) {
  if (method !== "GET") return false;
  const p = url.pathname.toLowerCase();
  return p.includes("/static/") || STATIC_EXT.test(p);
}

// Tam sayfa / iframe GEZİNMESİ mi? (mode === "navigate") Yani arayüzün kendisinin
// HTML'i. Bunları "önce eski, arkada tazele" ile saklarız; arayüz anında çıkar.
// DİKKAT: XHR/fetch ile gelen dinamik sorgu sonuçları "navigate" DEĞİLDİR; onlar
// hep taze tünellenir (bu fonksiyon onları kapsamaz).
function isPageDocument(req) {
  return req.method === "GET" && req.mode === "navigate";
}

function isHtml(resp) {
  const ct = (resp.headers.get("content-type") || "").toLowerCase();
  return ct.includes("text/html");
}

// İstek yönlendirme:
//   • statik varlık → "önce önbellek" (cache-first)
//   • tam sayfa gezinmesi (arayüz HTML'i) → "önce eski, arkada tazele" (SWR)
//   • diğer her şey (dinamik veri/sorgu) → doğrudan tünel (hep taze)
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

  if (isPageDocument(req)) {
    return staleWhileRevalidate(event);
  }

  return tunnelFetch(event);
}

// "Önce eski, arkada tazele": önbellekte arayüzün önceki hali varsa ANINDA döndür
// (tünele hiç beklemeden), aynı anda taze sürümü arkada çekip önbelleği güncelle —
// bir sonraki açılış da hızlı olsun. Önbellek yoksa tazeyi bekleriz (ilk sefer).
// Yalnızca 200 + text/html saklanır: yönlendirmeler (302 login vb.) ve hata
// sayfaları önbelleği kirletmez; oturum ofis tarafında açık kaldığından kabuk
// güncel kalır.
async function staleWhileRevalidate(event) {
  const req = event.request;
  let cache;
  try {
    cache = await caches.open(PAGE_CACHE);
  } catch (_) {
    return tunnelFetch(event);
  }

  const hit = await cache.match(req);

  const revalidate = tunnelFetch(event)
    .then((resp) => {
      if (resp && resp.status === 200 && isHtml(resp)) {
        cache.put(req, resp.clone()).catch(() => {});
      }
      return resp;
    })
    .catch(() => null);

  if (hit) {
    event.waitUntil(revalidate);   // taze sürüm arkada inip önbelleği günceller
    return hit;                    // arayüzün önceki hali ANINDA görünür
  }

  const fresh = await revalidate;  // ilk sefer: önbellek yok, tazeyi bekle
  return fresh || tunnelFetch(event);
}

async function tunnelFetch(event) {
  const req = event.request;
  const url = new URL(req.url);
  try {
    const client = await pickClient();
    if (!client) {
      return text(503, "Tünel sayfası bulunamadı. Ana sekmeyi açık tutup yenileyin.");
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
// Yalnızca GERÇEK ana sayfayı ("/" veya "/index.html") döndürürüz; iframe'e (UYAP yolu)
// asla düşmeyiz — yanlış pencereye postMessage sessiz takılmaya yol açardı.
// Liste geçici olarak boş olabilir (SW yeni etkinleşti / sayfa az önce kontrolü devraldı);
// bu yüzden kısa aralıklarla birkaç kez yeniden deneriz.
function findMainPage(list) {
  for (const c of list) {
    let pathname = "/";
    try { pathname = new URL(c.url).pathname; } catch (_) {}
    if (pathname === "/" || pathname === "/index.html") return c;
  }
  return null;
}

async function pickClient() {
  for (let attempt = 0; attempt < 5; attempt++) {
    const list = await self.clients.matchAll({ type: "window", includeUncontrolled: true });
    const main = findMainPage(list);
    if (main) return main;
    if (attempt === 0) {
      // Teşhis: konsola (ofis tarafı değil, ana sekmenin DevTools'una) yaz.
      console.warn("[sw] ana sayfa bulunamadı; görünen pencereler:",
        list.map((c) => c.url));
    }
    await new Promise((r) => setTimeout(r, 150));
  }
  return null;
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
