#!/usr/bin/env python3
"""
UYAP Satıcı Sunucusu (vendor_server.py) — TEK parça, bedava PaaS'a deploy edilir
-------------------------------------------------------------------------------
İki işi TEK aiohttp servisinde, TEK portta birleştirir:

  1. `webapp/` statik kabuğunu (index.html + Service Worker + tünel JS) HTTP(S) ile servis
     eder. Tarayıcı bunu bir kez indirir; sonrası Service Worker ile P2P tüneldir.
  2. `/ws` adresinde buluşturma (signaling): ofis ajanı ve tarayıcı aynı oda anahtarıyla
     buluşur, WebRTC el sıkışması (SDP offer/answer) aktarılır.

KASITLI olarak UYAP verisi taşımaz — o veri ofis ile tarayıcı arasında DOĞRUDAN (P2P,
DTLS) akar. Bu sunucu yalnızca statik dosya + SDP taşır. Bu yüzden ucuz/bedava bir kutuda
çalışır ve "satıcı veri yolunda değil" güvencesi korunur.

Neden tek parça: müşterinin/satıcının kendi sunucusu yok; Render/Fly gibi bedava bir PaaS'a
TEK servis olarak deploy edip ÜCRETSIZ HTTPS adı (ör. https://uyap-x.onrender.com) almak en
kolayı. Service Worker HTTPS ister; PaaS bunu hazır verir, alan adı GEREKMEZ.

Çalıştırma (yerel test):
    pip install aiohttp
    python vendor_server.py --host 127.0.0.1 --port 8080
    # Ofis: python office_agent.py --signaling ws://127.0.0.1:8080/ws --room test123
    # Tarayıcı: http://127.0.0.1:8080/?room=test123

Çalıştırma (PaaS/üretim): PORT ortam değişkeni PaaS tarafından verilir; host 0.0.0.0.
    python vendor_server.py            # host=0.0.0.0, port=$PORT
    # Ofis: python office_agent.py --signaling wss://<app>.onrender.com/ws --room <ODA>
    # Müvekkil: https://<app>.onrender.com/?room=<ODA>
"""

import os
import ssl
import sys
import json
import argparse

from aiohttp import web, WSMsgType

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEBAPP_DIR = os.path.join(BASE_DIR, "webapp")
CONFIG_PATH = os.path.join(BASE_DIR, "signaling_config.json")

# URL yolu -> (disk dosyası, content-type). Beyaz liste: dizin gezme (traversal) yok.
ROUTES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/__app__/sw.js": ("sw.js", "application/javascript; charset=utf-8"),
    "/__app__/tunnel.js": (os.path.join("js", "tunnel.js"), "application/javascript; charset=utf-8"),
    "/__app__/wire.js": (os.path.join("js", "wire.js"), "application/javascript; charset=utf-8"),
}

# ------------------------------------------------------------------------------------------
# Signaling (buluşturma) — signaling_server.py mantığının aiohttp WebSocket sürümü
# ------------------------------------------------------------------------------------------
ROOMS = {}      # room -> {"office": ws|None, "home": ws|None}
ALLOWED = None  # None => her oda serbest; set => yalnızca bu anahtarlar


def load_allowed(path=CONFIG_PATH):
    global ALLOWED
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                cfg = json.load(f)
            rooms = cfg.get("allowed_rooms") or []
            ALLOWED = set(rooms) if rooms else None
        except Exception as e:
            print(f"[!] signaling_config.json okunamadı ({e}); tüm odalar serbest.")
            ALLOWED = None
    else:
        ALLOWED = None
    print("[*] Oda allowlist'i yok: ortak anahtarı bilen her çift buluşabilir."
          if ALLOWED is None else f"[*] {len(ALLOWED)} oda anahtarı izinli (allowlist aktif).")


def _other(role):
    return "home" if role == "office" else "office"


async def _safe_send(ws, payload):
    if ws is None:
        return
    try:
        await ws.send_str(payload if isinstance(payload, str) else json.dumps(payload))
    except Exception:
        pass


async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024, heartbeat=30)
    await ws.prepare(request)

    role = room = None
    try:
        first = await ws.receive()
        if first.type != WSMsgType.TEXT:
            return ws
        join = json.loads(first.data)
        role = join.get("role")
        room = join.get("room")

        if role not in ("office", "home") or not room:
            await _safe_send(ws, {"type": "error", "error": "Geçersiz katılım (role/room)."})
            return ws
        if ALLOWED is not None and room not in ALLOWED:
            await _safe_send(ws, {"type": "error", "error": "Tanınmayan oda anahtarı."})
            return ws

        slot = ROOMS.setdefault(room, {"office": None, "home": None})
        old = slot.get(role)
        if old is not None:
            await old.close()
        slot[role] = ws

        await _safe_send(ws, {"type": "joined", "peer_present": slot[_other(role)] is not None})
        if slot["office"] is not None and slot["home"] is not None:
            await _safe_send(slot["home"], {"type": "start"})
        print(f"[+] Katıldı: room={str(room)[:8]}… role={role}")

        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                await _safe_send(slot.get(_other(role)), msg.data)
            elif msg.type == WSMsgType.ERROR:
                break
    except Exception as e:
        print(f"[!] Signaling handler hatası (room={room}): {e}")
    finally:
        if room in ROOMS:
            slot = ROOMS[room]
            if slot.get(role) is ws:
                slot[role] = None
                await _safe_send(slot.get(_other(role)), {"type": "peer_left"})
            if slot["office"] is None and slot["home"] is None:
                ROOMS.pop(room, None)
        print(f"[!] Ayrıldı: room={str(room)[:8]}… role={role}")
    return ws


# ------------------------------------------------------------------------------------------
# Statik webapp + dinamik config
# ------------------------------------------------------------------------------------------
def make_app(args):
    load_allowed(args.config)
    app = web.Application()

    def config_js(request):
        # signaling: AYNI origin'in /ws'i (tarayıcı location'dan türetir) -> boş bırakıyoruz.
        # ice: yerelse (127.0.0.1/localhost) boş; aksi halde STUN (gerekirse TURN ekleyin).
        host = (request.host or "").split(":")[0]
        is_local = host in ("127.0.0.1", "localhost")
        if args.ice:
            ice = json.loads(args.ice)
        else:
            ice = [] if is_local else [{"urls": "stun:stun.l.google.com:19302"}]
        cfg = {"signaling": "", "room": args.room, "ice": ice}
        body = "window.UYAP_CONFIG = " + json.dumps(cfg, ensure_ascii=False) + ";\n"
        return web.Response(body=body.encode("utf-8"), content_type="application/javascript",
                            charset="utf-8", headers={"Cache-Control": "no-store"})

    def serve_file(disk_rel, content_type, sw=False):
        async def handler(_request):
            path = os.path.join(WEBAPP_DIR, disk_rel)
            if not os.path.isfile(path):
                return web.Response(status=404, text="Bulunamadı.")
            with open(path, "rb") as f:
                data = f.read()
            # Uygulama kabuğu (index.html, tunnel.js, wire.js, sw.js) küçük ve sık güncellenir;
            # no-store ile tarayıcı her zaman taze indirir (eski sürüm yapışıp kalmaz). UYAP'ın
            # asıl statik varlıkları zaten SW Cache API'de tutuluyor; bu onları etkilemez.
            headers = {"Cache-Control": "no-store"}
            if sw:
                headers["Service-Worker-Allowed"] = "/"  # SW'nin "/" kapsamı için şart
            ct = content_type.split(";")[0].strip()
            return web.Response(body=data, content_type=ct, charset="utf-8", headers=headers)
        return handler

    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/__app__/config.js", config_js)
    for url_path, (disk_rel, ctype) in ROUTES.items():
        app.router.add_get(url_path, serve_file(disk_rel, ctype, sw=url_path.endswith("/sw.js")))

    async def favicon(_request):
        return web.Response(status=204)
    app.router.add_get("/favicon.ico", favicon)
    return app


def main():
    parser = argparse.ArgumentParser(description="UYAP satıcı sunucusu (statik webapp + signaling).")
    parser.add_argument("--host", default="0.0.0.0",
                        help="Dinleme adresi (PaaS: 0.0.0.0; yerel test isterseniz 127.0.0.1).")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", "8080")),
                        help="Port (PaaS PORT ortam değişkenini otomatik kullanır).")
    parser.add_argument("--room", default=os.environ.get("UYAP_ROOM", ""),
                        help="Varsayılan oda (yerel test kolaylığı). Üretimde URL'de ?room=<ODA>.")
    parser.add_argument("--ice", default=os.environ.get("UYAP_ICE", ""),
                        help="ICE sunucuları JSON listesi (boşsa: yerelde yok, uzakta STUN).")
    parser.add_argument("--config", default=CONFIG_PATH, help="Oda allowlist dosyası.")
    parser.add_argument("--ssl-certfile", default=None)
    parser.add_argument("--ssl-keyfile", default=None)
    args = parser.parse_args()

    if not os.path.isdir(WEBAPP_DIR):
        print(f"[!] webapp/ klasörü bulunamadı: {WEBAPP_DIR}")
        sys.exit(2)

    ssl_ctx = None
    if args.ssl_certfile and args.ssl_keyfile:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(args.ssl_certfile, args.ssl_keyfile)
    scheme = "https" if ssl_ctx else "http"

    app = make_app(args)
    print(f"[*] Satıcı sunucusu {scheme}://{args.host}:{args.port}/ "
          f"(webapp + /ws signaling tek serviste).")
    print(f"[*] Tarayıcı: {scheme}://{args.host}:{args.port}/?room=<ODA>")
    print(f"[*] Ofis:     office_agent.py --signaling {('wss' if ssl_ctx else 'ws')}://"
          f"{args.host}:{args.port}/ws --room <ODA>")
    if scheme == "http" and args.host not in ("127.0.0.1", "localhost", "0.0.0.0"):
        print("[!] DİKKAT: Service Worker yalnızca HTTPS ya da localhost'ta çalışır.")

    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_ctx, print=None)


if __name__ == "__main__":
    main()
