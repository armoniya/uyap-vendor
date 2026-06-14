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
import time
import html
import uuid
import hmac
import base64
import hashlib
import argparse

from aiohttp import web, WSMsgType

import accounts

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEBAPP_DIR = os.path.join(BASE_DIR, "webapp")
CONFIG_PATH = os.path.join(BASE_DIR, "signaling_config.json")

# Hesap/lisans deposu (benzersiz oda anahtarı + parola doğrulaması). Boşsa eski davranış
# (allowlist / serbest) korunur; hesap oluşturulunca signaling oda+parola DOĞRULAR.
STORE = accounts.AccountStore()

# Admin ekranı parolası (HTTP Basic). Ayarlı değilse /admin kapalıdır.
ADMIN_PASSWORD = os.environ.get("UYAP_ADMIN_PASSWORD", "")


# ── TURN / ICE ────────────────────────────────────────────────────────────────────────
# CGNAT/simetrik NAT ardındaki (ör. mobil veri) kullanıcılar için TURN gerekir. coturn'ün
# "use-auth-secret" (REST) yöntemiyle EFEMERAL kimlik üretiriz: paylaşılan gizli anahtardan
# (UYAP_TURN_SECRET) zaman sınırlı kullanıcı/parola türetilir; uzun ömürlü sır istemcilere
# gömülmez. UYAP_TURN_URLS virgülle ayrılmış TURN adresleridir, ör:
#   turn:turn.example.com:3478?transport=udp,turn:turn.example.com:3478?transport=tcp,turns:turn.example.com:5349
def _turn_servers():
    secret = os.environ.get("UYAP_TURN_SECRET")
    urls_raw = os.environ.get("UYAP_TURN_URLS")
    if not secret or not urls_raw:
        return []
    ttl = int(os.environ.get("UYAP_TURN_TTL", "86400"))
    username = f"{int(time.time()) + ttl}:uyap"
    key = hmac.new(secret.encode("utf-8"), username.encode("utf-8"), hashlib.sha1).digest()
    credential = base64.b64encode(key).decode("ascii")
    urls = [u.strip() for u in urls_raw.split(",") if u.strip()]
    return [{"urls": urls, "username": username, "credential": credential}]


def build_ice(is_local=False, static_ice=""):
    """İstemcilere verilecek ICE listesini üretir. UYAP_ICE (static_ice) verilmişse onu
    kullanır; yoksa yerelde boş, uzakta STUN + (yapılandırılmışsa) efemeral TURN."""
    if static_ice:
        try:
            return json.loads(static_ice)
        except Exception:
            pass
    if is_local:
        return []
    servers = [{"urls": "stun:stun.l.google.com:19302"}]
    servers.extend(_turn_servers())
    return servers

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
# Oda modeli: TEK ofis (e-imza sahibi) + AYNI ANDA N istemci. Bir oda anahtarı = bir ofis
# lisansı; o büronun personeli aynı anahtarla bağlanıp tek UYAP oturumunu paylaşır. Her
# istemciye sunucu benzersiz bir cid atar; offer/answer/relay mesajları cid ile adreslenir
# ki ofis her istemci için ayrı bir WebRTC bağlantısı tutabilsin (birbirini ATMADAN).
ROOMS = {}      # room -> {"office": ws|None, "homes": {cid: ws}, "office_meta": ...}
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

    role = room = cid = None
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

        # Hesap deposu doluysa oda anahtarı + parola DOĞRULANIR (ofis ve istemci aynı
        # lisansı paylaşır). Depo boşsa eski davranış: allowlist ya da serbest (yerel/dev).
        password = join.get("password") or ""
        if not STORE.is_empty():
            ok, reason = STORE.validate(room, password)
            if not ok:
                await _safe_send(ws, {"type": "error", "error": reason})
                return ws
        elif ALLOWED is not None and room not in ALLOWED:
            await _safe_send(ws, {"type": "error", "error": "Tanınmayan oda anahtarı."})
            return ws

        slot = ROOMS.setdefault(room, {"office": None, "homes": {}, "office_meta": None})

        if role == "office":
            slot["office_meta"] = {"local_ips": join.get("local_ips") or [],
                                   "port": join.get("port", 8800)}
            old = slot.get("office")
            if old is not None:
                await old.close()
            slot["office"] = ws
            await _safe_send(ws, {"type": "joined", "peer_present": len(slot["homes"]) > 0})
            # Ofis (yeniden) bağlandı: mevcut tüm istemcilere teklif üretmelerini söyle.
            for hcid, hws in list(slot["homes"].items()):
                start = {"type": "start", "cid": hcid}
                if slot.get("office_meta"):
                    start.update(slot["office_meta"])
                await _safe_send(hws, start)
        else:  # home
            cid = uuid.uuid4().hex
            slot["homes"][cid] = ws
            joined = {"type": "joined", "cid": cid, "peer_present": slot["office"] is not None}
            if slot.get("office_meta"):
                joined.update(slot["office_meta"])
            await _safe_send(ws, joined)
            if slot["office"] is not None:
                start = {"type": "start", "cid": cid}
                if slot.get("office_meta"):
                    start.update(slot["office_meta"])
                await _safe_send(ws, start)
        print(f"[+] Katıldı: room={str(room)[:8]}… role={role}"
              + (f" cid={cid[:6]}" if cid else f" istemci={len(slot['homes'])}"))

        async for msg in ws:
            if msg.type == WSMsgType.ERROR:
                break
            if msg.type != WSMsgType.TEXT:
                continue
            if role == "home":
                # İstemci → ofis: hangi istemci olduğunu cid ile imzalayıp ofise ilet.
                try:
                    m = json.loads(msg.data)
                except Exception:
                    continue
                m["cid"] = cid
                await _safe_send(slot.get("office"), json.dumps(m))
            else:
                # Ofis → istemci: ofis mesaja cid'i koyar; doğru istemciye yönlendir.
                try:
                    target_cid = json.loads(msg.data).get("cid")
                except Exception:
                    continue
                await _safe_send(slot["homes"].get(target_cid), msg.data)
    except Exception as e:
        print(f"[!] Signaling handler hatası (room={room}): {e}")
    finally:
        if room in ROOMS:
            slot = ROOMS[room]
            if role == "office" and slot.get("office") is ws:
                slot["office"] = None
                slot["office_meta"] = None
                for hws in list(slot["homes"].values()):
                    await _safe_send(hws, {"type": "peer_left"})
            elif role == "home" and cid and slot["homes"].get(cid) is ws:
                del slot["homes"][cid]
                await _safe_send(slot.get("office"), {"type": "peer_left", "cid": cid})
            if slot.get("office") is None and not slot["homes"]:
                ROOMS.pop(room, None)
        print(f"[!] Ayrıldı: room={str(room)[:8]}… role={role}"
              + (f" cid={cid[:6]}" if cid else ""))
    return ws


# ------------------------------------------------------------------------------------------
# Admin ekranı (kullanıcı/lisans oluşturma) — HTTP Basic ile korunur
# ------------------------------------------------------------------------------------------
def _admin_ok(request):
    if not ADMIN_PASSWORD:
        return False
    hdr = request.headers.get("Authorization", "")
    if not hdr.startswith("Basic "):
        return False
    try:
        decoded = base64.b64decode(hdr[6:]).decode("utf-8")
        _, _, pw = decoded.partition(":")
    except Exception:
        return False
    return hmac.compare_digest(pw, ADMIN_PASSWORD)


def _admin_unauth():
    return web.Response(status=401, text="Yetki gerekli.",
                        headers={"WWW-Authenticate": 'Basic realm="UYAP Admin"'})


def _render_admin(new_account=None, msg=None):
    rows = []
    for a in STORE.listing():
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(a["created"])) if a["created"] else "-"
        durum = ("<span style='color:#22c55e'>Aktif</span>" if a["active"]
                 else "<span style='color:#ef4444'>Pasif</span>")
        key = html.escape(a["room_key"])
        toggle = "revoke" if a["active"] else "activate"
        toggle_lbl = "İptal Et" if a["active"] else "Aktifleştir"
        rows.append(f"""<tr>
          <td><code>{key}</code></td><td>{html.escape(a['label'])}</td>
          <td>{durum}</td><td>{created}</td>
          <td class='act'>
            <form method='post' action='/admin/{toggle}'><input type='hidden' name='room_key' value='{key}'><button>{toggle_lbl}</button></form>
            <form method='post' action='/admin/reset'><input type='hidden' name='room_key' value='{key}'><button>Parola Sıfırla</button></form>
            <form method='post' action='/admin/delete' onsubmit="return confirm('Hesap silinsin mi?')"><input type='hidden' name='room_key' value='{key}'><button class='danger'>Sil</button></form>
          </td></tr>""")
    table = "\n".join(rows) or "<tr><td colspan='5' style='text-align:center;color:#94a3b8'>Henüz hesap yok.</td></tr>"

    banner = ""
    if new_account:
        banner = f"""<div class='new'>
          <b>Yeni lisans oluşturuldu</b> — bu bilgileri müşteriye verin (parola yalnızca BİR KEZ gösterilir):
          <div class='cred'>Oda Anahtarı: <code>{html.escape(new_account['room_key'])}</code></div>
          <div class='cred'>Parola: <code>{html.escape(new_account['password'])}</code></div>
        </div>"""
    note = f"<div class='msg'>{html.escape(msg)}</div>" if msg else ""

    return f"""<!doctype html><html lang='tr'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>UYAP Lisans Yönetimi</title><style>
  body{{background:#0f172a;color:#f8fafc;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:24px}}
  h1{{color:#0ea5e9;font-size:20px}} .card{{background:#1e293b;border-radius:10px;padding:18px;margin-bottom:18px;max-width:1000px}}
  input[type=text]{{background:#0f172a;border:1px solid #475569;color:#f8fafc;padding:8px;border-radius:6px;width:260px}}
  button{{background:#0ea5e9;border:0;color:#fff;padding:7px 12px;border-radius:6px;cursor:pointer;font-weight:600;margin:2px}}
  button.danger{{background:#ef4444}} table{{width:100%;border-collapse:collapse;max-width:1000px}}
  th,td{{text-align:left;padding:8px;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}}
  code{{background:#0f172a;padding:2px 6px;border-radius:4px;color:#7dd3fc}}
  .act form{{display:inline}} .new{{background:#064e3b;border:1px solid #22c55e;padding:14px;border-radius:8px;margin-bottom:14px}}
  .cred{{margin-top:6px;font-size:15px}} .msg{{background:#1e3a8a;padding:10px;border-radius:8px;margin-bottom:14px}}
</style></head><body>
  <h1>UYAP Lisans Yönetimi</h1>
  {note}{banner}
  <div class='card'>
    <h3>Yeni Lisans (Ofis) Oluştur</h3>
    <form method='post' action='/admin/create'>
      <input type='text' name='label' placeholder='Etiket (ör. Ahmet Hukuk Bürosu)' required>
      <input type='text' name='password' placeholder='Parola (boşsa otomatik üretilir)'>
      <button type='submit'>Oluştur</button>
    </form>
    <p style='color:#94a3b8;font-size:12px'>Oda anahtarı otomatik ve tahmin edilemez üretilir. Müşteri uygulamada bu anahtarı + parolayı girer.</p>
  </div>
  <div class='card'><h3>Lisanslar</h3>
    <table><thead><tr><th>Oda Anahtarı</th><th>Etiket</th><th>Durum</th><th>Oluşturma</th><th>İşlem</th></tr></thead>
    <tbody>{table}</tbody></table>
  </div>
</body></html>"""


def _admin_page(new_account=None, msg=None):
    return web.Response(text=_render_admin(new_account, msg), content_type="text/html",
                        charset="utf-8", headers={"Cache-Control": "no-store"})


async def admin_get(request):
    if not _admin_ok(request):
        return _admin_unauth()
    return _admin_page()


async def admin_create(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    label = (data.get("label") or "").strip()
    pw = (data.get("password") or "").strip() or None
    if not label:
        return _admin_page(msg="Etiket gerekli.")
    res = STORE.create(label, password=pw)
    return _admin_page(new_account=res, msg="Hesap oluşturuldu.")


async def admin_revoke(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.set_active((data.get("room_key") or "").strip(), False)
    return _admin_page(msg="Lisans iptal edildi (pasif).")


async def admin_activate(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.set_active((data.get("room_key") or "").strip(), True)
    return _admin_page(msg="Lisans aktifleştirildi.")


async def admin_reset(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    key = (data.get("room_key") or "").strip()
    new_pw = STORE.reset_password(key)
    if new_pw is None:
        return _admin_page(msg="Hesap bulunamadı.")
    return _admin_page(new_account={"room_key": key, "password": new_pw}, msg="Parola sıfırlandı.")


async def admin_delete(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.delete((data.get("room_key") or "").strip())
    return _admin_page(msg="Hesap silindi.")


# ------------------------------------------------------------------------------------------
# Statik webapp + dinamik config
# ------------------------------------------------------------------------------------------
def make_app(args):
    load_allowed(args.config)
    app = web.Application()

    def _is_local(request):
        return (request.host or "").split(":")[0] in ("127.0.0.1", "localhost")

    def config_js(request):
        # signaling: AYNI origin'in /ws'i (tarayıcı location'dan türetir) -> boş bırakıyoruz.
        ice = build_ice(_is_local(request), args.ice)
        cfg = {"signaling": "", "room": args.room, "ice": ice}
        body = "window.UYAP_CONFIG = " + json.dumps(cfg, ensure_ascii=False) + ";\n"
        return web.Response(body=body.encode("utf-8"), content_type="application/javascript",
                            charset="utf-8", headers={"Cache-Control": "no-store"})

    async def ice_endpoint(request):
        # Masaüstü ofis/istemci ICE'ı (efemeral TURN dahil) buradan çeker.
        return web.json_response({"iceServers": build_ice(_is_local(request), args.ice)},
                                 headers={"Cache-Control": "no-store"})

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
    app.router.add_get("/ice", ice_endpoint)
    # Admin (lisans/kullanıcı oluşturma) — HTTP Basic ile korunur.
    app.router.add_get("/admin", admin_get)
    app.router.add_post("/admin/create", admin_create)
    app.router.add_post("/admin/revoke", admin_revoke)
    app.router.add_post("/admin/activate", admin_activate)
    app.router.add_post("/admin/reset", admin_reset)
    app.router.add_post("/admin/delete", admin_delete)
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

    n = len(STORE.accounts)
    print(f"[*] Hesap deposu: {n} lisans ({accounts.ACCOUNTS_PATH})."
          + ("" if n else " Boş → eski davranış (allowlist/serbest)."))
    if ADMIN_PASSWORD:
        print(f"[*] Admin ekranı: {scheme}://{args.host}:{args.port}/admin (Basic-Auth açık).")
    else:
        print("[!] UYAP_ADMIN_PASSWORD ayarlı değil → /admin KAPALI. Hesap oluşturmak için ayarlayın.")
    if _turn_servers():
        print("[*] TURN: efemeral kimlikli TURN etkin (CGNAT/mobil veri desteklenir).")
    else:
        print("[!] TURN yok (yalnızca STUN). CGNAT ardındaki bazı istemciler bağlanamayabilir.")

    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_ctx, print=None)


if __name__ == "__main__":
    main()
