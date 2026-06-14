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
import random
import base64
import asyncio
import hashlib
import secrets
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

# Master self-servis paneli (/ofis) oturum çerezini imzalamak için gizli anahtar. Sabit bir
# sır ayarlanmazsa sürece özel rastgele bir anahtar üretilir (yeniden başlatınca oturumlar
# düşer — kabul edilebilir). UYAP_SESSION_SECRET verilirse oturumlar deploy'lar arası kalıcıdır.
SESSION_SECRET = (os.environ.get("UYAP_SESSION_SECRET") or ADMIN_PASSWORD
                  or secrets.token_hex(32))
SESSION_COOKIE = "uyap_ofis"
SESSION_TTL = int(os.environ.get("UYAP_SESSION_TTL", "43200"))  # 12 saat


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

    role = room = cid = rk = None
    try:
        first = await ws.receive()
        if first.type != WSMsgType.TEXT:
            return ws
        join = json.loads(first.data)
        role = join.get("role")
        # 'room' alanı v2'de KULLANICI ADI taşır (eski tel uyumu için ad değişmedi). İstemciler
        # (ofis ajanı + ev) bu alanda kullanıcı adını gönderir; parola ayrı alanda gelir.
        room = join.get("room")

        if role not in ("office", "home") or not room:
            await _safe_send(ws, {"type": "error", "error": "Geçersiz katılım (role/kullanıcı adı)."})
            return ws

        # rk = iç BULUŞMA anahtarı (ROOMS sözlüğü). Hesap deposu doluysa kullanıcı adı + parola
        # DOĞRULANIR ve buluşma KARARLI office_id ile yapılır: kullanıcıya çirkin/sabit bir oda
        # anahtarı gösterilmez, dönen jeton yalnızca savunma/gösterim içindir. Depo boşsa eski
        # dev davranışı: gelen 'room' alanı doğrudan buluşma anahtarıdır (allowlist/serbest).
        password = join.get("password") or ""
        if not STORE.is_empty():
            ok, reason, info = STORE.authenticate(room, password)
            if not ok:
                await _safe_send(ws, {"type": "error", "error": reason})
                return ws
            rk = info["office_id"]
        elif ALLOWED is not None and room not in ALLOWED:
            await _safe_send(ws, {"type": "error", "error": "Tanınmayan kullanıcı adı."})
            return ws
        else:
            rk = room

        slot = ROOMS.setdefault(rk, {"office": None, "homes": {}, "office_meta": None})

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
        if rk in ROOMS:
            slot = ROOMS[rk]
            if role == "office" and slot.get("office") is ws:
                slot["office"] = None
                slot["office_meta"] = None
                for hws in list(slot["homes"].values()):
                    await _safe_send(hws, {"type": "peer_left"})
            elif role == "home" and cid and slot["homes"].get(cid) is ws:
                del slot["homes"][cid]
                await _safe_send(slot.get("office"), {"type": "peer_left", "cid": cid})
            if slot.get("office") is None and not slot["homes"]:
                ROOMS.pop(rk, None)
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
    for a in STORE.listing_offices():
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(a["created"])) if a["created"] else "-"
        durum = ("<span style='color:#22c55e'>Aktif</span>" if a["active"]
                 else "<span style='color:#ef4444'>Pasif</span>")
        oid = html.escape(a["office_id"])
        master = html.escape(a.get("master_username", "") or "-")
        room = html.escape(a.get("room_key", "") or "-")
        toggle = "revoke" if a["active"] else "activate"
        toggle_lbl = "İptal Et" if a["active"] else "Aktifleştir"
        rows.append(f"""<tr>
          <td><code>{master}</code></td><td>{html.escape(a['label'])}</td>
          <td>{a.get('user_count', 0)}</td>
          <td><code title='İç/dönen jeton; kullanıcıya gösterilmez'>{room}</code></td>
          <td>{durum}</td><td>{created}</td>
          <td class='act'>
            <form method='post' action='/admin/{toggle}'><input type='hidden' name='office_id' value='{oid}'><button>{toggle_lbl}</button></form>
            <form method='post' action='/admin/reset'><input type='hidden' name='office_id' value='{oid}'><button>Master Parola Sıfırla</button></form>
            <form method='post' action='/admin/rotate'><input type='hidden' name='office_id' value='{oid}'><button>Oda Döndür</button></form>
            <form method='post' action='/admin/delete' onsubmit="return confirm('Ofis ve tüm kullanıcıları silinsin mi?')"><input type='hidden' name='office_id' value='{oid}'><button class='danger'>Sil</button></form>
          </td></tr>""")
    table = "\n".join(rows) or "<tr><td colspan='7' style='text-align:center;color:#94a3b8'>Henüz ofis yok.</td></tr>"

    banner = ""
    if new_account:
        banner = f"""<div class='new'>
          <b>Yeni ofis (lisans) oluşturuldu</b> — bu bilgileri müşteriye verin (parola yalnızca BİR KEZ gösterilir):
          <div class='cred'>Kullanıcı Adı: <code>{html.escape(new_account['username'])}</code></div>
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
    <h3>Yeni Ofis (Lisans) + Master Kullanıcı Oluştur</h3>
    <form method='post' action='/admin/create'>
      <input type='text' name='username' placeholder='Master kullanıcı adı (ör. ahmethukuk)' required>
      <input type='text' name='label' placeholder='Etiket (ör. Ahmet Hukuk Bürosu)' required>
      <input type='text' name='password' placeholder='Parola (boşsa otomatik üretilir)'>
      <button type='submit'>Oluştur</button>
    </form>
    <p style='color:#94a3b8;font-size:12px'>Müşteri uygulamada bu KULLANICI ADI + parolayı girer. Oda kimliği içeride otomatik üretilir, düzensiz aralıklarla DÖNER ve kullanıcıya hiç gösterilmez. Master sonradan kendi alt kullanıcılarını ekleyebilir.</p>
  </div>
  <div class='card'><h3>Ofisler</h3>
    <table><thead><tr><th>Master Kullanıcı</th><th>Etiket</th><th>Kullanıcı</th><th>Dönen Oda</th><th>Durum</th><th>Oluşturma</th><th>İşlem</th></tr></thead>
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
    username = (data.get("username") or "").strip()
    pw = (data.get("password") or "").strip() or None
    if not label or not username:
        return _admin_page(msg="Master kullanıcı adı ve etiket gerekli.")
    try:
        res = STORE.create_office(label, master_username=username, master_password=pw)
    except accounts.AccountError as e:
        return _admin_page(msg=str(e))
    return _admin_page(new_account={"username": res["master_username"], "password": res["password"]},
                       msg="Ofis ve master kullanıcı oluşturuldu.")


def _master_of(office_id):
    """Bir ofisin master kullanıcı adını bulur (parola sıfırlama için)."""
    for uname, r in STORE.users.items():
        if r.get("office_id") == office_id and r.get("role") == "master":
            return uname
    return None


async def admin_revoke(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.set_office_active((data.get("office_id") or "").strip(), False)
    return _admin_page(msg="Ofis lisansı iptal edildi (pasif).")


async def admin_activate(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.set_office_active((data.get("office_id") or "").strip(), True)
    return _admin_page(msg="Ofis lisansı aktifleştirildi.")


async def admin_reset(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    office_id = (data.get("office_id") or "").strip()
    master = _master_of(office_id)
    if not master:
        return _admin_page(msg="Ofisin master kullanıcısı bulunamadı.")
    new_pw = STORE.reset_user_password(master)
    if new_pw is None:
        return _admin_page(msg="Kullanıcı bulunamadı.")
    return _admin_page(new_account={"username": master, "password": new_pw},
                       msg="Master parolası sıfırlandı.")


async def admin_rotate(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    new_key = STORE.rotate_room_key((data.get("office_id") or "").strip())
    if new_key is None:
        return _admin_page(msg="Ofis bulunamadı.")
    return _admin_page(msg="Oda anahtarı döndürüldü (kullanıcı etkilenmez).")


async def admin_delete(request):
    if not _admin_ok(request):
        return _admin_unauth()
    data = await request.post()
    STORE.delete_office((data.get("office_id") or "").strip())
    return _admin_page(msg="Ofis ve bağlı kullanıcılar silindi.")


# ------------------------------------------------------------------------------------------
# Ofis self-servis — MASTER kullanıcının kendi üyelerini ve parolasını yönetmesi
# ------------------------------------------------------------------------------------------
# İki giriş kapısı, TEK yetki/iş mantığı:
#   • /api/office  : JSON API — masaüstü uygulamasının "Kullanıcılar" sekmesi kullanır
#                    (her istekte kullanıcı adı + parola gönderir; oturum tutulmaz).
#   • /ofis        : HTML panel — tarayıcıdan master girer; imzalı çerez ile oturum tutulur.
# Her ikisi de aşağıdaki _office_authorize + _office_action ortak mantığını çağırır; böylece
# yetki kontrolü (master mı? hedef aynı ofiste mi?) tek yerde toplanır.

def _office_authorize(username, password):
    """Kullanıcı adı + parola doğrular ve MASTER yetkisini şart koşar.
    (info, error) döndürür. info: office_id, role, office_label, username…"""
    ok, reason, info = STORE.authenticate(username, password)
    if not ok:
        return None, reason
    if info.get("role") != "master":
        return None, "Bu işlem için master (ofis sahibi) yetkisi gerekir."
    return info, None


def _office_action(info, action, params):
    """Master'ın bir self-servis işlemini yürütür. (result_dict, error) döndürür.
    result_dict gerektiğinde {'username','password'} gibi BİR KEZ gösterilecek bilgi taşır.
    Yetki: hedef kullanıcı master'ın AYNI ofisinde olmalı; master kendini kilitleyemez."""
    office_id = info["office_id"]
    me = info["username"]

    def _same_office(target):
        u = STORE.users.get(target)
        return bool(u) and u.get("office_id") == office_id

    if action == "list":
        office = STORE.get_office(office_id) or {}
        return {"office_label": office.get("label", ""),
                "users": STORE.listing_users(office_id)}, None

    if action == "add":
        new_user = (params.get("new_username") or "").strip()
        new_pw = (params.get("new_password") or "").strip() or None
        label = (params.get("label") or "").strip()
        role = (params.get("role") or "member").strip()
        if role not in ("member", "master"):
            role = "member"
        if not new_user:
            return None, "Yeni kullanıcı adı gerekli."
        try:
            res = STORE.create_user(office_id, new_user, password=new_pw, role=role, label=label)
        except accounts.AccountError as e:
            return None, str(e)
        return {"username": res["username"], "password": res["password"], "role": res["role"]}, None

    if action == "reset":
        target = (params.get("target") or "").strip()
        new_pw = (params.get("new_password") or "").strip() or None
        if not _same_office(target):
            return None, "Kullanıcı bu ofiste bulunamadı."
        pw = STORE.reset_user_password(target, password=new_pw)
        if pw is None:
            return None, "Kullanıcı bulunamadı."
        return {"username": target, "password": pw}, None

    if action == "passwd":
        new_pw = (params.get("new_password") or "").strip()
        if len(new_pw) < 4:
            return None, "Yeni parola en az 4 karakter olmalı."
        STORE.reset_user_password(me, password=new_pw)
        return {"username": me, "changed": True}, None

    if action == "toggle":
        target = (params.get("target") or "").strip()
        active = str(params.get("active", "")).lower() in ("1", "true", "on", "yes", "aktif")
        if target == me:
            return None, "Kendinizi pasifleştiremezsiniz."
        if not _same_office(target):
            return None, "Kullanıcı bu ofiste bulunamadı."
        STORE.set_user_active(target, active)
        return {"username": target, "active": active}, None

    if action == "delete":
        target = (params.get("target") or "").strip()
        if target == me:
            return None, "Kendinizi silemezsiniz."
        if not _same_office(target):
            return None, "Kullanıcı bu ofiste bulunamadı."
        try:
            STORE.delete_user(target)
        except accounts.AccountError as e:
            return None, str(e)
        return {"username": target, "deleted": True}, None

    return None, "Bilinmeyen işlem."


async def office_api(request):
    """Masaüstü 'Kullanıcılar' sekmesinin JSON API'si. Gövde: {username, password, action, …}.
    Tarayıcı değil masaüstü çağırdığı için CORS/çerez yok; kimlik her istekte gönderilir."""
    try:
        data = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Geçersiz JSON."}, status=400)
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    action = (data.get("action") or "").strip()

    # "passwd" (kendi parolanı değiştir) HER kullanıcıya açıktır (master şartı YOK): kullanıcı
    # mevcut parolasıyla kimliğini kanıtlar, sonra yenisini belirler. Diğer tüm işlemler master ister.
    if action == "passwd":
        ok, reason, _ = STORE.authenticate(username, password)
        if not ok:
            return web.json_response({"ok": False, "error": reason}, status=401)
        new_pw = (data.get("new_password") or "").strip()
        if len(new_pw) < 4:
            return web.json_response({"ok": False, "error": "Yeni parola en az 4 karakter olmalı."},
                                     status=400)
        STORE.reset_user_password(username, password=new_pw)
        return web.json_response({"ok": True, "username": username, "changed": True},
                                 headers={"Cache-Control": "no-store"})

    info, err = _office_authorize(username, password)
    if err:
        return web.json_response({"ok": False, "error": err}, status=401)
    result, err = _office_action(info, action, data)
    if err:
        return web.json_response({"ok": False, "error": err}, status=400)
    out = {"ok": True}
    out.update(result or {})
    return web.json_response(out, headers={"Cache-Control": "no-store"})


# ── /ofis oturum çerezi (imzalı, durumsuz) ────────────────────────────────────────────────
def _make_session(username: str) -> str:
    exp = int(time.time()) + SESSION_TTL
    payload = f"{username}|{exp}"
    sig = hmac.new(SESSION_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode("utf-8")).decode("ascii")


def _read_session(request):
    """Geçerli oturum çerezindeki master kullanıcı adını döndürür (yoksa None). Kullanıcı
    hâlâ var, master ve aktif olmalı; aksi halde oturum geçersizdir."""
    tok = request.cookies.get(SESSION_COOKIE)
    if not tok:
        return None
    try:
        payload = base64.urlsafe_b64decode(tok.encode("ascii")).decode("utf-8")
        username, exp, sig = payload.rsplit("|", 2)
        expected = hmac.new(SESSION_SECRET.encode("utf-8"),
                            f"{username}|{exp}".encode("utf-8"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected):
            return None
        if int(exp) < int(time.time()):
            return None
    except Exception:
        return None
    u = STORE.users.get(username)
    if not u or u.get("role") != "master" or not u.get("active", True):
        return None
    return username


def _office_info_for(username):
    """Oturumdaki master için _office_action'ın beklediği info sözlüğünü kurar."""
    u = STORE.users.get(username) or {}
    office = STORE.offices.get(u.get("office_id")) or {}
    return {"username": username, "office_id": u.get("office_id"),
            "role": u.get("role"), "office_label": office.get("label", "")}


def _render_ofis_login(msg=None):
    note = f"<div class='msg'>{html.escape(msg)}</div>" if msg else ""
    return f"""<!doctype html><html lang='tr'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>UYAP Ofis Paneli — Giriş</title>{_OFIS_CSS}</head><body>
  <div class='wrap'>
    <h1>Ofis Yönetim Paneli</h1>
    {note}
    <div class='card'>
      <p style='color:#94a3b8;font-size:13px'>Master (ofis sahibi) kullanıcı adınız ve parolanızla girin.</p>
      <form method='post' action='/ofis/login'>
        <input type='text' name='username' placeholder='Kullanıcı adı' autofocus required>
        <input type='password' name='password' placeholder='Parola' required>
        <button type='submit'>Giriş Yap</button>
      </form>
    </div>
  </div></body></html>"""


def _render_ofis_panel(username, new_cred=None, msg=None):
    info = _office_info_for(username)
    office_id = info["office_id"]
    users = STORE.listing_users(office_id)
    rows = []
    for u in users:
        created = time.strftime("%Y-%m-%d %H:%M", time.localtime(u["created"])) if u["created"] else "-"
        durum = ("<span style='color:#22c55e'>Aktif</span>" if u["active"]
                 else "<span style='color:#ef4444'>Pasif</span>")
        rol = "Master" if u["role"] == "master" else "Üye"
        uname = html.escape(u["username"])
        is_self = (u["username"] == username)
        if is_self:
            actions = "<span style='color:#94a3b8;font-size:12px'>(siz)</span>"
        else:
            toggle = "0" if u["active"] else "1"
            toggle_lbl = "Pasifleştir" if u["active"] else "Aktifleştir"
            actions = f"""
              <form method='post' action='/ofis/reset'><input type='hidden' name='target' value='{uname}'><button>Parola Sıfırla</button></form>
              <form method='post' action='/ofis/toggle'><input type='hidden' name='target' value='{uname}'><input type='hidden' name='active' value='{toggle}'><button>{toggle_lbl}</button></form>
              <form method='post' action='/ofis/delete' onsubmit="return confirm('{uname} silinsin mi?')"><input type='hidden' name='target' value='{uname}'><button class='danger'>Sil</button></form>"""
        rows.append(f"""<tr><td><code>{uname}</code></td><td>{rol}</td>
          <td>{html.escape(u['label'])}</td><td>{durum}</td><td>{created}</td>
          <td class='act'>{actions}</td></tr>""")
    table = "\n".join(rows) or "<tr><td colspan='6' style='text-align:center;color:#94a3b8'>Henüz kullanıcı yok.</td></tr>"

    banner = ""
    if new_cred and new_cred.get("password"):
        banner = f"""<div class='new'><b>Bilgileri kullanıcıya iletin (parola yalnızca BİR KEZ gösterilir):</b>
          <div class='cred'>Kullanıcı Adı: <code>{html.escape(new_cred['username'])}</code></div>
          <div class='cred'>Parola: <code>{html.escape(new_cred['password'])}</code></div></div>"""
    note = f"<div class='msg'>{html.escape(msg)}</div>" if msg else ""
    label = html.escape(info.get("office_label") or "")

    return f"""<!doctype html><html lang='tr'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>UYAP Ofis Paneli</title>{_OFIS_CSS}</head><body>
  <div class='wrap'>
    <div class='top'><h1>Ofis Yönetim Paneli</h1>
      <form method='post' action='/ofis/logout'><button class='ghost'>Çıkış</button></form></div>
    <p style='color:#94a3b8;margin-top:0'>Ofis: <b>{label or '-'}</b> · Master: <code>{html.escape(username)}</code></p>
    {note}{banner}
    <div class='card'>
      <h3>Yeni Kullanıcı (Üye) Ekle</h3>
      <form method='post' action='/ofis/add'>
        <input type='text' name='new_username' placeholder='Kullanıcı adı (ör. katip1)' required>
        <input type='text' name='label' placeholder='Etiket (ör. Kâtip Ayşe)'>
        <input type='text' name='new_password' placeholder='Parola (boşsa otomatik üretilir)'>
        <button type='submit'>Ekle</button>
      </form>
    </div>
    <div class='card'>
      <h3>Kendi Parolamı Değiştir</h3>
      <form method='post' action='/ofis/passwd'>
        <input type='password' name='new_password' placeholder='Yeni parola' required>
        <button type='submit'>Parolayı Güncelle</button>
      </form>
    </div>
    <div class='card'><h3>Kullanıcılar</h3>
      <table><thead><tr><th>Kullanıcı</th><th>Rol</th><th>Etiket</th><th>Durum</th><th>Oluşturma</th><th>İşlem</th></tr></thead>
      <tbody>{table}</tbody></table>
    </div>
  </div></body></html>"""


_OFIS_CSS = """<style>
  body{background:#0f172a;color:#f8fafc;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:24px}
  .wrap{max-width:920px;margin:0 auto}
  .top{display:flex;align-items:center;justify-content:space-between}
  h1{color:#0ea5e9;font-size:20px} h3{margin-top:0}
  .card{background:#1e293b;border-radius:10px;padding:18px;margin-bottom:16px}
  input{background:#0f172a;border:1px solid #475569;color:#f8fafc;padding:9px;border-radius:6px;width:240px;margin:3px 4px}
  button{background:#0ea5e9;border:0;color:#fff;padding:8px 12px;border-radius:6px;cursor:pointer;font-weight:600;margin:2px}
  button.danger{background:#ef4444} button.ghost{background:#334155}
  table{width:100%;border-collapse:collapse} th,td{text-align:left;padding:8px;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}
  code{background:#0f172a;padding:2px 6px;border-radius:4px;color:#7dd3fc}
  .act form{display:inline} .new{background:#064e3b;border:1px solid #22c55e;padding:14px;border-radius:8px;margin-bottom:14px}
  .cred{margin-top:6px;font-size:15px} .msg{background:#1e3a8a;padding:10px;border-radius:8px;margin-bottom:14px}
</style>"""


def _ofis_response(html_text, cookie=None, clear_cookie=False):
    resp = web.Response(text=html_text, content_type="text/html", charset="utf-8",
                        headers={"Cache-Control": "no-store"})
    if cookie is not None:
        resp.set_cookie(SESSION_COOKIE, cookie, max_age=SESSION_TTL, httponly=True,
                        samesite="Lax", path="/")
    if clear_cookie:
        resp.del_cookie(SESSION_COOKIE, path="/")
    return resp


async def ofis_get(request):
    username = _read_session(request)
    if not username:
        return _ofis_response(_render_ofis_login())
    return _ofis_response(_render_ofis_panel(username))


async def ofis_login(request):
    data = await request.post()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    info, err = _office_authorize(username, password)
    if err:
        return _ofis_response(_render_ofis_login(msg=err))
    return _ofis_response(_render_ofis_panel(username, msg="Giriş başarılı."),
                          cookie=_make_session(username))


async def ofis_logout(request):
    return _ofis_response(_render_ofis_login(msg="Çıkış yapıldı."), clear_cookie=True)


async def _ofis_do(request, action):
    """Oturumlu master için bir self-servis işlemini yürütüp paneli yeniden çizer."""
    username = _read_session(request)
    if not username:
        return _ofis_response(_render_ofis_login(msg="Oturum gerekli."))
    data = await request.post()
    info = _office_info_for(username)
    result, err = _office_action(info, action, dict(data))
    if err:
        return _ofis_response(_render_ofis_panel(username, msg=err))
    new_cred = result if (result and result.get("password")) else None
    nice = {"add": "Kullanıcı eklendi.", "reset": "Parola sıfırlandı.",
            "passwd": "Parolanız güncellendi.", "toggle": "Kullanıcı durumu değişti.",
            "delete": "Kullanıcı silindi."}.get(action, "Tamam.")
    return _ofis_response(_render_ofis_panel(username, new_cred=new_cred, msg=nice))


async def ofis_add(request):    return await _ofis_do(request, "add")
async def ofis_reset(request):  return await _ofis_do(request, "reset")
async def ofis_passwd(request): return await _ofis_do(request, "passwd")
async def ofis_toggle(request): return await _ofis_do(request, "toggle")
async def ofis_delete(request): return await _ofis_do(request, "delete")


# ── /sifre : HERHANGİ bir kullanıcının (üye dahil) kendi parolasını değiştirdiği basit sayfa ──
# Oturum yok; tek adımda kullanıcı adı + MEVCUT parola + YENİ parola ile kimlik kanıtlanır.
def _render_sifre(msg=None, ok=False):
    cls = "msg ok" if ok else "msg"
    note = f"<div class='{cls}'>{html.escape(msg)}</div>" if msg else ""
    return f"""<!doctype html><html lang='tr'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>UYAP — Parola Değiştir</title>{_OFIS_CSS}
<style>.msg.ok{{background:#064e3b;border:1px solid #22c55e}}</style></head><body>
  <div class='wrap'>
    <h1>Parola Değiştir</h1>
    {note}
    <div class='card'>
      <p style='color:#94a3b8;font-size:13px'>Kullanıcı adınız, MEVCUT parolanız ve yeni parolanızla değiştirin. (Master ya da üye fark etmez.)</p>
      <form method='post' action='/sifre'>
        <input type='text' name='username' placeholder='Kullanıcı adı' autofocus required><br>
        <input type='password' name='password' placeholder='Mevcut parola' required><br>
        <input type='password' name='new_password' placeholder='Yeni parola (en az 4 karakter)' required><br>
        <button type='submit'>Parolayı Güncelle</button>
      </form>
    </div>
  </div></body></html>"""


async def sifre_get(request):
    return _ofis_response(_render_sifre())


async def sifre_post(request):
    data = await request.post()
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    new_pw = (data.get("new_password") or "").strip()
    ok, reason, _ = STORE.authenticate(username, password)
    if not ok:
        return _ofis_response(_render_sifre(msg=reason, ok=False))
    if len(new_pw) < 4:
        return _ofis_response(_render_sifre(msg="Yeni parola en az 4 karakter olmalı.", ok=False))
    STORE.reset_user_password(username, password=new_pw)
    return _ofis_response(_render_sifre(msg="Parolanız güncellendi. Artık yeni parolayla girebilirsiniz.", ok=True))


# ------------------------------------------------------------------------------------------
# Otomatik oda anahtarı döndürme (rotation) — düzensiz aralıklarla, şeffaf
# ------------------------------------------------------------------------------------------
# Buluşma KARARLI office_id ile yapılır; bu yüzden room_key dönmesi CANLI bağlantıları
# ETKİLEMEZ. Kullanıcı kullanıcı adıyla giriş yaptığı için dönmeyi de hissetmez. Tek faydası:
# sızan/eski bir oda jetonunun ömrünü kısaltmak (savunma). Aralık env ile ayarlanır.
async def _rotation_loop():
    lo = int(os.environ.get("UYAP_ROTATE_MIN", "1800"))   # alt sınır (sn) — vars. 30 dk
    hi = max(lo + 1, int(os.environ.get("UYAP_ROTATE_MAX", "5400")))  # üst sınır — vars. 90 dk
    while True:
        await asyncio.sleep(random.uniform(lo, hi))  # düzensiz/tahmin edilemez aralık
        try:
            n = 0
            for oid in list(STORE.offices.keys()):
                if STORE.rotate_room_key(oid):
                    n += 1
            if n:
                print(f"[*] Otomatik döndürme: {n} ofisin oda anahtarı yenilendi.")
        except Exception as e:
            print(f"[!] Oda döndürme hatası: {e}")


async def _start_rotation(app):
    app["rotation_task"] = asyncio.ensure_future(_rotation_loop())


async def _stop_rotation(app):
    t = app.get("rotation_task")
    if t:
        t.cancel()
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass


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
    app.router.add_post("/admin/rotate", admin_rotate)
    app.router.add_post("/admin/delete", admin_delete)

    # Ofis self-servis: master kendi üyelerini + parolasını yönetir.
    app.router.add_post("/api/office", office_api)   # masaüstü "Kullanıcılar" sekmesi
    app.router.add_get("/ofis", ofis_get)            # tarayıcı paneli (oturumlu)
    app.router.add_post("/ofis/login", ofis_login)
    app.router.add_post("/ofis/logout", ofis_logout)
    app.router.add_post("/ofis/add", ofis_add)
    app.router.add_post("/ofis/reset", ofis_reset)
    app.router.add_post("/ofis/passwd", ofis_passwd)
    app.router.add_post("/ofis/toggle", ofis_toggle)
    app.router.add_post("/ofis/delete", ofis_delete)
    # Herkese açık parola değiştirme (üye dahil) — oturum gerektirmez.
    app.router.add_get("/sifre", sifre_get)
    app.router.add_post("/sifre", sifre_post)

    # Oda anahtarlarını düzensiz (rastgele) aralıklarla otomatik döndüren arka plan görevi.
    app.on_startup.append(_start_rotation)
    app.on_cleanup.append(_stop_rotation)
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

    no = len(STORE.offices)
    nu = len(STORE.users)
    print(f"[*] Hesap deposu: {no} ofis / {nu} kullanıcı ({accounts.ACCOUNTS_PATH})."
          + ("" if nu else " Boş → eski davranış (allowlist/serbest)."))
    if ADMIN_PASSWORD:
        print(f"[*] Admin ekranı: {scheme}://{args.host}:{args.port}/admin (Basic-Auth açık).")
    else:
        print("[!] UYAP_ADMIN_PASSWORD ayarlı değil → /admin KAPALI. Hesap oluşturmak için ayarlayın.")
    print(f"[*] Ofis paneli (master): {scheme}://{args.host}:{args.port}/ofis  ·  "
          f"Parola değiştir (herkes): {scheme}://{args.host}:{args.port}/sifre  ·  "
          f"Masaüstü API: {scheme}://{args.host}:{args.port}/api/office")
    if _turn_servers():
        print("[*] TURN: efemeral kimlikli TURN etkin (CGNAT/mobil veri desteklenir).")
    else:
        print("[!] TURN yok (yalnızca STUN). CGNAT ardındaki bazı istemciler bağlanamayabilir.")

    web.run_app(app, host=args.host, port=args.port, ssl_context=ssl_ctx, print=None)


if __name__ == "__main__":
    main()
