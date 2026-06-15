#!/usr/bin/env python3
"""
UYAP Kullanım Günlüğü (usage_logger.py) — EK MODÜL, orijinal yapıya DOKUNMAZ
---------------------------------------------------------------------------
Amaç: Render'a verdiğimiz her kullanıcı adının bu link üzerinden GERÇEKTEN
kullanılıp kullanılmadığını görmek. "Kullanım" = bir kullanıcının sunucuya
başarılı giriş yapması (özellikle /ws tüneline bağlanması).

Tasarım — neden ayrı dosya, neden monkeypatch:
  • vendor_server.py / accounts.py'ye TEK SATIR bile eklemeden çalışır. Bu modül
    çalıştırıldığında accounts.AccountStore.authenticate'i sarmalar (wrap eder):
    her BAŞARILI doğrulamayı kaydeder, sonra orijinal sonucu aynen döndürür.
  • İstemcinin IP'sini ve hangi kapıdan geldiğini (/ws tüneli mi, /api/office
    yönetim mi, /ofis web panel mi) öğrenmek için küçük bir aiohttp middleware
    her isteğin bağlamını bir contextvar'a koyar; sarmalanan authenticate bunu okur.
  • Kalıcılık accounts.py ile AYNI mantık: DATABASE_URL varsa PostgreSQL'deki
    'uyap_kv' tablosuna (k='usage') yazar (kalıcı), yoksa usage_log.json dosyasına
    (PaaS'ta efemeral — yeniden başlayınca sıfırlanabilir).

Çalıştırma — vendor_server.py YERİNE bunu başlatın (mantık aynı, üstüne günlük ekler):
    python usage_logger.py            # host=0.0.0.0, port=$PORT (Render ile birebir)

Render/Docker'da etkinleştirmek için Dockerfile'da SADECE iki satır (kod mantığı
değişmez):
    COPY usage_logger.py .            # (COPY accounts.py satırının yanına)
    CMD ["python", "usage_logger.py"] # eski: ["python", "vendor_server.py"]

Görüntüleme (admin parolası ile, HTTP Basic — vendor_server'ın /admin'i ile aynı parola):
    https://<app>.onrender.com/admin/usage        → tablo (kim, ne zaman, kaç kez)
    https://<app>.onrender.com/admin/usage.json    → ham JSON (dışa aktarma)
UYAP_ADMIN_PASSWORD ayarlı değilse bu sayfalar da kapalıdır (vendor_server ile aynı kural).
"""

import os
import json
import time
import html
import contextvars

from aiohttp import web

# Orijinal sunucu ve hesap deposu — değiştirmeden içe aktarıyoruz.
import vendor_server
import accounts


# ── Ayarlar (env ile değiştirilebilir) ─────────────────────────────────────────────────
# Aynı kullanıcı kısa sürede üst üste doğrulanırsa (ör. masaüstü "Kullanıcılar" sekmesi
# listeyi sık yeniler) her seferinde diske YAZMAYIZ; bu kadar saniye içindeki tekrarlar
# birleştirilir (gürültü + DB yükü azalır).
DEBOUNCE_SECONDS = int(os.environ.get("UYAP_USAGE_DEBOUNCE", "60"))
# İki giriş arasında bu süreden fazla boşluk varsa YENİ bir "oturum" sayılır.
SESSION_GAP_SECONDS = int(os.environ.get("UYAP_USAGE_SESSION_GAP", "600"))  # 10 dk
# Son olaylar listesinde en fazla bu kadar kayıt tutulur (en eskiler atılır).
MAX_EVENTS = int(os.environ.get("UYAP_USAGE_MAX_EVENTS", "1000"))

USAGE_PATH = os.path.join(accounts.DATA_DIR, "usage_log.json")

# Her isteğin bağlamı (IP + giriş kapısı) — middleware doldurur, authenticate sarmalı okur.
_REQ = contextvars.ContextVar("uyap_usage_req", default=None)


# ── Kalıcılık (accounts.py ile aynı yaklaşım; ayrı anahtar/dosya) ────────────────────────
class _UsageStore:
    """Kullanım dokümanını tek parça okur/yazar. DATABASE_URL varsa PostgreSQL ('uyap_kv'
    tablosu, k='usage'), yoksa JSON dosyası. accounts.py'nin _PostgresBackend/_FileBackend
    mantığını yansıtır ama ona dokunmadan, ayrı satırda saklar."""

    _KEY = "usage"
    _TABLE = "uyap_kv"

    def __init__(self):
        self.dsn = accounts.DATABASE_URL
        self._pg = None
        if self.dsn:
            try:
                import psycopg2  # tembel: yalnızca DB modunda gerekir
                self._pg = psycopg2
                self._ensure_table()
                print("[+] Kullanım günlüğü: PostgreSQL (kalıcı, k='usage').")
            except Exception as e:
                print(f"[!] Kullanım günlüğü DB'ye bağlanamadı ({e}); dosyaya düşülüyor.")
                self._pg = None
        if not self._pg:
            print(f"[!] Kullanım günlüğü: DOSYA ({USAGE_PATH}). PaaS'ta EFEMERAL olabilir.")

    def _ensure_table(self):
        with self._pg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(f"CREATE TABLE IF NOT EXISTS {self._TABLE} "
                            "(k TEXT PRIMARY KEY, v JSONB NOT NULL)")
            conn.commit()

    def load(self) -> dict:
        try:
            if self._pg:
                with self._pg.connect(self.dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(f"SELECT v FROM {self._TABLE} WHERE k = %s", (self._KEY,))
                        row = cur.fetchone()
                v = row[0] if row else None
                return v if isinstance(v, dict) else {}
            if os.path.exists(USAGE_PATH):
                with open(USAGE_PATH, "r", encoding="utf-8") as f:
                    v = json.load(f)
                return v if isinstance(v, dict) else {}
        except Exception as e:
            print(f"[!] Kullanım günlüğü yüklenemedi: {e}")
        return {}

    def save(self, doc: dict):
        try:
            if self._pg:
                payload = json.dumps(doc, ensure_ascii=False)
                with self._pg.connect(self.dsn) as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            f"INSERT INTO {self._TABLE} (k, v) VALUES (%s, %s::jsonb) "
                            "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
                            (self._KEY, payload))
                    conn.commit()
                return
            os.makedirs(os.path.dirname(USAGE_PATH) or ".", exist_ok=True)
            tmp = USAGE_PATH + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(doc, f, ensure_ascii=False, indent=2)
            os.replace(tmp, USAGE_PATH)
        except Exception as e:
            print(f"[!] Kullanım günlüğü kaydedilemedi: {e}")


# Bellek içi çalışma kopyası (event loop tek thread; kilit gerekmez).
_STORE = None          # _UsageStore
_DOC = {"users": {}, "events": []}
_last_logged = {}      # (username, source) -> son DİSKE yazılan zaman (debounce)


def _source_label(path: str) -> str:
    """İsteğin geldiği kapıyı insan-okur etikete çevirir."""
    if path == "/ws":
        return "Tünel (bağlantı)"
    if path == "/api/office":
        return "Masaüstü yönetim"
    if path.startswith("/ofis"):
        return "Web panel"
    if path.startswith("/admin"):
        return "Admin"
    return path or "?"


def _record(username: str, info: dict):
    """Başarılı bir doğrulamayı kaydeder. authenticate sarmalından çağrılır."""
    ctx = _REQ.get() or {}
    ip = ctx.get("ip") or "-"
    source = _source_label(ctx.get("path") or "")
    now = int(time.time())

    users = _DOC.setdefault("users", {})
    rec = users.get(username)
    if rec is None:
        rec = {"count": 0, "sessions": 0, "first": now, "last": 0,
               "last_ip": "", "last_source": "", "role": "", "office": "",
               "sources": {}}
        users[username] = rec

    # Her doğrulama bir "isabet"; aralarda boşluk büyükse ayrı "oturum" say.
    if now - rec.get("last", 0) >= SESSION_GAP_SECONDS:
        rec["sessions"] = rec.get("sessions", 0) + 1
    rec["count"] = rec.get("count", 0) + 1
    rec["last"] = now
    rec["last_ip"] = ip
    rec["last_source"] = source
    rec["role"] = (info or {}).get("role", rec.get("role", ""))
    rec["office"] = (info or {}).get("office_label", rec.get("office", ""))
    rec["sources"][source] = rec["sources"].get(source, 0) + 1

    # Debounce: aynı (kullanıcı, kapı) için kısa süre içinde tekrar gelirse diske YAZMA,
    # olay listesine de ekleme (sık yenilemeler günlüğü şişirmesin). Bellek yine güncel.
    key = (username, source)
    if now - _last_logged.get(key, 0) < DEBOUNCE_SECONDS:
        return
    _last_logged[key] = now

    events = _DOC.setdefault("events", [])
    events.append({"ts": now, "username": username, "ip": ip,
                   "source": source, "role": rec["role"], "office": rec["office"]})
    if len(events) > MAX_EVENTS:
        del events[:len(events) - MAX_EVENTS]

    _STORE.save(_DOC)


# ── authenticate sarmalı (monkeypatch) ──────────────────────────────────────────────────
_orig_authenticate = accounts.AccountStore.authenticate


def _patched_authenticate(self, username, password):
    ok, reason, info = _orig_authenticate(self, username, password)
    if ok:
        try:
            _record((username or "").strip(), info)
        except Exception as e:
            # Günlükleme HİÇBİR durumda asıl girişi bozmasın.
            print(f"[!] Kullanım günlüğü kaydı atlandı: {e}")
    return ok, reason, info


# ── IP / bağlam middleware ───────────────────────────────────────────────────────────────
def _client_ip(request) -> str:
    """Render gibi proxy ardında gerçek istemci IP'si X-Forwarded-For'un ilk adımıdır."""
    xff = request.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.remote or "-"


@web.middleware
async def _ctx_middleware(request, handler):
    token = _REQ.set({"ip": _client_ip(request), "path": request.path})
    try:
        return await handler(request)
    finally:
        _REQ.reset(token)


# ── Admin görüntüleme sayfaları (vendor_server'ın admin parolasıyla korunur) ──────────────
def _fmt_ago(ts: int) -> str:
    if not ts:
        return "-"
    d = int(time.time()) - int(ts)
    if d < 60:
        return f"{d} sn önce"
    if d < 3600:
        return f"{d // 60} dk önce"
    if d < 86400:
        return f"{d // 3600} sa önce"
    return f"{d // 86400} gün önce"


def _fmt_time(ts: int) -> str:
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else "-"


def _render_usage() -> str:
    users = _DOC.get("users", {})
    # En son görülen kullanıcı en üstte.
    ordered = sorted(users.items(), key=lambda kv: kv[1].get("last", 0), reverse=True)

    # Hiç giriş yapmamış kullanıcıları da göster (linki HİÇ kullanmayanlar en önemlisi).
    try:
        all_users = set(vendor_server.STORE.users.keys())
    except Exception:
        all_users = set()
    seen = set(users.keys())
    never = sorted(all_users - seen)

    rows = []
    for uname, r in ordered:
        rol = "Master" if r.get("role") == "master" else ("Üye" if r.get("role") else "-")
        rows.append(f"""<tr>
          <td><code>{html.escape(uname)}</code></td>
          <td>{html.escape(r.get('office', '') or '-')}</td>
          <td>{rol}</td>
          <td>{_fmt_time(r.get('last', 0))}<br><span class='muted'>{_fmt_ago(r.get('last', 0))}</span></td>
          <td>{r.get('sessions', 0)}</td>
          <td>{r.get('count', 0)}</td>
          <td><code>{html.escape(r.get('last_ip', '') or '-')}</code></td>
          <td>{html.escape(r.get('last_source', '') or '-')}</td>
          <td class='muted'>{_fmt_time(r.get('first', 0))}</td>
        </tr>""")
    table = "\n".join(rows) or "<tr><td colspan='9' class='muted' style='text-align:center'>Henüz hiç giriş kaydı yok.</td></tr>"

    never_html = ""
    if never:
        chips = " ".join(f"<code>{html.escape(u)}</code>" for u in never)
        never_html = (f"<div class='card'><h3>Linki Hiç Kullanmayanlar "
                      f"({len(never)})</h3><p class='muted'>Bu kullanıcı adları oluşturuldu ama "
                      f"henüz hiç başarılı giriş yapmadı:</p><div class='chips'>{chips}</div></div>")

    # Son olaylar
    ev_rows = []
    for e in reversed(_DOC.get("events", [])[-200:]):
        ev_rows.append(f"""<tr>
          <td class='muted'>{_fmt_time(e.get('ts', 0))}</td>
          <td><code>{html.escape(e.get('username', ''))}</code></td>
          <td>{html.escape(e.get('source', '') or '-')}</td>
          <td><code>{html.escape(e.get('ip', '') or '-')}</code></td>
          <td>{html.escape(e.get('office', '') or '-')}</td>
        </tr>""")
    ev_table = "\n".join(ev_rows) or "<tr><td colspan='5' class='muted' style='text-align:center'>Olay yok.</td></tr>"

    total_users = len(seen)
    return f"""<!doctype html><html lang='tr'><head><meta charset='utf-8'>
<meta name='viewport' content='width=device-width,initial-scale=1'>
<title>UYAP Kullanım Günlüğü</title><style>
  body{{background:#0f172a;color:#f8fafc;font-family:Segoe UI,system-ui,sans-serif;margin:0;padding:24px}}
  h1{{color:#0ea5e9;font-size:20px}} h3{{margin-top:0}}
  .card{{background:#1e293b;border-radius:10px;padding:18px;margin-bottom:18px;max-width:1100px}}
  table{{width:100%;border-collapse:collapse;max-width:1100px}}
  th,td{{text-align:left;padding:8px;border-bottom:1px solid #334155;font-size:13px;vertical-align:top}}
  th{{color:#94a3b8;font-weight:600}}
  code{{background:#0f172a;padding:2px 6px;border-radius:4px;color:#7dd3fc}}
  .muted{{color:#94a3b8;font-size:12px}} .chips code{{display:inline-block;margin:3px}}
  a{{color:#7dd3fc}}
</style></head><body>
  <h1>UYAP Kullanım Günlüğü</h1>
  <p class='muted'>Toplam {total_users} kullanıcı giriş yaptı · Ham veri:
     <a href='/admin/usage.json'>/admin/usage.json</a></p>
  <div class='card'>
    <h3>Kullanıcılar (son görülme sırasıyla)</h3>
    <table><thead><tr>
      <th>Kullanıcı</th><th>Ofis</th><th>Rol</th><th>Son Giriş</th>
      <th>Oturum</th><th>Toplam İsabet</th><th>Son IP</th><th>Son Kapı</th><th>İlk Giriş</th>
    </tr></thead><tbody>{table}</tbody></table>
  </div>
  {never_html}
  <div class='card'>
    <h3>Son Olaylar</h3>
    <table><thead><tr><th>Zaman</th><th>Kullanıcı</th><th>Kapı</th><th>IP</th><th>Ofis</th></tr></thead>
    <tbody>{ev_table}</tbody></table>
  </div>
</body></html>"""


async def usage_get(request):
    if not vendor_server._admin_ok(request):
        return vendor_server._admin_unauth()
    return web.Response(text=_render_usage(), content_type="text/html",
                        charset="utf-8", headers={"Cache-Control": "no-store"})


async def usage_json(request):
    if not vendor_server._admin_ok(request):
        return vendor_server._admin_unauth()
    return web.json_response(_DOC, headers={"Cache-Control": "no-store"})


# ── Bootstrap: orijinal make_app'i sarmala, sonra vendor_server.main()'i çalıştır ─────────
def _install():
    global _STORE
    _STORE = _UsageStore()
    _DOC.update(_STORE.load() or {})
    _DOC.setdefault("users", {})
    _DOC.setdefault("events", [])

    # 1) authenticate'i sarmala (her başarılı giriş kaydedilsin).
    accounts.AccountStore.authenticate = _patched_authenticate

    # 2) make_app'i sarmala: IP middleware + admin sayfaları ekle (orijinal app aynen korunur).
    _orig_make_app = vendor_server.make_app

    def make_app(args):
        app = _orig_make_app(args)
        app.middlewares.append(_ctx_middleware)
        app.router.add_get("/admin/usage", usage_get)
        app.router.add_get("/admin/usage.json", usage_json)
        return app

    vendor_server.make_app = make_app


if __name__ == "__main__":
    _install()
    print("[*] Kullanım günlüğü etkin: /admin/usage (admin parolası ile).")
    vendor_server.main()
