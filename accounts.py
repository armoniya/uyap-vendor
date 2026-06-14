#!/usr/bin/env python3
"""
Hesap / Lisans Deposu (accounts.py)
-----------------------------------
Satıcı sunucusunun (vendor_server.py) kullandığı küçük, bağımlılıksız hesap deposu.
Bir hesap = bir ofis lisansı: benzersiz + tahmin edilemez bir ODA ANAHTARI (room key) ve
bir PAROLA. O büronun ofisi ve personeli (istemciler) aynı oda anahtarı + parola ile
bağlanır; signaling sunucusu her bağlanışta bu ikiliyi DOĞRULAR.

Tasarım notları
  • Oda anahtarı `secrets.token_urlsafe` ile üretilir → tahmin edilemez, URL/JSON güvenli.
  • Parola pbkdf2-hmac-sha256 (stdlib) ile, hesap başına rastgele tuz (salt) ile saklanır;
    düz parola DİSKTE TUTULMAZ. Doğrulama sabit zamanlı karşılaştırma ile yapılır.
  • Kalıcılık TAKILABİLİR (pluggable):
      – `DATABASE_URL` ayarlıysa → PostgreSQL (Neon/Supabase vb.). Hesaplar tek bir JSONB
        satırında (`uyap_kv` tablosu, k='accounts') tutulur. Render free planda kalıcı disk
        olmadığından üretim yolu BUDUR.
      – Değilse → tek JSON dosyası (atomik yazım), `UYAP_DATA_DIR` ile yol değiştirilebilir.
        Yerel geliştirme/test içindir. DİKKAT: PaaS konteyner diski EFEMERAL'dir; orada
        DATABASE_URL kullanın, yoksa hesaplar her deploy'da kaybolur.

Bu modül ağ/asyncio bilmez; bellek içi sözlük çalışma kopyasıdır, arkadaki depo (DB/dosya)
yalnızca DAYANIKLILIK içindir. Doğrulama (validate) bellekten okur → DB gecikmesi sıcak
yola binmez. Yazımlar (oluştur/sıfırla/sil) seyrektir (admin) ve her birinde depoya basılır.
vendor_server tek event loop + tek instance'ta koştuğu için kilit gerekmez.
"""

import os
import json
import time
import base64
import hmac
import hashlib
import secrets

# Veri dizini: varsayılan bu dosyanın yanı; üretimde KALICI diske yöneltin (UYAP_DATA_DIR).
DATA_DIR = os.environ.get("UYAP_DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
ACCOUNTS_PATH = os.path.join(DATA_DIR, "accounts.json")

# Ayarlıysa dosya yerine PostgreSQL kullanılır (Neon/Supabase bağlantı dizesi).
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

_PBKDF2_ITERS = 200_000


def _hash_password(password: str, salt: bytes = None, iters: int = _PBKDF2_ITERS) -> dict:
    """Parolayı tuzlu pbkdf2-hmac-sha256 ile özetler. Saklanabilir bir sözlük döndürür."""
    if salt is None:
        salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return {
        "algo": "pbkdf2_sha256",
        "iters": iters,
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(dk).decode("ascii"),
    }


def _verify_password(password: str, rec: dict) -> bool:
    """Düz parolayı saklanan özetle sabit zamanlı karşılaştırır."""
    if not rec or rec.get("algo") != "pbkdf2_sha256":
        return False
    try:
        salt = base64.b64decode(rec["salt"])
        expected = base64.b64decode(rec["hash"])
        iters = int(rec.get("iters", _PBKDF2_ITERS))
    except Exception:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iters)
    return hmac.compare_digest(dk, expected)


def generate_room_key() -> str:
    """Tahmin edilemez, URL/JSON güvenli bir oda anahtarı üretir (ör. 'a1B2c3...')."""
    return "uyap_" + secrets.token_urlsafe(18)


def generate_password() -> str:
    """İnsan-paylaşılabilir, makul güçte rastgele bir parola üretir."""
    return secrets.token_urlsafe(9)


# ──────────────────────────────────────────────────────────────────────────────────────
# Kalıcılık arka uçları (backend). İkisi de tüm hesap sözlüğünü TEK PARÇA okur/yazar; küçük
# veri için yeterli ve AccountStore mantığını değiştirmeden takılır.
# ──────────────────────────────────────────────────────────────────────────────────────
class _FileBackend:
    """Tek JSON dosyası (atomik yazım). Yerel geliştirme/test için."""

    def __init__(self, path: str):
        self.path = path

    def load(self) -> dict:
        if not os.path.exists(self.path):
            return {}
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("accounts", {}) if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save(self, accounts: dict):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"accounts": accounts}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # atomik


class _PostgresBackend:
    """PostgreSQL (Neon/Supabase). Tüm hesaplar `uyap_kv` tablosunda tek JSONB satırında
    (k='accounts') tutulur. Tabloyu açılışta oluşturur. Driver (psycopg2) yalnızca burada,
    tembel (lazy) import edilir; DATABASE_URL yoksa import hiç denenmez."""

    _KEY = "accounts"
    _TABLE = "uyap_kv"

    def __init__(self, dsn: str):
        import psycopg2  # lazy: yalnızca DB modunda gerekir
        self._psycopg2 = psycopg2
        self.dsn = dsn
        self._ensure_table()

    def _connect(self):
        # autocommit kapalı; her işlemde açıkça commit ederiz.
        return self._psycopg2.connect(self.dsn)

    def _ensure_table(self):
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"CREATE TABLE IF NOT EXISTS {self._TABLE} "
                    "(k TEXT PRIMARY KEY, v JSONB NOT NULL)")
            conn.commit()

    def load(self) -> dict:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(f"SELECT v FROM {self._TABLE} WHERE k = %s", (self._KEY,))
                row = cur.fetchone()
        if not row or not row[0]:
            return {}
        v = row[0]  # psycopg2 JSONB'yi otomatik dict'e çevirir
        return v if isinstance(v, dict) else {}

    def save(self, accounts: dict):
        payload = json.dumps({} if accounts is None else accounts, ensure_ascii=False)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {self._TABLE} (k, v) VALUES (%s, %s::jsonb) "
                    "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
                    (self._KEY, payload))
            conn.commit()


def _make_backend():
    """DATABASE_URL ayarlıysa Postgres, değilse dosya arka ucunu seçer."""
    if DATABASE_URL:
        backend = _PostgresBackend(DATABASE_URL)
        print("[+] Hesap deposu: PostgreSQL (kalıcı).")
        return backend
    print(f"[!] Hesap deposu: DOSYA ({ACCOUNTS_PATH}). DATABASE_URL yok — PaaS'ta EFEMERAL olabilir!")
    return _FileBackend(ACCOUNTS_PATH)


class AccountStore:
    """Bellek içi hesap tablosu (çalışma kopyası) + takılabilir kalıcı depo (DB/dosya).
    room_key -> hesap kaydı. Tüm işlem mantığı bellekte; her yazımda depoya basılır."""

    def __init__(self, path: str = ACCOUNTS_PATH, backend=None):
        self.path = path
        self.backend = backend if backend is not None else _make_backend()
        self.accounts = {}   # room_key -> {"label","password","created","active"}
        self.load()

    # ── Kalıcılık ───────────────────────────────────────────────────────────────────
    def load(self):
        try:
            self.accounts = self.backend.load() or {}
        except Exception as e:
            print(f"[!] Hesap deposu yüklenemedi: {e}")
            self.accounts = {}

    def save(self):
        self.backend.save(self.accounts)

    # ── İşlemler ────────────────────────────────────────────────────────────────────
    def is_empty(self) -> bool:
        return not self.accounts

    def create(self, label: str, password: str = None, room_key: str = None) -> dict:
        """Yeni hesap oluşturur. Parola verilmezse üretilir. Düz parolayı (bir kez
        gösterilmek üzere) ve oda anahtarını döndürür; diskte yalnızca özet tutulur."""
        if not room_key:
            room_key = generate_room_key()
            while room_key in self.accounts:
                room_key = generate_room_key()
        plain_pw = password or generate_password()
        self.accounts[room_key] = {
            "label": label or "",
            "password": _hash_password(plain_pw),
            "created": int(time.time()),
            "active": True,
        }
        self.save()
        return {"room_key": room_key, "password": plain_pw, "label": label or ""}

    def set_active(self, room_key: str, active: bool) -> bool:
        acc = self.accounts.get(room_key)
        if not acc:
            return False
        acc["active"] = bool(active)
        self.save()
        return True

    def reset_password(self, room_key: str, password: str = None) -> str:
        acc = self.accounts.get(room_key)
        if not acc:
            return None
        plain_pw = password or generate_password()
        acc["password"] = _hash_password(plain_pw)
        self.save()
        return plain_pw

    def delete(self, room_key: str) -> bool:
        if room_key in self.accounts:
            del self.accounts[room_key]
            self.save()
            return True
        return False

    def validate(self, room_key: str, password: str):
        """signaling katılımını doğrular. (ok: bool, reason: str) döndürür."""
        acc = self.accounts.get(room_key)
        if not acc:
            return False, "Tanınmayan oda anahtarı."
        if not acc.get("active", True):
            return False, "Lisans pasif (iptal/askıda)."
        if not _verify_password(password or "", acc.get("password")):
            return False, "Parola hatalı."
        return True, "Başarılı"

    def listing(self):
        """Admin tablosu için parolasız özet liste."""
        out = []
        for key, acc in sorted(self.accounts.items(), key=lambda kv: kv[1].get("created", 0), reverse=True):
            out.append({
                "room_key": key,
                "label": acc.get("label", ""),
                "active": acc.get("active", True),
                "created": acc.get("created", 0),
            })
        return out
