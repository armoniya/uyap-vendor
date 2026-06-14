#!/usr/bin/env python3
"""
Hesap / Lisans Deposu (accounts.py) — v2: Ofis + Kullanıcı (master/üye) modeli
------------------------------------------------------------------------------
Satıcı sunucusunun (vendor_server.py) kullandığı küçük, bağımlılıksız hesap deposu.

İKİ KATMANLI KİMLİK MODELİ
  • OFİS (office)  = bir lisans + bir tünel/oda. Bir e-imza, bir UYAP oturumu. Sabit bir
    iç kimliği (office_id) ve DÖNEN bir public jetonu (room_key) vardır.
  • KULLANICI (user) = bir kişi. Kendi KULLANICI ADI + PAROLASI ile giriş yapar; bir ofise
    (office_id) bağlıdır ve rolü vardır: "master" (ofis sahibi) ya da "member" (alt kullanıcı).

Neden böyle:
  • Giriş ARTIK oda anahtarıyla değil, KULLANICI ADI + PAROLA ile yapılır. Sunucu kullanıcıyı
    doğrular → ait olduğu ofisin GÜNCEL room_key'ini kendi çözer → tünele bağlar. Alt kullanıcı
    ham oda anahtarını hiç görmez/yazmaz.
  • room_key bir İÇ/DÖNEN jetondur: kimse yazmadığı için düzensiz (asimetrik) aralıklarla
    DÖNDÜRÜLEBİLİR (rotate_room_key); sızsa bile kısa sürede geçersizleşir. Giriş sonrası
    gerekirse kopyalanabilir (hızlı paylaşım linki vb.).
  • Master kendi üyelerini yönetir (ekle/sil/parola sıfırla/iptal); vendor yalnızca ofisi +
    master'ı oluşturur.

Tasarım notları
  • Parola pbkdf2-hmac-sha256 (stdlib) + hesap başına rastgele tuz; düz parola DİSKTE TUTULMAZ.
    Doğrulama sabit zamanlı.
  • Kullanıcı adı GLOBAL benzersizdir (girişte ofis ipucu gerekmesin diye). Güvenlik geçişinde
    yeniden değerlendirilecek.
  • Kalıcılık TAKILABİLİR: DATABASE_URL varsa PostgreSQL (uyap_kv tablosu, tek JSONB satırı
    k='accounts', artık TÜM dokümanı {offices,users} tutar), yoksa tek JSON dosyası (yerel test).
  • Bellek içi sözlük çalışma kopyasıdır; doğrulama bellekten okur (DB gecikmesi sıcak yola
    binmez). Yazımlar (oluştur/sıfırla/sil/döndür) seyrektir, her birinde depoya basılır.
"""

import os
import json
import time
import base64
import hmac
import hashlib
import secrets

DATA_DIR = os.environ.get("UYAP_DATA_DIR", os.path.dirname(os.path.abspath(__file__)))
ACCOUNTS_PATH = os.path.join(DATA_DIR, "accounts.json")

# Ayarlıysa dosya yerine PostgreSQL kullanılır (Neon/Supabase bağlantı dizesi).
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()

_PBKDF2_ITERS = 200_000


# ──────────────────────────────────────────────────────────────────────────────────────
# Parola / jeton yardımcıları
# ──────────────────────────────────────────────────────────────────────────────────────
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
    """Tahmin edilemez, URL/JSON güvenli bir oda anahtarı (dönen public jeton)."""
    return "uyap_" + secrets.token_urlsafe(18)


def generate_office_id() -> str:
    """Sabit, iç ofis kimliği. room_key dönse de bu DEĞİŞMEZ; users buna bağlanır."""
    return "off_" + secrets.token_urlsafe(9)


def generate_password() -> str:
    """İnsan-paylaşılabilir, makul güçte rastgele bir parola üretir."""
    return secrets.token_urlsafe(9)


# ──────────────────────────────────────────────────────────────────────────────────────
# Kalıcılık arka uçları (backend). İkisi de TÜM dokümanı ({offices, users}) tek parça
# okur/yazar; küçük veri için yeterli.
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
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save(self, doc: dict):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # atomik


class _PostgresBackend:
    """PostgreSQL (Neon/Supabase). Tüm doküman `uyap_kv` tablosunda tek JSONB satırında
    (k='accounts') tutulur. Driver (psycopg2) yalnızca burada, tembel import edilir."""

    _KEY = "accounts"
    _TABLE = "uyap_kv"

    def __init__(self, dsn: str):
        import psycopg2  # lazy: yalnızca DB modunda gerekir
        self._psycopg2 = psycopg2
        self.dsn = dsn
        self._ensure_table()

    def _connect(self):
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

    def save(self, doc: dict):
        payload = json.dumps({} if doc is None else doc, ensure_ascii=False)
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    f"INSERT INTO {self._TABLE} (k, v) VALUES (%s, %s::jsonb) "
                    "ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v",
                    (self._KEY, payload))
            conn.commit()


def _make_backend():
    if DATABASE_URL:
        print("[+] Hesap deposu: PostgreSQL (kalıcı).")
        return _PostgresBackend(DATABASE_URL)
    print(f"[!] Hesap deposu: DOSYA ({ACCOUNTS_PATH}). DATABASE_URL yok — PaaS'ta EFEMERAL olabilir!")
    return _FileBackend(ACCOUNTS_PATH)


class AccountError(Exception):
    """Hesap işlemi hatası (ör. kullanıcı adı dolu, ofis yok). Mesaj kullanıcıya gösterilebilir."""


class AccountStore:
    """Bellek içi ofis + kullanıcı tablosu (çalışma kopyası) + takılabilir kalıcı depo.

    offices: office_id -> {label, room_key, active, created, rotated}
    users:   username  -> {office_id, role, password, label, active, created}
    """

    def __init__(self, path: str = ACCOUNTS_PATH, backend=None):
        self.path = path
        self.backend = backend if backend is not None else _make_backend()
        self.offices = {}     # office_id -> kayıt
        self.users = {}       # username  -> kayıt
        self._room_index = {}  # room_key -> office_id (bellek içi indeks)
        self.load()

    # ── Kalıcılık ───────────────────────────────────────────────────────────────────
    def load(self):
        try:
            doc = self.backend.load() or {}
        except Exception as e:
            print(f"[!] Hesap deposu yüklenemedi: {e}")
            doc = {}
        # v1 (eski) format tespiti: top-level "accounts" vardı, "offices"/"users" yoktu.
        if "offices" not in doc and "users" not in doc and "accounts" in doc:
            print("[!] Eski (v1) hesap formatı bulundu; v2'ye geçiş için yeni ofis/kullanıcı "
                  "oluşturun. Eski kayıtlar yok sayıldı.")
            doc = {}
        self.offices = doc.get("offices", {}) if isinstance(doc, dict) else {}
        self.users = doc.get("users", {}) if isinstance(doc, dict) else {}
        self._reindex()

    def _reindex(self):
        self._room_index = {o["room_key"]: oid for oid, o in self.offices.items() if o.get("room_key")}

    def save(self):
        self.backend.save({"offices": self.offices, "users": self.users})

    # ── Sorgular ────────────────────────────────────────────────────────────────────
    def is_empty(self) -> bool:
        """Hiç kullanıcı yoksa True (signaling 'serbest/dev' moduna düşer)."""
        return not self.users

    def get_office(self, office_id: str) -> dict:
        return self.offices.get(office_id)

    def office_by_room_key(self, room_key: str) -> dict:
        oid = self._room_index.get(room_key)
        return self.offices.get(oid) if oid else None

    # ── Ofis işlemleri (vendor /admin) ────────────────────────────────────────────────
    def create_office(self, label: str, master_username: str, master_password: str = None,
                      room_key: str = None) -> dict:
        """Yeni ofis (lisans) + master kullanıcı oluşturur. Düz master parolasını (bir kez
        gösterilmek üzere), oda anahtarını ve office_id'yi döndürür."""
        master_username = (master_username or "").strip()
        if not master_username:
            raise AccountError("Master kullanıcı adı gerekli.")
        if master_username in self.users:
            raise AccountError(f"Kullanıcı adı dolu: {master_username}")

        office_id = generate_office_id()
        while office_id in self.offices:
            office_id = generate_office_id()
        if not room_key:
            room_key = generate_room_key()
        while room_key in self._room_index:
            room_key = generate_room_key()

        now = int(time.time())
        self.offices[office_id] = {
            "label": label or "",
            "room_key": room_key,
            "active": True,
            "created": now,
            "rotated": now,
        }
        plain_pw = master_password or generate_password()
        self.users[master_username] = {
            "office_id": office_id,
            "role": "master",
            "password": _hash_password(plain_pw),
            "label": label or "",
            "active": True,
            "created": now,
        }
        self._reindex()
        self.save()
        return {"office_id": office_id, "room_key": room_key,
                "master_username": master_username, "password": plain_pw, "label": label or ""}

    def set_office_active(self, office_id: str, active: bool) -> bool:
        o = self.offices.get(office_id)
        if not o:
            return False
        o["active"] = bool(active)
        self.save()
        return True

    def delete_office(self, office_id: str) -> bool:
        """Ofisi ve ona bağlı TÜM kullanıcıları siler."""
        if office_id not in self.offices:
            return False
        del self.offices[office_id]
        for uname in [u for u, rec in self.users.items() if rec.get("office_id") == office_id]:
            del self.users[uname]
        self._reindex()
        self.save()
        return True

    def rotate_room_key(self, office_id: str) -> str:
        """Ofisin public oda anahtarını yeni, tahmin edilemez bir jetona DÖNDÜRÜR. Kullanıcılar
        kullanıcı adıyla giriş yaptığından bu işlem onları ETKİLEMEZ. Yeni room_key döner."""
        o = self.offices.get(office_id)
        if not o:
            return None
        new_key = generate_room_key()
        while new_key in self._room_index:
            new_key = generate_room_key()
        o["room_key"] = new_key
        o["rotated"] = int(time.time())
        self._reindex()
        self.save()
        return new_key

    # ── Kullanıcı işlemleri (master /ofis paneli + desktop sekmesi) ────────────────────
    def create_user(self, office_id: str, username: str, password: str = None,
                    role: str = "member", label: str = "") -> dict:
        """Bir ofise yeni kullanıcı ekler. Düz parolayı (bir kez gösterilmek üzere) döndürür."""
        username = (username or "").strip()
        if not username:
            raise AccountError("Kullanıcı adı gerekli.")
        if office_id not in self.offices:
            raise AccountError("Ofis bulunamadı.")
        if username in self.users:
            raise AccountError(f"Kullanıcı adı dolu: {username}")
        if role not in ("master", "member"):
            role = "member"
        plain_pw = password or generate_password()
        self.users[username] = {
            "office_id": office_id,
            "role": role,
            "password": _hash_password(plain_pw),
            "label": label or "",
            "active": True,
            "created": int(time.time()),
        }
        self.save()
        return {"username": username, "password": plain_pw, "role": role}

    def set_user_active(self, username: str, active: bool) -> bool:
        u = self.users.get(username)
        if not u:
            return False
        u["active"] = bool(active)
        self.save()
        return True

    def reset_user_password(self, username: str, password: str = None) -> str:
        u = self.users.get(username)
        if not u:
            return None
        plain_pw = password or generate_password()
        u["password"] = _hash_password(plain_pw)
        self.save()
        return plain_pw

    def delete_user(self, username: str) -> bool:
        if username in self.users:
            # Son master'ı silmeye izin verme (ofis yönetilemez kalmasın).
            u = self.users[username]
            if u.get("role") == "master":
                oid = u.get("office_id")
                masters = [n for n, r in self.users.items()
                           if r.get("office_id") == oid and r.get("role") == "master"]
                if len(masters) <= 1:
                    raise AccountError("Ofisin tek master'ı silinemez.")
            del self.users[username]
            self.save()
            return True
        return False

    # ── Doğrulama (signaling) ─────────────────────────────────────────────────────────
    def authenticate(self, username: str, password: str):
        """Kullanıcı adı + parola ile giriş doğrular ve kullanıcının ofisini çözer.
        (ok: bool, reason: str, info: dict|None) döndürür. info: office_id, room_key, role…"""
        u = self.users.get((username or "").strip())
        if not u:
            return False, "Kullanıcı bulunamadı.", None
        if not u.get("active", True):
            return False, "Kullanıcı pasif (askıda/iptal).", None
        office = self.offices.get(u.get("office_id"))
        if not office:
            return False, "Bağlı ofis bulunamadı.", None
        if not office.get("active", True):
            return False, "Ofis lisansı pasif.", None
        if not _verify_password(password or "", u.get("password")):
            return False, "Parola hatalı.", None
        return True, "Başarılı", {
            "username": username,
            "office_id": u["office_id"],
            "room_key": office["room_key"],
            "role": u.get("role", "member"),
            "office_label": office.get("label", ""),
        }

    # ── Listeler (yönetim arayüzleri) ─────────────────────────────────────────────────
    def listing_offices(self):
        out = []
        for oid, o in sorted(self.offices.items(), key=lambda kv: kv[1].get("created", 0), reverse=True):
            members = [u for u, r in self.users.items() if r.get("office_id") == oid]
            master = next((u for u, r in self.users.items()
                           if r.get("office_id") == oid and r.get("role") == "master"), "")
            out.append({
                "office_id": oid,
                "label": o.get("label", ""),
                "room_key": o.get("room_key", ""),
                "master_username": master,
                "active": o.get("active", True),
                "created": o.get("created", 0),
                "rotated": o.get("rotated", 0),
                "user_count": len(members),
            })
        return out

    def listing_users(self, office_id: str):
        out = []
        for uname, r in sorted(self.users.items(), key=lambda kv: kv[1].get("created", 0), reverse=True):
            if r.get("office_id") != office_id:
                continue
            out.append({
                "username": uname,
                "label": r.get("label", ""),
                "role": r.get("role", "member"),
                "active": r.get("active", True),
                "created": r.get("created", 0),
            })
        return out
