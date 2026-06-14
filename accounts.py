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
  • Kalıcılık: tek bir JSON dosyası (atomik yazım). Yol UYAP_DATA_DIR ile değiştirilebilir.
    DİKKAT (Render/PaaS): konteyner diski genelde EFEMERAL'dir; her deploy/yeniden başlatmada
    sıfırlanır. Üretimde UYAP_DATA_DIR'i KALICI bir diske (Render Persistent Disk vb.) yöneltin,
    yoksa oluşturduğunuz hesaplar kaybolur.

Bu modül ağ/asyncio bilmez; sadece bellek içi sözlük + dosya. vendor_server tek event
loop'ta koştuğu için kilit gerekmez, yine de süreçler arası tutarlılık için her yazımda
diske basar ve açılışta diskten yükler.
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


class AccountStore:
    """Bellek içi hesap tablosu + JSON dosyasına yazım. room_key -> hesap kaydı."""

    def __init__(self, path: str = ACCOUNTS_PATH):
        self.path = path
        self.accounts = {}   # room_key -> {"label","password","created","active"}
        self.load()

    # ── Kalıcılık ───────────────────────────────────────────────────────────────────
    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.accounts = data.get("accounts", {}) if isinstance(data, dict) else {}
            except Exception:
                self.accounts = {}
        else:
            self.accounts = {}

    def save(self):
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"accounts": self.accounts}, f, ensure_ascii=False, indent=2)
        os.replace(tmp, self.path)  # atomik

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
