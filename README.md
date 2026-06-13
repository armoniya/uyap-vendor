# UYAP Satıcı Sunucusu — Render Deploy Paketi

Bu klasör Render'a (ya da başka bir PaaS'a) yüklenecek **tek parça**dır:
`vendor_server.py` (statik webapp + `/ws` signaling). **UYAP verisi taşımaz** —
o veri ofis ile tarayıcı arasında doğrudan (P2P, DTLS şifreli) akar. Bu yüzden
ofis kodu, e-imza, PIN gibi HİÇBİR şey bu klasörde yoktur ve buraya konmamalıdır.

## İçerik
- `vendor_server.py` — aiohttp servisi (statik + signaling)
- `requirements-vendor.txt` — tek bağımlılık: aiohttp
- `Dockerfile` — Render bununla derler
- `render.yaml` — Render Blueprint tanımı (free plan)
- `webapp/` — index.html, sw.js, js/tunnel.js, js/wire.js

## Adımlar (özet — detay için bir üst klasördeki DEPLOY_VENDOR.md)
1. Bu klasörü bir GitHub deposuna (özel olabilir) push edin.
2. Render → New + → Blueprint → depoyu seçin. `render.yaml` okunur, Docker'dan derlenir.
3. Adresiniz hazır: `https://<app>.onrender.com`
4. Ofis (e-imza takılı makine):
   `python office_agent.py --signaling wss://<app>.onrender.com/ws --room <UZUN_ODA>`
5. Uzak bilgisayar/telefon (tarayıcı):
   `https://<app>.onrender.com/?room=<UZUN_ODA>`

## Oda anahtarı = lisans
`--room` ortak gizli anahtardır. Uzun/rastgele seçin. İptal için bu klasöre
`signaling_config.json` ekleyip yalnızca izinli odaları kabul ettirebilirsiniz:
`{ "allowed_rooms": ["uzun-anahtar-1", "uzun-anahtar-2"] }`
