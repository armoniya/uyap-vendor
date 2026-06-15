# UYAP satıcı sunucusu (vendor_server.py) — statik webapp + /ws signaling, TEK servis.
# Bilerek yalnızca sunucu + statik kabuğu kopyalar; UYAP kodu/PIN'ler imaja GİRMEZ.
# UYAP verisi taşımaz (o veri ofis↔tarayıcı P2P akar); bedava PaaS'ta çalışır, HTTPS'i PaaS verir.
FROM python:3.12-slim

WORKDIR /app

# Yalnızca satıcı bağımlılığı (aiohttp). aiortc/websockets GEREKMEZ.
COPY requirements-vendor.txt .
RUN pip install --no-cache-dir -r requirements-vendor.txt

COPY vendor_server.py .
COPY accounts.py . 
COPY usage_logger.py .   
COPY webapp/ ./webapp/

# PaaS dış 443'ü (https/wss) TLS sonlandırıp buraya düz iletir; vendor_server $PORT'u okur.
EXPOSE 8080

CMD ["python", "usage_logger.py"]
#CMD ["python", "vendor_server.py"]
