#!/usr/bin/env bash
# Instala el servidor de SecureChat en una máquina Linux (Ubuntu 22.04/24.04, x86 o ARM),
# por ejemplo la gratuita de Oracle Cloud. Uso, en la máquina:
#   curl -fsSL https://raw.githubusercontent.com/ZaperMaster/securechat/main/nube/instalar.sh | sudo bash
# Después: copia tus datos (nube/LEEME.md, paso 4) y conecta Tailscale (paso 5).
set -euo pipefail

APP=/opt/securechat
DATOS=/var/lib/securechat
REPO=https://github.com/ZaperMaster/securechat.git

echo "== Paquetes"
apt-get update -qq
apt-get install -y -qq python3 python3-venv git curl sqlite3 >/dev/null

echo "== Usuario y código"
id securechat >/dev/null 2>&1 || useradd --system --home-dir "$APP" --shell /usr/sbin/nologin securechat
mkdir -p "$APP" "$DATOS"
if [ -n "${SECURECHAT_CODIGO:-}" ]; then   # (para las pruebas: el código de esta carpeta)
  mkdir -p "$APP/app" && cp -rT "$SECURECHAT_CODIGO" "$APP/app"
elif [ -d "$APP/app/.git" ]; then
  git -C "$APP/app" pull -q
else
  git clone -q "$REPO" "$APP/app"
fi
python3 -m venv "$APP/venv"
"$APP/venv/bin/pip" install -q --upgrade pip
"$APP/venv/bin/pip" install -q -r "$APP/app/requirements.txt"
chown -R securechat:securechat "$APP" "$DATOS"
chmod 700 "$DATOS"

echo "== Servicio"
cp "$APP/app/nube/securechat.service" /etc/systemd/system/securechat.service
systemctl daemon-reload
systemctl enable securechat >/dev/null

echo "== Copia diaria de la base de datos (se guardan 14 días)"
cat > /etc/cron.daily/securechat-copia <<'EOF'
#!/bin/sh
mkdir -p /var/lib/securechat/copias
sqlite3 /var/lib/securechat/usuarios.db ".backup '/var/lib/securechat/copias/usuarios-$(date +%F).db'"
find /var/lib/securechat/copias -name 'usuarios-*.db' -mtime +14 -delete
chown -R securechat:securechat /var/lib/securechat/copias
EOF
chmod 755 /etc/cron.daily/securechat-copia

echo "== Tailscale"
command -v tailscale >/dev/null || curl -fsSL https://tailscale.com/install.sh | sh

cat <<'FIN'

Listo. Faltan dos pasos (los explica nube/LEEME.md):
  4) Copiar tus datos a /var/lib/securechat y arrancar:   sudo systemctl start securechat
  5) Conectar Tailscale con el nombre del servidor y publicarlo:
       sudo tailscale up --hostname=securechat
       sudo tailscale funnel --bg 8765
       sudo tailscale funnel --bg --tls-terminated-tcp=10000 tcp://localhost:3478
FIN
