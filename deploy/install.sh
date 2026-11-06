#!/usr/bin/env bash
# Kestrel 2.2 control-plane installer (Ubuntu 24.04 / Debian 12 with Python 3.12).
# Run from the unpacked release:  sudo bash deploy/install.sh
set -euo pipefail
umask 027
if [[ "${EUID}" -ne 0 ]]; then echo "Run as root." >&2; exit 1; fi
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEST=/opt/kestrel

apt-get update
apt-get install -y python3.12 python3.12-venv python3-pip build-essential pkg-config libvirt-dev libvirt-clients qemu-utils caddy rsync

getent group kestrel >/dev/null || groupadd --system kestrel
id -u kestrel >/dev/null 2>&1 || useradd --system --gid kestrel --home-dir /var/lib/kestrel --create-home --shell /usr/sbin/nologin kestrel
install -d -o kestrel -g kestrel -m 0750 /var/lib/kestrel /var/lib/kestrel/media
install -d -o root -g kestrel -m 0750 /etc/kestrel

# Code is owned by root and only readable by the service account, so a compromised
# panel process cannot modify its own code.
install -d -o root -g kestrel -m 0750 "$DEST"
if [[ "$SRC" != "$DEST" ]]; then
  rsync -a --delete --exclude '.env' --exclude '.venv' --exclude '__pycache__' --exclude '.git' "$SRC/" "$DEST/"
fi
python3.12 -m venv "$DEST/.venv"
"$DEST/.venv/bin/pip" install --upgrade pip==26.3
"$DEST/.venv/bin/pip" install "$DEST"
chown -R root:kestrel "$DEST"
chmod -R u=rwX,g=rX,o= "$DEST"

if [[ ! -f /etc/kestrel/kestrel.env ]]; then
  (cd /tmp && "$DEST/.venv/bin/python" - <<'PY'
import os, secrets
from cryptography.fernet import Fernet
path = "/etc/kestrel/kestrel.env"
fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o640)
with os.fdopen(fd, "w") as f:
    f.write("KESTREL_ENVIRONMENT=production\n"
            "KESTREL_TRUSTED_HOST=vps.mydomain.xyz\n"
            "KESTREL_DATABASE_URL=sqlite:////var/lib/kestrel/kestrel.db\n"
            f"KESTREL_SECRET_KEY={secrets.token_urlsafe(48)}\n"
            f"KESTREL_ENCRYPTION_KEY={Fernet.generate_key().decode()}\n"
            "KESTREL_SECURE_COOKIES=true\n")
PY
  )
  chown root:kestrel /etc/kestrel/kestrel.env
  chmod 0640 /etc/kestrel/kestrel.env
  echo "Created /etc/kestrel/kestrel.env with unique secrets. Back it up: the encryption key protects node SSH keys."
fi

# Database schema (also used for upgrades from 2.x).
# Secrets are sourced inside the child shell, never passed on a command line.
runuser -u kestrel -- sh -c "set -a; . /etc/kestrel/kestrel.env; set +a; cd $DEST && .venv/bin/alembic -c alembic.ini upgrade head"

install -m 0644 "$DEST/deploy/kestrel.service" /etc/systemd/system/
install -m 0644 "$DEST/deploy/kestrel-worker.service" /etc/systemd/system/
systemctl daemon-reload

cat <<MSG
Kestrel is installed in $DEST.
Next steps:
  1. Set KESTREL_TRUSTED_HOST in /etc/kestrel/kestrel.env to the panel hostname
     (the services refuse to start with the placeholder value).
  2. Put the hostname into $DEST/deploy/Caddyfile and install it as /etc/caddy/Caddyfile,
     then: systemctl reload caddy
  3. Create the first administrator:
       sudo -u kestrel sh -c 'set -a; . /etc/kestrel/kestrel.env; set +a; cd $DEST && .venv/bin/python -m app.setup create-admin you@example.com --username admin'
  4. systemctl enable --now kestrel kestrel-worker
MSG
