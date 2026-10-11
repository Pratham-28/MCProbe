#!/usr/bin/env bash
# One-shot setup for a fresh Ubuntu EC2 instance (t3.small is plenty).
# Usage on the instance:  curl -fsSL <raw url of this file> | REPO_URL=https://github.com/<owner>/<repo>.git bash
# Afterwards: edit /opt/airlock/.env (keys), then: sudo systemctl restart airlock
set -euo pipefail
REPO_URL="${REPO_URL:?set REPO_URL to the public git repo}"
APP_DIR=/opt/airlock
PORT="${PORT:-80}"

sudo apt-get update -y && sudo apt-get install -y git curl
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

sudo mkdir -p "$APP_DIR" && sudo chown "$USER" "$APP_DIR"
if [ ! -d "$APP_DIR/.git" ]; then git clone "$REPO_URL" "$APP_DIR"; else git -C "$APP_DIR" pull; fi
cd "$APP_DIR"
uv python install 3.13
uv sync --no-dev
[ -f .env ] || cp .env.example .env

UV="$(command -v uv)"
sudo tee /etc/systemd/system/airlock-fixtures.service >/dev/null <<UNIT
[Unit]
Description=Airlock demo MCP servers (clean 8101, evil 8102)
After=network.target
[Service]
WorkingDirectory=$APP_DIR
ExecStart=/bin/bash $APP_DIR/scripts/run_fixtures.sh
Environment=PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
Restart=always
User=$USER
[Install]
WantedBy=multi-user.target
UNIT

sudo tee /etc/systemd/system/airlock.service >/dev/null <<UNIT
[Unit]
Description=Airlock MCP security assessment
After=network.target airlock-fixtures.service
[Service]
WorkingDirectory=$APP_DIR
EnvironmentFile=$APP_DIR/.env
ExecStart=$UV run uvicorn app.main:app --host 0.0.0.0 --port $PORT
Environment=PATH=$HOME/.local/bin:/usr/local/bin:/usr/bin:/bin
AmbientCapabilities=CAP_NET_BIND_SERVICE
Restart=always
User=$USER
[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now airlock-fixtures airlock
echo "Airlock is starting on port $PORT. Put your keys in $APP_DIR/.env then: sudo systemctl restart airlock"
