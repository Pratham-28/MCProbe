#!/usr/bin/env bash
# Put Caddy in front of MCProbe for HTTPS. Run on the instance after setup_ec2.sh.
# Usage: HOSTNAME=mcprobe.duckdns.org bash deploy/enable_https.sh
# Prerequisites: the hostname resolves to this machine; security group allows TCP 80 and 443.
set -euo pipefail
HOSTNAME="${HOSTNAME:?set HOSTNAME to the DNS name that points at this server}"
APP_DIR="${APP_DIR:-/opt/mcprobe}"

# MCProbe moves to an internal port; Caddy takes 80 and 443.
sudo sed -i 's/--port 80\b/--port 8000/' /etc/systemd/system/mcprobe.service
sudo systemctl daemon-reload && sudo systemctl restart mcprobe

sudo apt-get install -y debian-keyring debian-archive-keyring apt-transport-https curl
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor --yes -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list >/dev/null
sudo apt-get update && sudo apt-get install -y caddy

sed "s/mcprobe.duckdns.org/$HOSTNAME/" "$APP_DIR/deploy/Caddyfile" | sudo tee /etc/caddy/Caddyfile >/dev/null
sudo systemctl restart caddy
sleep 5
sudo journalctl -u caddy -n 10 --no-pager | grep -i "certificate obtained" && echo "HTTPS ready: https://$HOSTNAME/" || \
  echo "Caddy is running; if no certificate line appeared yet, check: sudo journalctl -u caddy -n 30"
