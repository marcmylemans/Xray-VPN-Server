# Using the cloudinit script

## 0) Prerequisites

- A VPS with ports **22**, **80**, **443** reachable (check provider firewall/security groups).  
- A **DuckDNS** subdomain + **token**: <https://www.duckdns.org/>  
- An email address for Let’s Encrypt notifications.  
- A domain you’ll use: `your-subdomain.duckdns.org`.


      # ==== EDIT THESE BEFORE DEPLOY ====
      DUCKDNS_SUBDOMAIN="your-subdomain" 
      DUCKDNS_TOKEN="your-duckdns-token"   # from https://www.duckdns.org/
      EMAIL="admin@example.com"
      TROJAN_PASSWORD="$(openssl rand -base64 24)"
      # ==================================
      
Copy and past the contents from "cloudinit-duckdns-dualstack-qr.yaml.example"

---

# Manual Setup Guide — Trojan (Xray) + TLS + Nginx + DuckDNS + QR page

This README explains **every step** of the cloud-init you shared so that anyone can **manually copy/paste commands** on a fresh Ubuntu VPS and end up with the same result:

- Dual-stack DuckDNS dynamic DNS (IPv4 + IPv6)
- Let’s Encrypt (acme.sh) **ECDSA** cert via **DNS-01** (DuckDNS)
- **Xray (Trojan over TLS)** on port **443** with **HTTPS fallback** to Nginx on **:8080**
- Minimal **/qr** page protected with **Basic Auth** + local QR/URL (no external CDN)
- **UFW** firewall + **BBR** TCP congestion control

> Tested on Ubuntu 22.04/24.04 (root). Adapt paths for other distros if needed.

---

## 0) Prerequisites

- A VPS with ports **22**, **80**, **443** reachable (check provider firewall/security groups).  
- A **DuckDNS** subdomain + **token**: <https://www.duckdns.org/>  
- An email address for Let’s Encrypt notifications.  
- A domain you’ll use: `your-subdomain.duckdns.org`.

---

## 1) Set variables (edit these first)

Replace values and paste:

```bash
cat >/etc/vpn.env <<'EOF'
# ==== EDIT THESE BEFORE DEPLOY ====
DUCKDNS_SUBDOMAIN="your-subdomain" 
DUCKDNS_TOKEN="your-duckdns-token"   # from https://www.duckdns.org/
EMAIL="admin@example.com"
TROJAN_PASSWORD="$(openssl rand -base64 24)"
# ==================================
DOMAIN="${DUCKDNS_SUBDOMAIN}.duckdns.org"
EOF

chmod 0640 /etc/vpn.env
```

Export them into your shell for convenience:

```bash
set -a
source /etc/vpn.env
set +a
```

---

## 2) Update system & install packages

```bash
apt update
apt -y upgrade
apt -y install curl wget git ufw jq socat nginx openssl qrencode
```

---

## 3) Enable **BBR** (better TCP performance)

```bash
if ! sysctl net.ipv4.tcp_congestion_control | grep -qi bbr; then
  sed -i '/^net.core.default_qdisc/d' /etc/sysctl.conf || true
  sed -i '/^net.ipv4.tcp_congestion_control/d' /etc/sysctl.conf || true
  echo "net.core.default_qdisc=fq" >> /etc/sysctl.conf
  echo "net.ipv4.tcp_congestion_control=bbr" >> /etc/sysctl.conf
  sysctl -p
fi
```

---

## 4) Configure firewall (**UFW**)

```bash
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
yes | ufw enable || true
ufw status verbose
```

---

## 5) DuckDNS (dual-stack) updater

Create env and updater script:

```bash
cat >/etc/duckdns.env <<EOF
DUCKDNS_SUBDOMAIN="${DUCKDNS_SUBDOMAIN}"
DUCKDNS_TOKEN="${DUCKDNS_TOKEN}"
EOF
chmod 600 /etc/duckdns.env

cat >/usr/local/bin/duckdns-update.sh <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source /etc/duckdns.env
IPV4="$(curl -4 -fsS https://api.ipify.org || true)"
IPV6="$(curl -6 -fsS https://api64.ipify.org || ip -6 addr show scope global | awk '/inet6/{print $2}' | head -n1 | cut -d/ -f1 || true)"
URL="https://www.duckdns.org/update?domains=${DUCKDNS_SUBDOMAIN}&token=${DUCKDNS_TOKEN}"
[ -n "${IPV4:-}" ] && URL="${URL}&ip=${IPV4}"
[ -n "${IPV6:-}" ] && URL="${URL}&ipv6=${IPV6}"
OUT="$(curl -fsS "${URL}")" || OUT="KO"
echo "$(date -Is) duckdns-update: ${OUT} v4=${IPV4:-NA} v6=${IPV6:-NA}"
EOF
chmod 0755 /usr/local/bin/duckdns-update.sh
```

Create systemd unit + timer (runs every 5 minutes):

```bash
cat >/etc/systemd/system/duckdns-update.service <<'EOF'
[Unit]
Description=DuckDNS updater (IPv4 + IPv6)

[Service]
Type=oneshot
ExecStart=/usr/local/bin/duckdns-update.sh
EOF

cat >/etc/systemd/system/duckdns-update.timer <<'EOF'
[Unit]
Description=Run DuckDNS update every 5 minutes

[Timer]
OnBootSec=30sec
OnUnitActiveSec=5min
Unit=duckdns-update.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now duckdns-update.timer
systemctl start duckdns-update.service || true
journalctl -u duckdns-update.service --no-pager --since "5 min ago" || true
```

## 6) Nginx: HTTP redirect + HTTPS fallback on :8080

Create a tiny placeholder page:

```bash
mkdir -p /var/www/html
cat >/var/www/html/index.html <<EOF
<!doctype html><html><head><meta charset="utf-8"><title>${DOMAIN}</title></head>
<body style="font-family:sans-serif"><h1>${DOMAIN}</h1><p>HTTPS placeholder.</p></body></html>
EOF
```

Remove Ubuntu’s default site to avoid clashes:

```bash
rm -f /etc/nginx/sites-enabled/default
```

Force HTTP→HTTPS redirect on :80:

```bash
cat >/etc/nginx/sites-available/00_http_redirect.conf <<'EOF'
server {
  listen 80 default_server;
  listen [::]:80 default_server;
  server_name _;
  return 301 https://$host$request_uri;
}
EOF
ln -sf /etc/nginx/sites-available/00_http_redirect.conf /etc/nginx/sites-enabled/00_http_redirect.conf
```

Create fallback HTTPS vhost on :8080 (Xray will ALPN-fallback to this):

```bash
cat >/etc/nginx/sites-available/fallback.conf <<'EOF'
server {
  listen 8080 default_server;
  listen [::]:8080 default_server;
  server_name _;
  root /var/www/html;
  index index.html;

  # Add this exact-match first: send /qr -> /qr/
  location = /qr {
    return 302 /qr/;
  }

  # Auth-protected directory match (note the trailing slash)
  location ^~ /qr/ {
    auth_basic "VPN Access";
    auth_basic_user_file /etc/nginx/.htpasswd;
  
    root /var/www/html;
    index index.html;
  }

  access_log off;
  error_log  /var/log/nginx/fallback_error.log;
  location / { try_files $uri $uri/ =404; }
}
EOF
ln -sf /etc/nginx/sites-available/fallback.conf /etc/nginx/sites-enabled/fallback.conf

nginx -t
systemctl enable nginx
systemctl restart nginx
```

## 7) Install acme.sh and issue ECDSA cert via DuckDNS DNS-01

Install acme.sh:

```bash
export HOME=/root
if [ ! -d "/root/.acme.sh" ] && [ ! -d "/.acme.sh" ]; then
  curl -s https://get.acme.sh | sh -s email=${EMAIL}
fi
[ -d "/.acme.sh" ] && [ ! -d "/root/.acme.sh" ] && mv /.acme.sh /root/.acme.sh
export PATH="$PATH:/root/.acme.sh:/.acme.sh"
ACME_BIN="$(command -v acme.sh || true)"
[ -z "$ACME_BIN" ] && [ -x "/root/.acme.sh/acme.sh" ] && ACME_BIN="/root/.acme.sh/acme.sh"
[ -z "$ACME_BIN" ] && { echo "ERROR: acme.sh not found"; exit 1; }
```

Issue cert with DuckDNS plugin (env var name is case-sensitive):

```bash
export DuckDNS_Token="${DUCKDNS_TOKEN}"
"$ACME_BIN" --set-default-ca --server letsencrypt
"$ACME_BIN" --issue -d "${DOMAIN}" --dns dns_duckdns --keylength ec-256 --force
```

Install cert to /etc/xray and set reload hook:

```bash
mkdir -p /etc/xray
"$ACME_BIN" --install-cert -d "${DOMAIN}" --ecc \
  --key-file /etc/xray/tls.key \
  --fullchain-file /etc/xray/tls.crt \
  --reloadcmd "systemctl restart xray || true"
chmod 600 /etc/xray/tls.*
```

## 8) Install Xray

```bash
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
install -d -m 0755 /usr/local/etc/xray
```

## 9) Xray config (Trojan/TLS, ALPN fallback → Nginx:8080)

Create config and inject your Trojan password:

```bash
cat >/usr/local/etc/xray/config.json <<'JSON'
{
  "log": { "loglevel": "warning" },
  "inbounds": [
    {
      "port": 443,
      "listen": "::",
      "protocol": "trojan",
      "settings": {
        "clients": [ { "password": "__TROJAN_PASSWORD__" } ],
        "fallbacks": [
          { "alpn": "http/1.1", "dest": "127.0.0.1:8080" },
          { "alpn": "h2",       "dest": "127.0.0.1:8080" }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "tls",
        "tlsSettings": {
          "alpn": ["http/1.1","h2"],
          "certificates": [
            { "certificateFile": "/etc/xray/tls.crt", "keyFile": "/etc/xray/tls.key" }
          ]
        }
      }
    }
  ],
  "outbounds": [
    { "protocol": "freedom", "settings": {} },
    { "protocol": "blackhole", "settings": {}, "tag": "blocked" }
  ],
  "routing": { "domainStrategy": "AsIs", "rules": [] }
}
JSON

ESCAPED_PASS="$(printf '%s' "${TROJAN_PASSWORD}" | sed -e 's/[\/&]/\\&/g')"
sed -i "s/__TROJAN_PASSWORD__/${ESCAPED_PASS}/" /usr/local/etc/xray/config.json
```

## 10) Secure /qr page + generate local QR/URL

Create the standard Trojan URL, save it, protect the page with Basic Auth (user: vpn, password = your TROJAN_PASSWORD), and render a local QR PNG + text:

```bash
# Trojan URL
TROJAN_URL="trojan://${TROJAN_PASSWORD}@${DOMAIN}:443?security=tls&type=tcp&sni=${DOMAIN}#Trojan-${DOMAIN}"
echo "${TROJAN_URL}" > /root/trojan-url.txt

# Basic Auth for /qr (user=vpn)
printf "vpn:%s\n" "$(openssl passwd -apr1 "$TROJAN_PASSWORD")" > /etc/nginx/.htpasswd
chown root:www-data /etc/nginx/.htpasswd
chmod 640 /etc/nginx/.htpasswd

# Static assets
mkdir -p /var/www/html/qr
echo "${TROJAN_URL}" > /var/www/html/qr/trojan.txt
qrencode -o /var/www/html/qr/trojan.png -s 10 -m 2 "${TROJAN_URL}"
chmod 644 /var/www/html/qr/trojan.txt /var/www/html/qr/trojan.png
```

Create a minimal HTML page (no external JS/CDN):

```bash
cat >/var/www/html/qr/index.html <<'HTML'
<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>VPN QR</title>
  <style>
    body{font-family:sans-serif;max-width:720px;margin:40px auto;text-align:center}
    code{word-break:break-all}
    img{width:260px;height:260px}
    button{padding:8px 12px;margin-top:10px}
  </style>
</head>
<body>
  <h1>Trojan QR</h1>
  <p>Scan this with Hiddify / Shadowrocket / v2rayNG</p>
  <img src="trojan.png" alt="QR">
  <p><code id="link"></code></p>
  <button id="copy">Copy URL</button>
  <script>
    fetch('trojan.txt').then(r=>r.text()).then(t=>{
      const u=t.trim();
      document.getElementById('link').textContent=u;
      document.getElementById('copy').onclick=async()=>{try{await navigator.clipboard.writeText(u);alert('Copied!');}catch(e){alert('Copy failed');}};
    });
  </script>
</body>
</html>
HTML

systemctl reload nginx
```

## 11) File ownership/permissions for xray service

```bash
SRVUSER="$(systemctl show -p User xray --value)"; [ -z "$SRVUSER" ] && SRVUSER=nobody
SRVGROUP="$(systemctl show -p Group xray --value)"
if [ -z "$SRVGROUP" ]; then
  if getent group nogroup >/dev/null 2>&1; then SRVGROUP=nogroup; else SRVGROUP="$SRVUSER"; fi
fi
chown "$SRVUSER:$SRVGROUP" /etc/xray/tls.key /etc/xray/tls.crt
chmod 640 /etc/xray/tls.key /etc/xray/tls.crt
chmod 755 /etc/xray
chown -R "$SRVUSER:$SRVGROUP" /usr/local/etc/xray
chmod 644 /usr/local/etc/xray/config.json
chmod 755 /usr/local/etc/xray

mkdir -p /etc/systemd/system/xray.service.d
cat >/etc/systemd/system/xray.service.d/caps.conf <<'EOF'
[Service]
AmbientCapabilities=CAP_NET_BIND_SERVICE
EOF

systemctl daemon-reload
```

## 12) Enable & start services

```bash
systemctl enable xray
systemctl restart xray

systemctl enable --now duckdns-update.timer
systemctl restart nginx
```

## 13) Verify everything

DNS updates:

```bash
journalctl -u duckdns-update.service --no-pager --since "10 min ago"
```

Cert files exist:

```bash
ls -l /etc/xray/tls.*
```

Nginx config OK:

```bash
nginx -t && systemctl status nginx --no-pager
```

Xray running:

```bash
systemctl status xray --no-pager
journalctl -u xray --no-pager | tail -n 50
ss -tulpen | egrep ':80 |:443 |:8080 '
```

Open a browser:

https://YOUR-SUBDOMAIN.duckdns.org/ → should redirect and fall back correctly if ALPN non-Trojan.

https://YOUR-SUBDOMAIN.duckdns.org/qr → prompts Basic Auth
- User: vpn
- Pass: (your TROJAN_PASSWORD)
- Shows QR + copyable URL.

## 14) Client setup (quick notes)

Hiddify / Shadowrocket / v2rayNG:

Scan the QR from /qr, or paste the trojan://... URL.
Ensure client SNI/Server Name is your ${DOMAIN} and TLS is enabled.

## 15) Routine operations

Rotate Trojan password and regenerate QR:

```bash
NEW_PASS="$(openssl rand -base64 24)"
jq --arg p "$NEW_PASS" '(.inbounds[0].settings.clients[0].password) = $p' \
  /usr/local/etc/xray/config.json > /usr/local/etc/xray/config.json.new && \
mv /usr/local/etc/xray/config.json.new /usr/local/etc/xray/config.json

systemctl restart xray

TROJAN_URL="trojan://${NEW_PASS}@${DOMAIN}:443?security=tls&type=tcp&sni=${DOMAIN}#Trojan-${DOMAIN}"
echo "${TROJAN_URL}" > /var/www/html/qr/trojan.txt
qrencode -o /var/www/html/qr/trojan.png -s 10 -m 2 "${TROJAN_URL}"
printf "vpn:%s\n" "$(openssl passwd -apr1 "$NEW_PASS")" > /etc/nginx/.htpasswd
systemctl reload nginx
```

Renewals: acme.sh installs its own cron; cert reload triggers systemctl restart xray.

## 16) Troubleshooting

DNS-01 fails (acme.sh):

- Confirm DuckDNS_Token is correct and DUCKDNS_SUBDOMAIN/DOMAIN matches.
- Wait a few minutes for DNS propagation and re-run the --issue command.

Port conflicts:

- Make sure nothing else listens on :443 (only Xray should).
- Nginx should not bind :443 in this design.

Firewall:

- Provider-level firewall must allow 80/443 (and 22 for SSH).

IPv6:

- If no global IPv6, DuckDNS update still works with IPv4 only.

## 17) Security tips

- Treat /etc/vpn.env as sensitive (already 0640).
- Consider disabling SSH password logins and use keys.
- Keep system updated (unattended-upgrades or regular patching).
- Restrict /qr page with VPN Basic Auth (already done) and share creds out-of-band.

## 18) Uninstall / rollback (optional)

```bash
systemctl disable --now xray nginx duckdns-update.timer
rm -f /etc/systemd/system/duckdns-update.{service,timer}
systemctl daemon-reload

# Remove Xray & config
rm -rf /usr/local/etc/xray /etc/xray

# Remove Nginx sites (if you only used them for this setup)
rm -f /etc/nginx/sites-enabled/{00_http_redirect.conf,fallback.conf}
rm -f /etc/nginx/sites-available/{00_http_redirect.conf,fallback.conf}
rm -rf /var/www/html/qr /var/www/html/index.html
systemctl restart nginx || true

# acme.sh certs (optional)
rm -rf /root/.acme.sh

# DuckDNS files
rm -f /etc/duckdns.env /usr/local/bin/duckdns-update.sh
```

---

You’re done! You now have a hardened Trojan (Xray) server with valid TLS, automatic DuckDNS updates, and a convenient /qr onboarding page for clients.
