#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# SENTINEL WAF - Auto Installer for Ubuntu/Debian
# Usage: sudo bash install.sh
# ─────────────────────────────────────────────────────────────────────────────

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

log()   { echo -e "${CYAN}[Sentinel]${NC} $1"; }
ok()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()  { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; exit 1; }

# ── Check root ────────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && error "Run as root: sudo bash install.sh"

INSTALL_DIR="/opt/sentinel-waf"
SERVICE_USER="sentinel"

log "Starting Sentinel WAF installation..."

# ── System dependencies ───────────────────────────────────────────────────────
log "Installing system dependencies..."
apt-get update -qq
apt-get install -y -qq curl git iptables-persistent nftables || warn "Some packages may have failed"

# ── Node.js 20 ───────────────────────────────────────────────────────────────
if ! command -v node &>/dev/null || [[ $(node -v | cut -d. -f1 | tr -d 'v') -lt 18 ]]; then
  log "Installing Node.js 20..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash - >/dev/null
  apt-get install -y -qq nodejs
fi
ok "Node.js $(node -v)"

# ── Create service user ───────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
  useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
  ok "Created user: $SERVICE_USER"
fi

# ── Copy project files ────────────────────────────────────────────────────────
log "Installing Sentinel WAF to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR/"
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# ── Install backend deps ──────────────────────────────────────────────────────
log "Installing backend dependencies..."
cd "$INSTALL_DIR/backend"
sudo -u "$SERVICE_USER" npm install --production --quiet
ok "Backend dependencies installed"

# ── Build dashboard ───────────────────────────────────────────────────────────
log "Building dashboard..."
cd "$INSTALL_DIR/dashboard"
sudo -u "$SERVICE_USER" npm install --quiet
sudo -u "$SERVICE_USER" npm run build
ok "Dashboard built"

# ── Configure .env ────────────────────────────────────────────────────────────
if [[ ! -f "$INSTALL_DIR/.env" ]]; then
  cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  warn "Created .env from template. EDIT IT: nano $INSTALL_DIR/.env"
fi

# ── Give backend permission to read nginx logs ────────────────────────────────
log "Configuring log permissions..."
if id "www-data" &>/dev/null; then
  usermod -aG adm "$SERVICE_USER" 2>/dev/null || true
fi
# Ensure nginx logs are readable
chmod 644 /var/log/nginx/access.log 2>/dev/null || warn "Could not chmod nginx access.log"
chmod 644 /var/log/nginx/error.log 2>/dev/null || warn "Could not chmod nginx error.log"

# ── iptables setup ────────────────────────────────────────────────────────────
log "Setting up iptables persistent..."
mkdir -p /etc/iptables
iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true

# Give sentinel user sudo for iptables/nft only
cat > /etc/sudoers.d/sentinel-waf << 'EOF'
sentinel ALL=(ALL) NOPASSWD: /sbin/iptables, /sbin/ip6tables, /usr/sbin/nft, /sbin/iptables-save, /sbin/ip6tables-save
EOF
chmod 0440 /etc/sudoers.d/sentinel-waf
ok "iptables sudoers configured"

# ── systemd service ───────────────────────────────────────────────────────────
log "Creating systemd service..."
cat > /etc/systemd/system/sentinel-waf.service << EOF
[Unit]
Description=Sentinel WAF - AI-Powered Security
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR/backend
EnvironmentFile=$INSTALL_DIR/.env
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sentinel-waf

# Security hardening
NoNewPrivileges=false
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable sentinel-waf
ok "systemd service created"

# ── nginx reverse proxy config ────────────────────────────────────────────────
log "Creating nginx config for dashboard..."
cat > /etc/nginx/sites-available/sentinel-waf << 'EOF'
# Sentinel WAF Dashboard
# Place this in your nginx sites-available and link it

server {
    listen 8080;
    # Change to your actual domain:
    server_name sentinel.yourdomain.com;

    # Basic auth (optional but recommended)
    # auth_basic "Sentinel WAF";
    # auth_basic_user_file /etc/nginx/.htpasswd;

    # Proxy to backend
    location / {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_cache_bypass $http_upgrade;
    }

    # Block access from outside (optional - only allow your IP)
    # allow YOUR_IP;
    # deny all;
}
EOF

ln -sf /etc/nginx/sites-available/sentinel-waf /etc/nginx/sites-enabled/ 2>/dev/null || true
nginx -t && systemctl reload nginx 2>/dev/null || warn "Nginx reload failed, check config"
ok "Nginx config installed (port 8080)"

# ── Firewall: protect dashboard ───────────────────────────────────────────────
log "Firewall: restricting dashboard access..."
iptables -I INPUT -p tcp --dport 3001 -j DROP 2>/dev/null || true
warn "Port 3001 (backend) blocked externally. Access via nginx on port 8080."

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Sentinel WAF installed successfully!${NC}"
echo -e "${GREEN}══════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${CYAN}Next steps:${NC}"
echo -e "  1. Edit config:    ${YELLOW}nano $INSTALL_DIR/.env${NC}"
echo -e "     - Set ANTHROPIC_API_KEY"
echo -e "     - Set CF_API_TOKEN, CF_ZONE_ID"
echo -e "     - Set ALLOWED_IPS (your IP)"
echo ""
echo -e "  2. Start service:  ${YELLOW}systemctl start sentinel-waf${NC}"
echo -e "  3. View logs:      ${YELLOW}journalctl -u sentinel-waf -f${NC}"
echo -e "  4. Dashboard:      ${YELLOW}http://YOUR_VPS_IP:8080${NC}"
echo ""
echo -e "  ${CYAN}Useful commands:${NC}"
echo -e "  ${YELLOW}systemctl status sentinel-waf${NC}  → check status"
echo -e "  ${YELLOW}systemctl restart sentinel-waf${NC} → restart"
echo -e "  ${YELLOW}journalctl -u sentinel-waf -f${NC}  → live logs"
echo ""
