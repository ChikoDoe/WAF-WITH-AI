<div align="center">

<img src="docs/assets/banner.png" alt="Sentinel WAF Banner" width="100%"/>

# 🛡️ Sentinel WAF

**AI-powered Web Application Firewall yang jalan otomatis.**  
Monitor nginx logs, deteksi serangan, dan langsung generate rules untuk Cloudflare + iptables/nftables — semua ditenagai Claude AI.

[![Node.js](https://img.shields.io/badge/Node.js-20+-339933?style=flat-square&logo=node.js&logoColor=white)](https://nodejs.org)
[![Cloudflare](https://img.shields.io/badge/Cloudflare-WAF%20%2B%20Rate%20Limit-F38020?style=flat-square&logo=cloudflare&logoColor=white)](https://cloudflare.com)
[![Claude AI](https://img.shields.io/badge/AI-Claude%20Sonnet-CC785C?style=flat-square&logo=anthropic&logoColor=white)](https://anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)](LICENSE)
[![Ubuntu](https://img.shields.io/badge/Ubuntu-20.04%2B-E95420?style=flat-square&logo=ubuntu&logoColor=white)](https://ubuntu.com)

[Demo](#demo) · [Instalasi Cepat](#-instalasi-cepat) · [Konfigurasi](#-konfigurasi) · [API Docs](#-rest-api) · [Kontribusi](#-kontribusi)

</div>

---

<div align="center">

### Live Threat Feed
<img src="docs/assets/screenshot-threats.png" alt="Live Threats Dashboard" width="90%"/>

### AI Rule Generator
<img src="docs/assets/screenshot-ai-rules.png" alt="AI Rule Generator" width="90%"/>

### Cloudflare & iptables Rules
<img src="docs/assets/screenshot-rules.png" alt="Firewall Rules" width="90%"/>

</div>

---

## ✨ Fitur Utama

| Fitur | Keterangan |
|-------|-----------|
| 🔍 **Real-time Log Monitoring** | Tail nginx `access.log` secara live, parse setiap request masuk |
| 🧠 **AI Rule Generation** | Claude Sonnet analyze breach dan generate rules yang presisi |
| ☁️ **Cloudflare WAF** | Auto-push WAF rules, rate limiting HTTPS, IP block via API |
| 🔥 **iptables / nftables** | Block di level L3/L4, rate limiting, subnet block otomatis |
| 📊 **Dashboard Realtime** | React UI dengan WebSocket, update tanpa perlu refresh |
| 🎯 **URL Targeting** | Tambah URL/domain spesifik yang mau di-monitor |
| ⏰ **Auto-expiry Rules** | Rules bisa di-set expire otomatis (misal: ban 1 jam) |
| 🛡️ **Allowlist** | IP yang tidak akan pernah diblokir (IP kamu, monitoring server, dll) |
| 💾 **Persistent Rules** | Rules disimpan otomatis ke disk, survive reboot |

---

## 🏗️ Arsitektur

```
┌─────────────────────────────────────────────────────────────────┐
│                          VPS / Server                           │
│                                                                 │
│   [Nginx]  ──access.log──►  [Log Reader]                       │
│                                   │                             │
│                            detect threat                        │
│                                   │                             │
│                                   ▼                             │
│                           [Threat Engine]                       │
│                          SQL/XSS/RCE/DDoS                       │
│                                   │                             │
│                          breach detected                        │
│                                   │                             │
│                                   ▼                             │
│                            [Claude AI] 🤖                       │
│                      analyze → generate rules                   │
│                                   │                             │
│              ┌────────────────────┼────────────────────┐        │
│              ▼                    ▼                    ▼        │
│     [Cloudflare API]      [iptables/nft]       [WebSocket]      │
│     - WAF rules (L7)      - L3/L4 block        Dashboard UI    │
│     - Rate limit HTTPS    - Rate limiting       Live updates   │
│     - Geo challenge       - Subnet block                        │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📋 Prasyarat

Sebelum install, pastikan kamu punya:

- **VPS Ubuntu 20.04+** atau Debian 11+ (bare metal)
- **Nginx** sudah berjalan dan melayani traffic
- **Node.js 18+** (installer otomatis install jika belum ada)
- **Cloudflare** sebagai DNS proxy untuk domain kamu
- **Anthropic API Key** — daftar di [console.anthropic.com](https://console.anthropic.com)
- **Cloudflare API Token** — dengan permission `Firewall Services:Edit`
- Akses **root/sudo** ke server

---

## 🚀 Instalasi Cepat

### Opsi A — One-liner (Direkomendasikan)

```bash
git clone https://github.com/ChikoDoe/sentinel-waf.git
cd sentinel-waf
sudo bash install.sh
```

Installer akan otomatis melakukan:
- ✅ Install Node.js 20 jika belum ada
- ✅ Setup `iptables-persistent` dan `nftables`
- ✅ Install semua npm dependencies
- ✅ Build dashboard React
- ✅ Buat systemd service (`sentinel-waf`)
- ✅ Konfigurasi nginx reverse proxy di port 8080
- ✅ Setup sudoers agar bisa eksekusi iptables tanpa password prompt

Setelah installer selesai, lanjut ke [Konfigurasi](#-konfigurasi).

---

### Opsi B — Manual Setup

<details>
<summary>Klik untuk expand langkah manual</summary>

#### 1. Clone repository

```bash
git clone https://github.com/ChikoDoe/sentinel-waf.git
cd sentinel-waf
```

#### 2. Install dependencies backend

```bash
cd backend
npm install
```

#### 3. Build dashboard

```bash
cd ../dashboard
npm install
npm run build
```

#### 4. Konfigurasi

```bash
cd ..
cp .env.example .env
nano .env
```

#### 5. Jalankan backend

```bash
cd backend
node server.js
```

Dashboard tersedia di: `http://localhost:3001`

</details>

---

## ⚙️ Konfigurasi

Edit file `.env` (jika pakai installer, ada di `/opt/sentinel-waf/.env`):

```bash
sudo nano /opt/sentinel-waf/.env
```

### Variabel Wajib

```env
# ── AI Engine ────────────────────────────────
ANTHROPIC_API_KEY=sk-ant-xxxxxxxxxxxxxxxxxxxx

# ── Cloudflare ───────────────────────────────
CF_API_TOKEN=your_cloudflare_api_token
CF_ZONE_ID=your_zone_id
CF_ACCOUNT_ID=your_account_id

# ── Keamanan ─────────────────────────────────
# PENTING: tambahkan IP kamu sendiri supaya tidak terblokir!
ALLOWED_IPS=1.2.3.4,5.6.7.8
```

### Cara Dapat API Keys

#### 🔑 Anthropic API Key
1. Buka [console.anthropic.com](https://console.anthropic.com)
2. Klik **API Keys** → **Create Key**
3. Copy ke `ANTHROPIC_API_KEY`

#### 🔑 Cloudflare API Token
1. Buka [dash.cloudflare.com](https://dash.cloudflare.com) → **Profile** → **API Tokens**
2. Klik **Create Token** → **Custom Token**
3. Set permissions berikut:
   | Permission | Nilai |
   |-----------|-------|
   | Zone → Zone | Read |
   | Zone → Firewall Services | Edit |
   | Zone → Zone WAF | Edit |
4. **Zone Resources** → Include → pilih domain kamu
5. Copy token ke `CF_API_TOKEN`

#### 🔑 Cloudflare Zone ID
1. Buka [dash.cloudflare.com](https://dash.cloudflare.com) → pilih domain
2. Di sidebar kanan, scroll ke bawah → **Zone ID**
3. Copy ke `CF_ZONE_ID`

---

## 🔧 Mengelola Service

```bash
# Start
sudo systemctl start sentinel-waf

# Stop
sudo systemctl stop sentinel-waf

# Restart (setelah ubah .env)
sudo systemctl restart sentinel-waf

# Cek status
sudo systemctl status sentinel-waf

# Lihat log secara live
sudo journalctl -u sentinel-waf -f
```

Akses dashboard di: **`http://YOUR_VPS_IP:8080`**

---

## 📁 Struktur Project

```
sentinel-waf/
├── install.sh              # Auto-installer untuk Ubuntu/Debian
├── .env.example            # Template konfigurasi
├── README.md
├── docs/
│   └── assets/             # ← taruh screenshot dashboard di sini
│
├── backend/
│   ├── server.js           # Express API + WebSocket server
│   ├── log-reader.js       # Nginx log parser + threat detection engine
│   ├── ai-engine.js        # Claude AI rule generator
│   ├── cloudflare.js       # Cloudflare API integration (WAF + rate limit)
│   ├── firewall.js         # iptables/nftables manager
│   └── package.json
│
└── dashboard/
    ├── index.html
    ├── vite.config.js
    ├── package.json
    └── src/
        ├── main.jsx
        └── App.jsx         # React dashboard (realtime via WebSocket)
```

---

## 🔍 Threat Detection Engine

Sentinel WAF mendeteksi 10+ jenis serangan secara otomatis:

| Pattern | Tipe Serangan | Severity |
|---------|--------------|----------|
| `UNION SELECT`, `' OR 1=1`, `sleep()` | SQL Injection | 🔴 CRITICAL |
| `<script>`, `onerror=`, `alert()`, `document.cookie` | XSS Attack | 🟠 HIGH |
| `../`, `/etc/passwd`, `/proc/` | Path Traversal | 🔴 CRITICAL |
| `;ls`, `;cat`, `` `cmd` ``, `$(cmd)` | RCE Attempt | 🔴 CRITICAL |
| `base64_decode`, `eval(base64`, `gzinflate` | Encoded Payload | 🟠 HIGH |
| `wp-login.php`, `.env`, `.git/`, `phpMyAdmin` | Scanner Probe | 🟡 MEDIUM |
| `sqlmap`, `nikto`, `nuclei`, `Metasploit` | Attack Tool | 🟠 HIGH |
| `file=/`, `include=/`, `LFI` | LFI / RFI | 🔴 CRITICAL |
| > 100 req/menit dari 1 IP | DDoS / Rate Flood | 🔴 CRITICAL |
| `.htpasswd`, `web.config` | Sensitive File Access | 🟠 HIGH |

---

## 🤖 Cara Kerja AI Rule Generator

Saat breach terdeteksi (severity HIGH/CRITICAL dan tidak terblokir oleh rules yang ada), Claude AI langsung bekerja:

**1. Menerima konteks lengkap:**
```
Attack Type: RCE Attempt
Source IP: 45.33.32.156
Country: US
Target Path: /api/upload?file=;bash${IFS}-i
Requests/min: 23
Severity: CRITICAL
```

**2. Generate rules yang presisi:**
```json
[
  {
    "ruleName": "Block RCE from 45.33.32.156",
    "targets": ["cloudflare", "iptables"],
    "cfExpression": "(ip.src eq 45.33.32.156) or (http.request.uri.query contains \";bash\")",
    "cfAction": "block",
    "iptablesRules": [
      "iptables -I SENTINEL_WAF 1 -s 45.33.32.156 -j DROP"
    ],
    "nftablesRules": [
      "nft add element ip sentinel blocklist { 45.33.32.156 timeout 86400s }"
    ],
    "confidence": 97,
    "reasoning": "RCE via command injection in URI query. Immediate permanent block at L3 and L7.",
    "expiresIn": 0
  }
]
```

**3. Rules langsung di-push ke Cloudflare API dan dieksekusi di iptables/nftables.**

**4. Dashboard update via WebSocket real-time.**

---

## 🌐 REST API

Base URL: `http://localhost:3001`

| Method | Endpoint | Keterangan |
|--------|----------|------------|
| `GET` | `/api/status` | Status server + statistik |
| `GET` | `/api/events?limit=100` | Threat events terbaru |
| `GET` | `/api/rules` | Semua active rules |
| `POST` | `/api/urls` | Tambah URL yang di-monitor |
| `DELETE` | `/api/urls` | Hapus URL dari monitoring |
| `POST` | `/api/analyze` | Manual trigger AI untuk event tertentu |
| `POST` | `/api/rules/manual` | Tambah rule secara manual |
| `DELETE` | `/api/rules/:id` | Hapus rule (CF + iptables sekaligus) |
| `GET` | `/api/cloudflare/rules` | Lihat rules aktif di Cloudflare |
| `GET` | `/api/firewall` | Lihat rules aktif di iptables/nftables |

### Contoh: Tambah URL Monitor

```bash
curl -X POST http://localhost:3001/api/urls \
  -H "Content-Type: application/json" \
  -d '{"url": "https://yourdomain.com/api"}'
```

### Contoh: Manual AI Analyze

```bash
curl -X POST http://localhost:3001/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"eventId": "abc123xyz"}'
```

---

## 📡 WebSocket Events

Connect ke `ws://localhost:3001` untuk real-time updates:

```javascript
const ws = new WebSocket('ws://localhost:3001');

ws.onmessage = ({ data }) => {
  const { type, data: payload } = JSON.parse(data);
  
  switch (type) {
    case 'init':        // state awal saat connect
    case 'event':       // threat baru terdeteksi
    case 'breach':      // threat lolos → AI otomatis triggered
    case 'stats':       // update statistik
    case 'rule_added':  // rule baru berhasil dibuat dan diapply
    case 'ai_thinking': // AI sedang menganalisis
    case 'ai_done':     // AI selesai, rules sudah diapply
    case 'ai_error':    // AI gagal
    case 'url_added':   // URL baru ditambahkan ke monitoring
    case 'url_removed': // URL dihapus dari monitoring
  }
};
```

---

## 🔒 Nginx Log Format

Sentinel WAF support format `combined` (default nginx):

```nginx
# /etc/nginx/nginx.conf
http {
    log_format combined '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent"';
    
    access_log /var/log/nginx/access.log combined;
}
```

---

## 🛡️ Security Hardening

### Protect Dashboard dengan Basic Auth

```bash
sudo apt install apache2-utils
sudo htpasswd -c /etc/nginx/.htpasswd admin
```

Lalu uncomment di `/etc/nginx/sites-available/sentinel-waf`:
```nginx
auth_basic "Sentinel WAF";
auth_basic_user_file /etc/nginx/.htpasswd;
```

### Batasi Akses ke IP Tertentu

```nginx
allow YOUR_IP_ADDRESS;
deny all;
```

### Setup HTTPS dengan Let's Encrypt

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d sentinel.yourdomain.com
```

---

## ❓ Troubleshooting

<details>
<summary><strong>Service tidak mau start</strong></summary>

```bash
journalctl -u sentinel-waf -n 50 --no-pager
```

Kemungkinan penyebab:
- `.env` belum diisi atau ada typo
- Port 3001 sudah dipakai proses lain: `lsof -i :3001`
- Node.js versi terlalu lama: `node -v` (butuh v18+)

</details>

<details>
<summary><strong>AI tidak generate rules</strong></summary>

1. Cek `ANTHROPIC_API_KEY` sudah benar
2. Pastikan VPS punya koneksi internet: `curl https://api.anthropic.com`
3. Cek log: `journalctl -u sentinel-waf -f | grep -i ai`

</details>

<details>
<summary><strong>Cloudflare rules tidak terpush</strong></summary>

1. Verifikasi token punya permission `Firewall Services:Edit`
2. Test token:
   ```bash
   curl -X GET "https://api.cloudflare.com/client/v4/zones/YOUR_ZONE_ID" \
     -H "Authorization: Bearer YOUR_TOKEN"
   ```
3. Cek `CF_ZONE_ID` sesuai dengan domain yang benar

</details>

<details>
<summary><strong>iptables rules tidak dieksekusi</strong></summary>

1. Cek sudoers: `sudo -l -U sentinel`
2. Pastikan iptables tersedia: `which iptables`
3. Cek log: `journalctl -u sentinel-waf -f | grep -i firewall`

</details>

<details>
<summary><strong>Dashboard tidak update real-time</strong></summary>

1. Buka DevTools → Network → filter **WS**
2. Pastikan koneksi WebSocket terbentuk ke `ws://`
3. Jika pakai reverse proxy, pastikan nginx mengizinkan WebSocket upgrade:
   ```nginx
   proxy_set_header Upgrade $http_upgrade;
   proxy_set_header Connection "upgrade";
   ```

</details>

---

## 🗺️ Roadmap

- [ ] Support Apache log format
- [ ] Notifikasi Telegram / Discord saat breach
- [ ] Dashboard mobile responsive
- [ ] Integrasi AbuseIPDB threat intelligence
- [ ] Grafik historis serangan (chart 24h/7d/30d)
- [ ] Multi-server support
- [ ] Export rules ke format fail2ban / ModSecurity
- [ ] Docker Compose setup

---

## 🤝 Kontribusi

PR welcome! Untuk perubahan besar, buka Issue dulu untuk diskusi.

```bash
# Fork repo, lalu:
git clone https://github.com/ChikoDoe/sentinel-waf.git
cd sentinel-waf
git checkout -b feature/nama-fitur

# Buat perubahan...

git commit -m "feat: tambah fitur X"
git push origin feature/nama-fitur
# Buka Pull Request di GitHub
```

---

## 📄 License

[MIT License](LICENSE) — bebas dipakai, dimodifikasi, dan didistribusikan.

---

<div align="center">

Dibuat dengan ☕ dan terlalu banyak ngintip nginx logs.

**[⭐ Star repo ini kalau berguna!](https://github.com/ChikoDoe/sentinel-waf)**

</div>
