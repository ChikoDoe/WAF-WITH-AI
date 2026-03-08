/**
 * SENTINEL WAF - Nginx Log Reader
 * Real-time tail + parse nginx access/error logs, detect threats
 */

const { EventEmitter } = require('events');
const { spawn } = require('child_process');
const { createReadStream } = require('fs');
const { createInterface } = require('readline');
const path = require('path');

// ─── Threat Patterns ──────────────────────────────────────────────────────────
const THREAT_SIGNATURES = [
  { pattern: /(\bunion\b.*\bselect\b|\bselect\b.*\bfrom\b|\bdrop\b.*\btable\b|'.*or.*'.*=.*'|1=1|sleep\(|benchmark\()/i, type: 'SQL Injection', severity: 'CRITICAL', score: 95 },
  { pattern: /<script[\s>]|javascript:|onerror\s*=|onload\s*=|alert\s*\(|document\.cookie|\.innerHTML|eval\s*\(/i, type: 'XSS Attack', severity: 'HIGH', score: 85 },
  { pattern: /\.\.\/|\.\.\\|\/etc\/passwd|\/etc\/shadow|\/proc\/|\/var\/www|\/home\/|\/root\//i, type: 'Path Traversal', severity: 'CRITICAL', score: 90 },
  { pattern: /;.*(\bls\b|\bcat\b|\bwhoami\b|\buname\b|\bpwd\b|\bwget\b|\bcurl\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b)|`[^`]+`|\$\([^)]+\)/i, type: 'RCE Attempt', severity: 'CRITICAL', score: 98 },
  { pattern: /wp-login\.php|wp-admin|xmlrpc\.php|phpmyadmin|\.env|config\.php|\.git\/|\.svn\//i, type: 'Scanner Probe', severity: 'MEDIUM', score: 60 },
  { pattern: /nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|wfuzz|hydra|metasploit/i, type: 'Attack Tool', severity: 'HIGH', score: 88 },
  { pattern: /\bLFI\b|file=\/|include=\/|require=|load_file\(|into\s+outfile/i, type: 'LFI/RFI', severity: 'CRITICAL', score: 92 },
  { pattern: /base64_decode|base64,|eval\(base64|gzinflate|gzuncompress|str_rot13/i, type: 'Encoded Payload', severity: 'HIGH', score: 82 },
  { pattern: /(\bpasswd\b|\bshadow\b|\bhtpasswd\b|\.htaccess|web\.config|app\.config)/i, type: 'Sensitive File Access', severity: 'HIGH', score: 80 },
  { pattern: /bot|crawler|spider|scraper|curl\/|python-requests|go-http|libwww-perl|wget\//i, type: 'Bot/Scraper', severity: 'LOW', score: 35 },
];

const HIGH_RATE_THRESHOLD = 100; // requests per minute from same IP = potential DDoS

// ─── Nginx Log Format Parser ──────────────────────────────────────────────────
// Supports: combined, main, custom with $time_local $remote_addr etc.
const NGINX_COMBINED_RE = /^(\S+)\s+-\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*?)"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;

function parseNginxLine(line) {
  const m = line.match(NGINX_COMBINED_RE);
  if (!m) return null;

  const [, ip, user, timeStr, request, status, bytes, referer, ua] = m;
  const [method, path, proto] = (request || '').split(' ');

  return {
    ip,
    user: user === '-' ? null : user,
    time: timeStr,
    method: method || 'GET',
    path: path || '/',
    protocol: proto || 'HTTP/1.1',
    status: parseInt(status),
    bytes: parseInt(bytes),
    referer: referer === '-' ? null : referer,
    userAgent: ua,
    raw: line,
  };
};

// ─── Log Reader Class ─────────────────────────────────────────────────────────
class LogReader extends EventEmitter {
  constructor(options = {}) {
    super();
    this.logPaths = options.logPaths || [
      '/var/log/nginx/access.log',
      '/var/log/nginx/error.log',
    ];
    this.tailProcs = [];
    this.ipRateMap = new Map();   // ip -> [timestamps]
    this.monitoredHosts = new Set();
    this.running = false;
  }

  addMonitoredHost(hostname) {
    this.monitoredHosts.add(hostname);
    console.log(`[LogReader] Now monitoring host: ${hostname}`);
  }

  start() {
    if (this.running) return;
    this.running = true;

    for (const logPath of this.logPaths) {
      this._tailFile(logPath);
    }

    // Clean rate map every minute
    setInterval(() => this._cleanRateMap(), 60_000);
    console.log(`[LogReader] Watching: ${this.logPaths.join(', ')}`);
  }

  stop() {
    this.running = false;
    for (const proc of this.tailProcs) proc.kill();
    this.tailProcs = [];
  }

  _tailFile(filePath) {
    const tail = spawn('tail', ['-F', '-n', '0', filePath], { stdio: ['ignore', 'pipe', 'pipe'] });
    this.tailProcs.push(tail);

    const rl = createInterface({ input: tail.stdout });
    rl.on('line', (line) => this._processLine(line, filePath));

    tail.stderr.on('data', (d) => {
      const msg = d.toString().trim();
      if (!msg.includes('file truncated')) {
        this.emit('error', new Error(`tail ${filePath}: ${msg}`));
      }
    });

    tail.on('exit', (code) => {
      if (this.running) {
        console.warn(`[LogReader] tail exited ${code}, restarting in 3s...`);
        setTimeout(() => this._tailFile(filePath), 3000);
      }
    });
  }

  _processLine(line, filePath) {
    const parsed = parseNginxLine(line);
    if (!parsed) return;

    // If we have monitored URLs, filter to only those hosts
    // (reads host from referer or nginx $host - adjust if using $host in log format)
    const threat = this._detectThreat(parsed);
    if (threat) this.emit('threat', threat);
  }

  _detectThreat(req) {
    const fullReq = `${req.path} ${req.userAgent || ''} ${req.referer || ''}`;
    let topMatch = null;
    let totalScore = 0;

    for (const sig of THREAT_SIGNATURES) {
      if (sig.pattern.test(fullReq)) {
        totalScore += sig.score;
        if (!topMatch || sig.score > topMatch.score) topMatch = sig;
      }
    }

    // Check rate (DDoS detection)
    const rateInfo = this._trackRate(req.ip);
    const isDDoS = rateInfo.rpm > HIGH_RATE_THRESHOLD;

    if (isDDoS && !topMatch) {
      topMatch = { type: 'DDoS / Rate Flood', severity: 'CRITICAL', score: 90 };
      totalScore = 90;
    }

    // 4xx/5xx errors can also indicate scanning
    const is4xx = req.status >= 400 && req.status < 500;

    if (!topMatch && !is4xx) return null;

    if (!topMatch) {
      topMatch = { type: 'Suspicious Request', severity: 'LOW', score: 25 };
      totalScore = 25;
    }

    const blocked = req.status === 403 || req.status === 444 || req.status === 429;

    return {
      id: `${Date.now()}-${Math.random().toString(36).substr(2, 6)}`,
      timestamp: new Date().toISOString(),
      ip: req.ip,
      method: req.method,
      path: req.path,
      status: req.status,
      bytes: req.bytes,
      userAgent: req.userAgent,
      referer: req.referer,
      type: topMatch.type,
      severity: isDDoS ? 'CRITICAL' : topMatch.severity,
      score: Math.min(totalScore, 100),
      blocked,
      requestsPerMin: rateInfo.rpm,
      raw: req.raw,
    };
  }

  _trackRate(ip) {
    const now = Date.now();
    const window = 60_000; // 1 minute

    if (!this.ipRateMap.has(ip)) this.ipRateMap.set(ip, []);
    const times = this.ipRateMap.get(ip);
    times.push(now);

    // Keep only last minute
    const recent = times.filter(t => now - t < window);
    this.ipRateMap.set(ip, recent);

    return { rpm: recent.length };
  }

  _cleanRateMap() {
    const now = Date.now();
    for (const [ip, times] of this.ipRateMap.entries()) {
      const recent = times.filter(t => now - t < 60_000);
      if (recent.length === 0) this.ipRateMap.delete(ip);
      else this.ipRateMap.set(ip, recent);
    }
  }

  // Parse historical log (for initial load / re-analysis)
  async parseHistorical(filePath, lines = 1000) {
    return new Promise((resolve, reject) => {
      const results = [];
      const rl = createInterface({ input: createReadStream(filePath) });
      let count = 0;

      rl.on('line', (line) => {
        if (count++ > lines) return rl.close();
        const parsed = parseNginxLine(line);
        if (parsed) {
          const threat = this._detectThreat(parsed);
          if (threat) results.push(threat);
        }
      });

      rl.on('close', () => resolve(results));
      rl.on('error', reject);
    });
  }
}

module.exports = LogReader;
