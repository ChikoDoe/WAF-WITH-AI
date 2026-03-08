/**
 * SENTINEL WAF - Firewall Manager
 * Manages iptables/nftables rules at L3/L4 level
 * Requires root/sudo privileges
 */

const { exec, execSync } = require('child_process');
const { promisify } = require('util');
const fs = require('fs');

const execAsync = promisify(exec);

// Detect available firewall backend
function detectBackend() {
  try { execSync('which nft', { stdio: 'ignore' }); return 'nftables'; } catch {}
  try { execSync('which iptables', { stdio: 'ignore' }); return 'iptables'; } catch {}
  return null;
}

const BACKEND = detectBackend();
const SENTINEL_CHAIN = 'SENTINEL_WAF';
const SENTINEL_TABLE = 'sentinel';

// Allowlist - never block these
const ALLOWLIST = new Set([
  '127.0.0.1', '::1', '10.0.0.0/8',
  ...(process.env.ALLOWED_IPS || '').split(',').filter(Boolean),
]);

class FirewallManager {
  constructor() {
    this.backend = BACKEND;
    this.rules = new Map(); // id -> rule info
    this.initialized = false;
    console.log(`[Firewall] Backend: ${this.backend || 'NONE (rules will be logged only)'}`);
  }

  async init() {
    if (this.initialized || !this.backend) return;

    try {
      if (this.backend === 'nftables') {
        await this._initNftables();
      } else {
        await this._initIptables();
      }
      this.initialized = true;
      console.log('[Firewall] Initialized successfully');
    } catch (err) {
      console.error('[Firewall] Init failed (running without L3 protection):', err.message);
    }
  }

  async _initIptables() {
    // Create Sentinel chain if not exists
    const cmds = [
      `iptables -N ${SENTINEL_CHAIN} 2>/dev/null || true`,
      `ip6tables -N ${SENTINEL_CHAIN} 2>/dev/null || true`,
      // Jump to chain from INPUT (insert at top)
      `iptables -C INPUT -j ${SENTINEL_CHAIN} 2>/dev/null || iptables -I INPUT 1 -j ${SENTINEL_CHAIN}`,
      `ip6tables -C INPUT -j ${SENTINEL_CHAIN} 2>/dev/null || ip6tables -I INPUT 1 -j ${SENTINEL_CHAIN}`,
      // Also protect HTTP/HTTPS ports
      `iptables -N ${SENTINEL_CHAIN}_HTTP 2>/dev/null || true`,
      `iptables -C INPUT -p tcp --dport 80 -j ${SENTINEL_CHAIN}_HTTP 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 80 -j ${SENTINEL_CHAIN}_HTTP`,
      `iptables -C INPUT -p tcp --dport 443 -j ${SENTINEL_CHAIN}_HTTP 2>/dev/null || iptables -I INPUT 1 -p tcp --dport 443 -j ${SENTINEL_CHAIN}_HTTP`,
    ];

    for (const cmd of cmds) {
      await this._run(cmd, { ignoreError: true });
    }
  }

  async _initNftables() {
    const setup = `
nft add table ip ${SENTINEL_TABLE} 2>/dev/null || true
nft add chain ip ${SENTINEL_TABLE} input { type filter hook input priority -100 \\; policy accept \\; } 2>/dev/null || true
nft add set ip ${SENTINEL_TABLE} blocklist { type ipv4_addr \\; flags interval \\; timeout 3600s \\; } 2>/dev/null || true
nft add rule ip ${SENTINEL_TABLE} input ip saddr @blocklist drop 2>/dev/null || true
`;
    for (const line of setup.trim().split('\n')) {
      await this._run(line, { ignoreError: true });
    }
  }

  // ── Add Rule ──────────────────────────────────────────────────────────────

  async addRule(rule, ip) {
    if (!ip || this._isAllowlisted(ip)) {
      console.log(`[Firewall] Skipping ${ip} (allowlisted)`);
      return null;
    }

    await this.init();

    const ruleId = rule.id || `fw_${Date.now()}`;
    const expiresAt = rule.expiresIn ? Date.now() + rule.expiresIn * 1000 : null;

    const commands = [];

    if (this.backend === 'nftables') {
      commands.push(...this._buildNftRules(rule, ip));
    } else if (this.backend === 'iptables') {
      commands.push(...this._buildIptablesRules(rule, ip));
    }

    const applied = [];
    for (const cmd of commands) {
      try {
        await this._run(cmd);
        applied.push(cmd);
        console.log(`[Firewall] Applied: ${cmd}`);
      } catch (err) {
        console.error(`[Firewall] Failed: ${cmd} — ${err.message}`);
      }
    }

    const ruleInfo = {
      id: ruleId, ip, rule,
      commands: applied,
      appliedAt: Date.now(), expiresAt,
      backend: this.backend,
    };

    this.rules.set(ruleId, ruleInfo);

    // Schedule removal if expiry set
    if (expiresAt) {
      const delay = expiresAt - Date.now();
      setTimeout(() => this.removeRule(ruleId), delay);
    }

    return ruleInfo;
  }

  _buildIptablesRules(rule, ip) {
    const cmds = [];
    const isSubnet = ip.includes('/');
    const src = ip;

    // If AI provided specific iptables rules, sanitize and use them
    if (rule.iptablesRules?.length) {
      for (const cmd of rule.iptablesRules) {
        // Replace placeholder IPs with actual IP
        const sanitized = cmd
          .replace(/iptables\s+/g, 'iptables ')
          .replace(/<ip>/gi, src)
          .replace(/PLACEHOLDER_IP/gi, src);

        // Safety: only allow expected iptables patterns
        if (/^ip6?tables\s+-[AID]\s+\w/.test(sanitized)) {
          cmds.push(sanitized);
        }
      }
      if (cmds.length) return cmds;
    }

    // Default rules based on threat type
    const type = rule.type || rule.ruleName || '';
    const chain = SENTINEL_CHAIN;

    if (/ddos|flood|rate/i.test(type)) {
      // Rate limiting with hashlimit
      cmds.push(
        `iptables -I ${chain} -s ${src} -p tcp -m hashlimit --hashlimit-above 60/minute --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name waf_rate_${ip.replace(/[./]/g, '_')} -j DROP`
      );
    } else if (/rce|command|execution/i.test(type)) {
      // Permanent block for RCE
      cmds.push(
        `iptables -I ${chain} 1 -s ${src} -j DROP`,
        `ip6tables -I ${chain} 1 -s ${src} -j DROP`,
      );
    } else {
      // Default: block IP on HTTP/HTTPS ports
      cmds.push(
        `iptables -I ${chain} -s ${src} -p tcp -m multiport --dports 80,443 -j DROP`,
        `iptables -I ${chain} -s ${src} -p tcp --dport 8080 -j DROP`,
      );
    }

    // Log before drop
    cmds.unshift(
      `iptables -I ${chain} -s ${src} -j LOG --log-prefix "[SENTINEL DROP] " --log-level 4`
    );

    return cmds;
  }

  _buildNftRules(rule, ip) {
    const cmds = [];

    // Use AI-provided nftables rules if available
    if (rule.nftablesRules?.length) {
      for (const cmd of rule.nftablesRules) {
        const sanitized = cmd.replace(/<ip>/gi, ip).replace(/PLACEHOLDER_IP/gi, ip);
        if (/^nft\s+/.test(sanitized)) cmds.push(sanitized);
      }
      if (cmds.length) return cmds;
    }

    const type = rule.type || rule.ruleName || '';

    if (/ddos|flood|rate/i.test(type)) {
      cmds.push(
        `nft add rule ip ${SENTINEL_TABLE} input ip saddr ${ip} meter rate_limit_${Date.now()} { ip saddr limit rate over 60/minute burst 10 packets } drop`
      );
    } else {
      // Add to blocklist set (supports auto-timeout)
      const timeout = rule.expiresIn ? `${rule.expiresIn}s` : '86400s';
      cmds.push(
        `nft add element ip ${SENTINEL_TABLE} blocklist { ${ip} timeout ${timeout} }`
      );
    }

    return cmds;
  }

  // ── Remove Rule ───────────────────────────────────────────────────────────

  async removeRule(ruleId) {
    const info = this.rules.get(ruleId);
    if (!info) return false;

    for (const cmd of info.commands) {
      // Convert -I/-A to -D for deletion
      const del = cmd.replace(/\s+-I\s+/, ' -D ').replace(/\s+-A\s+/, ' -D ');
      try {
        await this._run(del, { ignoreError: true });
      } catch {}
    }

    // Remove from nftables blocklist
    if (this.backend === 'nftables' && info.ip) {
      await this._run(
        `nft delete element ip ${SENTINEL_TABLE} blocklist { ${info.ip} }`,
        { ignoreError: true }
      );
    }

    this.rules.delete(ruleId);
    console.log(`[Firewall] Removed rule ${ruleId}`);
    return true;
  }

  // ── List Rules ────────────────────────────────────────────────────────────

  async listRules() {
    const managed = Array.from(this.rules.values());

    let systemRules = [];
    try {
      if (this.backend === 'nftables') {
        const { stdout } = await this._run(`nft list ruleset`);
        systemRules = [{ raw: stdout }];
      } else if (this.backend === 'iptables') {
        const { stdout } = await this._run(`iptables -L ${SENTINEL_CHAIN} -n -v 2>/dev/null || echo "chain not found"`);
        systemRules = stdout.split('\n').filter(Boolean).map(l => ({ raw: l }));
      }
    } catch {}

    return { managed, systemRules };
  }

  // ── Flush All Sentinel Rules ──────────────────────────────────────────────

  async flushAll() {
    try {
      if (this.backend === 'nftables') {
        await this._run(`nft flush set ip ${SENTINEL_TABLE} blocklist 2>/dev/null || true`);
      } else {
        await this._run(`iptables -F ${SENTINEL_CHAIN} 2>/dev/null || true`);
        await this._run(`ip6tables -F ${SENTINEL_CHAIN} 2>/dev/null || true`);
      }
    } catch (err) {
      console.error('[Firewall] Flush error:', err.message);
    }
    this.rules.clear();
  }

  // ── Save Rules (persist across reboot) ───────────────────────────────────

  async saveRules() {
    try {
      if (this.backend === 'iptables') {
        await this._run('iptables-save > /etc/iptables/rules.v4');
        await this._run('ip6tables-save > /etc/iptables/rules.v6');
      } else if (this.backend === 'nftables') {
        await this._run(`nft list ruleset > /etc/nftables.conf`);
      }
      console.log('[Firewall] Rules saved');
    } catch (err) {
      console.error('[Firewall] Save error:', err.message);
    }
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  _isAllowlisted(ip) {
    if (ALLOWLIST.has(ip)) return true;
    // Simple CIDR check for private ranges
    if (/^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)/.test(ip)) return true;
    return false;
  }

  async _run(cmd, opts = {}) {
    try {
      return await execAsync(cmd);
    } catch (err) {
      if (!opts.ignoreError) throw err;
      return { stdout: '', stderr: err.message };
    }
  }
}

module.exports = new FirewallManager();
