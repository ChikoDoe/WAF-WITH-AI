/**
 * SENTINEL WAF - Cloudflare Manager
 * Satu rule blacklist yang terus di-update dengan IP baru
 * ip.src in {1.2.3.4 5.6.7.8 ...} — bukan bikin rule baru tiap IP
 */

const CF_API = 'https://api.cloudflare.com/client/v4';
const BLACKLIST_RULE_NAME = 'Sentinel WAF - IP Blacklist';

class CloudflareManager {
  constructor() {
    this.apiToken  = process.env.CF_API_TOKEN;
    this.zoneId    = process.env.CF_ZONE_ID;
    this.accountId = process.env.CF_ACCOUNT_ID;

    this._blacklistRuleId = null;
    this._blacklistedIPs  = new Set();
  }

  _headers() {
    return {
      'Authorization': `Bearer ${this.apiToken}`,
      'Content-Type': 'application/json',
    };
  }

  async _request(method, endpoint, body) {
    if (!this.apiToken || !this.zoneId) {
      throw new Error('CF_API_TOKEN and CF_ZONE_ID must be set in .env');
    }

    const res = await fetch(`${CF_API}${endpoint}`, {
      method,
      headers: this._headers(),
      body: body ? JSON.stringify(body) : undefined,
    });

    const data = await res.json();
    if (!data.success) {
      const errors = data.errors?.map(e => `${e.code}: ${e.message}`).join(', ') || 'Unknown CF error';
      throw new Error(`Cloudflare API: ${errors}`);
    }
    return data.result;
  }

  // ── Blacklist: 1 Rule, Banyak IP ──────────────────────────────────────────

  async loadBlacklist() {
    try {
      const ruleset = await this._request('GET',
        `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`
      );

      const existing = ruleset?.rules?.find(r => r.description === BLACKLIST_RULE_NAME);
      if (existing) {
        this._blacklistRuleId = existing.id;
        const match = existing.expression.match(/\{([^}]+)\}/);
        if (match) {
          match[1].trim().split(/\s+/).forEach(ip => this._blacklistedIPs.add(ip));
        }
        console.log(`[CF] Loaded blacklist rule: ${existing.id} — ${this._blacklistedIPs.size} IPs`);
      } else {
        console.log('[CF] No existing blacklist rule found, will create on first block');
      }
    } catch (err) {
      console.error('[CF] loadBlacklist error:', err.message);
    }
  }

  async addToBlacklist(ip) {
    if (!ip) throw new Error('IP required');
    if (this._blacklistedIPs.has(ip)) {
      console.log(`[CF] ${ip} already in blacklist, skipping`);
      return { alreadyBlocked: true, ip, total: this._blacklistedIPs.size };
    }

    this._blacklistedIPs.add(ip);
    const expression = this._buildExpression();

    try {
      if (this._blacklistRuleId) {
        await this._request('PATCH',
          `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/${this._blacklistRuleId}`,
          {
            action: 'block',
            expression,
            description: BLACKLIST_RULE_NAME,
            enabled: true,
          }
        );
        console.log(`[CF] Blacklist updated: +${ip} (total: ${this._blacklistedIPs.size} IPs)`);
      } else {
        const result = await this._request('POST',
          `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules`,
          {
            action: 'block',
            expression,
            description: BLACKLIST_RULE_NAME,
            enabled: true,
          }
        );
        this._blacklistRuleId = result.id;
        console.log(`[CF] Blacklist rule created: ${result.id} — ${ip}`);
      }

      return {
        ruleId: this._blacklistRuleId,
        ip,
        total: this._blacklistedIPs.size,
        expression,
      };
    } catch (err) {
      this._blacklistedIPs.delete(ip);
      throw err;
    }
  }

  async removeFromBlacklist(ip) {
    if (!this._blacklistedIPs.has(ip)) return false;

    this._blacklistedIPs.delete(ip);

    if (this._blacklistedIPs.size === 0) {
      if (this._blacklistRuleId) {
        await this.deleteRule(this._blacklistRuleId);
        this._blacklistRuleId = null;
      }
    } else {
      const expression = this._buildExpression();
      await this._request('PATCH',
        `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/${this._blacklistRuleId}`,
        { action: 'block', expression, description: BLACKLIST_RULE_NAME, enabled: true }
      );
    }

    console.log(`[CF] Removed ${ip} from blacklist (remaining: ${this._blacklistedIPs.size})`);
    return true;
  }

  async createRule(rule) {
    const ipMatch = rule.cfExpression?.match(/ip\.src\s+eq\s+([\d.]+)/);
    if (ipMatch) {
      return this.addToBlacklist(ipMatch[1]);
    }
    return this._createCustomRule(rule);
  }

  _buildExpression() {
    const ips = Array.from(this._blacklistedIPs).join(' ');
    return `(ip.src in {${ips}})`;
  }

  getBlacklist() {
    return {
      ruleId: this._blacklistRuleId,
      ips: Array.from(this._blacklistedIPs),
      total: this._blacklistedIPs.size,
      expression: this._blacklistedIPs.size > 0 ? this._buildExpression() : null,
    };
  }

  // ── Non-IP Custom Rules ───────────────────────────────────────────────────

  async _createCustomRule(rule) {
    if (!rule.cfExpression) throw new Error('cfExpression required');

    const result = await this._request('POST',
      `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules`,
      {
        action: rule.cfAction || 'block',
        expression: rule.cfExpression,
        description: rule.ruleName || 'Sentinel WAF rule',
        enabled: true,
      }
    );

    console.log(`[CF] Custom rule created: ${result.id}`);
    return { ...result, type: 'waf' };
  }

  async createRateLimit(rule) {
    if (!rule.cfRateLimit) throw new Error('cfRateLimit config required');
    const rl = rule.cfRateLimit;

    const result = await this._request('POST',
      `/zones/${this.zoneId}/rulesets/phases/http_ratelimit/entrypoint/rules`,
      {
        action: 'block',
        expression: rule.cfExpression || `(http.request.uri.path contains "/")`,
        description: `${rule.ruleName || 'Rate limit'} - Sentinel WAF`,
        enabled: true,
        ratelimit: {
          characteristics: ['ip.src'],
          period: rl.period || 60,
          requests_per_period: rl.requests || 100,
          mitigation_timeout: rl.banDuration || 600,
        },
      }
    );

    console.log(`[CF] Rate limit created: ${result.id}`);
    return { ...result, type: 'ratelimit' };
  }

  async deleteRule(ruleId) {
    await this._request('DELETE',
      `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules/${ruleId}`
    );
    console.log(`[CF] Rule deleted: ${ruleId}`);
  }

  async listRules() {
    try {
      const waf = await this._request('GET',
        `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint`
      );
      const rl = await this._request('GET',
        `/zones/${this.zoneId}/rulesets/phases/http_ratelimit/entrypoint`
      ).catch(() => ({ rules: [] }));

      return {
        wafRules: waf?.rules || [],
        rateLimitRules: rl?.rules || [],
        blacklist: this.getBlacklist(),
      };
    } catch (err) {
      console.error('[CF] listRules error:', err.message);
      return { wafRules: [], rateLimitRules: [], blacklist: this.getBlacklist() };
    }
  }

  async setSecurityLevel(level = 'high') {
    return this._request('PATCH', `/zones/${this.zoneId}/settings/security_level`, { value: level });
  }

  async enableUnderAttackMode() {
    return this.setSecurityLevel('under_attack');
  }

  async applyHTTPSRateLimit(options = {}) {
    const cfg = { requests: 200, period: 60, banDuration: 3600, paths: ['/api/', '/login', '/admin'], ...options };
    const pathExpr = cfg.paths.map(p => `http.request.uri.path contains "${p}"`).join(' or ');

    return this.createRateLimit({
      cfExpression: `(${pathExpr}) and ssl`,
      cfRateLimit: { requests: cfg.requests, period: cfg.period, banDuration: cfg.banDuration },
      ruleName: 'HTTPS Rate Limit - Sentinel WAF',
    });
  }
}

module.exports = new CloudflareManager();
