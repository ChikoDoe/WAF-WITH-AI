/**
 * SENTINEL WAF - Cloudflare Manager
 * Manages WAF rules, rate limiting, firewall rules via Cloudflare API
 */

const CF_API = 'https://api.cloudflare.com/client/v4';

class CloudflareManager {
  constructor() {
    this.apiToken = process.env.CF_API_TOKEN;
    this.zoneId   = process.env.CF_ZONE_ID;
    this.accountId = process.env.CF_ACCOUNT_ID;
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

  // ── WAF / Firewall Rules (L7) ──────────────────────────────────────────────

  async createRule(rule) {
    if (!rule.cfExpression) throw new Error('cfExpression required');

    // Cloudflare custom rules (new ruleset-based API)
    const result = await this._request('POST',
      `/zones/${this.zoneId}/rulesets/phases/http_request_firewall_custom/entrypoint/rules`,
      {
        action: rule.cfAction || 'block',
        expression: rule.cfExpression,
        description: rule.ruleName || 'Sentinel WAF auto-rule',
        enabled: true,
      }
    );

    console.log(`[CF] Rule created: ${result.id} — ${rule.ruleName}`);
    return { ...result, type: 'waf' };
  }

  async createRateLimit(rule) {
    if (!rule.cfRateLimit) throw new Error('cfRateLimit config required');
    const rl = rule.cfRateLimit;

    // Rate limiting via Cloudflare Rulesets API
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

  async createIPBlock(ip, reason = 'Sentinel WAF') {
    // Block specific IP via WAF expression
    return this.createRule({
      cfExpression: `(ip.src eq ${ip})`,
      cfAction: 'block',
      ruleName: `Block IP ${ip} - ${reason}`,
    });
  }

  async createGeoBlock(countries, paths) {
    const countryList = countries.map(c => `"${c}"`).join(' ');
    const pathExpr = paths ? `and (${paths.map(p => `http.request.uri.path contains "${p}"`).join(' or ')})` : '';

    return this.createRule({
      cfExpression: `(ip.geoip.country in {${countryList}}) ${pathExpr}`.trim(),
      cfAction: 'managed_challenge',
      ruleName: `Geo challenge ${countries.join(',')}`,
    });
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
      };
    } catch (err) {
      console.error('[CF] listRules error:', err.message);
      return { wafRules: [], rateLimitRules: [] };
    }
  }

  // ── Analytics ─────────────────────────────────────────────────────────────

  async getFirewallEvents(limit = 100) {
    try {
      // GraphQL Analytics API
      const query = `{
        viewer {
          zones(filter: {zoneTag: "${this.zoneId}"}) {
            firewallEventsAdaptive(
              filter: { datetime_gt: "${new Date(Date.now() - 3600000).toISOString()}" }
              limit: ${limit}
              orderBy: [datetime_DESC]
            ) {
              action datetime clientIP clientASNDescription
              clientCountryName clientRequestHTTPHost
              clientRequestHTTPMethodName clientRequestPath
              ruleId source userAgent
            }
          }
        }
      }`;

      const res = await fetch('https://api.cloudflare.com/client/v4/graphql', {
        method: 'POST',
        headers: this._headers(),
        body: JSON.stringify({ query }),
      });

      const data = await res.json();
      return data?.data?.viewer?.zones?.[0]?.firewallEventsAdaptive || [];
    } catch (err) {
      console.error('[CF] Analytics error:', err.message);
      return [];
    }
  }

  // ── Zone Settings ─────────────────────────────────────────────────────────

  async setSecurityLevel(level = 'high') {
    // levels: off, essentially_off, low, medium, high, under_attack
    return this._request('PATCH', `/zones/${this.zoneId}/settings/security_level`, { value: level });
  }

  async enableUnderAttackMode() {
    return this.setSecurityLevel('under_attack');
  }

  async setSSLMode(mode = 'full_strict') {
    return this._request('PATCH', `/zones/${this.zoneId}/settings/ssl`, { value: mode });
  }

  // ── HTTPS Rate Limit Preset ───────────────────────────────────────────────

  async applyHTTPSRateLimit(options = {}) {
    const defaults = {
      requests: 200,
      period: 60,
      banDuration: 3600,
      paths: ['/api/', '/login', '/admin'],
    };
    const cfg = { ...defaults, ...options };
    const pathExpr = cfg.paths.map(p => `http.request.uri.path contains "${p}"`).join(' or ');

    return this.createRateLimit({
      cfExpression: `(${pathExpr}) and ssl`,
      cfRateLimit: { requests: cfg.requests, period: cfg.period, banDuration: cfg.banDuration },
      ruleName: 'HTTPS Rate Limit - Sentinel WAF',
    });
  }
}

module.exports = new CloudflareManager();
