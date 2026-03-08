/**
 * SENTINEL WAF - AI Engine
 * Claude generates firewall rules for Cloudflare + iptables/nftables
 */

const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';

const SYSTEM_PROMPT = `You are an expert WAF security engineer. Analyze attack events and generate precise firewall rules.

Respond ONLY with a valid JSON array (no markdown, no backticks, no explanation) of rule objects.
Each rule object must have:
{
  "id": "rule_<random 8 chars>",
  "ruleName": "short descriptive name",
  "targets": ["cloudflare", "iptables"],  // include both unless only one is appropriate
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0-100,
  "reasoning": "1-2 sentence explanation",
  
  // Cloudflare WAF rule (include if targets has "cloudflare"):
  "cfExpression": "valid Cloudflare firewall rules expression",
  "cfAction": "block|challenge|js_challenge|managed_challenge|log",
  "cfRateLimit": {                        // only for rate limiting rules
    "requests": 100,
    "period": 60,
    "action": "block"
  },
  
  // iptables rule (include if targets has "iptables"):
  "iptablesRules": [
    "iptables -A INPUT -s <ip> -j DROP",  // exact commands, ready to execute
    "iptables -A INPUT -s <ip>/24 -p tcp --dport 80 -j DROP"
  ],
  
  // nftables alternative (always include):
  "nftablesRules": [
    "nft add rule ip filter INPUT ip saddr <ip> drop"
  ],

  // Auto-expiry (optional):
  "expiresIn": 3600  // seconds, 0 = permanent
}

Rules for generating good rules:
- SQL injection / XSS: Block IP + Cloudflare WAF expression on URI/body
- DDoS/flood: Rate limit on Cloudflare + iptables connlimit/hashlimit
- Path traversal / scanner: Block IP at L3 + Cloudflare geo/UA rules
- Bot/scraper: Cloudflare js_challenge, iptables log+drop
- RCE: Immediately block IP permanently, CF block, no exceptions
- Always generate BOTH cloudflare and iptables rules unless it's clearly only L7
- For iptables, use actual IP from event
- Consider subnet blocks (/24 or /16) for clear attack patterns`;

class AIEngine {
  static async generateRules(event) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not set');

    const prompt = `Analyze this attack and generate firewall rules:

Attack Event:
- Type: ${event.type}
- Severity: ${event.severity}
- Score: ${event.score}/100
- Source IP: ${event.ip}
- Method: ${event.method}
- Path: ${event.path}
- User-Agent: ${event.userAgent || 'unknown'}
- HTTP Status returned: ${event.status}
- Requests per minute from this IP: ${event.requestsPerMin}
- Was blocked by current rules: ${event.blocked}
- Raw request: ${event.raw?.slice(0, 300) || 'N/A'}

Generate appropriate rules. For DDoS (${event.requestsPerMin} req/min), focus on rate limiting.
For ${event.type}, block at both L3 (iptables) and L7 (Cloudflare).`;

    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 1500,
        system: SYSTEM_PROMPT,
        messages: [{ role: 'user', content: prompt }],
      }),
    });

    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Anthropic API error ${res.status}: ${err}`);
    }

    const data = await res.json();
    const text = data.content?.map(b => b.text || '').join('') || '';

    // Strip markdown fences if present
    const clean = text.replace(/```json\n?|```\n?/g, '').trim();

    let rules;
    try {
      rules = JSON.parse(clean);
    } catch {
      // Try extracting JSON array from response
      const match = clean.match(/\[[\s\S]*\]/);
      if (match) rules = JSON.parse(match[0]);
      else throw new Error('AI returned invalid JSON: ' + clean.slice(0, 200));
    }

    if (!Array.isArray(rules)) rules = [rules];

    // Attach source event ref
    return rules.map(r => ({
      ...r,
      sourceEventId: event.id,
      sourceIp: event.ip,
      generatedAt: Date.now(),
      auto: true,
    }));
  }

  // Quick triage: is this a real threat? (fast, cheap call)
  static async quickTriage(events) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) return events.map(e => ({ ...e, triaged: false }));

    const prompt = `Triage these ${events.length} security events. For each, return:
{"index": N, "realThreat": true/false, "priority": 1-10}
Events: ${JSON.stringify(events.map((e, i) => ({ i, type: e.type, path: e.path, ip: e.ip, rpm: e.requestsPerMin })))}
Respond ONLY with JSON array, no explanation.`;

    try {
      const res = await fetch(ANTHROPIC_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
        body: JSON.stringify({
          model: 'claude-haiku-4-5-20251001',
          max_tokens: 500,
          messages: [{ role: 'user', content: prompt }],
        }),
      });

      const data = await res.json();
      const text = data.content?.map(b => b.text || '').join('') || '[]';
      const triages = JSON.parse(text.replace(/```.*?```/gs, '').trim());

      return events.map((e, i) => {
        const t = triages.find(x => x.index === i);
        return { ...e, realThreat: t?.realThreat ?? true, priority: t?.priority ?? 5 };
      });
    } catch {
      return events;
    }
  }
}

module.exports = AIEngine;
