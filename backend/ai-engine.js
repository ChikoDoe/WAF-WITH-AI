/**
 * SENTINEL WAF - AI Engine
 * Claude generates a single IP block rule per breach
 */

const ANTHROPIC_API = 'https://api.anthropic.com/v1/messages';

const SYSTEM_PROMPT = `You are a WAF security engineer. When given an attack event, generate EXACTLY ONE rule that blocks the source IP.

Respond ONLY with a valid JSON array containing exactly one object (no markdown, no backticks, no explanation):
[{
  "id": "rule_<random 8 chars>",
  "ruleName": "Block <IP> - <attack type>",
  "targets": ["cloudflare", "iptables"],
  "severity": "LOW|MEDIUM|HIGH|CRITICAL",
  "confidence": 0-100,
  "reasoning": "1 sentence why this IP is blocked",
  "cfExpression": "(ip.src eq <IP>)",
  "cfAction": "block",
  "iptablesRules": ["iptables -I INPUT -s <IP> -j DROP"],
  "nftablesRules": ["nft add element ip sentinel blocklist { <IP> timeout 86400s }"],
  "expiresIn": 0
}]

Rules:
- ALWAYS block the full source IP, never generate pattern-based or path-based rules
- cfExpression MUST be exactly: (ip.src eq <IP>)
- iptablesRules MUST be exactly: iptables -I INPUT -s <IP> -j DROP
- expiresIn: 0 for CRITICAL/HIGH (permanent), 3600 for MEDIUM, 1800 for LOW
- Replace <IP> with the actual source IP from the event
- Only return ONE rule in the array, nothing else`;

class AIEngine {
  static async generateRules(event) {
    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) throw new Error('ANTHROPIC_API_KEY not set');

    const prompt = `Block this attacker:
- Source IP: ${event.ip}
- Attack Type: ${event.type}
- Severity: ${event.severity}
- Path: ${event.path}
- Requests/min: ${event.requestsPerMin}
- Raw: ${event.raw?.slice(0, 200) || 'N/A'}

Generate ONE IP block rule for ${event.ip}.`;

    const res = await fetch(ANTHROPIC_API, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-20250514',
        max_tokens: 500,
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
    const clean = text.replace(/```json\n?|```\n?/g, '').trim();

    let rules;
    try {
      rules = JSON.parse(clean);
    } catch {
      const match = clean.match(/\[[\s\S]*\]/);
      if (match) rules = JSON.parse(match[0]);
      else throw new Error('AI returned invalid JSON: ' + clean.slice(0, 200));
    }

    if (!Array.isArray(rules)) rules = [rules];

    // Enforce: selalu 1 rule, selalu IP block
    const rule = rules[0];
    rule.cfExpression = `(ip.src eq ${event.ip})`;
    rule.cfAction = 'block';
    rule.iptablesRules = [`iptables -I INPUT -s ${event.ip} -j DROP`];
    rule.nftablesRules = [`nft add element ip sentinel blocklist { ${event.ip} timeout ${rule.expiresIn === 0 ? '0' : (rule.expiresIn || 86400) + 's'} }`];

    return [{
      ...rule,
      sourceEventId: event.id,
      sourceIp: event.ip,
      generatedAt: Date.now(),
      auto: true,
    }];
  }

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
