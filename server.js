/**
 * SENTINEL WAF - Backend API Server
 * Express + WebSocket server untuk real-time threat monitoring
 */

const express = require('express');
const { createServer } = require('http');
const { WebSocketServer } = require('ws');
const cors = require('cors');
const path = require('path');

const LogReader = require('./log-reader');
const AIEngine = require('./ai-engine');
const CloudflareManager = require('./cloudflare');
const FirewallManager = require('./firewall');

const app = express();
const httpServer = createServer(app);
const wss = new WebSocketServer({ server: httpServer });

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '../dashboard/dist')));

// ─── State ────────────────────────────────────────────────────────────────────
const state = {
  events: [],          // last 500 threat events
  rules: [],           // active rules (CF + iptables)
  stats: { total: 0, blocked: 0, breached: 0, startTime: Date.now() },
  clients: new Set(),  // WebSocket clients
  monitoredUrls: [],   // URLs to analyze
};

// ─── WebSocket Broadcast ──────────────────────────────────────────────────────
function broadcast(type, data) {
  const msg = JSON.stringify({ type, data, ts: Date.now() });
  for (const client of state.clients) {
    if (client.readyState === 1) client.send(msg);
  }
}

wss.on('connection', (ws) => {
  state.clients.add(ws);
  // Send current state to new client
  ws.send(JSON.stringify({ type: 'init', data: {
    events: state.events.slice(-50),
    rules: state.rules,
    stats: state.stats,
    monitoredUrls: state.monitoredUrls,
  }}));
  ws.on('close', () => state.clients.delete(ws));
});

// ─── Log Reader Events ────────────────────────────────────────────────────────
const logReader = new LogReader();

logReader.on('threat', async (event) => {
  state.events.unshift(event);
  if (state.events.length > 500) state.events.pop();

  state.stats.total++;
  if (event.blocked) state.stats.blocked++;
  else {
    state.stats.breached++;
    broadcast('breach', event);

    // Auto-generate rules on breach
    if (event.severity === 'HIGH' || event.severity === 'CRITICAL') {
      broadcast('ai_thinking', { eventId: event.id });
      try {
        const rules = await AIEngine.generateRules(event);
        for (const rule of rules) {
          await applyRule(rule, event);
        }
        broadcast('ai_done', { eventId: event.id, rules });
      } catch (err) {
        broadcast('ai_error', { eventId: event.id, error: err.message });
      }
    }
  }

  broadcast('event', event);
  broadcast('stats', state.stats);
});

logReader.on('error', (err) => console.error('[LogReader]', err.message));

// ─── Apply Rule (Cloudflare + iptables) ──────────────────────────────────────
async function applyRule(rule, event) {
  const result = { ...rule, applied: [], errors: [] };

  if (rule.targets.includes('cloudflare')) {
    try {
      await CloudflareManager.createRule(rule);
      result.applied.push('cloudflare');
    } catch (e) { result.errors.push(`CF: ${e.message}`); }
  }

  if (rule.targets.includes('iptables')) {
    try {
      await FirewallManager.addRule(rule, event.ip);
      result.applied.push('iptables');
    } catch (e) { result.errors.push(`iptables: ${e.message}`); }
  }

  state.rules.unshift(result);
  if (state.rules.length > 200) state.rules.pop();
  broadcast('rule_added', result);
  return result;
}

// ─── REST API ─────────────────────────────────────────────────────────────────

// GET /api/status
app.get('/api/status', (req, res) => {
  res.json({
    ok: true,
    uptime: Date.now() - state.stats.startTime,
    stats: state.stats,
    monitoredUrls: state.monitoredUrls,
    rulesCount: state.rules.length,
  });
});

// GET /api/events
app.get('/api/events', (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 500);
  res.json(state.events.slice(0, limit));
});

// GET /api/rules
app.get('/api/rules', (req, res) => {
  res.json(state.rules);
});

// POST /api/urls - Add URL to monitor
app.post('/api/urls', (req, res) => {
  const { url } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });

  try {
    const parsed = new URL(url);
    const entry = { url: parsed.href, host: parsed.hostname, path: parsed.pathname, addedAt: Date.now() };

    if (!state.monitoredUrls.find(u => u.url === entry.url)) {
      state.monitoredUrls.push(entry);
      logReader.addMonitoredHost(parsed.hostname);
      broadcast('url_added', entry);
    }

    res.json({ ok: true, entry });
  } catch {
    res.status(400).json({ error: 'invalid URL' });
  }
});

// DELETE /api/urls
app.delete('/api/urls', (req, res) => {
  const { url } = req.body;
  state.monitoredUrls = state.monitoredUrls.filter(u => u.url !== url);
  broadcast('url_removed', { url });
  res.json({ ok: true });
});

// POST /api/analyze - Manual analyze specific event
app.post('/api/analyze', async (req, res) => {
  const { eventId } = req.body;
  const event = state.events.find(e => e.id === eventId);
  if (!event) return res.status(404).json({ error: 'event not found' });

  try {
    const rules = await AIEngine.generateRules(event);
    const applied = [];
    for (const rule of rules) {
      const r = await applyRule(rule, event);
      applied.push(r);
    }
    res.json({ ok: true, rules: applied });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// POST /api/rules/manual - Manually add rule
app.post('/api/rules/manual', async (req, res) => {
  const rule = req.body;
  try {
    const result = await applyRule(rule, { ip: rule.ip || '0.0.0.0' });
    res.json({ ok: true, rule: result });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// DELETE /api/rules/:id - Remove rule
app.delete('/api/rules/:id', async (req, res) => {
  const rule = state.rules.find(r => r.id === req.params.id);
  if (!rule) return res.status(404).json({ error: 'rule not found' });

  try {
    if (rule.targets?.includes('cloudflare') && rule.cfRuleId) {
      await CloudflareManager.deleteRule(rule.cfRuleId);
    }
    if (rule.targets?.includes('iptables') && rule.iptablesId) {
      await FirewallManager.removeRule(rule.iptablesId);
    }
    state.rules = state.rules.filter(r => r.id !== req.params.id);
    broadcast('rule_removed', { id: req.params.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/firewall - Current iptables rules
app.get('/api/firewall', async (req, res) => {
  try {
    const rules = await FirewallManager.listRules();
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// GET /api/cloudflare/rules - Current CF rules
app.get('/api/cloudflare/rules', async (req, res) => {
  try {
    const rules = await CloudflareManager.listRules();
    res.json(rules);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Start ────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3001;
httpServer.listen(PORT, () => {
  console.log(`[Sentinel WAF] Backend running on :${PORT}`);
  logReader.start();
});

process.on('SIGTERM', () => {
  logReader.stop();
  process.exit(0);
});
