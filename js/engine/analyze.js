// Click-log analysis: labels every click as human, suspicious or bot, with reasons,
// and aggregates by traffic source, placement, flow, network and country.
// Reason categories follow the MRC invalid-traffic split:
//  GIVT (lists and standard checks): crawlers, data-center traffic, non-browser user agents
//  Behaviour (activity-based filtration): repeat clicks, machine-regular timing, subnet farms
import { parseIP, subnetKey, isPrivate } from './ip.js';
import { classifyUA } from './ua.js';
import { parseFlag, parseTime } from './columns.js';

export const REASONS = {
  'empty-ua': { label: 'Empty user agent', layer: 'user agent', verdict: 'bot', givt: 'Non-browser user agent' },
  'library': { label: 'HTTP library or script', layer: 'user agent', verdict: 'bot', givt: 'Non-browser user agent' },
  'app-http': { label: 'App HTTP stack, not a browser', layer: 'user agent', verdict: 'bot', givt: 'Non-browser user agent' },
  'unknown-ua': { label: 'Unknown or malformed user agent', layer: 'user agent', verdict: 'bot', givt: 'Unknown browser' },
  'headless': { label: 'Headless or automated browser', layer: 'user agent', verdict: 'bot', givt: 'Automated browser' },
  'crawler': { label: 'Declared crawler', layer: 'user agent', verdict: 'bot', givt: 'Bots, spiders and crawlers' },
  'verified-crawler': { label: 'Real crawler (IP in the provider\'s published list)', layer: 'network', verdict: 'bot', givt: 'Bots, spiders and crawlers' },
  'fake-crawler': { label: 'Fake crawler (claims Googlebot/Bingbot/etc. from an unlisted IP)', layer: 'network', verdict: 'bot', givt: 'Bots, spiders and crawlers' },
  'platform-network': { label: 'Ad-platform network (Meta) with a browser user agent', layer: 'network', verdict: 'bot', givt: 'Bots, spiders and crawlers' },
  'monitor-network': { label: 'Uptime-monitor network', layer: 'network', verdict: 'bot', givt: 'Bots, spiders and crawlers' },
  'datacenter': { label: 'Data-center network with a browser user agent', layer: 'network', verdict: 'bot', givt: 'Known data-center traffic' },
  'repeat-device': { label: 'Same IP + user agent clicked 6+ times in 10 minutes', layer: 'behaviour', verdict: 'bot', givt: 'Activity-based filtration' },
  'metronome': { label: 'Clicks at machine-regular intervals', layer: 'behaviour', verdict: 'bot', givt: 'Activity-based filtration' },
  'subnet-farm': { label: '10+ clicks from 4+ IPs in one subnet, same user agent, 10 minutes', layer: 'behaviour', verdict: 'bot', givt: 'Activity-based filtration' },
  'vpn': { label: 'Commercial VPN network', layer: 'network', verdict: 'suspicious', givt: null },
  'outdated': { label: 'Browser engine 40+ releases out of date', layer: 'user agent', verdict: 'suspicious', givt: null },
  'incongruous': { label: 'Inconsistent user agent (iOS with desktop Chrome token)', layer: 'user agent', verdict: 'suspicious', givt: null },
  'repeat-light': { label: 'Same IP + user agent clicked 3-5 times in 10 minutes', layer: 'behaviour', verdict: 'suspicious', givt: null },
  'ua-rotation': { label: 'One IP with 8+ different user agents in 10 minutes', layer: 'behaviour', verdict: 'suspicious', givt: null },
  'cdn-edge': { label: 'IP is a Cloudflare edge address, not the visitor', layer: 'network', verdict: 'suspicious', givt: null },
  'private-ip': { label: 'Private or reserved IP (log or proxy setup issue)', layer: 'network', verdict: 'suspicious', givt: null },
  'bad-ip': { label: 'IP missing or unreadable', layer: 'network', verdict: 'suspicious', givt: null },
};

export const DEFAULTS = {
  windowMs: 10 * 60 * 1000,
  repeatBot: 6, repeatSuspicious: 3,
  metronomeMinClicks: 5, metronomeMaxCv: 0.1, metronomeMaxGapMs: 60 * 60 * 1000,
  farmClicks: 10, farmIps: 4,
  rotationUas: 8,
};

function maxInWindow(times, windowMs) {
  // times sorted ascending; returns per-index count of events in [t - window, t]
  const out = new Array(times.length);
  let lo = 0;
  for (let hi = 0; hi < times.length; hi++) {
    while (times[hi] - times[lo] > windowMs) lo++;
    out[hi] = hi - lo + 1;
  }
  return out;
}

export function analyzeClicks(table, map, netdb, options = {}) {
  const o = { ...DEFAULTS, ...options };
  const get = (row, f) => (map[f] === undefined ? undefined : row[map[f]]);
  const refDate = o.refDate || null;

  // ---- 1. normalise ----
  const clicks = table.rows.map((row, i) => {
    const ipStr = (get(row, 'ip') || '').trim();
    const t = parseTime(get(row, 'time'));
    return {
      i, ip: ipStr, ipParsed: parseIP(ipStr), ua: get(row, 'ua') ?? '', t,
      country: (get(row, 'country') || '').trim(), isp: (get(row, 'isp') || '').trim(),
      source: (get(row, 'source') || '').trim() || '(no source)', campaign: (get(row, 'campaign') || '').trim(),
      flow: (get(row, 'flow') || '').trim(), placement: (get(row, 'placement') || '').trim(),
      connection: (get(row, 'connection') || '').trim(),
      keitaroBot: parseFlag(get(row, 'isBot')), keitaroProxy: parseFlag(get(row, 'isProxy')), lead: parseFlag(get(row, 'isLead')),
      reasons: [], net: null, uaInfo: null,
    };
  });

  // ---- 2. per-click checks: user agent and network ----
  for (const c of clicks) {
    const u = classifyUA(c.ua, { refDate: c.t || refDate || undefined });
    c.uaInfo = u;
    if (u.kind === 'empty') c.reasons.push('empty-ua');
    else if (u.kind === 'library') c.reasons.push('library');
    else if (u.kind === 'app-http') c.reasons.push('app-http');
    else if (u.kind === 'unknown') c.reasons.push('unknown-ua');
    else if (u.kind === 'headless') c.reasons.push('headless');
    if (u.outdated) c.reasons.push('outdated');
    if (u.incongruous) c.reasons.push('incongruous');

    if (!c.ipParsed) { c.reasons.push('bad-ip'); }
    else if (isPrivate(c.ipParsed)) { c.reasons.push('private-ip'); }
    else if (netdb) {
      const n = netdb.lookup(c.ipParsed);
      c.net = n;
      const sp = n && n.special;
      if (u.kind === 'crawler') {
        if (u.claims) c.reasons.push(sp && sp.tag === u.claims ? 'verified-crawler' : 'fake-crawler');
        else c.reasons.push('crawler');
      } else if (sp && sp.kind === 'crawler') {
        c.reasons.push('verified-crawler'); // a crawler network using a browser-like UA
      } else if (sp && sp.kind === 'platform' && !u.bot) {
        c.reasons.push('platform-network');
      } else if (sp && sp.kind === 'monitor') {
        c.reasons.push('monitor-network');
      } else if (sp && sp.kind === 'cdn') {
        c.reasons.push('cdn-edge');
      } else if (sp && sp.kind === 'relay') {
        // iCloud Private Relay: real Safari users. Deliberately not data-center traffic.
      } else if (n && n.hosting && !u.bot) {
        c.reasons.push('datacenter');
      } else if (n && n.vpn && !u.bot) {
        c.reasons.push('vpn');
      }
    } else if (u.kind === 'crawler') {
      c.reasons.push('crawler');
    }
  }

  // ---- 3. behaviour: needs timestamps ----
  const timed = clicks.filter((c) => c.t !== null && c.ipParsed);
  const group = (keyFn) => {
    const m = new Map();
    for (const c of timed) { const k = keyFn(c); if (k === null) continue; let a = m.get(k); if (!a) m.set(k, (a = [])); a.push(c); }
    for (const a of m.values()) a.sort((x, y) => x.t - y.t);
    return m;
  };
  // Same device = same IP and same user agent
  for (const arr of group((c) => c.ip + '\u0000' + c.ua).values()) {
    if (arr.length < o.repeatSuspicious) continue;
    const counts = maxInWindow(arr.map((c) => c.t), o.windowMs);
    // a click belongs to a burst if any window containing it reaches the threshold
    const peak = new Array(arr.length).fill(0);
    let lo = 0;
    for (let hi = 0; hi < arr.length; hi++) {
      while (arr[hi].t - arr[lo].t > o.windowMs) lo++;
      for (let k = lo; k <= hi; k++) peak[k] = Math.max(peak[k], counts[hi]);
    }
    arr.forEach((c, k) => {
      if (peak[k] >= o.repeatBot) c.reasons.push('repeat-device');
      else if (peak[k] >= o.repeatSuspicious) c.reasons.push('repeat-light');
    });
    // machine-regular timing
    if (arr.length >= o.metronomeMinClicks) {
      const gaps = [];
      for (let k = 1; k < arr.length; k++) gaps.push(arr[k].t - arr[k - 1].t);
      const mean = gaps.reduce((a, b) => a + b, 0) / gaps.length;
      const sd = Math.sqrt(gaps.reduce((a, b) => a + (b - mean) ** 2, 0) / gaps.length);
      if (mean > 0 && mean <= o.metronomeMaxGapMs && sd / mean <= o.metronomeMaxCv) arr.forEach((c) => c.reasons.push('metronome'));
    }
  }
  // Subnet farm: same subnet + same UA, many IPs in a short window
  for (const arr of group((c) => (c.uaInfo && !c.uaInfo.bot ? subnetKey(c.ipParsed) + '\u0000' + c.ua : null)).values()) {
    if (arr.length < o.farmClicks) continue;
    let lo = 0;
    const ipCount = new Map();
    const hit = new Set();
    for (let hi = 0; hi < arr.length; hi++) {
      ipCount.set(arr[hi].ip, (ipCount.get(arr[hi].ip) || 0) + 1);
      while (arr[hi].t - arr[lo].t > o.windowMs) {
        const v = ipCount.get(arr[lo].ip) - 1;
        if (v) ipCount.set(arr[lo].ip, v); else ipCount.delete(arr[lo].ip);
        lo++;
      }
      if (hi - lo + 1 >= o.farmClicks && ipCount.size >= o.farmIps) for (let k = lo; k <= hi; k++) hit.add(arr[k]);
    }
    for (const c of hit) c.reasons.push('subnet-farm');
  }
  // UA rotation: one IP, many user agents
  for (const arr of group((c) => c.ip).values()) {
    if (arr.length < o.rotationUas) continue;
    let lo = 0;
    const uaCount = new Map();
    const hit = new Set();
    for (let hi = 0; hi < arr.length; hi++) {
      uaCount.set(arr[hi].ua, (uaCount.get(arr[hi].ua) || 0) + 1);
      while (arr[hi].t - arr[lo].t > o.windowMs) {
        const v = uaCount.get(arr[lo].ua) - 1;
        if (v) uaCount.set(arr[lo].ua, v); else uaCount.delete(arr[lo].ua);
        lo++;
      }
      if (uaCount.size >= o.rotationUas) for (let k = lo; k <= hi; k++) hit.add(arr[k]);
    }
    for (const c of hit) c.reasons.push('ua-rotation');
  }

  // ---- 4. verdicts ----
  for (const c of clicks) {
    c.reasons = [...new Set(c.reasons)];
    c.verdict = c.reasons.some((r) => REASONS[r].verdict === 'bot') ? 'bot' : c.reasons.length ? 'suspicious' : 'human';
  }

  return { clicks, summary: summarize(clicks, map, o), timed: timed.length };
}

function bump(m, key, c) {
  let g = m.get(key);
  if (!g) m.set(key, (g = { key, clicks: 0, bot: 0, suspicious: 0, human: 0, keitaroBot: 0, passedKeitaro: 0, leads: 0, reasons: {} }));
  g.clicks++; g[c.verdict]++;
  if (c.keitaroBot) g.keitaroBot++;
  if (c.verdict === 'bot' && c.keitaroBot === false) g.passedKeitaro++;
  if (c.lead) g.leads++;
  for (const r of c.reasons) g.reasons[r] = (g.reasons[r] || 0) + 1;
  return g;
}

function finish(m, minClicks = 1) {
  return [...m.values()].filter((g) => g.clicks >= minClicks).map((g) => ({
    ...g,
    botShare: g.clicks ? g.bot / g.clicks : 0,
    invalidShare: g.clicks ? (g.bot + g.suspicious) / g.clicks : 0,
    topReason: Object.entries(g.reasons).sort((a, b) => b[1] - a[1])[0]?.[0] || null,
  })).sort((a, b) => b.bot - a.bot || b.clicks - a.clicks);
}

function summarize(clicks, map, o) {
  const total = clicks.length;
  const count = (v) => clicks.filter((c) => c.verdict === v).length;
  const reasons = {};
  for (const c of clicks) for (const r of c.reasons) reasons[r] = (reasons[r] || 0) + 1;
  const by = { source: new Map(), placement: new Map(), flow: new Map(), country: new Map(), network: new Map(), campaign: new Map() };
  for (const c of clicks) {
    bump(by.source, c.source, c);
    if (map.placement !== undefined) bump(by.placement, `${c.source} · ${c.placement || '(empty)'}`, c);
    if (map.flow !== undefined) bump(by.flow, c.flow || '(none)', c);
    if (map.country !== undefined) bump(by.country, c.country || '(unknown)', c);
    if (map.campaign !== undefined) bump(by.campaign, c.campaign || '(none)', c);
    const netKey = c.net && c.net.asn ? `AS${c.net.asn} ${c.net.name || ''}`.trim() : (c.isp || '(unknown network)');
    bump(by.network, netKey, c);
  }
  const hasKeitaroFlag = map.isBot !== undefined;
  let keitaro = null;
  if (hasKeitaroFlag) {
    const kb = clicks.filter((c) => c.keitaroBot === true);
    keitaro = {
      flaggedByKeitaro: kb.length,
      flaggedByBoth: kb.filter((c) => c.verdict === 'bot').length,
      botsKeitaroMissed: clicks.filter((c) => c.verdict === 'bot' && c.keitaroBot === false).length,
      keitaroOnly: kb.filter((c) => c.verdict !== 'bot').length,
    };
  }
  // Flows that mostly receive Keitaro-flagged bots are treated as the bot flow(s).
  let flowExposure = null;
  if (map.flow !== undefined) {
    const flows = finish(by.flow);
    const botFlows = hasKeitaroFlag ? flows.filter((f) => f.clicks >= 5 && f.keitaroBot / f.clicks >= 0.9).map((f) => f.key) : [];
    const leaked = clicks.filter((c) => c.verdict === 'bot' && !botFlows.includes(c.flow || '(none)'));
    flowExposure = { botFlows, botsInOtherFlows: leaked.length, byFlow: Object.fromEntries(flows.map((f) => [f.key, f.bot])) };
  }
  const cdn = reasons['cdn-edge'] || 0;
  const times = clicks.map((c) => c.t).filter((t) => t !== null);
  const hourly = new Map();
  for (const c of clicks) {
    if (c.t === null) continue;
    const h = Math.floor(c.t / 3600000) * 3600000;
    let e = hourly.get(h); if (!e) hourly.set(h, (e = { t: h, human: 0, suspicious: 0, bot: 0 }));
    e[c.verdict]++;
  }
  return {
    total, bot: count('bot'), suspicious: count('suspicious'), human: count('human'),
    botShare: total ? count('bot') / total : 0,
    reasons, keitaro, flowExposure,
    cdnEdgeShare: total ? cdn / total : 0,
    timeRange: times.length ? [Math.min(...times), Math.max(...times)] : null,
    hourly: [...hourly.values()].sort((a, b) => a.t - b.t),
    bySource: finish(by.source), byPlacement: finish(by.placement), byFlow: finish(by.flow),
    byCountry: finish(by.country), byNetwork: finish(by.network), byCampaign: finish(by.campaign),
    leads: { human: clicks.filter((c) => c.lead && c.verdict === 'human').length, bot: clicks.filter((c) => c.lead && c.verdict === 'bot').length, total: clicks.filter((c) => c.lead).length },
    options: { windowMinutes: o.windowMs / 60000, repeatBot: o.repeatBot, farmClicks: o.farmClicks, farmIps: o.farmIps },
  };
}
