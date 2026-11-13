// Turns an analysis into values that paste into Keitaro:
//  - Settings → Bot lists: IP/CIDR lines (single IPs and CIDR are accepted, one per line)
//  - Flow filter "IP": semicolon-separated values, at most 65,534 characters per filter
//  - Flow filter "UserAgent": a PCRE between slashes
//  - Placements to block at the traffic source
import { v4RangeToCidrs, v6RangeToCidrs } from './ip.js';
import { escapeForPcre } from './ua.js';

// Real browser user agents a UA filter must never match (desktop, mobile, in-app, Linux distros).
export const BROWSER_GUARD = [
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.1 Safari/605.1.15',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.7 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (Linux; Android 14; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:145.0) Gecko/20100101 Firefox/145.0',
  'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36 Edg/157.0.0.0',
  'Mozilla/5.0 (Linux; Android 14; SAMSUNG SM-A546B) AppleWebKit/537.36 (KHTML, like Gecko) SamsungBrowser/28.0 Chrome/130.0.0.0 Mobile Safari/537.36',
  'Mozilla/5.0 (Linux; Android 10; K; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/156.0.0.0 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/586.0.0.55.92;]',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148 Instagram 400.0.0.0.0 (iPhone15,2; iOS 18_6; en_US; en; scale=3.00; 1179x2556)',
  'Mozilla/5.0 (Linux; Android 13; 22101316G Build/TP1A.220624.014; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/150.0.0.0 Mobile Safari/537.36 trill_420001 BytedanceWebview/d8a21c6',
  'Mozilla/5.0 (iPhone; CPU iPhone OS 26_5_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) GSA/402.0.850515619 Mobile/15E148 Safari/604.1',
  'Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 Safari/537.36',
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/157.0.0.0 YaBrowser/25.10.0.0 Safari/537.36',
  'Opera/9.80 (Android; Opera Mini/7.6.40234/191.316; U; en) Presto/2.12.423 Version/12.16',
  'Mozilla/5.0 (Linux; Android 13; CUBOT P80) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/156.0.0.0 Mobile Safari/537.36',
];

// Bare category words are too broad for an unanchored filter (e.g. "bot" is inside "CUBOT").
const GENERIC_WORDS = new Set(['bot', 'bots', 'crawler', 'crawl', 'spider', 'scraper', 'slurp', 'fetcher', 'archiver', 'checker', 'validator', 'scanner', 'monitor', 'preview', 'indexer', 'webcrawler']);

export const IP_FILTER_MAX = 65534;

export function chunkJoin(values, sep, max) {
  const out = []; let cur = '';
  for (const v of values) {
    const next = cur ? cur + sep + v : v;
    if (next.length > max) { if (cur) out.push(cur); cur = v; } else cur = next;
  }
  if (cur) out.push(cur);
  return out;
}

export function buildKeitaroOutputs(result, opts = {}) {
  const minBotClicks = opts.minBotClicks ?? 1;
  const { clicks } = result;

  // Networks (BGP prefixes) that sent data-center, fake-crawler or farm traffic.
  const nets = new Map();
  for (const c of clicks) {
    if (c.verdict !== 'bot' || !c.net || c.net.rangeStart === null) continue;
    const infraReason = c.reasons.find((r) => ['datacenter', 'fake-crawler', 'subnet-farm', 'headless', 'library', 'crawler'].includes(r));
    if (!infraReason || !(c.net.hosting || c.net.vpn)) continue;
    if (c.net.special && ['relay', 'crawler', 'platform'].includes(c.net.special.kind)) continue;
    const key = String(c.net.rangeStart) + '-' + String(c.net.rangeEnd);
    let e = nets.get(key);
    if (!e) nets.set(key, (e = { v: c.ipParsed.v, start: c.net.rangeStart, end: c.net.rangeEnd, asn: c.net.asn, name: c.net.name, bots: 0, reasons: {} }));
    e.bots++;
    for (const r of c.reasons) e.reasons[r] = (e.reasons[r] || 0) + 1;
  }
  const netRows = [...nets.values()].filter((e) => e.bots >= minBotClicks).sort((a, b) => b.bots - a.bots).map((e) => ({
    ...e,
    cidrs: e.v === 4 ? v4RangeToCidrs(e.start, e.end) : v6RangeToCidrs(e.start, e.end),
    start: undefined, end: undefined,
  }));
  const cidrs = [...new Set(netRows.flatMap((e) => e.cidrs))];

  // Individual residential IPs with flood or machine timing: short-lived blocks only.
  const ipMap = new Map();
  for (const c of clicks) {
    if (!c.reasons.some((r) => r === 'repeat-device' || r === 'metronome')) continue;
    if (c.net && (c.net.hosting || c.net.vpn)) continue;
    ipMap.set(c.ip, (ipMap.get(c.ip) || 0) + 1);
  }
  const floodIps = [...ipMap.entries()].sort((a, b) => b[1] - a[1]).map(([ip, n]) => ({ ip, clicks: n }));

  // Literal user-agent fragments of non-browser and automated clients seen in this log.
  // Counted case-insensitively; the most common spelling is kept.
  const tokens = new Map();
  for (const c of clicks) {
    const u = c.uaInfo;
    if (!u || !u.bot || !u.match || u.kind === 'empty' || u.kind === 'unknown') continue;
    if (u.kind === 'crawler' && u.via === 'isbot') continue;
    const anchored = u.match.startsWith('^');
    const lit = u.match.replace(/^\^/, '').replace(/\s+$/, '');
    if (lit.length < 3 || GENERIC_WORDS.has(lit.toLowerCase().replace(/[^a-z]/g, ''))) continue;
    const k = (anchored ? '^' : '') + lit.toLowerCase();
    const e = tokens.get(k) || { lit, anchored, n: 0 };
    e.n++; tokens.set(k, e);
  }
  // Drop any fragment that would also match a real browser.
  const safe = [...tokens.values()].filter((e) => {
    const re = new RegExp((e.anchored ? '^' : '') + escapeForPcre(e.lit).replace(/\\\//g, '/'), 'i');
    return !BROWSER_GUARD.some((b) => re.test(b));
  });
  const tokenList = safe.sort((a, b) => b.n - a.n).map((e) => [e.lit, e.n, e.anchored]);
  const regexBody = tokenList.map(([t, , a]) => (a ? '^' : '') + escapeForPcre(t));
  const uaRegex = regexBody.length ? `/(?i)(?:${regexBody.join('|')})/` : '';

  // Placements with heavy invalid traffic (block at the traffic source, then claim refunds).
  const placements = (result.summary.byPlacement || []).filter((p) => p.clicks >= (opts.minPlacementClicks ?? 20) && p.botShare >= (opts.placementBotShare ?? 0.3));

  const hostingNames = new Map();
  for (const e of netRows) hostingNames.set(e.name || `AS${e.asn}`, (hostingNames.get(e.name || `AS${e.asn}`) || 0) + e.bots);

  return {
    botList: { lines: cidrs, text: cidrs.join('\n'), networks: netRows },
    ipFilter: { chunks: chunkJoin(cidrs, ';', IP_FILTER_MAX), maxChars: IP_FILTER_MAX },
    floodIps: { list: floodIps, filterChunks: chunkJoin(floodIps.map((x) => x.ip), ';', IP_FILTER_MAX) },
    userAgent: { tokens: tokenList, regex: uaRegex, signatures: tokenList.map(([t]) => t).join('\n'), droppedForBrowserMatch: tokens.size - safe.length },
    ispNames: [...hostingNames.entries()].sort((a, b) => b[1] - a[1]).map(([name, bots]) => ({ name, bots })),
    placements,
  };
}
