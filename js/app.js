// Page logic: runs the analyzer (in a worker), renders results, the sample audit and measurements.
import { REASONS } from './engine/analyze.js';
import { FIELDS } from './engine/columns.js';

const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmt = (n) => Number(n).toLocaleString('en-US');
const pct = (x, d = 1) => `${(x * 100).toFixed(d)}%`;

// ---------- worker with a main-thread fallback ----------
let worker = null; let seq = 0; const pending = new Map();
try {
  worker = new Worker(new URL('./worker.js', import.meta.url), { type: 'module' });
  worker.onmessage = (e) => { const p = pending.get(e.data.id); if (p) { pending.delete(e.data.id); p(e.data); } };
  worker.onerror = () => { worker = null; };
} catch { worker = null; }
async function call(msg) {
  if (worker) {
    const id = ++seq;
    return new Promise((resolve) => { pending.set(id, resolve); worker.postMessage({ ...msg, id }); });
  }
  const { handle } = await import('./worker.js');
  try { return await handle(msg); } catch (e) { return { type: 'error', message: e.message }; }
}

const status = (text, err = false) => { const el = $('#status'); el.textContent = text; el.classList.toggle('err', err); };

// ---------- analysis flow ----------
let current = { source: 'sample', name: 'sample-clicks.csv', text: null };

async function analyze(text, map = null) {
  status(current.source === 'sample' ? 'Analyzing the sample log…' : `Analyzing ${current.name}…`);
  const res = await call({ type: 'analyze', text, map });
  if (res.type === 'error') { status(`Couldn't analyze ${current.name}: ${res.message}`, true); return; }
  if (res.type === 'need-mapping') { showMapping(res); return; }
  $('#mapping').hidden = true;
  render(res);
}

function showMapping(res) {
  const f = $('#mapping'); const grid = $('#map-grid');
  status(`${current.name}: ${fmt(res.rows)} rows. ${res.missing.map((m) => FIELDS[m].label).join(' and ')} not found.`, true);
  grid.innerHTML = Object.entries(FIELDS).map(([key, def]) => `<label>${esc(def.label)}${def.required ? ' (required)' : ''}<select name="${key}"><option value="">Not in this file</option>${res.headers.map((h, i) => `<option value="${i}"${res.map[key] === i ? ' selected' : ''}>${esc(h || `Column ${i + 1}`)}</option>`).join('')}</select></label>`).join('');
  f.hidden = false;
  f.onsubmit = (e) => {
    e.preventDefault();
    const map = {};
    for (const s of grid.querySelectorAll('select')) if (s.value !== '') map[s.name] = Number(s.value);
    if (map.ip === undefined || map.ua === undefined) { status('Pick the IP and user agent columns to continue.', true); return; }
    analyze(current.text, map);
  };
  grid.querySelector('select').focus();
}

async function runSample(animate = false) {
  current = { source: 'sample', name: 'sample-clicks.csv', text: null };
  status('Loading the sample log…');
  const r = await fetch('data/sample/sample-clicks.csv');
  if (!r.ok) { status(`Couldn't load the sample (HTTP ${r.status}).`, true); return; }
  current.text = await r.text();
  animateNext = animate;
  await analyze(current.text);
}

$('#run-sample').addEventListener('click', () => runSample(true));
$('#file-input').addEventListener('change', async (e) => {
  const file = e.target.files && e.target.files[0];
  if (!file) return;
  current = { source: 'file', name: file.name, text: await file.text() };
  animateNext = true;
  await analyze(current.text);
  $('#analyzer').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth' });
});

// ---------- rendering ----------
let animateNext = true;
let lastResult = null;

function render(res) {
  lastResult = res;
  const s = res.summary;
  const range = s.timeRange ? `${new Date(s.timeRange[0]).toISOString().slice(0, 16).replace('T', ' ')} to ${new Date(s.timeRange[1]).toISOString().slice(0, 16).replace('T', ' ')} UTC` : 'no timestamps (behaviour checks skipped)';
  status(`${current.source === 'sample' ? 'Sample log' : current.name}: ${fmt(res.rows)} clicks, ${range}. Analyzed in ${fmt(res.timing.analyzeMs)} ms in this tab.`);
  $('#results').hidden = false;
  renderFlowstack(s);
  renderKpis(s);
  renderReasons(s);
  renderHourly(s);
  renderNetworks(s);
  renderSources(s);
  renderPlacements(res.outputs.placements);
  renderOutputs(res.outputs);
  renderClicks(res);
}

function laneMeta(name, s) {
  const isBotFlow = s.flowExposure && s.flowExposure.botFlows.includes(name);
  const type = /forced/i.test(name) || isBotFlow ? 'Forced' : /default/i.test(name) ? 'Default' : /regular/i.test(name) ? 'Regular' : 'Flow';
  return { type, label: name.replace(/\s*\((forced|regular|default)[^)]*\)\s*/i, '').trim() || name, order: type === 'Forced' ? 0 : type === 'Default' ? 2 : 1 };
}

function renderFlowstack(s) {
  let lanes = s.byFlow && s.byFlow.length ? s.byFlow.map((f) => ({ ...f, ...laneMeta(f.key, s) })) : [{ key: 'all', label: 'All clicks', type: 'Flow', order: 1, clicks: s.total, bot: s.bot, suspicious: s.suspicious, human: s.human, passedKeitaro: 0 }];
  lanes.sort((a, b) => a.order - b.order || b.clicks - a.clicks);
  if (lanes.length > 6) { const rest = lanes.slice(5); lanes = lanes.slice(0, 5).concat([{ label: `${rest.length} more flows`, type: 'Flow', clicks: rest.reduce((a, x) => a + x.clicks, 0), bot: rest.reduce((a, x) => a + x.bot, 0), suspicious: rest.reduce((a, x) => a + x.suspicious, 0), human: rest.reduce((a, x) => a + x.human, 0) }]); }
  const steps = [1, 2, 5, 10, 20, 50, 100, 200, 500, 1000, 2000, 5000];
  const scale = steps.find((x) => s.total / x <= 700) || 10000;
  $('#fs-scale').textContent = `1 square = ${fmt(scale)} click${scale > 1 ? 's' : ''}`;
  $('#fs-title').textContent = current.source === 'sample' ? "Sample log, in Keitaro's flow order" : `${current.name}, by flow`;
  const anim = animateNext && !matchMedia('(prefers-reduced-motion: reduce)').matches;
  let delayIndex = 0;
  $('#lanes').innerHTML = lanes.map((l) => {
    const n = Math.max(1, Math.round(l.clicks / scale));
    let b = l.bot ? Math.max(1, Math.round((l.bot / l.clicks) * n)) : 0;
    let su = l.suspicious ? Math.max(1, Math.round((l.suspicious / l.clicks) * n)) : 0;
    if (b + su > n) su = Math.max(0, n - b);
    const h = Math.max(0, n - b - su);
    const sq = (cls, k) => Array.from({ length: k }, () => `<i${cls ? ` class="${cls}"` : ''}${anim ? ` style="animation-delay:${Math.min(900, (delayIndex++) * 1.2)}ms"` : ''}></i>`).join('');
    const botNote = l.type === 'Forced' ? `${fmt(l.bot)} bots caught` : l.bot ? `<b>${fmt(l.bot)} bots</b> reached this flow` : 'no bots';
    return `<li class="lane"><div><span class="lane-type ${l.type === 'Forced' ? 'forced' : ''}">${esc(l.type)}</span><span class="lane-name">${esc(l.label)}</span><span class="lane-count">${fmt(l.clicks)} clicks, ${botNote}</span></div><div class="waffle${anim ? ' animate' : ''}" role="img" aria-label="${esc(l.label)}: ${fmt(l.human)} people, ${fmt(l.suspicious)} suspicious, ${fmt(l.bot)} bots">${sq('', h)}${sq('s', su)}${sq('b', b)}</div></li>`;
  }).join('');
  animateNext = false;
  const k = s.keitaro;
  const leaked = s.flowExposure ? s.flowExposure.botsInOtherFlows : null;
  $('#fs-cap').textContent = current.source === 'sample'
    ? `Synthetic sample: ${fmt(s.total)} clicks over three days from real browser user agents and real network ranges. Its "Is bot" column is simulated. ${leaked !== null ? `${fmt(leaked)} of ${fmt(s.bot)} bots ended up in offer flows.` : ''}`
    : `${fmt(s.total)} clicks.${k ? ` Keitaro flagged ${fmt(k.flaggedByKeitaro)}; ${fmt(k.botsKeitaroMissed)} more bots passed its flag.` : ''}${leaked !== null && s.flowExposure.botFlows.length ? ` ${fmt(leaked)} bots ended up outside the bot flow.` : ''}`;
}

function renderKpis(s) {
  const k = s.keitaro;
  const items = [
    ['', 'Clicks', fmt(s.total), ''],
    ['bot', 'Bots', fmt(s.bot), pct(s.bot / s.total)],
    ['sus', 'Suspicious', fmt(s.suspicious), pct(s.suspicious / s.total)],
    ['hum', 'People', fmt(s.human), pct(s.human / s.total)],
    k ? ['bot', "Bots the tracker's flag missed", fmt(k.botsKeitaroMissed), `of ${fmt(s.bot)}`] : ['', 'Leads from people', fmt(s.leads.human), s.leads.total ? `of ${fmt(s.leads.total)}` : ''],
  ];
  $('#kpis').innerHTML = items.map(([c, dt, dd, sm]) => `<div class="${c}"><dt>${esc(dt)}</dt><dd>${dd}${sm ? `<small>${esc(sm)}</small>` : ''}</dd></div>`).join('');
  const notes = [];
  if (s.cdnEdgeShare > 0.01) notes.push(`${pct(s.cdnEdgeShare)} of clicks come from Cloudflare edge addresses: the tracker is logging the proxy, not the visitor, so GEO, ISP and bot checks see the wrong IP.`);
  if (!s.timeRange) notes.push('No timestamp column, so the behaviour checks (repeat clicks, machine timing, subnet farms) were skipped.');
  if (current.source === 'sample') notes.push('Suspicious clicks are not counted as bots. They are mostly outdated browsers and the same visitor clicking 3 to 5 times in ten minutes.');
  $('#kpi-note').textContent = notes.join(' ');
}

function renderReasons(s) {
  const layers = ['user agent', 'network', 'behaviour'];
  const max = Math.max(1, ...Object.values(s.reasons));
  $('#reasons').innerHTML = layers.map((layer) => {
    const rows = Object.entries(s.reasons).filter(([r]) => REASONS[r].layer === layer).sort((a, b) => b[1] - a[1]);
    if (!rows.length) return '';
    return `<div class="layer"><p class="layer-h">${layer === 'user agent' ? 'User agent' : layer === 'network' ? 'Network' : 'Behaviour'}</p>${rows.map(([r, n]) => {
      const d = REASONS[r];
      return `<div class="rrow ${d.verdict}"><span class="rlabel">${esc(d.label)}<span class="rgivt">${d.verdict === 'bot' ? `Counted as bot: ${esc(d.givt)}` : 'Suspicious, not counted as bot'}</span></span><span class="rn">${fmt(n)}</span><span class="rbar"><i style="width:${(n / max) * 100}%"></i></span></div>`;
    }).join('')}</div>`;
  }).join('') || '<p class="hint">Nothing flagged.</p>';
}

function renderHourly(s) {
  const el = $('#hourly');
  if (!s.hourly.length) { el.innerHTML = '<p class="hint">No timestamps in this file.</p>'; return; }
  let buckets = s.hourly, unit = 'hour';
  if (buckets.length > 240) {
    const m = new Map();
    for (const b of buckets) { const d = Math.floor(b.t / 86400000) * 86400000; const e = m.get(d) || { t: d, human: 0, suspicious: 0, bot: 0 }; e.human += b.human; e.suspicious += b.suspicious; e.bot += b.bot; m.set(d, e); }
    buckets = [...m.values()]; unit = 'day';
  }
  const W = 560, H = 170, pad = 22, n = buckets.length;
  const max = Math.max(...buckets.map((b) => b.human + b.suspicious + b.bot));
  const bw = (W - 2) / n;
  const y = (v) => ((H - pad) * v) / max;
  const bars = buckets.map((b, i) => {
    const x = 1 + i * bw, w = Math.max(1, bw - (bw > 4 ? 1 : 0));
    let top = H - pad;
    const seg = (v, c) => { if (!v) return ''; const h = y(v); top -= h; return `<rect x="${x.toFixed(1)}" y="${top.toFixed(1)}" width="${w.toFixed(1)}" height="${h.toFixed(1)}" fill="var(--${c})"/>`; };
    return seg(b.human, 'human') + seg(b.suspicious, 'suspicious') + seg(b.bot, 'bot');
  }).join('');
  const days = buckets.filter((b) => unit === 'day' || new Date(b.t).getUTCHours() === 0);
  const labels = days.slice(0, 12).map((b) => { const i = buckets.indexOf(b); return `<text class="axis" x="${(1 + i * bw).toFixed(1)}" y="${H - 6}">${new Date(b.t).toISOString().slice(5, 10)}</text>`; }).join('');
  const peakBot = buckets.reduce((a, b) => (b.bot > a.bot ? b : a), buckets[0]);
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="Clicks per ${unit}: people, suspicious and bots stacked. Busiest ${unit} for bots: ${fmt(peakBot.bot)} bot clicks at ${new Date(peakBot.t).toISOString().slice(0, 13).replace('T', ' ')}:00 UTC">${bars}<line x1="0" x2="${W}" y1="${H - pad}" y2="${H - pad}" stroke="var(--rule)"/>${labels}</svg><p class="hint">Per ${unit}, UTC. Bot bursts that don't follow the daily rhythm usually come from one placement.</p>`;
}

function renderNetworks(s) {
  const nets = s.byNetwork.filter((n) => n.bot > 0).slice(0, 7);
  $('#networks').innerHTML = nets.map((n) => `<li><span class="n">${fmt(n.bot)}</span> ${esc(n.key)}</li>`).join('') || '<li>No bot traffic by network.</li>';
}

const shareCell = (x) => `<span class="share"><i><b style="width:${Math.min(100, x * 100).toFixed(1)}%"></b></i>${pct(x)}</span>`;

function renderSources(s) {
  const hasK = !!s.keitaro;
  const rows = s.bySource.slice(0, 20);
  $('#sources').innerHTML = `<thead><tr><th scope="col">Source</th><th scope="col" class="num">Clicks</th><th scope="col" class="num">Bots</th><th scope="col">Bot share</th><th scope="col" class="num">Suspicious</th>${hasK ? '<th scope="col" class="num">Bots past the tracker flag</th>' : ''}<th scope="col" class="num">Leads from people</th></tr></thead><tbody>${rows.map((r) => `<tr><th scope="row">${esc(r.key)}</th><td class="num">${fmt(r.clicks)}</td><td class="num">${fmt(r.bot)}</td><td>${shareCell(r.botShare)}</td><td class="num">${fmt(r.suspicious)}</td>${hasK ? `<td class="num">${fmt(r.passedKeitaro)}</td>` : ''}<td class="num">${fmt(r.leads)}</td></tr>`).join('')}</tbody>`;
}

function renderPlacements(list) {
  if (!list.length) { $('#placements').innerHTML = '<tbody><tr><td>No placement above the threshold, or no placement column in the file.</td></tr></tbody>'; return; }
  $('#placements').innerHTML = `<thead><tr><th scope="col">Source and placement</th><th scope="col" class="num">Clicks</th><th scope="col" class="num">Bots</th><th scope="col">Bot share</th><th scope="col">Main reason</th></tr></thead><tbody>${list.slice(0, 15).map((p) => `<tr><th scope="row">${esc(p.key)}</th><td class="num">${fmt(p.clicks)}</td><td class="num">${fmt(p.bot)}</td><td>${shareCell(p.botShare)}</td><td>${esc(REASONS[p.topReason] ? REASONS[p.topReason].label : '')}</td></tr>`).join('')}</tbody>`;
}

function renderOutputs(o) {
  const tabs = [
    { id: 'botlist', label: 'Bot list', where: '<b>Settings → Bot lists → Add.</b> One IP or CIDR per line; the Bot filter reads this list. These are the routed prefixes of data-center networks that sent bots in this log (Private Relay, published crawler and Meta ranges excluded).', blocks: [{ text: o.botList.text, label: 'Bot list lines' }], hint: `${fmt(o.botList.lines.length)} prefixes from ${fmt(o.botList.networks.length)} network ranges.` },
    { id: 'ipfilter', label: 'IP filter', where: '<b>Bot flow → Filters → IP, IS.</b> For a campaign-level block without touching the global list. Keitaro caps one filter at 65,534 characters, so long lists are split.', blocks: o.ipFilter.chunks.map((c, i, a) => ({ text: c, label: a.length > 1 ? `IP filter ${i + 1} of ${a.length}` : 'IP filter' })), hint: `${fmt(o.ipFilter.chunks.length)} filter${o.ipFilter.chunks.length === 1 ? '' : 's'}, each under 65,534 characters.` },
    { id: 'ua', label: 'User-agent filter', where: '<b>Bot flow → Filters → UserAgent, IS.</b> A PCRE between slashes, case-insensitive. The plain tokens below it go into Settings → Bot lists → Additional Bot signatures.', blocks: [{ text: o.userAgent.regex, label: 'UserAgent filter regex' }, { text: o.userAgent.signatures, label: 'Additional bot signatures' }], hint: `${fmt(o.userAgent.tokens.length)} tools and crawlers seen in this log.` },
    { id: 'flood', label: 'Flood IPs', where: '<b>Bot flow → Filters → IP, IS, for one week.</b> Home connections that clicked in bursts or at machine-regular intervals. Home IPs get reassigned, so remove these after a week.', blocks: (o.floodIps.filterChunks.length ? o.floodIps.filterChunks : ['']).map((c) => ({ text: c, label: 'Flood IPs' })), hint: `${fmt(o.floodIps.list.length)} addresses.` },
    { id: 'isp', label: 'ISP names', where: '<b>Filters → ISP.</b> Needs Keitaro Geo or IP2Location DB4. Names come from routing data; pick the matching names in Keitaro\'s list.', blocks: [{ text: o.ispNames.map((x) => `${x.name}\t${x.bots} bot clicks`).join('\n'), label: 'ISP names' }], hint: `${fmt(o.ispNames.length)} data-center networks.` },
  ];
  const tabsEl = $('#out-tabs'); const panel = $('#out-panel');
  tabsEl.innerHTML = tabs.map((t, i) => `<button type="button" role="tab" id="tab-${t.id}" aria-controls="out-panel" aria-selected="${i === 0}" tabindex="${i === 0 ? 0 : -1}">${esc(t.label)}</button>`).join('');
  const show = (i) => {
    const t = tabs[i];
    [...tabsEl.children].forEach((b, k) => { b.setAttribute('aria-selected', String(k === i)); b.tabIndex = k === i ? 0 : -1; });
    panel.setAttribute('aria-labelledby', `tab-${t.id}`);
    panel.innerHTML = `<p class="where">${t.where}</p>${t.blocks.map((b, k) => `${t.blocks.length > 1 ? `<p class="block-label">${esc(b.label)}</p>` : ''}<textarea readonly aria-label="${esc(b.label)}" spellcheck="false">${esc(b.text)}</textarea><div class="out-row"><p class="hint">${k === 0 ? esc(t.hint) + ' ' : ''}${fmt(b.text.length)} characters.</p><button type="button" class="btn copy" data-k="${k}" aria-label="Copy ${esc(b.label)}">Copy</button></div>`).join('')}`;
    panel.querySelectorAll('.copy').forEach((btn) => btn.addEventListener('click', async () => {
      const ta = panel.querySelectorAll('textarea')[Number(btn.dataset.k)];
      try { await navigator.clipboard.writeText(ta.value); } catch { ta.select(); document.execCommand('copy'); }
      const old = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = old; }, 1600);
    }));
  };
  [...tabsEl.children].forEach((b, i) => {
    b.addEventListener('click', () => show(i));
    b.addEventListener('keydown', (e) => {
      const k = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
      if (!k) return;
      const j = (i + k + tabs.length) % tabs.length; show(j); tabsEl.children[j].focus();
    });
  });
  show(0);
}

function renderClicks(res) {
  const sel = $('#reason-filter');
  const counts = res.summary.reasons;
  const opts = [['all', `All flagged (${fmt(res.flaggedTotal)})`], ['bot', `Bots only (${fmt(res.summary.bot)})`], ...Object.entries(counts).sort((a, b) => b[1] - a[1]).map(([r, n]) => [r, `${REASONS[r].label} (${fmt(n)})`])];
  sel.innerHTML = opts.map(([v, l]) => `<option value="${v}">${esc(l)}</option>`).join('');
  const draw = () => {
    const v = sel.value;
    const rows = res.flagged.filter((c) => v === 'all' || (v === 'bot' ? c.v === 'bot' : c.r.includes(v)));
    const shown = rows.slice(0, 150);
    $('#inspect-count').textContent = `Showing ${fmt(shown.length)} of ${fmt(rows.length)}${res.flagged.length < res.flaggedTotal ? ` (first ${fmt(res.flagged.length)} flagged clicks loaded)` : ''}.`;
    $('#clicks').innerHTML = `<thead><tr><th scope="col">Why</th><th scope="col">IP</th><th scope="col">Network</th><th scope="col">User agent</th><th scope="col">Source / placement</th></tr></thead><tbody>${shown.map((c) => `<tr><td>${c.r.map((r) => `<span class="tag ${REASONS[r].verdict}">${esc(REASONS[r].label.split(' (')[0])}</span>`).join('')}</td><td class="ip">${esc(c.ip)}</td><td>${esc(c.net)}</td><td class="ua">${esc(c.ua || '(empty)')}</td><td>${esc(c.src)}${c.pl ? ` / ${esc(c.pl)}` : ''}</td></tr>`).join('')}</tbody>`;
  };
  sel.onchange = draw;
  draw();
}

// ---------- audit sample ----------
async function renderAudit() {
  const r = await fetch('data/audit-sample.json');
  const a = await r.json();
  const sc = a.score;
  $('#audit-score').textContent = `${a.findings.length} findings on the sample tracker: ${sc.high} high, ${sc.medium} medium, ${sc.low} low, ${sc.info} info. The clean campaign has none.`;
  const sevs = [['all', 'All'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']];
  const chips = $('#sev-chips');
  chips.innerHTML = sevs.map(([v, l], i) => `<button type="button" aria-pressed="${i === 0}" data-sev="${v}">${l}${v !== 'all' ? ` (${sc[v]})` : ''}</button>`).join('');
  const draw = (sev) => {
    $('#findings').innerHTML = a.findings.filter((f) => sev === 'all' || f.severity === sev).map((f) => `<article class="finding ${f.severity}"><p class="f-meta"><span class="f-sev">${f.severity[0].toUpperCase() + f.severity.slice(1)}</span><span>${esc(f.rule)}</span><span>${esc(f.area)}</span></p><h4>${esc(f.title)}</h4><p class="f-ent">${esc(f.entity.name ?? '')}</p><p>${esc(f.detail)}</p><p class="f-fix"><b>Fix.</b> ${esc(f.fix)}</p><p class="f-where">${esc(f.where)}${f.source ? `. <a href="${esc(f.source)}">Keitaro docs</a>` : ''}</p></article>`).join('');
  };
  chips.querySelectorAll('button').forEach((b) => b.addEventListener('click', () => { chips.querySelectorAll('button').forEach((x) => x.setAttribute('aria-pressed', String(x === b))); draw(b.dataset.sev); }));
  draw('all');
}

async function renderMeasured() {
  const r = await fetch('data/measured.json');
  const m = await r.json();
  $('#measured-table tbody').innerHTML = m.lines.map(([a, b, c]) => `<tr><td>${esc(a)}</td><td>${esc(b)}</td><td>${esc(c)}</td></tr>`).join('');
}

// ---------- start ----------
renderAudit().catch(() => { $('#findings').textContent = "Couldn't load the sample audit."; });
renderMeasured().catch(() => {});
call({ type: 'warm' }).then((r) => {
  if (r.type === 'ready' && r.info && r.info.sources) $('#data-date').textContent = `Network data built ${r.info.built}: BGP origin table ${String(r.info.sources.origin_asn.version).split(' ')[1] || ''}, ${r.info.sources.hosting_asns.count} data-center networks, provider ranges ${String(r.info.sources.ranges.version).split(' ')[1] || ''}.`;
});
runSample(true);
