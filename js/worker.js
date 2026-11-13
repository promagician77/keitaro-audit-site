// Runs the analysis off the main thread. Same engine modules as the Node tests.
import { loadNetDBBrowser } from './engine/netdb.js';
import { parseCSV } from './engine/csv.js';
import { autoMap, missingRequired } from './engine/columns.js';
import { analyzeClicks } from './engine/analyze.js';
import { buildKeitaroOutputs } from './engine/keitaro-out.js';

let dbPromise = null;
const db = () => (dbPromise ||= loadNetDBBrowser(new URL('../data/netdb/', import.meta.url).href));

export async function handle(msg) {
  if (msg.type === 'warm') { const d = await db(); return { type: 'ready', info: d.info }; }
  if (msg.type !== 'analyze') return { type: 'error', message: 'unknown request' };
  const t0 = performance.now();
  const table = parseCSV(msg.text);
  if (!table.rows.length) return { type: 'error', message: 'The file has a header row but no clicks.' };
  const map = msg.map || autoMap(table.headers);
  const missing = missingRequired(map);
  if (missing.length) return { type: 'need-mapping', headers: table.headers, map, missing, rows: table.rows.length };
  const netdb = await db();
  const t1 = performance.now();
  const res = analyzeClicks(table, map, netdb);
  const outputs = buildKeitaroOutputs(res);
  const t2 = performance.now();
  const flaggedAll = res.clicks.filter((c) => c.verdict !== 'human');
  const flagged = flaggedAll.slice(0, 3000).map((c) => ({
    v: c.verdict, ip: c.ip, ua: String(c.ua).slice(0, 240), src: c.source, pl: c.placement, flow: c.flow, r: c.reasons,
    net: c.net && c.net.asn ? `AS${c.net.asn} ${c.net.name}`.trim() : c.isp || '', kb: c.keitaroBot, t: c.t,
  }));
  return {
    type: 'result', headers: table.headers, map, rows: table.rows.length, summary: res.summary, outputs,
    flagged, flaggedTotal: flaggedAll.length, timing: { totalMs: Math.round(t2 - t0), analyzeMs: Math.round(t2 - t1) },
  };
}

if (typeof self !== 'undefined' && typeof window === 'undefined') {
  self.onmessage = async (e) => {
    const { id } = e.data;
    try { self.postMessage({ id, ...(await handle(e.data)) }); }
    catch (err) { self.postMessage({ id, type: 'error', message: err && err.message ? err.message : String(err) }); }
  };
}
