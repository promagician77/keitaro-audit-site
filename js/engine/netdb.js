// Network lookup: IP -> origin ASN, network name, hosting/VPN flags and
// provider-published special ranges (crawlers, iCloud Private Relay, Cloudflare edges).
import { parseIP, findRange } from './ip.js';

export const RANGE_PRIORITY = ['googlebot', 'bingbot', 'duckduckbot', 'openai', 'perplexity', 'meta', 'pingdom', 'statuscake', 'icloud_relay', 'cloudflare'];

function decodeV4(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const magic = String.fromCharCode(bytes[0], bytes[1], bytes[2]);
  if (magic !== 'KV4') throw new Error('netdb-v4: bad header');
  const version = dv.getUint32(4, true);
  const n = dv.getUint32(8, true);
  const starts = new Float64Array(n); // Float64 keeps full uint32 range and fast compares
  const asns = new Uint32Array(n);
  let acc = 0;
  for (let i = 0; i < n; i++) {
    const v = dv.getUint32(12 + i * 4, true);
    acc = version >= 2 ? (i ? acc + v : v) : v;
    starts[i] = acc;
  }
  for (let i = 0; i < n; i++) asns[i] = dv.getUint32(12 + n * 4 + i * 4, true);
  return { starts, asns };
}

export class NetDB {
  constructor({ v4, v6, meta, ranges, info }) {
    const { starts, asns } = decodeV4(v4);
    this.v4Starts = starts;
    this.v4Asns = asns;
    this.v6 = v6.map(([s, e, a]) => [BigInt('0x' + s), BigInt('0x' + e), a]);
    this.v6Starts = this.v6.map((r) => r[0]);
    this.meta = meta;
    this.info = info || {};
    this.ranges = {};
    for (const [tag, r] of Object.entries(ranges)) {
      this.ranges[tag] = {
        kind: r.kind, label: r.label,
        v4: r.v4, v4Starts: r.v4.map((x) => x[0]),
        v6: r.v6.map(([s, e]) => [BigInt('0x' + s), BigInt('0x' + e)]).sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0)),
      };
      this.ranges[tag].v6Starts = this.ranges[tag].v6.map((x) => x[0]);
    }
  }

  asnName(asn) { const m = this.meta[asn]; return m ? m[0] : ''; }
  asnFlags(asn) { const m = this.meta[asn]; return m && m[1] ? m[1] : ''; }

  specialRange(ip) {
    for (const tag of RANGE_PRIORITY) {
      const r = this.ranges[tag];
      if (!r) continue;
      if (ip.v === 4) {
        const i = findRange(r.v4Starts, ip.n);
        if (i >= 0 && ip.n <= r.v4[i][1]) return { tag, kind: r.kind, label: r.label, start: r.v4[i][0], end: r.v4[i][1] };
      } else {
        const i = findRange(r.v6Starts, ip.n);
        if (i >= 0 && ip.n <= r.v6[i][1]) return { tag, kind: r.kind, label: r.label, start: r.v6[i][0], end: r.v6[i][1] };
      }
    }
    return null;
  }

  // Returns network facts for one IP string (or parsed IP).
  lookup(ipIn) {
    const ip = typeof ipIn === 'string' ? parseIP(ipIn) : ipIn;
    if (!ip) return null;
    let asn = 0, start = null, end = null;
    if (ip.v === 4) {
      const i = findRange(this.v4Starts, ip.n);
      if (i >= 0) {
        asn = this.v4Asns[i];
        start = this.v4Starts[i];
        end = i + 1 < this.v4Starts.length ? this.v4Starts[i + 1] - 1 : 0xffffffff;
      }
    } else {
      const i = findRange(this.v6Starts, ip.n);
      if (i >= 0 && ip.n <= this.v6[i][1]) { asn = this.v6[i][2]; start = this.v6[i][0]; end = this.v6[i][1]; }
    }
    const flags = asn ? this.asnFlags(asn) : '';
    return {
      ip, asn, name: asn ? this.asnName(asn) : '',
      hosting: flags.includes('h'), vpn: flags.includes('v'), consumer: flags.includes('c'),
      rangeStart: start, rangeEnd: end,
      special: this.specialRange(ip),
    };
  }
}

// Node loader (tests, CLI). Reads engine/data/*.
export async function loadNetDBNode(dir) {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const base = dir || new URL('./data/', import.meta.url).pathname;
  const zlib = await import('node:zlib');
  const read = (f) => {
    const p = path.join(base, f);
    if (fs.existsSync(p)) return fs.readFileSync(p);
    return zlib.gunzipSync(fs.readFileSync(p + '.gz'));
  };
  return new NetDB({
    v4: new Uint8Array(read('netdb-v4.bin')),
    v6: JSON.parse(read('netdb-v6.json')),
    meta: JSON.parse(read('asn-meta.json')),
    ranges: JSON.parse(read('ranges.json')),
    info: JSON.parse(read('info.json')),
  });
}

// Browser loader: fetches the gzipped files and inflates them with DecompressionStream.
export async function loadNetDBBrowser(baseUrl, onProgress) {
  const get = async (name) => {
    const res = await fetch(baseUrl + name);
    if (!res.ok) throw new Error(`Couldn't load ${name} (HTTP ${res.status})`);
    let buf = await res.arrayBuffer();
    const head = new Uint8Array(buf, 0, 2);
    // Some hosts already undo the gzip layer (Content-Encoding); only inflate real gzip bytes.
    if (head[0] === 0x1f && head[1] === 0x8b) {
      const stream = new Blob([buf]).stream().pipeThrough(new DecompressionStream('gzip'));
      buf = await new Response(stream).arrayBuffer();
    }
    onProgress && onProgress(name);
    return buf;
  };
  const json = async (name) => JSON.parse(new TextDecoder().decode(await get(name)));
  const [v4, v6, meta, ranges] = await Promise.all([
    get('netdb-v4.bin.gz'), json('netdb-v6.json.gz'), json('asn-meta.json.gz'), json('ranges.json.gz'),
  ]);
  let info = {};
  try { info = await (await fetch(baseUrl + 'info.json')).json(); } catch { /* optional */ }
  return new NetDB({ v4: new Uint8Array(v4), v6, meta, ranges, info });
}
