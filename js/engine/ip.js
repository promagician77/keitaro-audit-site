// IP parsing and range helpers shared by the browser and Node.
// IPv4 values are plain numbers (0..2^32-1). IPv6 values are BigInt.

export function parseIPv4(s) {
  if (typeof s !== 'string') return null;
  const parts = s.trim().split('.');
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = n * 256 + v;
  }
  return n;
}

export function parseIPv6(s) {
  if (typeof s !== 'string') return null;
  let str = s.trim();
  if (str.startsWith('[') && str.endsWith(']')) str = str.slice(1, -1);
  const zone = str.indexOf('%');
  if (zone >= 0) str = str.slice(0, zone);
  if (!str.includes(':')) return null;
  // Embedded IPv4 tail (e.g. ::ffff:1.2.3.4) becomes two hex groups.
  const lastColon = str.lastIndexOf(':');
  const maybeV4 = str.slice(lastColon + 1);
  if (maybeV4.includes('.')) {
    const v4 = parseIPv4(maybeV4);
    if (v4 === null) return null;
    str = str.slice(0, lastColon + 1) + ((v4 >>> 16) & 0xffff).toString(16) + ':' + (v4 & 0xffff).toString(16);
  }
  const dbl = str.split('::');
  if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const rest = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  let groups;
  if (dbl.length === 2) {
    const fill = 8 - head.length - rest.length;
    if (fill < 1) return null;
    groups = [...head, ...Array(fill).fill('0'), ...rest];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;
  let n = 0n;
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    n = (n << 16n) | BigInt(parseInt(g, 16));
  }
  return n;
}

export function parseIP(s) {
  if (s === null || s === undefined) return null;
  const str = String(s).trim();
  if (!str) return null;
  const v4 = parseIPv4(str);
  if (v4 !== null) return { v: 4, n: v4 };
  const v6 = parseIPv6(str);
  if (v6 !== null) {
    // IPv4-mapped IPv6 (::ffff:a.b.c.d) is treated as IPv4.
    if ((v6 >> 32n) === 0xffffn) return { v: 4, n: Number(v6 & 0xffffffffn) };
    return { v: 6, n: v6 };
  }
  return null;
}

export function v4ToString(n) {
  return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
}

export function v6ToString(n) {
  const g = [];
  for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn).toString(16));
  // compress the longest run of zero groups
  let best = -1, bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] === '0') {
      let j = i;
      while (j < 8 && g[j] === '0') j++;
      if (j - i > bestLen && j - i > 1) { best = i; bestLen = j - i; }
      i = j;
    } else i++;
  }
  if (best < 0) return g.join(':');
  const left = g.slice(0, best).join(':');
  const right = g.slice(best + bestLen).join(':');
  return `${left}::${right}`;
}

export function ipToString(ip) {
  return ip.v === 4 ? v4ToString(ip.n) : v6ToString(ip.n);
}

export function parseCIDR(s) {
  const [addr, lenStr] = String(s).trim().split('/');
  const ip = parseIP(addr);
  if (!ip) return null;
  const max = ip.v === 4 ? 32 : 128;
  const len = lenStr === undefined ? max : Number(lenStr);
  if (!Number.isInteger(len) || len < 0 || len > max) return null;
  if (ip.v === 4) {
    const size = 2 ** (32 - len);
    const start = Math.floor(ip.n / size) * size;
    return { v: 4, start, end: start + size - 1, len };
  }
  const hostBits = BigInt(128 - len);
  const mask = (1n << hostBits) - 1n;
  const start = ip.n & ~mask & ((1n << 128n) - 1n);
  return { v: 6, start, end: start | mask, len };
}

// Minimal list of CIDRs covering [start, end] (IPv4 numbers, inclusive).
export function v4RangeToCidrs(start, end) {
  const out = [];
  let cur = start;
  while (cur <= end) {
    let len = 32;
    // grow the block while aligned and inside the range
    while (len > 0) {
      const size = 2 ** (32 - (len - 1));
      if (cur % size !== 0 || cur + size - 1 > end) break;
      len--;
    }
    out.push(`${v4ToString(cur)}/${len}`);
    cur += 2 ** (32 - len);
  }
  return out;
}

export function v6RangeToCidrs(start, end) {
  const out = [];
  let cur = start;
  while (cur <= end) {
    let len = 128;
    while (len > 0) {
      const size = 1n << BigInt(128 - (len - 1));
      if (cur % size !== 0n || cur + size - 1n > end) break;
      len--;
    }
    out.push(`${v6ToString(cur)}/${len}`);
    cur += 1n << BigInt(128 - len);
  }
  return out;
}

// Network key used for "same subnet" grouping: /24 for IPv4, /64 for IPv6.
export function subnetKey(ip) {
  if (ip.v === 4) return `${v4ToString(Math.floor(ip.n / 256) * 256)}/24`;
  const net = (ip.n >> 64n) << 64n;
  return `${v6ToString(net)}/64`;
}

export function isPrivate(ip) {
  if (ip.v === 4) {
    const n = ip.n;
    const inR = (a, b) => n >= a && n <= b;
    return inR(0x0a000000, 0x0affffff) || inR(0xac100000, 0xac1fffff) || inR(0xc0a80000, 0xc0a8ffff) ||
      inR(0x7f000000, 0x7fffffff) || inR(0x64400000, 0x647fffff) || inR(0xa9fe0000, 0xa9feffff) || n === 0;
  }
  const top = ip.n >> 120n;
  return ip.n === 1n || ip.n === 0n || top === 0xfcn || top === 0xfdn || (ip.n >> 118n) === 0x3fan; // ::1, ULA, fe80::/10
}

// Sorted, non-overlapping range table lookup (binary search over starts).
export function findRange(starts, value) {
  let lo = 0, hi = starts.length - 1, ans = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    if (starts[mid] <= value) { ans = mid; lo = mid + 1; } else hi = mid - 1;
  }
  return ans;
}
