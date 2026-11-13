// Maps the headers of a click export to the fields the analyzer needs. Covers Keitaro's
// report column names in English and Russian plus the Admin API field names.

const norm = (h) => String(h).toLowerCase().replace(/[\s_\-.]+/g, ' ').trim();

export const FIELDS = {
  ip: { label: 'IP address', required: true, alias: [/^ip$/, /^ip ?address$/, /^visitor ip$/, /^client ip$/, /^ip адрес$/, /^ip-адрес$/] },
  ua: { label: 'User agent', required: true, alias: [/^user ?agent$/, /^useragent$/, /^ua$/, /^юзер ?агент$/] },
  time: { label: 'Date and time', alias: [/^datetime$/, /^date ?time$/, /^date and time$/, /^click time$/, /^created at$/, /^timestamp$/, /^time$/, /^date$/, /^дата и время$/, /^дата$/, /^время$/] },
  country: { label: 'Country', alias: [/^country$/, /^country ?code$/, /^страна$/] },
  isp: { label: 'ISP', alias: [/^isp$/, /^provider$/, /^isp name$/, /^провайдер$/] },
  connection: { label: 'Connection type', alias: [/^connection ?type$/, /^connection$/, /^тип соединения$/] },
  source: { label: 'Traffic source', alias: [/^traffic ?source$/, /^ts$/, /^ts ?id$/, /^source$/, /^источник( трафика)?$/] },
  campaign: { label: 'Campaign', alias: [/^campaign$/, /^campaign ?name$/, /^campaign ?id$/, /^кампания$/] },
  flow: { label: 'Flow', alias: [/^flow$/, /^stream$/, /^stream ?id$/, /^flow ?name$/, /^поток$/] },
  placement: { label: 'Placement (zone/site)', alias: [/^placement$/, /^zone( ?id)?$/, /^site( ?id)?$/, /^publisher( ?id)?$/, /^source ?id$/, /^sub ?id ?1$/] },
  subid: { label: 'Click ID (subid)', alias: [/^subid$/, /^sub ?id$/, /^click ?id$/] },
  referrer: { label: 'Referrer', alias: [/^referr?er$/, /^реферер$/] },
  language: { label: 'Language', alias: [/^language$/, /^язык$/] },
  isBot: { label: 'Keitaro "is bot" flag', alias: [/^is ?bot$/, /^bot$/, /^бот$/] },
  isProxy: { label: 'Keitaro "proxy" flag', alias: [/^is ?using ?proxy$/, /^proxy$/, /^is ?proxy$/, /^прокси$/] },
  isLead: { label: 'Lead/sale flag', alias: [/^is ?lead$/, /^is ?sale$/, /^conversion$/, /^is ?conversion$/, /^лид$/] },
};

export function autoMap(headers) {
  const map = {};
  const used = new Set();
  const normed = headers.map(norm);
  for (const [field, def] of Object.entries(FIELDS)) {
    for (const re of def.alias) {
      const idx = normed.findIndex((h, i) => !used.has(i) && re.test(h));
      if (idx >= 0) { map[field] = idx; used.add(idx); break; }
    }
  }
  return map;
}

export function missingRequired(map) {
  return Object.entries(FIELDS).filter(([f, d]) => d.required && map[f] === undefined).map(([f]) => f);
}

const TRUE = new Set(['1', 'true', 'yes', 'y', 'да', 't']);
export function parseFlag(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim().toLowerCase();
  if (s === '') return null;
  return TRUE.has(s);
}

// Accepts ISO, "YYYY-MM-DD HH:MM:SS", "DD.MM.YYYY HH:MM(:SS)", unix seconds or ms. Times without a
// zone are read as UTC (Keitaro exports in the report's time zone; the analysis only uses gaps).
export function parseTime(v) {
  if (v === undefined || v === null) return null;
  const s = String(v).trim();
  if (!s) return null;
  if (/^\d{9,10}$/.test(s)) return Number(s) * 1000;
  if (/^\d{12,13}$/.test(s)) return Number(s);
  let m = s.match(/^(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2})(?::(\d{2}))?(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?$/);
  if (m) {
    if (m[7]) { const t = Date.parse(s.replace(' ', 'T')); return Number.isNaN(t) ? null : t; }
    return Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0));
  }
  m = s.match(/^(\d{2})\.(\d{2})\.(\d{4})[ ,]+(\d{2}):(\d{2})(?::(\d{2}))?$/);
  if (m) return Date.UTC(+m[3], +m[2] - 1, +m[1], +m[4], +m[5], +(m[6] || 0));
  m = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (m) return Date.UTC(+m[1], +m[2] - 1, +m[3]);
  const t = Date.parse(s);
  return Number.isNaN(t) ? null : t;
}
