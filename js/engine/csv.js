// CSV reader for tracker exports: auto-detects the delimiter (comma, semicolon, tab),
// handles quotes, doubled quotes, CRLF and a UTF-8 BOM.

export function detectDelimiter(text) {
  const firstLine = text.slice(0, text.indexOf('\n') > 0 ? text.indexOf('\n') : text.length);
  const counts = { ',': 0, ';': 0, '\t': 0 };
  let q = false;
  for (const c of firstLine) {
    if (c === '"') q = !q;
    else if (!q && c in counts) counts[c]++;
  }
  return Object.entries(counts).sort((a, b) => b[1] - a[1])[0][1] > 0 ? Object.entries(counts).sort((a, b) => b[1] - a[1])[0][0] : ',';
}

export function parseCSV(input, opts = {}) {
  let text = String(input);
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1);
  const d = opts.delimiter || detectDelimiter(text);
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') { field += '"'; i++; } else q = false;
      } else field += c;
      continue;
    }
    if (c === '"' && field === '') { q = true; continue; }
    if (c === d) { row.push(field); field = ''; continue; }
    if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field); field = '';
      if (row.length > 1 || row[0] !== '') rows.push(row);
      row = [];
      continue;
    }
    field += c;
  }
  if (field !== '' || row.length) { row.push(field); if (row.length > 1 || row[0] !== '') rows.push(row); }
  const headers = rows.shift() || [];
  return { headers: headers.map((h) => h.trim()), rows, delimiter: d };
}

export function toCSV(headers, rows, delimiter = ',') {
  const esc = (v) => {
    const s = v === null || v === undefined ? '' : String(v);
    return /["\n\r]/.test(s) || s.includes(delimiter) ? '"' + s.replace(/"/g, '""') + '"' : s;
  };
  return [headers, ...rows].map((r) => r.map(esc).join(delimiter)).join('\n') + '\n';
}
