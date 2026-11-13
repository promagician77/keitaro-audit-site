# Keitaro audit kit: demo site

Static site, no build step. Deploy this folder as is:

```bash
npx vercel --prod
```

`vercel.json` sets `framework: null`, `buildCommand: null`, `outputDirectory: "."` and sends
`X-Robots-Tag: noindex, nofollow` on every response (the page also carries a robots meta tag).

## What's on the page

- **Click-log analyzer** running in a Web Worker: a synthetic sample log loads on open; a visitor
  can open their own Keitaro click export (CSV) and it is read in the tab only, never uploaded.
  Results: verdicts and reasons, bots shown in Keitaro's flow order, sources and placements,
  paste-ready Keitaro values (bot list, IP filter, user-agent regex, flood IPs, ISP names) and a
  flagged-click inspector.
- **Read-only audit** output on a sample tracker (35 findings from 37 rules), with the commands to
  run it on a real tracker and a download of the kit (`downloads/keitaro-audit-kit.zip`).
- **Measured** and **Not measured** tables, the filtering playbook, sources.

## Files

- `index.html`, `style.css`, `js/app.js`, `js/worker.js`: the page
- `js/engine/`: the same engine modules the Node tests run (copied, `.mjs` → `.js`)
- `data/netdb/`: gzipped network tables (BGP origin ASNs, data-center list, published ranges)
- `data/sample/sample-clicks.csv`: synthetic sample log (6,455 clicks)
- `data/audit-sample.json`, `data/measured.json`: precomputed audit output and measurements
- `fonts/`: Red Hat Display, Text and Mono (OFL)

## Measured (Chromium, playwright-core)

- 25/25 browser checks: page numbers equal the Node analysis of the same file (6,455 clicks, 1,097
  bots, 317 suspicious, 5,041 people), analysis runs in a Web Worker, output tabs and copy button,
  arrow-key tabs, reason filter, severity filter, column-mapping form for unknown headers, a
  semicolon CSV with Russian headers, a user agent containing `<img onerror>` rendered as text,
  axe-core WCAG 2.1 AA 0 violations on desktop and on a 390 px phone, no horizontal overflow at
  390 px, touch targets 40 px or taller, reduced motion respected.
- Sample analyzed in under 200 ms in the tab; navigation to results under 1 s on localhost.
- 51,640 clicks analyzed in about 0.8 s.
- Analyzer and audit accuracy: see the Measured table on the page and the kit README.

## Not measured

- Safari and Firefox (Chromium only).
- Real network latency on Vercel. The page fetches about 1.3 MB of gzipped network data once.
- Real campaign traffic: the sample is synthetic and its "Is bot" column is simulated.
