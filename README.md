# Keitaro Audit Demo

38-check health report for Keitaro tracker installations.

## Measured

- 38 checks across 8 categories (Server, Domains, Campaigns, Flows, Offers, Bot Filtering, Filters, Performance)
- 42 / 42 automated test assertions pass across 4 fixture scenarios
- Weighted health score (0–100) with letter grade
- 5 severity tiers: critical, high, medium, low, info
- Each check returns status (pass / warn / fail / skip), a summary, detail, and a fix

## Not measured

- Against a live Keitaro instance (demo uses fixtures; the engine connects via the Admin API)
- Click-level data analysis (requires live data export)
- Landing-page load speed (requires headless browser)

## Deploy

```
npx vercel --prod
```

## Sources

- https://docs.keitaro.io/en/campaigns/filters.html
- https://docs.keitaro.io/en/development/admin-api.html
- https://docs.keitaro.io/en/settings/bot-lists.html
- https://docs.keitaro.io/en/maintenance/status.html
- https://blog.ishosting.com/en/keitaro-on-vps
- https://adsafee.com/blog/en/click-fraud-protection-affiliate-trackers/
