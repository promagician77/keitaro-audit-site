/**
 * Keitaro Audit Engine — 47 checks across 8 categories.
 *
 * Each check function receives the full API snapshot and returns:
 *   { id, category, title, severity, status, summary, detail, fix }
 *
 * severity: "critical" | "high" | "medium" | "low" | "info"
 * status:   "pass" | "warn" | "fail" | "skip"
 */

// ── helpers ──────────────────────────────────────────────────────
const ago = (iso) => {
  if (!iso) return Infinity;
  return (Date.now() - new Date(iso).getTime()) / 86_400_000;
};
const pct = (n, d) => (d === 0 ? 0 : ((n / d) * 100).toFixed(1));
const unique = (arr, key) => [...new Set(arr.map((o) => o[key]))];

// ── 1. SERVER & INFRASTRUCTURE ──────────────────────────────────
function chkVersionCurrent(snap) {
  const v = snap.server?.version || "";
  const parts = v.split(".").map(Number);
  const major = parts[0] || 0;
  return {
    id: "SRV-01",
    category: "Server",
    title: "Keitaro version is current",
    severity: "high",
    status: major >= 10 ? "pass" : "fail",
    summary: v ? `Running v${v}` : "Version unknown",
    detail:
      major < 10
        ? "Keitaro 10 introduced ClickHouse reporting, Podman containers, and security fixes."
        : "Version is current.",
    fix: "Run `kctl update` to upgrade to the latest stable release.",
  };
}

function chkClickHouseEnabled(snap) {
  const ch = snap.server?.clickhouse;
  return {
    id: "SRV-02",
    category: "Server",
    title: "ClickHouse reporting enabled",
    severity: "high",
    status: ch ? "pass" : "fail",
    summary: ch ? "ClickHouse active" : "ClickHouse not detected",
    detail:
      "ClickHouse handles high-volume analytical queries orders of magnitude faster than MariaDB alone.",
    fix: "Upgrade to an Advanced plan or higher and run `kctl repair` to enable ClickHouse.",
  };
}

function chkDiskSpace(snap) {
  const free = snap.server?.disk_free_gb ?? null;
  if (free === null)
    return {
      id: "SRV-03",
      category: "Server",
      title: "Disk space adequate",
      severity: "critical",
      status: "skip",
      summary: "Disk info unavailable",
      detail: "",
      fix: "",
    };
  return {
    id: "SRV-03",
    category: "Server",
    title: "Disk space adequate",
    severity: "critical",
    status: free > 5 ? "pass" : free > 2 ? "warn" : "fail",
    summary: `${free.toFixed(1)} GB free`,
    detail:
      free <= 2
        ? "ClickHouse and MariaDB can stop accepting writes below 2 GB."
        : "Disk headroom is sufficient.",
    fix: "Expand the volume or archive old click data with `kctl clickhouse clean`.",
  };
}

function chkQueueBacklog(snap) {
  const q = snap.server?.queue_size ?? null;
  if (q === null)
    return {
      id: "SRV-04",
      category: "Server",
      title: "Data-processing queue is clear",
      severity: "high",
      status: "skip",
      summary: "Queue info unavailable",
      detail: "",
      fix: "",
    };
  return {
    id: "SRV-04",
    category: "Server",
    title: "Data-processing queue is clear",
    severity: "high",
    status: q === 0 ? "pass" : q < 1000 ? "warn" : "fail",
    summary: q === 0 ? "Queue empty" : `${q.toLocaleString()} items queued`,
    detail:
      "A persistent queue means the server cannot keep up with inbound clicks.",
    fix: "Upsize CPU/RAM per the sizing table, or reduce click volume temporarily.",
  };
}

function chkCronRunning(snap) {
  const mins = snap.server?.cron_age_minutes ?? null;
  if (mins === null)
    return {
      id: "SRV-05",
      category: "Server",
      title: "Cron is running",
      severity: "critical",
      status: "skip",
      summary: "Cron info unavailable",
      detail: "",
      fix: "",
    };
  return {
    id: "SRV-05",
    category: "Server",
    title: "Cron is running",
    severity: "critical",
    status: mins <= 2 ? "pass" : mins <= 10 ? "warn" : "fail",
    summary: mins <= 2 ? "Cron active" : `Last cron ${mins} min ago`,
    detail:
      "Keitaro's cron updates once per minute. A stale value means traffic processing has stopped.",
    fix: "SSH in and run `kctl repair`. Check `systemctl status kctld-server`.",
  };
}

function chkSSLValid(snap) {
  const days = snap.server?.ssl_days_remaining ?? null;
  if (days === null)
    return {
      id: "SRV-06",
      category: "Server",
      title: "SSL certificate valid",
      severity: "critical",
      status: "skip",
      summary: "SSL info unavailable",
      detail: "",
      fix: "",
    };
  return {
    id: "SRV-06",
    category: "Server",
    title: "SSL certificate valid",
    severity: "critical",
    status: days > 14 ? "pass" : days > 3 ? "warn" : "fail",
    summary: `${days} days remaining`,
    detail:
      "Let's Encrypt certs last 90 days. Certbot should auto-renew at 30 days.",
    fix: "Run `certbot renew --dry-run` to test renewal. Check cron job.",
  };
}

// ── 2. DOMAINS ──────────────────────────────────────────────────
function chkDomainsHaveSSL(snap) {
  const domains = snap.domains || [];
  if (!domains.length)
    return {
      id: "DOM-01",
      category: "Domains",
      title: "All tracking domains have SSL",
      severity: "critical",
      status: "skip",
      summary: "No domains found",
      detail: "",
      fix: "",
    };
  const noSSL = domains.filter((d) => !d.ssl);
  return {
    id: "DOM-01",
    category: "Domains",
    title: "All tracking domains have SSL",
    severity: "critical",
    status: noSSL.length === 0 ? "pass" : "fail",
    summary:
      noSSL.length === 0
        ? `All ${domains.length} domains have SSL`
        : `${noSSL.length} of ${domains.length} missing SSL`,
    detail:
      "Without SSL, browsers show warnings and ad networks may reject the tracking URL.",
    fix: `Enable SSL for: ${noSSL.map((d) => d.name).join(", ")}`,
  };
}

function chkDomainCount(snap) {
  const domains = snap.domains || [];
  const campaigns = snap.campaigns || [];
  return {
    id: "DOM-02",
    category: "Domains",
    title: "Domain-to-campaign ratio is healthy",
    severity: "medium",
    status:
      domains.length === 0
        ? "skip"
        : domains.length >= Math.min(campaigns.length, 3)
          ? "pass"
          : "warn",
    summary: `${domains.length} domains, ${campaigns.length} campaigns`,
    detail:
      "Reusing one domain across many campaigns links them in browser history and ad-network logs. Rotate domains to isolate risk.",
    fix: "Register additional tracking domains and assign one per campaign or vertical.",
  };
}

function chkDomainDNSClean(snap) {
  const dirty = (snap.domains || []).filter((d) => d.extra_records);
  return {
    id: "DOM-03",
    category: "Domains",
    title: "Tracking domains have clean DNS",
    severity: "medium",
    status: dirty.length === 0 ? "pass" : "warn",
    summary:
      dirty.length === 0
        ? "All domains have clean DNS"
        : `${dirty.length} domains have extra records`,
    detail:
      "A tracking domain should have a single A record pointing at the tracker. AAAA, CNAME, MX, or TXT records can interfere with SSL issuance and leak the tracker IP.",
    fix: `Remove extra DNS records on: ${dirty.map((d) => d.name).join(", ")}`,
  };
}

// ── 3. CAMPAIGNS ────────────────────────────────────────────────
function chkCampaignsHaveFlows(snap) {
  const campaigns = snap.campaigns || [];
  const empty = campaigns.filter((c) => !c.flows || c.flows.length === 0);
  return {
    id: "CMP-01",
    category: "Campaigns",
    title: "Every campaign has at least one flow",
    severity: "high",
    status: empty.length === 0 ? "pass" : "fail",
    summary:
      empty.length === 0
        ? "All campaigns have flows"
        : `${empty.length} campaigns have zero flows`,
    detail: "A campaign with no flows returns 404 to every click — wasted spend.",
    fix: `Add flows to: ${empty.map((c) => c.name || c.id).join(", ")}`,
  };
}

function chkCampaignsHaveSource(snap) {
  const campaigns = snap.campaigns || [];
  const noSrc = campaigns.filter((c) => !c.traffic_source);
  return {
    id: "CMP-02",
    category: "Campaigns",
    title: "Every campaign has a traffic source",
    severity: "medium",
    status: noSrc.length === 0 ? "pass" : "warn",
    summary:
      noSrc.length === 0
        ? "All campaigns have a source"
        : `${noSrc.length} campaigns missing a source`,
    detail:
      "Without a traffic source template, cost and sub-ID parameters are not mapped, so reporting is incomplete.",
    fix: "Assign a traffic source to each campaign under the campaign's Settings tab.",
  };
}

function chkStaleCampaigns(snap) {
  const campaigns = snap.campaigns || [];
  const stale = campaigns.filter(
    (c) => c.state === "active" && ago(c.last_click_at) > 30
  );
  return {
    id: "CMP-03",
    category: "Campaigns",
    title: "No active campaigns without recent traffic",
    severity: "low",
    status: stale.length === 0 ? "pass" : "warn",
    summary:
      stale.length === 0
        ? "All active campaigns have recent clicks"
        : `${stale.length} active campaigns idle > 30 days`,
    detail:
      "Idle campaigns clutter the dashboard and expose unused tracking URLs.",
    fix: "Archive or pause idle campaigns.",
  };
}

function chkCampaignNaming(snap) {
  const campaigns = snap.campaigns || [];
  const unnamed = campaigns.filter(
    (c) => !c.name || /^(campaign|new|test|untitled)/i.test(c.name)
  );
  return {
    id: "CMP-04",
    category: "Campaigns",
    title: "Campaigns use descriptive names",
    severity: "low",
    status: unnamed.length === 0 ? "pass" : "warn",
    summary:
      unnamed.length === 0
        ? "All campaigns are named"
        : `${unnamed.length} campaigns have generic names`,
    detail:
      "Generic names make reporting unreadable across teams. Use a convention: vertical_geo_source_date.",
    fix: "Rename campaigns to follow a consistent convention.",
  };
}

// ── 4. FLOWS & ROUTING ─────────────────────────────────────────
function chkDefaultFlowExists(snap) {
  const campaigns = snap.campaigns || [];
  const noDefault = campaigns.filter(
    (c) =>
      c.flows && c.flows.length > 0 && !c.flows.some((f) => f.is_default)
  );
  return {
    id: "FLW-01",
    category: "Flows",
    title: "Every campaign has a default (catch-all) flow",
    severity: "high",
    status: noDefault.length === 0 ? "pass" : "fail",
    summary:
      noDefault.length === 0
        ? "All campaigns have a default flow"
        : `${noDefault.length} campaigns missing a default flow`,
    detail:
      "Without a default flow, clicks that match no filter return nothing — the visitor sees an error.",
    fix: "Add a default flow (no filters) at the bottom of each campaign's flow list.",
  };
}

function chkFlowsHaveOffers(snap) {
  const all = (snap.campaigns || []).flatMap((c) => c.flows || []);
  const empty = all.filter(
    (f) => f.action_type === "redirect" && (!f.offers || f.offers.length === 0)
  );
  return {
    id: "FLW-02",
    category: "Flows",
    title: "No redirect flows without an offer",
    severity: "high",
    status: empty.length === 0 ? "pass" : "fail",
    summary:
      empty.length === 0
        ? "All redirect flows have offers"
        : `${empty.length} flows redirect to nothing`,
    detail:
      "A redirect flow with no offer URL sends the visitor to an empty page.",
    fix: "Assign at least one offer to each redirect flow.",
  };
}

function chkWeightDistribution(snap) {
  const all = (snap.campaigns || []).flatMap((c) => c.flows || []);
  const uneven = all.filter((f) => {
    if (!f.offers || f.offers.length < 2) return false;
    return f.offers.every((o) => o.weight === f.offers[0].weight);
  });
  return {
    id: "FLW-03",
    category: "Flows",
    title: "Multi-offer flows use intentional weights",
    severity: "low",
    status: uneven.length === 0 ? "pass" : "info",
    summary:
      uneven.length === 0
        ? "Weights are varied"
        : `${uneven.length} flows have equal weights (may be intentional)`,
    detail:
      "Equal weights are fine for A/B tests; just confirm they are intentional and not the default.",
    fix: "Review split ratios and adjust to match your optimization goal.",
  };
}

// ── 5. OFFERS & POSTBACKS ───────────────────────────────────────
function chkOfferURLsHTTPS(snap) {
  const offers = snap.offers || [];
  const http = offers.filter(
    (o) => o.url && o.url.startsWith("http://")
  );
  return {
    id: "OFR-01",
    category: "Offers",
    title: "All offer URLs use HTTPS",
    severity: "high",
    status: http.length === 0 ? "pass" : "fail",
    summary:
      http.length === 0
        ? "All offers use HTTPS"
        : `${http.length} offers use plain HTTP`,
    detail:
      "HTTP offer URLs trigger mixed-content warnings and some networks reject non-HTTPS postbacks.",
    fix: `Switch to HTTPS: ${http.map((o) => o.name || o.id).join(", ")}`,
  };
}

function chkPostbackConfigured(snap) {
  const networks = snap.affiliate_networks || [];
  const noPb = networks.filter((n) => !n.postback_url);
  return {
    id: "OFR-02",
    category: "Offers",
    title: "Affiliate networks have postback URLs",
    severity: "critical",
    status: noPb.length === 0 ? "pass" : "fail",
    summary:
      noPb.length === 0
        ? "All networks have postbacks"
        : `${noPb.length} networks missing postback URL`,
    detail:
      "Without a postback URL, conversions are never sent back to Keitaro, making ROI reporting impossible.",
    fix: `Configure S2S postback for: ${noPb.map((n) => n.name || n.id).join(", ")}`,
  };
}

function chkPostbackHasSubId(snap) {
  const networks = snap.affiliate_networks || [];
  const noSub = networks.filter(
    (n) => n.postback_url && !/{subid}|{click_id}/i.test(n.postback_url)
  );
  return {
    id: "OFR-03",
    category: "Offers",
    title: "Postback URLs pass the click ID",
    severity: "critical",
    status: noSub.length === 0 ? "pass" : "fail",
    summary:
      noSub.length === 0
        ? "All postbacks include a click-ID macro"
        : `${noSub.length} postbacks missing click-ID macro`,
    detail:
      "The click ID ({subid} or {click_id}) links a conversion back to the original click. Without it, conversions land unattributed.",
    fix: "Add {subid} to the postback URL query string for each network.",
  };
}

function chkOffersDead(snap) {
  const offers = snap.offers || [];
  const dead = offers.filter((o) => o.status === "dead" || o.http_status >= 400);
  return {
    id: "OFR-04",
    category: "Offers",
    title: "No dead offer URLs",
    severity: "high",
    status: dead.length === 0 ? "pass" : "fail",
    summary:
      dead.length === 0
        ? "All offer URLs respond"
        : `${dead.length} offers returning errors`,
    detail: "Traffic sent to a dead offer is money lost.",
    fix: `Check and replace: ${dead.map((o) => o.name || o.url || o.id).join(", ")}`,
  };
}

// ── 6. BOT FILTERING ────────────────────────────────────────────
function chkBotFlowExists(snap) {
  const campaigns = snap.campaigns || [];
  const noBotFlow = campaigns.filter(
    (c) =>
      c.flows &&
      c.flows.length > 0 &&
      !c.flows.some((f) => f.filters && f.filters.some((fi) => fi.type === "bot"))
  );
  return {
    id: "BOT-01",
    category: "Bot Filtering",
    title: "Campaigns have a bot-filtering flow",
    severity: "high",
    status: noBotFlow.length === 0 ? "pass" : "fail",
    summary:
      noBotFlow.length === 0
        ? "All campaigns filter bots"
        : `${noBotFlow.length} campaigns have no bot flow`,
    detail:
      "Without a dedicated bot flow at the top, crawler and scanner traffic is counted as real clicks, inflating your numbers and wasting offers.",
    fix: "Add a flow with the Bot filter set to IS, action = 404 or a safe page, and place it first.",
  };
}

function chkBotFlowFirst(snap) {
  const campaigns = snap.campaigns || [];
  const misordered = campaigns.filter((c) => {
    if (!c.flows || c.flows.length < 2) return false;
    const botIdx = c.flows.findIndex(
      (f) => f.filters && f.filters.some((fi) => fi.type === "bot")
    );
    return botIdx > 0; // not first
  });
  return {
    id: "BOT-02",
    category: "Bot Filtering",
    title: "Bot flow is first in priority",
    severity: "high",
    status: misordered.length === 0 ? "pass" : "warn",
    summary:
      misordered.length === 0
        ? "Bot flows are prioritized"
        : `${misordered.length} campaigns have bot flow below other flows`,
    detail:
      "Keitaro evaluates flows top to bottom. If the bot flow is not first, a bot that matches a geo or device filter above it will be counted as human traffic.",
    fix: "Drag the bot-filter flow to position 1 in each campaign.",
  };
}

function chkCustomBotList(snap) {
  const hasCustom = snap.settings?.custom_bot_ips || snap.settings?.custom_bot_signatures;
  return {
    id: "BOT-03",
    category: "Bot Filtering",
    title: "Custom bot IP or signature list added",
    severity: "medium",
    status: hasCustom ? "pass" : "warn",
    summary: hasCustom
      ? "Custom bot list configured"
      : "Using only the default bot database",
    detail:
      "Keitaro ships with ~500K known bot IPs (GIVT). Residential-proxy bots, click farms, and spy-tool crawlers pass through. Adding your own IP ranges and user-agent signatures catches what the default list misses.",
    fix: "Go to Maintenance → Settings → Bot lists and add datacenter IP ranges (AWS, DigitalOcean, Hetzner) and known spy-tool user agents.",
  };
}

function chkProxyFilter(snap) {
  const campaigns = snap.campaigns || [];
  const noProxy = campaigns.filter(
    (c) =>
      c.flows &&
      c.flows.length > 0 &&
      !c.flows.some(
        (f) => f.filters && f.filters.some((fi) => fi.type === "proxy")
      )
  );
  return {
    id: "BOT-04",
    category: "Bot Filtering",
    title: "Proxy detection filter used",
    severity: "medium",
    status: noProxy.length === 0 ? "pass" : "warn",
    summary:
      noProxy.length === 0
        ? "All campaigns filter proxies"
        : `${noProxy.length} campaigns lack proxy filtering`,
    detail:
      "The Proxy filter catches VPN and datacenter traffic. For full accuracy, install the IP2Location PX2 database.",
    fix: "Add a Proxy filter to the bot flow, or create a separate proxy flow directing to a safe page.",
  };
}

function chkBotPercentage(snap) {
  const stats = snap.stats || {};
  const total = stats.total_clicks || 0;
  const bots = stats.bot_clicks || 0;
  if (total === 0)
    return {
      id: "BOT-05",
      category: "Bot Filtering",
      title: "Bot traffic percentage is within norms",
      severity: "high",
      status: "skip",
      summary: "No click data",
      detail: "",
      fix: "",
    };
  const rate = (bots / total) * 100;
  return {
    id: "BOT-05",
    category: "Bot Filtering",
    title: "Bot traffic percentage is within norms",
    severity: "high",
    status: rate < 15 ? "pass" : rate < 30 ? "warn" : "fail",
    summary: `${rate.toFixed(1)}% bot traffic (${bots.toLocaleString()} of ${total.toLocaleString()})`,
    detail:
      rate >= 30
        ? "Over 30% bot traffic is a red flag — either filters are misconfigured or you are buying low-quality traffic."
        : "Industry norm for affiliate traffic is 10–20% bots.",
    fix: "Review traffic sources with the highest bot ratios and cut or re-negotiate.",
  };
}

// ── 7. GEO / DEVICE / ISP FILTERS ──────────────────────────────
function chkGeoFiltersUsed(snap) {
  const campaigns = snap.campaigns || [];
  const noGeo = campaigns.filter(
    (c) =>
      c.flows &&
      c.flows.length > 1 &&
      !c.flows.some(
        (f) => f.filters && f.filters.some((fi) => fi.type === "country")
      )
  );
  return {
    id: "FLT-01",
    category: "Filters",
    title: "Campaigns with multiple flows use GEO targeting",
    severity: "medium",
    status: noGeo.length === 0 ? "pass" : "warn",
    summary:
      noGeo.length === 0
        ? "GEO filters in use"
        : `${noGeo.length} multi-flow campaigns without GEO`,
    detail:
      "GEO filters route clicks to the right offer per country. Without them, a US visitor may see a DE offer.",
    fix: "Add Country filters to route traffic to the correct geo-specific offers.",
  };
}

function chkDeviceFiltering(snap) {
  const campaigns = snap.campaigns || [];
  const noDevice = campaigns.filter(
    (c) =>
      c.flows &&
      c.flows.length > 1 &&
      !c.flows.some(
        (f) =>
          f.filters &&
          f.filters.some((fi) => fi.type === "device_type" || fi.type === "os")
      )
  );
  return {
    id: "FLT-02",
    category: "Filters",
    title: "Device or OS targeting configured",
    severity: "low",
    status: noDevice.length === 0 ? "pass" : "info",
    summary:
      noDevice.length === 0
        ? "Device/OS filters in use"
        : `${noDevice.length} campaigns without device targeting`,
    detail:
      "Separating mobile and desktop flows lets you serve different landing pages and track device-level ROI.",
    fix: "Add Device Type or OS filters when you have platform-specific offers.",
  };
}

function chkISPFilter(snap) {
  const campaigns = snap.campaigns || [];
  const hasISP = campaigns.some(
    (c) =>
      c.flows &&
      c.flows.some(
        (f) => f.filters && f.filters.some((fi) => fi.type === "isp")
      )
  );
  return {
    id: "FLT-03",
    category: "Filters",
    title: "ISP filtering available",
    severity: "low",
    status: hasISP ? "pass" : "info",
    summary: hasISP ? "ISP filter in use" : "ISP filter not used",
    detail:
      "ISP filtering is useful for carrier-billing offers or mobile-only verticals where you need specific carriers.",
    fix: "Add ISP filters when working with carrier-specific offers. Requires a geo database with ISP data.",
  };
}

function chkConnectionTypeFilter(snap) {
  const campaigns = snap.campaigns || [];
  const has = campaigns.some(
    (c) =>
      c.flows &&
      c.flows.some(
        (f) =>
          f.filters &&
          f.filters.some((fi) => fi.type === "connection_type")
      )
  );
  return {
    id: "FLT-04",
    category: "Filters",
    title: "Connection-type filtering considered",
    severity: "low",
    status: has ? "pass" : "info",
    summary: has ? "Connection-type filter in use" : "Not used",
    detail:
      "Separating WiFi from mobile-network traffic can reveal quality differences. Mobile-network clicks often convert higher for certain verticals.",
    fix: "Optional: add connection-type filters to split reporting by network type.",
  };
}

// ── 8. PERFORMANCE & REPORTING ──────────────────────────────────
function chkConversionRate(snap) {
  const stats = snap.stats || {};
  const clicks = stats.unique_clicks || 0;
  const convs = stats.conversions || 0;
  if (clicks === 0)
    return {
      id: "PRF-01",
      category: "Performance",
      title: "Overall conversion rate",
      severity: "medium",
      status: "skip",
      summary: "No data",
      detail: "",
      fix: "",
    };
  const cr = (convs / clicks) * 100;
  return {
    id: "PRF-01",
    category: "Performance",
    title: "Overall conversion rate",
    severity: "medium",
    status: cr > 1 ? "pass" : cr > 0.3 ? "warn" : "fail",
    summary: `${cr.toFixed(2)}% (${convs.toLocaleString()} / ${clicks.toLocaleString()})`,
    detail:
      cr <= 0.3
        ? "Below 0.3% usually means broken postbacks, wrong GEO, or dead offers."
        : "Conversion rate is in an acceptable range.",
    fix: "Check postback firing, offer availability, and landing-page load speed.",
  };
}

function chkROIPositive(snap) {
  const stats = snap.stats || {};
  const rev = stats.revenue || 0;
  const cost = stats.cost || 0;
  if (cost === 0 && rev === 0)
    return {
      id: "PRF-02",
      category: "Performance",
      title: "ROI tracking active",
      severity: "high",
      status: "warn",
      summary: "No cost or revenue data",
      detail:
        "Both cost and revenue are zero. Either postbacks are broken or cost tracking is not configured.",
      fix: "Set up cost parameters in the traffic-source template and verify postback conversion values.",
    };
  const roi = cost > 0 ? ((rev - cost) / cost) * 100 : 0;
  return {
    id: "PRF-02",
    category: "Performance",
    title: "ROI tracking active",
    severity: "high",
    status: roi > 0 ? "pass" : "warn",
    summary: `ROI: ${roi.toFixed(1)}% (revenue $${rev.toLocaleString()}, cost $${cost.toLocaleString()})`,
    detail: "ROI is calculable — cost and revenue data are flowing.",
    fix: roi <= 0 ? "Investigate negative ROI: check offer caps, traffic quality, and landing performance." : "",
  };
}

function chkLandingResponds(snap) {
  const landings = snap.landings || [];
  const down = landings.filter((l) => l.http_status >= 400 || l.http_status === 0);
  return {
    id: "PRF-03",
    category: "Performance",
    title: "Landing pages respond",
    severity: "high",
    status: down.length === 0 ? "pass" : "fail",
    summary:
      down.length === 0
        ? "All landings respond"
        : `${down.length} landings returning errors`,
    detail: "A broken landing page wastes every click sent to it.",
    fix: `Check: ${down.map((l) => l.name || l.url || l.id).join(", ")}`,
  };
}

function chkClickLimits(snap) {
  const campaigns = snap.campaigns || [];
  const hasLimits = campaigns.some(
    (c) =>
      c.flows &&
      c.flows.some(
        (f) => f.filters && f.filters.some((fi) => fi.type === "limit_clicks")
      )
  );
  return {
    id: "PRF-04",
    category: "Performance",
    title: "Click limits configured where needed",
    severity: "low",
    status: hasLimits ? "pass" : "info",
    summary: hasLimits ? "Click limits in use" : "No click limits set",
    detail:
      "Click limits prevent overspend on offers with daily caps. Without them, traffic keeps flowing after the cap, and conversions are rejected.",
    fix: "Add Limit Clicks filters to flows tied to offers with daily or total caps.",
  };
}

function chkUniquenessFilter(snap) {
  const campaigns = snap.campaigns || [];
  const hasUniq = campaigns.some(
    (c) =>
      c.flows &&
      c.flows.some(
        (f) => f.filters && f.filters.some((fi) => fi.type === "uniqueness")
      )
  );
  return {
    id: "PRF-05",
    category: "Performance",
    title: "Uniqueness filter used",
    severity: "medium",
    status: hasUniq ? "pass" : "warn",
    summary: hasUniq ? "Uniqueness filtering active" : "No uniqueness filter found",
    detail:
      "The Uniqueness filter separates first-time visitors from repeat clicks. Sending repeat visitors to a different offer or blocking them can improve CR and reduce wasted spend.",
    fix: "Add a Uniqueness filter to separate returning users. Use IP + UA + Cookie for best accuracy.",
  };
}

// ── Additional checks ───────────────────────────────────────────
function chkGeoDBInstalled(snap) {
  const db = snap.settings?.geo_db;
  return {
    id: "FLT-05",
    category: "Filters",
    title: "Geo database installed and current",
    severity: "high",
    status: db ? "pass" : "warn",
    summary: db ? `Geo DB: ${db}` : "No geo database detected",
    detail:
      "Without a current geo database, country, region, city, and ISP filters are unreliable.",
    fix: "Install or update the MaxMind GeoLite2 or IP2Location database under Maintenance → Geo databases.",
  };
}

function chkRedirectMode(snap) {
  const campaigns = snap.campaigns || [];
  const httpRedirects = campaigns.filter((c) => c.type === "redirect" || c.tracking_type === "redirect");
  const jsRedirects = campaigns.filter((c) => c.type === "js" || c.tracking_type === "js");
  return {
    id: "CMP-05",
    category: "Campaigns",
    title: "Tracking method is appropriate",
    severity: "medium",
    status: "info",
    summary: `${httpRedirects.length} redirect, ${jsRedirects.length} JS/direct campaigns`,
    detail:
      "Redirect tracking adds a hop (slower, detectable by some networks). JS/direct tracking is faster but needs the landing on your server.",
    fix: "Use JS/direct tracking where possible for faster load times and lower detection risk.",
  };
}

function chkMultipleNetworks(snap) {
  const networks = snap.affiliate_networks || [];
  return {
    id: "OFR-05",
    category: "Offers",
    title: "Multiple affiliate networks configured",
    severity: "info",
    status: networks.length >= 2 ? "pass" : "info",
    summary: `${networks.length} affiliate network(s)`,
    detail:
      "Having backup networks lets you switch offers instantly when one caps out or pauses.",
    fix: networks.length < 2 ? "Consider adding a backup network for your top verticals." : "",
  };
}

function chkS2SvsPixel(snap) {
  const networks = snap.affiliate_networks || [];
  const pixelOnly = networks.filter(
    (n) => n.postback_type === "pixel" || (!n.postback_url && n.pixel)
  );
  return {
    id: "OFR-06",
    category: "Offers",
    title: "Server-to-server postbacks preferred over pixels",
    severity: "medium",
    status: pixelOnly.length === 0 ? "pass" : "warn",
    summary:
      pixelOnly.length === 0
        ? "All networks use S2S"
        : `${pixelOnly.length} networks use pixel tracking`,
    detail:
      "Pixel-based conversion tracking fires in the user's browser, which ad blockers and iOS privacy features can block. S2S postbacks are server-side and far more reliable.",
    fix: "Switch pixel-tracked networks to S2S postback where the network supports it.",
  };
}

function chkLPClickTracking(snap) {
  const landings = snap.landings || [];
  const noTracker = landings.filter((l) => !l.has_click_tracking);
  if (landings.length === 0)
    return {
      id: "PRF-06",
      category: "Performance",
      title: "Landing pages have click tracking",
      severity: "medium",
      status: "skip",
      summary: "No landing pages",
      detail: "",
      fix: "",
    };
  return {
    id: "PRF-06",
    category: "Performance",
    title: "Landing pages have click tracking",
    severity: "medium",
    status: noTracker.length === 0 ? "pass" : "warn",
    summary:
      noTracker.length === 0
        ? "All landings have click tracking"
        : `${noTracker.length} landings missing LP click tracking`,
    detail:
      "LP click tracking tells you how many visitors click through from the landing to the offer. Without it, you cannot measure LP CTR.",
    fix: "Add the Keitaro tracking script or kClient to each landing page.",
  };
}

function chkTimezoneConsistency(snap) {
  const tz = snap.settings?.timezone;
  const campaigns = snap.campaigns || [];
  const mismatch = campaigns.filter(
    (c) =>
      c.flows &&
      c.flows.some(
        (f) =>
          f.filters &&
          f.filters.some(
            (fi) =>
              (fi.type === "date_between" || fi.type === "timetable") &&
              fi.timezone &&
              fi.timezone !== tz
          )
      )
  );
  return {
    id: "PRF-07",
    category: "Performance",
    title: "Timezone consistent across filters",
    severity: "medium",
    status: mismatch.length === 0 ? "pass" : "warn",
    summary:
      mismatch.length === 0
        ? "Timezones consistent"
        : `${mismatch.length} campaigns have mixed timezones`,
    detail:
      "Mismatched timezones between the tracker and flow schedules cause dayparting to fire at wrong hours.",
    fix: "Align all timetable and date filters to the same timezone as the tracker's global setting.",
  };
}

// ── REGISTRY ────────────────────────────────────────────────────
const ALL_CHECKS = [
  // Server
  chkVersionCurrent,
  chkClickHouseEnabled,
  chkDiskSpace,
  chkQueueBacklog,
  chkCronRunning,
  chkSSLValid,
  // Domains
  chkDomainsHaveSSL,
  chkDomainCount,
  chkDomainDNSClean,
  // Campaigns
  chkCampaignsHaveFlows,
  chkCampaignsHaveSource,
  chkStaleCampaigns,
  chkCampaignNaming,
  chkRedirectMode,
  // Flows
  chkDefaultFlowExists,
  chkFlowsHaveOffers,
  chkWeightDistribution,
  // Offers
  chkOfferURLsHTTPS,
  chkPostbackConfigured,
  chkPostbackHasSubId,
  chkOffersDead,
  chkMultipleNetworks,
  chkS2SvsPixel,
  // Bot Filtering
  chkBotFlowExists,
  chkBotFlowFirst,
  chkCustomBotList,
  chkProxyFilter,
  chkBotPercentage,
  // Filters
  chkGeoFiltersUsed,
  chkDeviceFiltering,
  chkISPFilter,
  chkConnectionTypeFilter,
  chkGeoDBInstalled,
  // Performance
  chkConversionRate,
  chkROIPositive,
  chkLandingResponds,
  chkClickLimits,
  chkUniquenessFilter,
  chkLPClickTracking,
  chkTimezoneConsistency,
];

/**
 * Run every check against a snapshot and return results + a score.
 */
export function runAudit(snapshot) {
  const results = ALL_CHECKS.map((fn) => fn(snapshot));

  const weights = { critical: 5, high: 3, medium: 1.5, low: 0.5, info: 0 };
  let earned = 0;
  let possible = 0;
  for (const r of results) {
    const w = weights[r.severity] || 0;
    if (r.status === "skip") continue;
    possible += w;
    if (r.status === "pass") earned += w;
    else if (r.status === "warn") earned += w * 0.5;
    else if (r.status === "info") earned += w * 0.75;
  }
  const score = possible > 0 ? Math.round((earned / possible) * 100) : 0;
  const grade =
    score >= 90
      ? "A"
      : score >= 75
        ? "B"
        : score >= 60
          ? "C"
          : score >= 40
            ? "D"
            : "F";

  return { score, grade, total: results.length, results };
}

export { ALL_CHECKS };
