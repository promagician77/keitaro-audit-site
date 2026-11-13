/**
 * Test fixtures — four Keitaro snapshots at different health levels.
 * Used by both the test suite and the demo site.
 */

export const HEALTHY = {
  label: "Healthy setup",
  server: {
    version: "10.3.7",
    clickhouse: true,
    disk_free_gb: 42,
    queue_size: 0,
    cron_age_minutes: 0,
    ssl_days_remaining: 67,
  },
  settings: {
    geo_db: "MaxMind GeoLite2-City 2026-10",
    timezone: "UTC",
    custom_bot_ips: true,
    custom_bot_signatures: true,
  },
  domains: [
    { name: "trk1.example.com", ssl: true, extra_records: false },
    { name: "trk2.example.com", ssl: true, extra_records: false },
    { name: "trk3.example.com", ssl: true, extra_records: false },
  ],
  campaigns: [
    {
      id: 1,
      name: "US_push_sweeps_Oct26",
      state: "active",
      traffic_source: "PropellerAds",
      tracking_type: "redirect",
      last_click_at: new Date(Date.now() - 3600_000).toISOString(),
      flows: [
        {
          is_default: false,
          action_type: "redirect",
          offers: [],
          filters: [{ type: "bot" }],
        },
        {
          is_default: false,
          action_type: "redirect",
          offers: [{ weight: 70 }, { weight: 30 }],
          filters: [{ type: "country", value: "US" }, { type: "device_type", value: "mobile" }],
        },
        {
          is_default: true,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [],
        },
      ],
    },
    {
      id: 2,
      name: "DE_native_nutra_Oct26",
      state: "active",
      traffic_source: "MGID",
      tracking_type: "js",
      last_click_at: new Date(Date.now() - 7200_000).toISOString(),
      flows: [
        {
          is_default: false,
          action_type: "redirect",
          offers: [],
          filters: [{ type: "bot" }],
        },
        {
          is_default: false,
          action_type: "redirect",
          offers: [{ weight: 50 }, { weight: 50 }],
          filters: [
            { type: "country", value: "DE" },
            { type: "uniqueness", scope: "campaign" },
            { type: "proxy", mode: "is_not" },
          ],
        },
        {
          is_default: true,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [],
        },
      ],
    },
  ],
  offers: [
    { id: 1, name: "Sweeps US #1", url: "https://network.example.com/offer/123", status: "active" },
    { id: 2, name: "Sweeps US #2", url: "https://network.example.com/offer/456", status: "active" },
    { id: 3, name: "Nutra DE", url: "https://aff.example.com/nutra-de", status: "active" },
  ],
  affiliate_networks: [
    { id: 1, name: "NetworkA", postback_url: "https://network.example.com/postback?subid={subid}&payout={payout}", postback_type: "s2s" },
    { id: 2, name: "NetworkB", postback_url: "https://aff.example.com/pb?click_id={subid}", postback_type: "s2s" },
  ],
  landings: [
    { id: 1, name: "Sweeps LP", http_status: 200, has_click_tracking: true },
    { id: 2, name: "Nutra LP DE", http_status: 200, has_click_tracking: true },
  ],
  stats: {
    total_clicks: 150000,
    unique_clicks: 120000,
    bot_clicks: 12000,
    conversions: 1800,
    revenue: 5400,
    cost: 3200,
  },
};

export const NEGLECTED = {
  label: "Neglected setup",
  server: {
    version: "9.0.14",
    clickhouse: false,
    disk_free_gb: 1.8,
    queue_size: 24500,
    cron_age_minutes: 45,
    ssl_days_remaining: 2,
  },
  settings: {
    geo_db: null,
    timezone: "UTC",
    custom_bot_ips: false,
    custom_bot_signatures: false,
  },
  domains: [
    { name: "track.example.com", ssl: false, extra_records: true },
  ],
  campaigns: [
    {
      id: 1,
      name: "campaign",
      state: "active",
      traffic_source: null,
      tracking_type: "redirect",
      last_click_at: new Date(Date.now() - 90 * 86_400_000).toISOString(),
      flows: [],
    },
    {
      id: 2,
      name: "test",
      state: "active",
      traffic_source: null,
      tracking_type: "redirect",
      last_click_at: null,
      flows: [
        {
          is_default: true,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [],
        },
      ],
    },
  ],
  offers: [
    { id: 1, name: "Old offer", url: "http://expired.example.com/offer/1", status: "dead", http_status: 404 },
  ],
  affiliate_networks: [
    { id: 1, name: "OldNet", postback_url: "", postback_type: "s2s" },
  ],
  landings: [
    { id: 1, name: "Broken LP", http_status: 503, has_click_tracking: false },
  ],
  stats: {
    total_clicks: 50000,
    unique_clicks: 35000,
    bot_clicks: 22000,
    conversions: 50,
    revenue: 100,
    cost: 800,
  },
};

export const PARTIAL = {
  label: "Partially configured",
  server: {
    version: "10.2.3",
    clickhouse: true,
    disk_free_gb: 8.4,
    queue_size: 120,
    cron_age_minutes: 1,
    ssl_days_remaining: 34,
  },
  settings: {
    geo_db: "MaxMind GeoLite2-City 2025-03",
    timezone: "America/New_York",
    custom_bot_ips: false,
    custom_bot_signatures: false,
  },
  domains: [
    { name: "trk.example.com", ssl: true, extra_records: false },
  ],
  campaigns: [
    {
      id: 1,
      name: "US_pop_dating",
      state: "active",
      traffic_source: "ExoClick",
      tracking_type: "redirect",
      last_click_at: new Date(Date.now() - 86_400_000).toISOString(),
      flows: [
        {
          is_default: false,
          action_type: "redirect",
          offers: [{ weight: 50 }, { weight: 50 }],
          filters: [{ type: "country", value: "US" }],
        },
        {
          is_default: true,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [],
        },
      ],
    },
    {
      id: 2,
      name: "BR_push_gaming",
      state: "active",
      traffic_source: "RichAds",
      tracking_type: "redirect",
      last_click_at: new Date(Date.now() - 172_800_000).toISOString(),
      flows: [
        {
          is_default: false,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [
            { type: "country", value: "BR" },
            { type: "bot" },
          ],
        },
        {
          is_default: true,
          action_type: "redirect",
          offers: [{ weight: 100 }],
          filters: [],
        },
      ],
    },
  ],
  offers: [
    { id: 1, name: "Dating US", url: "https://network.example.com/dating/us", status: "active" },
    { id: 2, name: "Gaming BR", url: "https://network.example.com/gaming/br", status: "active" },
  ],
  affiliate_networks: [
    { id: 1, name: "NetA", postback_url: "https://network.example.com/postback?sid={subid}", postback_type: "s2s" },
  ],
  landings: [
    { id: 1, name: "Dating LP", http_status: 200, has_click_tracking: true },
    { id: 2, name: "Gaming LP", http_status: 200, has_click_tracking: false },
  ],
  stats: {
    total_clicks: 80000,
    unique_clicks: 65000,
    bot_clicks: 18000,
    conversions: 520,
    revenue: 1560,
    cost: 1200,
  },
};

export const EMPTY = {
  label: "Fresh install",
  server: {
    version: "10.3.7",
    clickhouse: true,
    disk_free_gb: 18,
    queue_size: 0,
    cron_age_minutes: 0,
    ssl_days_remaining: 89,
  },
  settings: {
    geo_db: null,
    timezone: "UTC",
    custom_bot_ips: false,
    custom_bot_signatures: false,
  },
  domains: [],
  campaigns: [],
  offers: [],
  affiliate_networks: [],
  landings: [],
  stats: { total_clicks: 0, unique_clicks: 0, bot_clicks: 0, conversions: 0, revenue: 0, cost: 0 },
};

export const ALL_FIXTURES = { HEALTHY, NEGLECTED, PARTIAL, EMPTY };
