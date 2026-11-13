// User-agent classifier for tracker click logs.
// Categories follow the MRC invalid-traffic list: crawlers, non-browser user agents,
// automated (headless) browsers, and unknown browsers. Browsers and in-app browsers are
// "human-looking"; an outdated engine is only "suspicious".

import { isbot as isbotTest, findBotMatch } from './vendor/isbot.js';

const EMPTY = new Set(['', '-', 'null', 'undefined', '0', 'none', 'unknown']);

// [regex, label] — automation and headless browsers
const HEADLESS = [
  [/HeadlessChrome/i, 'HeadlessChrome'], [/PhantomJS/i, 'PhantomJS'], [/SlimerJS/i, 'SlimerJS'],
  [/\bjsdom\b/i, 'jsdom'], [/Zombie\.js/i, 'Zombie.js'], [/HtmlUnit/i, 'HtmlUnit'], [/Nightmare/i, 'Nightmare'],
  [/Puppeteer/i, 'Puppeteer'], [/Playwright/i, 'Playwright'], [/Selenium/i, 'Selenium'], [/WebDriver/i, 'WebDriver'],
  [/Chrome-Lighthouse|Lighthouse/i, 'Lighthouse'], [/\bCypress\b/i, 'Cypress'], [/\bSplash\b/, 'Splash'],
  [/\bwkhtmlto(?:pdf|image)\b/i, 'wkhtmltopdf'],
];

// [regex, label] — HTTP libraries and command-line tools (non-browser user agents)
const LIBRARY = [
  [/^curl\//i, 'curl'], [/^Wget\//i, 'Wget'], [/python-requests/i, 'python-requests'], [/Python-urllib/i, 'Python-urllib'],
  [/python-httpx/i, 'python-httpx'], [/aiohttp/i, 'aiohttp'], [/^Go-http-client/i, 'Go-http-client'], [/^Java\//i, 'Java'],
  [/Apache-HttpClient/i, 'Apache-HttpClient'], [/axios\//i, 'axios'], [/node-fetch/i, 'node-fetch'], [/^undici/i, 'undici'],
  [/^node\b/i, 'node'], [/^got \(/i, 'got'], [/PostmanRuntime/i, 'PostmanRuntime'], [/^insomnia/i, 'insomnia'],
  [/libwww-perl/i, 'libwww-perl'], [/LWP::Simple/i, 'LWP'], [/^Ruby\b/i, 'Ruby'], [/Faraday/i, 'Faraday'],
  [/GuzzleHttp/i, 'Guzzle'], [/^PHP\//i, 'PHP'], [/WinHttp/i, 'WinHttp'], [/^Dart\//i, 'Dart'], [/^reqwest/i, 'reqwest'],
  [/Scrapy/i, 'Scrapy'], [/\bcolly\b/i, 'colly'], [/^HTTPie/i, 'HTTPie'], [/Mechanize/i, 'Mechanize'], [/Typhoeus/i, 'Typhoeus'],
  [/RestSharp/i, 'RestSharp'], [/^WordPress\//i, 'WordPress'], [/Zend_Http_Client/i, 'Zend'], [/http\.rb/i, 'http.rb'],
  [/^Deno\//i, 'Deno'], [/^Bun\//i, 'Bun'], [/aria2/i, 'aria2'], [/libcurl/i, 'libcurl'], [/Jakarta Commons-HttpClient/i, 'Commons-HttpClient'],
  [/^AHC\//i, 'AsyncHttpClient'], [/fasthttp/i, 'fasthttp'], [/Indy Library/i, 'Indy'], [/^HTTP_Request2/i, 'HTTP_Request2'],
  [/^Embarcadero/i, 'Embarcadero'], [/^RestClient/i, 'RestClient'], [/^Apache-CXF/i, 'Apache-CXF'], [/^lua-resty-http/i, 'lua-resty-http'],
  [/^Mojolicious/i, 'Mojolicious'], [/^http-kit/i, 'http-kit'], [/^nghttp2/i, 'nghttp2'], [/^Rust\b|^hyper\//i, 'hyper'],
  [/^python\//i, 'python'], [/^Python\b/i, 'python'], [/^Microsoft Office\b|^Microsoft URL Control/i, 'MS URL fetch'],
];

// [regex, label, group, claims] — named crawlers. `claims` links a crawler to the
// provider-published IP list used to tell real crawlers from fakes.
const CRAWLERS = [
  [/AdsBot-Google/i, 'AdsBot-Google', 'ads', 'googlebot'], [/Mediapartners-Google/i, 'Mediapartners-Google', 'ads', 'googlebot'],
  [/Google-Adwords|Google-Ads-/i, 'Google Ads checker', 'ads', null], [/adidxbot/i, 'adidxbot (Bing Ads)', 'ads', 'bingbot'],
  [/Google-InspectionTool|GoogleOther|Storebot-Google|Google-Site-Verification|Google-Read-Aloud|Google-Safety|Google-CloudVertexBot|APIs-Google|FeedFetcher-Google|Google Favicon|Google-PageRenderer|Google-Structured-Data|Google-?Agent/i, 'Google special crawler', 'search', null],
  [/Googlebot/i, 'Googlebot', 'search', 'googlebot'],
  [/bingbot|BingPreview|msnbot/i, 'Bingbot', 'search', 'bingbot'],
  [/DuckDuckBot|DuckAssistBot/i, 'DuckDuckBot', 'search', 'duckduckbot'],
  [/Applebot/i, 'Applebot', 'search', null], [/Yandex[A-Za-z]*\//i, 'Yandex', 'search', null], [/Baiduspider/i, 'Baiduspider', 'search', null],
  [/Sogou/i, 'Sogou', 'search', null], [/360Spider|HaosouSpider/i, '360Spider', 'search', null], [/PetalBot|AspiegelBot/i, 'PetalBot', 'search', null],
  [/SeznamBot/i, 'SeznamBot', 'search', null], [/Qwant(ify|bot)/i, 'Qwant', 'search', null], [/Exabot/i, 'Exabot', 'search', null],
  [/\bYeti\//i, 'Yeti (Naver)', 'search', null], [/Daum(oa)?/i, 'Daum', 'search', null], [/MojeekBot/i, 'Mojeek', 'search', null],
  [/coccoc/i, 'CocCoc', 'search', null], [/Slurp/i, 'Yahoo Slurp', 'search', null],
  [/facebookexternalhit|Facebot|facebookcatalog|meta-externalfetcher/i, 'Meta crawler', 'social', 'meta'],
  [/meta-externalagent/i, 'Meta AI crawler', 'ai', 'meta'],
  [/GPTBot|ChatGPT-User|OAI-SearchBot/i, 'OpenAI bot', 'ai', 'openai'],
  [/PerplexityBot|Perplexity-User/i, 'PerplexityBot', 'ai', 'perplexity'],
  [/ClaudeBot|Claude-User|Claude-SearchBot|anthropic-ai/i, 'Anthropic bot', 'ai', null],
  [/Bytespider|TikTokSpider/i, 'Bytespider', 'ai', null], [/CCBot/i, 'CCBot', 'ai', null], [/cohere-ai/i, 'cohere-ai', 'ai', null],
  [/Diffbot/i, 'Diffbot', 'ai', null], [/YouBot/i, 'YouBot', 'ai', null], [/Amazonbot/i, 'Amazonbot', 'ai', null],
  [/DeepSeekBot/i, 'DeepSeekBot', 'ai', null], [/MistralAI/i, 'MistralAI', 'ai', null], [/ImagesiftBot/i, 'ImagesiftBot', 'ai', null],
  [/Timpibot/i, 'Timpibot', 'ai', null], [/omgili/i, 'omgili', 'ai', null],
  [/Twitterbot/i, 'Twitterbot', 'social', null], [/LinkedInBot/i, 'LinkedInBot', 'social', null], [/Pinterestbot|Pinterest\/0\./i, 'Pinterestbot', 'social', null],
  [/Slackbot|Slack-ImgProxy/i, 'Slackbot', 'social', null], [/Discordbot/i, 'Discordbot', 'social', null], [/TelegramBot/i, 'TelegramBot', 'social', null],
  [/^WhatsApp\//i, 'WhatsApp preview', 'social', null], [/^Viber\b/i, 'Viber preview', 'social', null], [/SkypeUriPreview/i, 'Skype preview', 'social', null],
  [/Snap URL Preview/i, 'Snapchat preview', 'social', null], [/redditbot/i, 'redditbot', 'social', null], [/Embedly|Iframely/i, 'Embed fetcher', 'social', null],
  [/vkShare/i, 'vkShare', 'social', null], [/Mastodon\//i, 'Mastodon', 'social', null],
  [/AhrefsBot|AhrefsSiteAudit/i, 'AhrefsBot', 'seo', null], [/SemrushBot|SiteAuditBot/i, 'SemrushBot', 'seo', null], [/MJ12bot/i, 'MJ12bot', 'seo', null],
  [/DotBot/i, 'DotBot', 'seo', null], [/BLEXBot/i, 'BLEXBot', 'seo', null], [/DataForSeoBot/i, 'DataForSeoBot', 'seo', null],
  [/serpstatbot/i, 'serpstatbot', 'seo', null], [/Screaming Frog/i, 'Screaming Frog', 'seo', null], [/rogerbot/i, 'rogerbot', 'seo', null],
  [/Barkrowler/i, 'Barkrowler', 'seo', null], [/MegaIndex/i, 'MegaIndex', 'seo', null], [/Seekport/i, 'Seekport', 'seo', null],
  [/UptimeRobot/i, 'UptimeRobot', 'monitor', null], [/Pingdom/i, 'Pingdom', 'monitor', null], [/StatusCake/i, 'StatusCake', 'monitor', null],
  [/Site24x7/i, 'Site24x7', 'monitor', null], [/Datadog/i, 'Datadog', 'monitor', null], [/GTmetrix/i, 'GTmetrix', 'monitor', null],
  [/Uptime-Kuma/i, 'Uptime Kuma', 'monitor', null], [/NewRelicPinger/i, 'New Relic', 'monitor', null], [/Better ?Uptime|Betteruptime/i, 'Better Uptime', 'monitor', null],
  [/Checkly/i, 'Checkly', 'monitor', null], [/HetrixTools/i, 'HetrixTools', 'monitor', null], [/Zabbix/i, 'Zabbix', 'monitor', null],
  [/zgrab/i, 'zgrab', 'scanner', null], [/masscan/i, 'masscan', 'scanner', null], [/\bNmap\b/i, 'Nmap', 'scanner', null],
  [/Nuclei/i, 'Nuclei', 'scanner', null], [/sqlmap/i, 'sqlmap', 'scanner', null], [/Nikto/i, 'Nikto', 'scanner', null],
  [/CensysInspect/i, 'Censys', 'scanner', null], [/Expanse|Xpanse/i, 'Palo Alto Xpanse', 'scanner', null], [/InternetMeasurement/i, 'InternetMeasurement', 'scanner', null],
  [/l9explore|l9tcpid/i, 'LeakIX', 'scanner', null],
  [/ia_archiver|archive\.org_bot|Wayback/i, 'Archiver', 'archiver', null], [/heritrix/i, 'Heritrix', 'archiver', null],
  [/Feedly|NewsBlur|Inoreader|Blogtrottr|Tiny Tiny RSS|FreshRSS|Feedbin/i, 'Feed reader', 'feed', null],
  [/Prerender/i, 'Prerender', 'other', null],
];

// Generic crawler wording; checked after named crawlers and browser tokens.
const GENERIC_CRAWLER = /(?:^|[^a-z])(?:[a-z0-9_-]*(?:bot|crawler|crawl|spider|scraper|slurp|fetcher|archiver|checker|validator|scanner|monitor|preview|indexer))(?:[^a-z]|$)/i;
const BOT_URL = /\+https?:\/\/|\(\+?https?:\/\/[^)]*\)|@[a-z0-9-]+\.[a-z]{2,}/i;
// Device names that contain the letters "bot" but are phones.
const BOT_FALSE_FRIENDS = /CUBOT|Cubot|BOTHE|Robotics? Edition/;

// App HTTP stacks: requests made by app code, not a browser tab.
const APP_HTTP = [[/^okhttp\//i, 'okhttp'], [/^Dalvik\//i, 'Dalvik'], [/CFNetwork\/.*Darwin\//i, 'CFNetwork'], [/AppleCoreMedia/i, 'AppleCoreMedia'], [/stagefright/i, 'stagefright'], [/^Mozilla\/5\.0 \(Linux; U; Android [^)]*\) Dalvik/i, 'Dalvik']];

// In-app browsers: real people in social or messenger apps.
const INAPP = [[/FBAN|FBAV|FB_IAB|FBIOS/i, 'Facebook app'], [/Instagram/i, 'Instagram app'], [/musical_ly|TikTok|BytedanceWebview|trill_/i, 'TikTok app'],
  [/Snapchat/i, 'Snapchat app'], [/\bLine\//i, 'LINE app'], [/KAKAOTALK/i, 'KakaoTalk app'], [/Twitter for/i, 'X app'], [/\bGSA\//i, 'Google app'],
  [/Pinterest for/i, 'Pinterest app'], [/MicroMessenger/i, 'WeChat'], [/\bTelegram\b.*(?:Android|iPhone)/i, 'Telegram app']];

// Legacy or minor mobile browsers that real people still use.
const LEGACY_HUMAN = /^Opera\/9\.80|Opera Mini|UCWEB|UCBrowser|UC Browser|^Nokia|NokiaBrowser|^SAMSUNG-|^SonyEricsson|^LG-|^MOT-|BlackBerry|^KaiOS|KAIOS/i;

const BROWSERS = [
  [/EdgA?\/(\d+)|EdgiOS\/(\d+)|Edge\/(\d+)/, 'Edge'], [/OPR\/(\d+)|OPiOS\/(\d+)/, 'Opera'], [/SamsungBrowser\/(\d+)/, 'Samsung Internet'],
  [/YaBrowser\/(\d+)/, 'Yandex Browser'], [/CriOS\/(\d+)/, 'Chrome iOS'], [/FxiOS\/(\d+)/, 'Firefox iOS'], [/Firefox\/(\d+)/, 'Firefox'],
  [/Chrome\/(\d+)/, 'Chrome'], [/Version\/(\d+)[\d.]* (?:Mobile\/\S+ )?Safari/, 'Safari'], [/MSIE (\d+)|Trident\/.*rv:(\d+)/, 'Internet Explorer'],
];

const CHROME_ANCHOR = { major: 157, date: Date.UTC(2026, 10, 13) }; // calibrated on the 2026-11-13 user-agents snapshot
const FIREFOX_ANCHOR = { major: 160, date: Date.UTC(2026, 10, 13) };
const RELEASE_DAYS = 28;

export function expectedMajor(anchor, refDate) {
  const t = refDate instanceof Date ? refDate.getTime() : (refDate || Date.now());
  return anchor.major + Math.floor((t - anchor.date) / (RELEASE_DAYS * 86400000));
}

function firstMatch(list, ua) {
  for (const row of list) if (row[0].test(ua)) return row;
  return null;
}

function parseBrowser(ua) {
  for (const [re, name] of BROWSERS) {
    const m = ua.match(re);
    if (m) {
      const major = Number(m.slice(1).find((x) => x !== undefined));
      return { name, major: Number.isFinite(major) ? major : null };
    }
  }
  return null;
}

function parseOS(ua) {
  if (/iPhone|iPad|iPod/.test(ua)) return 'iOS';
  if (/Android/.test(ua)) return 'Android';
  if (/Windows NT/.test(ua)) return 'Windows';
  if (/Mac OS X|Macintosh/.test(ua)) return 'macOS';
  if (/CrOS/.test(ua)) return 'ChromeOS';
  if (/Linux/.test(ua)) return 'Linux';
  return '';
}

function parseDevice(ua) {
  if (/iPad|Tablet|SM-T\d|Tab\b/.test(ua)) return 'tablet';
  if (/Mobi|iPhone|Android.*Mobile|Opera Mini/.test(ua)) return 'mobile';
  if (/Android/.test(ua)) return 'tablet';
  if (/Windows NT|Macintosh|X11|CrOS/.test(ua)) return 'desktop';
  return '';
}

const cache = new Map();

export function classifyUA(rawUa, opts = {}) {
  const ua = rawUa === null || rawUa === undefined ? '' : String(rawUa).trim();
  const refKey = opts.refDate ? Math.floor((opts.refDate instanceof Date ? opts.refDate.getTime() : opts.refDate) / (7 * 86400000)) : 0;
  const key = ua + '\u0000' + refKey + (opts.isbotFallback === false ? '\u0000own' : '');
  const hit = cache.get(key);
  if (hit) return hit;
  const res = classifyUncached(ua, opts);
  if (cache.size > 50000) cache.clear();
  cache.set(key, res);
  return res;
}

function result(kind, extra) {
  const bot = ['empty', 'library', 'headless', 'crawler', 'app-http', 'unknown'].includes(kind);
  return { kind, bot, suspicious: false, group: null, claims: null, token: null, browser: null, os: '', device: '', ...extra };
}

function classifyUncached(ua, opts) {
  if (EMPTY.has(ua.toLowerCase())) return result('empty', { token: '(empty user agent)' });
  const os = parseOS(ua), device = parseDevice(ua);

  // `match` is the literal text found in the user agent (used to build Keitaro filters);
  // `token` is the readable name shown in reports.
  const lit = (row) => { const m = ua.match(row[0]); return m ? (row[0].source.startsWith('^') ? '^' : '') + m[0] : null; };
  const hl = firstMatch(HEADLESS, ua);
  if (hl) return result('headless', { token: hl[1], match: lit(hl), os, device });

  const cr = firstMatch(CRAWLERS, ua);
  if (cr) return result('crawler', { token: cr[1], match: lit(cr), group: cr[2], claims: cr[3], os, device });

  const lib = firstMatch(LIBRARY, ua);
  if (lib) return result('library', { token: lib[1], match: lit(lib) });

  const app = firstMatch(APP_HTTP, ua);
  if (app) return result('app-http', { token: app[1], match: lit(app), os, device });

  const looksBrowser = /^Mozilla\/5\.0 \(/.test(ua) && /(AppleWebKit|Gecko\/|Trident|Presto)/.test(ua);
  const generic = !BOT_FALSE_FRIENDS.test(ua) && (GENERIC_CRAWLER.test(ua) || BOT_URL.test(ua));
  if (generic) {
    const m = ua.match(/([A-Za-z0-9_.-]*(?:bot|crawler|crawl|spider|scraper|slurp|fetcher|archiver|checker|validator|scanner|monitor|preview|indexer))/i);
    return result('crawler', { token: m ? m[1] : 'crawler wording', match: m ? m[1] : null, group: 'other', os, device });
  }
  if (/^Mozilla\/5\.0 \(compatible;/i.test(ua) && !/MSIE|Trident/.test(ua)) {
    return result('crawler', { token: 'Mozilla/5.0 (compatible; …)', group: 'other', os, device });
  }

  // Second opinion: the isbot pattern list (community-maintained). Used only when the
  // string otherwise looks like a browser, so categories above stay specific.
  if (opts.isbotFallback !== false && isbotTest(ua)) {
    return result('crawler', { token: findBotMatch(ua) || 'isbot pattern', match: findBotMatch(ua) || null, group: 'other', os, device, via: 'isbot' });
  }

  const inapp = firstMatch(INAPP, ua);
  const browser = parseBrowser(ua);
  if (!looksBrowser && !LEGACY_HUMAN.test(ua) && !(ua.startsWith('Mozilla/4.0 (compatible; MSIE'))) {
    return result('unknown', { token: ua.slice(0, 40), os, device, browser });
  }

  const out = result(inapp ? 'inapp' : 'browser', { browser, os, device, token: inapp ? inapp[1] : null });
  // Outdated engines: more than 40 releases (about three years) behind the current major at the
  // click date. Chromium browsers are judged by their Chrome engine version, not their brand version.
  const ref = opts.refDate || Date.now();
  const chromeEngine = ua.match(/(?:Chrome|CriOS)\/(\d+)/);
  const firefoxEngine = ua.match(/Firefox\/(\d+)/);
  let engine = null, expected = null;
  if (chromeEngine) { engine = Number(chromeEngine[1]); expected = expectedMajor(CHROME_ANCHOR, ref); }
  else if (firefoxEngine) { engine = Number(firefoxEngine[1]); expected = expectedMajor(FIREFOX_ANCHOR, ref); }
  if (engine !== null && engine < expected - 40) {
    out.suspicious = true;
    out.outdated = { major: engine, expected };
  }
  if (browser && browser.name === 'Internet Explorer') { out.suspicious = true; out.outdated = { major: browser.major, expected: null }; }
  // Incongruous: an iPhone/iPad string carrying a desktop Chrome token. Chrome on iOS says CriOS.
  if (/iPhone|iPad|iPod/.test(ua) && /\bChrome\/\d/.test(ua) && !/CriOS|EdgiOS|GSA\//.test(ua)) {
    out.suspicious = true;
    out.incongruous = 'iOS user agent with a desktop Chrome token';
  }
  return out;
}

// Regex-safe token for Keitaro's UserAgent filter (PCRE between slashes).
export function escapeForPcre(s) {
  return s.replace(/[\\^$.*+?()[\]{}|/]/g, '\\$&');
}
