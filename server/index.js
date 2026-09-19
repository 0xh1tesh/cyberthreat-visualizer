require('dotenv').config({ path: require('path').join(__dirname, '.env') });

const express = require('express');
const cors = require('cors');
const net = require('net');
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5000;

const PLACEHOLDER_KEY_PATTERN = /^your_[a-z0-9_]+_key_here$/i;

function readApiKey(envName) {
  const value = String(process.env[envName] || '').trim();
  if (!value) return '';
  if (PLACEHOLDER_KEY_PATTERN.test(value)) return '';
  return value;
}

const ABUSE_KEY = readApiKey('ABUSEIPDB_API_KEY');
const IPINFO_KEY = readApiKey('IPINFO_API_KEY');
const OTX_KEY = readApiKey('OTX_API_KEY');
const SHODAN_KEY = readApiKey('SHODAN_API_KEY');
const GEMINI_API_KEY = readApiKey('GEMINI_API_KEY');
const OPENAI_API_KEY = readApiKey('OPENAI_API_KEY');
const AI_PROVIDER = String(process.env.AI_PROVIDER || 'auto').trim().toLowerCase();

const hasGemini = !!GEMINI_API_KEY;
const hasOpenAI = !!OPENAI_API_KEY;

function getActiveProvider() {
  if (AI_PROVIDER === "gemini" && hasGemini) return "gemini";
  if (AI_PROVIDER === "openai" && hasOpenAI) return "openai";

  if (AI_PROVIDER === "auto") {
    if (hasGemini) return "gemini";
    if (hasOpenAI) return "openai";
  }

  return null;
}
const AI_MODEL = (process.env.AI_MODEL || 'gpt-4o-mini').trim();
const AI_TIMEOUT_MS = clampNumber(process.env.AI_CLASSIFIER_TIMEOUT_MS, 200, 800, 800);
const AI_REPORT_TIMEOUT_MS_RAW = Number(process.env.AI_REPORT_TIMEOUT_MS || 0);
const AI_REPORT_TIMEOUT_MS = Number.isFinite(AI_REPORT_TIMEOUT_MS_RAW) && AI_REPORT_TIMEOUT_MS_RAW > 0
  ? clampNumber(AI_REPORT_TIMEOUT_MS_RAW, 1000, 120000, 10000)
  : 10000;
const GEMINI_MODEL = (process.env.GEMINI_MODEL || 'gemini-flash-latest').trim();

// Gemini free-tier guard: never exceed the documented requests-per-minute / per-day limits.
const geminiRateLimit = {
  minuteRequests: [],
  dayRequests: [],
  MAX_RPM: Number(process.env.GEMINI_MAX_RPM) || 5,
  MAX_RPD: Number(process.env.GEMINI_MAX_RPD) || 20,
};

function isGeminiRateLimited() {
  const now = Date.now();
  geminiRateLimit.minuteRequests = geminiRateLimit.minuteRequests.filter((time) => now - time < 60 * 1000);
  geminiRateLimit.dayRequests = geminiRateLimit.dayRequests.filter((time) => now - time < 24 * 60 * 60 * 1000);
  return (
    geminiRateLimit.minuteRequests.length >= geminiRateLimit.MAX_RPM
    || geminiRateLimit.dayRequests.length >= geminiRateLimit.MAX_RPD
  );
}

function recordGeminiRequest() {
  const now = Date.now();
  geminiRateLimit.minuteRequests.push(now);
  geminiRateLimit.dayRequests.push(now);
}
const ACTIVE_AI_PROVIDER = getActiveProvider();
const ENABLE_AI_CLASSIFIER = ACTIVE_AI_PROVIDER !== null;
const AI_CONFIG_MODEL = ACTIVE_AI_PROVIDER === 'openai'
  ? AI_MODEL
  : ACTIVE_AI_PROVIDER === 'gemini'
    ? getGeminiModelName()
    : 'none';

// ── Startup Diagnostic ──────────────────────────────────────
console.log('\n[AI CONFIG]');
console.log(`Provider: ${ACTIVE_AI_PROVIDER || 'none'}`);
console.log(`Model: ${AI_CONFIG_MODEL}`);
console.log(`Gemini key present: ${hasGemini}`);
console.log(`AI enabled: ${ENABLE_AI_CLASSIFIER}`);
console.log('');
const AI_ENV_TOP_N = process.env.AI_TOP_N ?? process.env.AI_TOP_N_THREATS;
const AI_ENV_MIN_SCORE = process.env.AI_MIN_SCORE ?? process.env.AI_MIN_SCORE_FOR_CALL;
const AI_MIN_SCORE = clampNumber(AI_ENV_MIN_SCORE, 0, 100, 40);
const AI_AMBIGUOUS_SCORE_MIN = clampNumber(process.env.AI_AMBIGUOUS_SCORE_MIN, 30, 70, 35);
const AI_AMBIGUOUS_SCORE_MAX = clampNumber(process.env.AI_AMBIGUOUS_SCORE_MAX, 35, 85, 55);
const AI_TOP_N = Math.round(clampNumber(AI_ENV_TOP_N, 1, 10, 3));
const AI_THROTTLE_MS = clampNumber(process.env.AI_THROTTLE_MS, 100, 1500, 300);
const AI_CACHE_TTL_MS = clampNumber(process.env.AI_CACHE_TTL_MS, 5 * 60 * 1000, 10 * 60 * 1000, 10 * 60 * 1000);

const ENABLE_ABUSE = !!ABUSE_KEY;
const ENABLE_IPINFO = !!IPINFO_KEY;
const ENABLE_OTX = true; // allow keyless
const ENABLE_SHODAN = !!SHODAN_KEY;
const AI_PROVIDER_OPTIONS = ['openai', 'gemini', 'auto', 'off'];
const AI_REPORT_REASON_CODES = {
  NONE: 'none',
  NO_PROVIDER: 'no_provider',
  INVALID_MODEL: 'invalid_model',
  UPSTREAM_HTTP_ERROR: 'upstream_http_error',
  THROTTLED: 'throttled',
  TIMEOUT: 'timeout',
  NETWORK_ERROR: 'network_error',
  SCHEMA_MISMATCH: 'schema_mismatch',
  INTERNAL_ERROR: 'internal_error',
};

const SOURCE_STATUS_OK = 'ok';
const SOURCE_STATUS_FAILED = 'failed';
const SOURCE_STATUS_RATE_LIMITED = 'rate_limited';
const SOURCE_STATUS_UNAUTHORIZED = 'unauthorized';
const SOURCE_STATUS_VALUES = new Set([
  SOURCE_STATUS_OK,
  SOURCE_STATUS_FAILED,
  SOURCE_STATUS_RATE_LIMITED,
  SOURCE_STATUS_UNAUTHORIZED,
]);

const PROVIDER_STATUS = {
  abuseipdb: ENABLE_ABUSE ? SOURCE_STATUS_OK : 'missing_key',
  otx: ENABLE_OTX ? (OTX_KEY ? SOURCE_STATUS_OK : 'public') : 'disabled',
  shodan: ENABLE_SHODAN ? SOURCE_STATUS_OK : 'missing_key',
  ipinfo: ENABLE_IPINFO ? SOURCE_STATUS_OK : 'missing_key',
};

const PROVIDER_STATUS_UPDATED_AT = {
  abuseipdb: null,
  otx: null,
  shodan: null,
  ipinfo: null,
};

const PROVIDER_OUTAGE_GRACE_MS = 5 * 60 * 1000;
const PROVIDER_LAST_OK_AT = { abuseipdb: 0, otx: 0, shodan: 0, ipinfo: 0 };

function setProviderStatus(provider, status) {
  if (!provider || !Object.prototype.hasOwnProperty.call(PROVIDER_STATUS, provider)) return;
  const current = PROVIDER_STATUS[provider];
  if (current === 'missing_key' || current === 'disabled') return;
  if (status === SOURCE_STATUS_OK) PROVIDER_LAST_OK_AT[provider] = Date.now();
  // Concurrent per-IP lookups report independently; a lone failure must not mask recent successes.
  if (status === SOURCE_STATUS_FAILED && Date.now() - PROVIDER_LAST_OK_AT[provider] < PROVIDER_OUTAGE_GRACE_MS) return;
  if (current === status) return;
  PROVIDER_STATUS[provider] = status;
  PROVIDER_STATUS_UPDATED_AT[provider] = Date.now();
}

function getProviderStatus(provider) {
  if (!provider || !Object.prototype.hasOwnProperty.call(PROVIDER_STATUS, provider)) return 'unknown';
  return PROVIDER_STATUS[provider] || 'unknown';
}

function getProviderHealthLabel(provider) {
  const status = getProviderStatus(provider);
  if (status === SOURCE_STATUS_RATE_LIMITED) return 'rate_limited';
  if (status === SOURCE_STATUS_UNAUTHORIZED) return 'unauthorized';
  if (status === SOURCE_STATUS_FAILED) return 'offline';
  if (status === 'missing_key') return 'missing_key';
  if (status === 'disabled') return 'disabled';
  if (status === 'public') return 'enabled_public';
  return 'enabled';
}

function getProviderBaselineSourceStatus(provider) {
  const status = getProviderStatus(provider);
  if (status === SOURCE_STATUS_RATE_LIMITED) return SOURCE_STATUS_RATE_LIMITED;
  if (status === SOURCE_STATUS_UNAUTHORIZED) return SOURCE_STATUS_UNAUTHORIZED;
  return SOURCE_STATUS_FAILED;
}

const AI_ERROR_CODES = {
  INVALID_MODEL: 'invalid_model',
  TIMEOUT: 'timeout',
  THROTTLED: 'throttled',
  UPSTREAM_HTTP_ERROR: 'upstream_http_error',
  NETWORK_ERROR: 'network_error',
  NO_PROVIDER: 'no_provider',
};

const AI_ERROR_LABELS = {
  [AI_ERROR_CODES.INVALID_MODEL]: 'Invalid model',
  [AI_ERROR_CODES.TIMEOUT]: 'AI timeout',
  [AI_ERROR_CODES.THROTTLED]: 'AI throttled',
  [AI_ERROR_CODES.UPSTREAM_HTTP_ERROR]: 'AI upstream error',
  [AI_ERROR_CODES.NETWORK_ERROR]: 'AI network error',
  [AI_ERROR_CODES.NO_PROVIDER]: 'No AI provider available',
};

function buildAiError(code, detail = null, provider = null) {
  return {
    code,
    reason: AI_ERROR_LABELS[code] || 'AI error',
    detail: detail ? String(detail).trim() : null,
    provider,
  };
}


function normalizeAiProviderMode(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return AI_PROVIDER_OPTIONS.includes(normalized) ? normalized : null;
}

function resolveAiProviderFromMode(mode) {
  if (mode === 'off') return null;
  if (mode === 'openai') return hasOpenAI ? 'openai' : null;
  if (mode === 'gemini') return hasGemini ? 'gemini' : null;
  if (mode === 'auto') {
    if (hasGemini) return 'gemini';
    if (hasOpenAI) return 'openai';
    return null;
  }
  return null;
}

function resolveDefaultAiProviderMode() {
  return normalizeAiProviderMode(AI_PROVIDER) || 'auto';
}

function resolveRequestAiSelection(req) {
  const headerMode = normalizeAiProviderMode(req?.get('X-AI-Provider'));
  const bodyMode = normalizeAiProviderMode(req?.body?.provider || req?.body?.aiProvider || req?.body?.mode);
  const queryMode = normalizeAiProviderMode(req?.query?.provider || req?.query?.aiProvider || req?.query?.mode);
  const requestedMode = headerMode || queryMode || bodyMode;
  const mode = requestedMode || resolveDefaultAiProviderMode();

  const thresholdCandidates = [req?.get('X-AI-Threshold'), req?.query?.threshold, req?.body?.threshold];
  let threshold = 70;
  for (const candidate of thresholdCandidates) {
    if (candidate === undefined || candidate === null || candidate === '') continue;
    const parsed = Number(candidate);
    if (Number.isFinite(parsed)) {
      threshold = Math.max(0, Math.min(100, parsed));
      break;
    }
  }

  return {
    mode,
    requestedMode,
    provider: resolveAiProviderFromMode(mode),
    threshold,
  };
}

function getAiProviderCacheKey(mode) {
  return resolveAiProviderFromMode(normalizeAiProviderMode(mode)) || 'off';
}




const CORS_ORIGINS = String(process.env.CORS_ORIGIN || 'http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173')
  .split(',')
  .map((origin) => origin.trim())
  .filter(Boolean);

app.disable('x-powered-by');
app.use(helmet());
app.use(cors({ origin: CORS_ORIGINS }));
app.use(express.json({ limit: '16kb' }));

const aiRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  limit: Number(process.env.AI_RATE_LIMIT_PER_MIN) || 10,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many AI requests. Please slow down.' },
});

const CACHE_TTL_MS = 60 * 1000;
const REQUEST_TIMEOUT_MS = 4500;
const ABUSE_DAILY_SAFE_THRESHOLD = 4;
const MAX_ATTACKS = 10;

const THREAT_CACHE_MAX = 20;
const threatCache = new Map();
let latestThreatCacheAt = 0;

const aiCache = new Map();
let lastAiCallTime = 0;

const aiMetrics = {
  totalCalls: 0,
  successCalls: 0,
  failedCalls: 0,
  skippedLowScore: 0,
  skippedThrottle: 0,
  skippedCache: 0,
  cacheHits: 0,
  cacheMisses: 0,
};

function incrementAiMetric(metricKey, amount = 1) {
  if (!Object.prototype.hasOwnProperty.call(aiMetrics, metricKey)) return;
  const numericAmount = Number(amount);
  if (!Number.isFinite(numericAmount)) return;
  aiMetrics[metricKey] += numericAmount;
}

function snapshotAiMetrics() {
  return {
    totalCalls: aiMetrics.totalCalls,
    successCalls: aiMetrics.successCalls,
    failedCalls: aiMetrics.failedCalls,
    skippedLowScore: aiMetrics.skippedLowScore,
    skippedThrottle: aiMetrics.skippedThrottle,
    skippedCache: aiMetrics.skippedCache,
    cacheHits: aiMetrics.cacheHits,
    cacheMisses: aiMetrics.cacheMisses,
  };
}

const inFlightFetchPromises = new Map();

let usage = loadPersistedUsage() || {
  dayKey: getDayKey(),
  abuseipdb: 0,
  otx: 0,
  shodan: 0,
  ipinfo: 0,
};

const warnedKeys = new Set();


const COLOR_MAP = {
  DDoS: '#ff4757',
  Malware: '#ffa502',
  Scan: '#2ed573',
};

const THREAT_CLASSIFICATION = {
  DDOS: 'DDOS',
  MALWARE: 'MALWARE',
  SCAN: 'SCAN',
  LOW: 'LOW',
};

const CLASSIFICATION_TO_TYPE = {
  [THREAT_CLASSIFICATION.DDOS]: 'DDoS',
  [THREAT_CLASSIFICATION.MALWARE]: 'Malware',
  [THREAT_CLASSIFICATION.SCAN]: 'Scan',
  [THREAT_CLASSIFICATION.LOW]: 'Scan',
};

const COUNTRY_CODE_MAP = {
  US: 'United States',
  GB: 'United Kingdom',
  DE: 'Germany',
  FR: 'France',
  JP: 'Japan',
  AU: 'Australia',
  CA: 'Canada',
  IN: 'India',
  BR: 'Brazil',
  KR: 'South Korea',
  NL: 'Netherlands',
  SG: 'Singapore',
  CN: 'China',
  RU: 'Russia',
  ES: 'Spain',
  IT: 'Italy',
  PT: 'Portugal',
  PL: 'Poland',
  VN: 'Vietnam',
  CO: 'Colombia',
  IE: 'Ireland',
  UA: 'Ukraine',
};

const COUNTRY_COORDS = {
  'United States': { lat: 38.9072, lng: -77.0369 },
  'United Kingdom': { lat: 51.5074, lng: -0.1278 },
  Germany: { lat: 52.52, lng: 13.405 },
  France: { lat: 48.8566, lng: 2.3522 },
  Japan: { lat: 35.6895, lng: 139.6917 },
  Australia: { lat: -33.8688, lng: 151.2093 },
  Canada: { lat: 43.6532, lng: -79.3832 },
  India: { lat: 28.6139, lng: 77.209 },
  Brazil: { lat: -23.5505, lng: -46.6333 },
  'South Korea': { lat: 37.5665, lng: 126.978 },
  Netherlands: { lat: 52.3676, lng: 4.9041 },
  Singapore: { lat: 1.3521, lng: 103.8198 },
  China: { lat: 39.9042, lng: 116.4074 },
  Russia: { lat: 55.7558, lng: 37.6173 },
  Spain: { lat: 40.4168, lng: -3.7038 },
  Italy: { lat: 41.9028, lng: 12.4964 },
  Portugal: { lat: 38.7223, lng: -9.1393 },
  Poland: { lat: 52.2297, lng: 21.0122 },
  Vietnam: { lat: 21.0278, lng: 105.8342 },
  Colombia: { lat: 4.711, lng: -74.0721 },
  Ireland: { lat: 53.3498, lng: -6.2603 },
  Ukraine: { lat: 50.4501, lng: 30.5234 },
};

const OTX_FALLBACK_IPS = [
  '185.220.101.1',
  '45.95.147.229',
  '89.248.165.198',
  '146.70.138.17',
  '193.56.29.221',
  '5.188.206.43',
  '45.129.33.42',
  '91.134.14.24',
];

let regionNameFormatter = null;
try {
  regionNameFormatter = new Intl.DisplayNames(['en'], { type: 'region' });
} catch {
  regionNameFormatter = null;
}

// ── Helpers ──────────────────────────────────────────────────
function getDayKey() {
  return new Date().toISOString().slice(0, 10);
}

const USAGE_FILE = path.join(__dirname, '.usage.json');

function loadPersistedUsage() {
  try {
    const parsed = JSON.parse(fs.readFileSync(USAGE_FILE, 'utf8'));
    if (parsed && parsed.dayKey === getDayKey()) {
      return {
        dayKey: parsed.dayKey,
        abuseipdb: Number(parsed.abuseipdb) || 0,
        otx: Number(parsed.otx) || 0,
        shodan: Number(parsed.shodan) || 0,
        ipinfo: Number(parsed.ipinfo) || 0,
      };
    }
  } catch {
    // no persisted usage yet
  }
  return null;
}

function persistUsage() {
  try {
    fs.writeFileSync(USAGE_FILE, JSON.stringify(usage));
  } catch (err) {
    console.warn('[Usage] could not persist counters:', err.code || err.message);
  }
}

function resetUsageIfNeeded() {
  const today = getDayKey();
  if (usage.dayKey !== today) {
    usage = {
      dayKey: today,
      abuseipdb: 0,
      otx: 0,
      shodan: 0,
      ipinfo: 0,
    };
    persistUsage();
  }
}

function incrementUsage(provider) {
  resetUsageIfNeeded();
  if (Object.prototype.hasOwnProperty.call(usage, provider)) {
    usage[provider] += 1;
    persistUsage();
  }
}

function warnMissingKeyOnce(provider, envName) {
  if (!warnedKeys.has(provider)) {
    warnedKeys.add(provider);
    console.warn(`Missing ${envName} key — skipping ${provider} provider`);
  }
}

const PROVIDER_FAILURE_CATEGORIES = {
  TIMEOUT: 'timeout',
  RATE_LIMIT: 'rate_limit',
  HTTP_ERROR: 'http_error',
  NETWORK_ERROR: 'network_error',
  UNAVAILABLE: 'unavailable',
};

function isProviderTimeoutError(err) {
  if (err?.name === 'AbortError' || err?.name === 'TimeoutError' || err?.code === 'ETIMEDOUT') return true;
  const message = String(err?.message || '').toLowerCase();
  return message.includes('timed out');
}

function getProviderHttpFailureCategory(statusCode) {
  return Number(statusCode) === 429
    ? PROVIDER_FAILURE_CATEGORIES.RATE_LIMIT
    : PROVIDER_FAILURE_CATEGORIES.HTTP_ERROR;
}

function getProviderErrorCategory(err) {
  return isProviderTimeoutError(err)
    ? PROVIDER_FAILURE_CATEGORIES.TIMEOUT
    : PROVIDER_FAILURE_CATEGORIES.NETWORK_ERROR;
}

function scrubSecrets(text) {
  let out = String(text || '');
  for (const secret of [ABUSE_KEY, IPINFO_KEY, OTX_KEY, SHODAN_KEY, GEMINI_API_KEY, OPENAI_API_KEY]) {
    if (secret) out = out.split(secret).join('[redacted]');
  }
  return out.replace(/([?&](?:key|token)=)[^&\s]+/gi, '$1[redacted]');
}

function logProviderFailure(
  provider,
  {
    category = PROVIDER_FAILURE_CATEGORIES.UNAVAILABLE,
    status = null,
    reason = '',
    ipAddress = '',
    details = '',
  } = {}
) {
  const parts = [`[Provider:${String(provider || 'unknown')}]`];
  parts.push(`category=${String(category || PROVIDER_FAILURE_CATEGORIES.UNAVAILABLE)}`);

  const numericStatus = Number(status);
  if (Number.isFinite(numericStatus)) {
    parts.push(`status=${numericStatus}`);
  }
  if (ipAddress) {
    parts.push(`ip=${String(ipAddress)}`);
  }
  if (reason) {
    parts.push(`reason=${String(reason)}`);
  }
  if (details) {
    parts.push(`details=${truncateForLog(scrubSecrets(details), 140)}`);
  }

  console.warn(parts.join(' | '));
}

function getThreatCacheKey(mode, threshold) {
  return `${getAiProviderCacheKey(mode)}|${Math.round(clampNumber(threshold, 0, 100, 70))}`;
}

function peekThreatCache(key) {
  return threatCache.get(key) || null;
}

function readThreatCache(key, now = Date.now()) {
  const entry = threatCache.get(key);
  if (!entry || (now - entry.timestamp) >= CACHE_TTL_MS) return null;
  return entry;
}

function writeThreatCache(key, entry) {
  threatCache.delete(key);
  threatCache.set(key, entry);
  latestThreatCacheAt = entry.timestamp;
  while (threatCache.size > THREAT_CACHE_MAX) {
    threatCache.delete(threatCache.keys().next().value);
  }
}

function isPrivateOrBogon(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const version = net.isIP(ip);
  if (version === 0) return true;

  if (version === 4) {
    const [a, b, c] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 192 && b === 0 && (c === 0 || c === 2)) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    if (a === 198 && b === 51 && c === 100) return true;
    if (a === 203 && b === 0 && c === 113) return true;
    if (a >= 224) return true;
    return false;
  }

  const lower = ip.toLowerCase();
  if (lower === '::' || lower === '::1') return true;
  if (lower.startsWith('::ffff:')) return true;
  if (/^f[cd]/.test(lower)) return true;
  if (/^fe[89ab]/.test(lower)) return true;
  if (lower.startsWith('ff')) return true;
  if (lower.startsWith('2001:db8')) return true;
  return false;
}

async function fetchWithTimeout(url, options = {}, timeoutMs = 4000, usageProvider = null) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    if (usageProvider && response.ok) incrementUsage(usageProvider);
    return response;
  } finally {
    clearTimeout(timer);
  }
}

function fetchWithOptionalTimeout(url, options = {}, timeoutMs = 0) {
  const numericTimeout = Number(timeoutMs);
  if (!Number.isFinite(numericTimeout) || numericTimeout <= 0) {
    return fetch(url, options);
  }
  return fetchWithTimeout(url, options, numericTimeout);
}

function clampNumber(value, min, max, fallback = 0) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
}

function toNonNegativeNumber(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return 0;
  return numeric;
}

function normalizePortExposureScore(portExposure) {
  return clampNumber(toNonNegativeNumber(portExposure) * 10, 0, 100, 0);
}

const CLASSIFICATION_SCORE_BANDS = {
  [THREAT_CLASSIFICATION.DDOS]: { min: 75, max: 100 },
  [THREAT_CLASSIFICATION.MALWARE]: { min: 50, max: 74.99 },
  [THREAT_CLASSIFICATION.SCAN]: { min: 30, max: 49.99 },
  [THREAT_CLASSIFICATION.LOW]: { min: 0, max: 29.99 },
};

function classifyFromScore(score) {
  const safeScore = clampNumber(score, 0, 100, 0);
  if (safeScore >= 75) return THREAT_CLASSIFICATION.DDOS;
  if (safeScore >= 50) return THREAT_CLASSIFICATION.MALWARE;
  if (safeScore >= 30) return THREAT_CLASSIFICATION.SCAN;
  return THREAT_CLASSIFICATION.LOW;
}

function mapClassificationToType(classification) {
  const normalized = String(classification || '').toUpperCase();
  return CLASSIFICATION_TO_TYPE[normalized] || CLASSIFICATION_TO_TYPE[THREAT_CLASSIFICATION.LOW];
}

const SIGNAL_WEIGHTS = {
  abuseScore: 0.4,
  otxHits: 0.3,
  portExposure: 0.3,
};

const SOURCE_SIGNAL_KEYS = {
  abuseipdb: 'abuseScore',
  otx: 'otxHits',
  shodan: 'portExposure',
};

const SOURCE_WEIGHTS = {
  abuseipdb: SIGNAL_WEIGHTS.abuseScore,
  otx: SIGNAL_WEIGHTS.otxHits,
  shodan: SIGNAL_WEIGHTS.portExposure,
};

function isSignalPresent(value) {
  return value !== null && value !== undefined;
}

function normalizeSourceStatus(sourceStatus = {}, signals = {}) {
  const normalizeStatus = (value) => {
    const normalized = String(value || '').trim().toLowerCase();
    if (SOURCE_STATUS_VALUES.has(normalized)) return normalized;
    return null;
  };

  const resolveStatus = (sourceKey, signalKey) => {
    const explicitStatus = normalizeStatus(sourceStatus[sourceKey]);
    if (explicitStatus) return explicitStatus;
    return isSignalPresent(signals[signalKey]) ? 'ok' : 'failed';
  };

  return {
    abuseipdb: resolveStatus('abuseipdb', SOURCE_SIGNAL_KEYS.abuseipdb),
    otx: resolveStatus('otx', SOURCE_SIGNAL_KEYS.otx),
    shodan: resolveStatus('shodan', SOURCE_SIGNAL_KEYS.shodan),
  };
}

function getAvailableSources(sourceStatus = {}) {
  return Object.entries(sourceStatus)
    .filter((entry) => entry[1] === 'ok')
    .map((entry) => entry[0]);
}

function getActiveWeightFromSources(availableSources = []) {
  return Number(
    availableSources
      .reduce((sum, source) => sum + (SOURCE_WEIGHTS[source] || 0), 0)
      .toFixed(2)
  );
}

function calculateThreatScore(signals = {}, sourceStatus = {}) {
  const normalizedSourceStatus = normalizeSourceStatus(sourceStatus, signals);
  const availableSources = getAvailableSources(normalizedSourceStatus);
  const missingSources = Object.keys(SOURCE_SIGNAL_KEYS).filter(
    (source) => !availableSources.includes(source)
  );

  const abuseScoreValue = clampNumber(signals.abuseScore ?? 0, 0, 100, 0);
  const otxHitsValue = toNonNegativeNumber(signals.otxHits ?? 0);
  const portExposureValue = toNonNegativeNumber(signals.portExposure ?? 0);

  const otxNormalized = clampNumber(otxHitsValue * 10, 0, 100, 0);
  const portNormalized = normalizePortExposureScore(portExposureValue);

  let rawScore = 0;

  if (normalizedSourceStatus.abuseipdb === 'ok') {
    rawScore += SIGNAL_WEIGHTS.abuseScore * abuseScoreValue;
  }
  if (normalizedSourceStatus.otx === 'ok') {
    rawScore += SIGNAL_WEIGHTS.otxHits * otxNormalized;
  }
  if (normalizedSourceStatus.shodan === 'ok') {
    rawScore += SIGNAL_WEIGHTS.portExposure * portNormalized;
  }

  const activeWeight = getActiveWeightFromSources(availableSources);
  const normalizedScore = activeWeight > 0
    ? clampNumber(Number((rawScore / activeWeight).toFixed(2)), 0, 100, 0)
    : 0;

  const classification = classifyFromScore(normalizedScore);

  return {
    score: normalizedScore,
    classification,
    signals: {
      abuseScore: abuseScoreValue,
      otxHits: otxHitsValue,
      portExposure: portExposureValue,
      otxScore: otxNormalized,
      portExposureScore: portNormalized,
      usedSources: [...availableSources],
      sourcesUsed: [...availableSources],
      missingSources,
      availableSources: [...availableSources],
      sourceStatus: normalizedSourceStatus,
      activeWeight,
    },
  };
}

function normalizeAiClassification(value) {
  const text = String(value || '').trim().toUpperCase();
  if (!text) return null;
  if (text === THREAT_CLASSIFICATION.DDOS || text === 'DDoS'.toUpperCase()) return THREAT_CLASSIFICATION.DDOS;
  if (text === THREAT_CLASSIFICATION.MALWARE) return THREAT_CLASSIFICATION.MALWARE;
  if (text === THREAT_CLASSIFICATION.SCAN) return THREAT_CLASSIFICATION.SCAN;
  if (text === THREAT_CLASSIFICATION.LOW) return THREAT_CLASSIFICATION.LOW;
  return null;
}

function parseAiJson(content) {
  if (!content || typeof content !== 'string') return null;

  try {
    return JSON.parse(content);
  } catch {
    const firstBrace = content.indexOf('{');
    const lastBrace = content.lastIndexOf('}');
    if (firstBrace === -1 || lastBrace === -1 || lastBrace <= firstBrace) return null;
    const candidate = content.slice(firstBrace, lastBrace + 1);
    try {
      return JSON.parse(candidate);
    } catch {
      return null;
    }
  }
}

function safeErrorDetail(err) {
  if (isProviderTimeoutError(err)) return 'timeout';
  const code = err?.cause?.code || err?.code;
  if (code && /^[A-Z_]{3,32}$/.test(String(code))) return String(code);
  return 'request_failed';
}

function truncateForLog(value, maxLength = 180) {
  const text = scrubSecrets(value).replace(/\s+/g, ' ').trim();
  if (!text) return '';
  if (text.length <= maxLength) return text;
  return `${text.slice(0, maxLength)}...`;
}

async function readResponseTextSafe(response) {
  try {
    return await response.text();
  } catch {
    return '';
  }
}

function normalizeSignalHashValue(value) {
  if (!isSignalPresent(value)) return 'null';
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'null';
  return numeric.toFixed(2);
}

function buildSignalHash(signals = {}) {
  return [
    normalizeSignalHashValue(signals.abuseScore),
    normalizeSignalHashValue(signals.otxHits),
    normalizeSignalHashValue(signals.portExposure),
  ].join('|');
}

function buildAiCacheKey(kind, payload = {}) {
  const ip = String(payload.sourceIp || payload.ip || 'unknown').trim() || 'unknown';
  const signalShape = {
    abuseScore: payload?.signals?.abuseScore ?? payload.abuseConfidenceScore ?? null,
    otxHits: payload?.signals?.otxHits ?? payload.otxHits ?? null,
    portExposure: payload?.signals?.portExposure ?? payload.openPorts ?? payload.portExposure ?? null,
  };
  return `${String(kind || 'generic')}|${ip}|${buildSignalHash(signalShape)}`;
}

const AI_CACHE_MAX_ENTRIES = 1000;
const AI_FAILURE_CACHE_TTL_MS = 30 * 1000;

function pruneAiCache(now = Date.now()) {
  for (const [key, entry] of aiCache.entries()) {
    if (!entry || !Number.isFinite(entry.expiresAt) || entry.expiresAt <= now) {
      aiCache.delete(key);
    }
  }
}

setInterval(() => pruneAiCache(Date.now()), 60 * 1000).unref();

function readAiCache(cacheKey) {
  const entry = aiCache.get(cacheKey);
  if (!entry) return null;
  if (!Number.isFinite(entry.expiresAt) || entry.expiresAt <= Date.now()) {
    aiCache.delete(cacheKey);
    return null;
  }
  // Re-insert so Map iteration order tracks recency (LRU).
  aiCache.delete(cacheKey);
  aiCache.set(cacheKey, entry);
  return entry.value;
}

function writeAiCache(cacheKey, value, ttlMs = AI_CACHE_TTL_MS) {
  aiCache.delete(cacheKey);
  aiCache.set(cacheKey, { value, expiresAt: Date.now() + ttlMs });
  while (aiCache.size > AI_CACHE_MAX_ENTRIES) {
    aiCache.delete(aiCache.keys().next().value);
  }
}

function isScanMalwareAmbiguous(score, classification) {
  const safeScore = clampNumber(score, 0, 100, 0);
  const normalizedClassification = String(classification || '').toUpperCase();
  if (normalizedClassification !== THREAT_CLASSIFICATION.SCAN && normalizedClassification !== THREAT_CLASSIFICATION.MALWARE) {
    return false;
  }
  return safeScore >= AI_AMBIGUOUS_SCORE_MIN && safeScore <= AI_AMBIGUOUS_SCORE_MAX;
}

function shouldAttemptAiForThreat(ruleThreat, explicitRequest = false) {
  if (explicitRequest) {
    return { shouldCall: true, reason: 'explicit request' };
  }

  const score = clampNumber(ruleThreat?.score, 0, 100, 0);
  const classification = String(ruleThreat?.classification || '').toUpperCase();

  if (score >= AI_MIN_SCORE) {
    return { shouldCall: true, reason: `score >= ${AI_MIN_SCORE}` };
  }

  if (isScanMalwareAmbiguous(score, classification)) {
    return { shouldCall: true, reason: 'ambiguous SCAN/MALWARE boundary' };
  }

  return { shouldCall: false, reason: 'low score' };
}

function isAiThrottled(now = Date.now()) {
  return (now - lastAiCallTime) < AI_THROTTLE_MS;
}

function markAiCallStart(now = Date.now()) {
  lastAiCallTime = now;
}

function resolveAiAttemptProviders(mode) {
  if (mode === 'off') return [];
  if (mode === 'openai') return hasOpenAI ? ['openai'] : [];
  if (mode === 'gemini') return hasGemini ? ['gemini'] : [];
  if (mode === 'auto') {
    const providers = [];
    if (hasGemini) providers.push('gemini');
    if (hasOpenAI) providers.push('openai');
    return providers;
  }
  return [];
}

async function classifyThreatWithAI(normalizedThreat, mode) {
  if (!normalizedThreat || typeof normalizedThreat !== 'object') {
    return {
      result: null,
      providerUsed: 'none',
      fallback: false,
      attemptedProviders: [],
    };
  }

  const attemptedProviders = resolveAiAttemptProviders(mode);
  if (attemptedProviders.length === 0) {
    return {
      result: null,
      providerUsed: 'none',
      fallback: false,
      attemptedProviders,
    };
  }

  const requestPayload = {
    sourceCountry: normalizedThreat.sourceCountry,
    provider: normalizedThreat.provider,
    sourceIp: normalizedThreat.sourceIp,
    score: normalizedThreat.score,
    intensity: normalizedThreat.intensity,
    signals: normalizedThreat.signals,
  };

  let lastError = null;
  for (let i = 0; i < attemptedProviders.length; i += 1) {
    const provider = attemptedProviders[i];
    const outcome = provider === 'openai'
      ? await classifyWithOpenAI(requestPayload)
      : await classifyWithGemini(requestPayload);

    if (outcome?.result) {
      return {
        result: outcome.result,
        providerUsed: provider,
        fallback: i > 0,
        attemptedProviders,
        error: null,
      };
    }

    if (outcome?.error) {
      lastError = outcome.error;
    }
  }

  return {
    result: null,
    providerUsed: 'none',
    fallback: attemptedProviders.length > 1,
    attemptedProviders,
    error: lastError,
  };
}

function normalizeAiResponse(parsed) {
  const type = normalizeAiClassification(parsed?.type);
  if (!type) return null;
  return {
    type,
    confidence: clampNumber(parsed?.confidence, 0, 100, 0),
    reason: String(parsed?.reasoning || parsed?.reason || '').trim().slice(0, 280),
    reasoning: String(parsed?.reasoning || parsed?.reason || '').trim().slice(0, 280),
  };
}

async function classifyWithOpenAI(data) {
  if (!OPENAI_API_KEY) {
    return { result: null, error: buildAiError(AI_ERROR_CODES.NO_PROVIDER, 'OPENAI_API_KEY missing', 'openai') };
  }

  const body = {
    model: AI_MODEL,
    temperature: 0,
    max_tokens: 140,
    messages: [
      {
        role: 'system',
        content: 'You classify cyber threats. Return strict JSON object only with keys: type, confidence, reason. type must be one of DDOS, MALWARE, SCAN, LOW. confidence must be number 0-100. Keep reason short.',
      },
      {
        role: 'user',
        content: JSON.stringify(data),
      },
    ],
    response_format: { type: 'json_object' },
  };

  try {
    const response = await fetchWithTimeout(
      'https://api.openai.com/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${OPENAI_API_KEY}`,
        },
        body: JSON.stringify(body),
      },
      AI_TIMEOUT_MS
    );
    if (!response.ok) {
      if (response.status === 429) {
        return { result: null, error: buildAiError(AI_ERROR_CODES.THROTTLED, 'openai_rate_limited', 'openai') };
      }
      return { result: null, error: buildAiError(AI_ERROR_CODES.UPSTREAM_HTTP_ERROR, `openai_http_${response.status}`, 'openai') };
    }

    const json = await response.json();
    const content = json?.choices?.[0]?.message?.content;
    const parsed = parseAiJson(content);
    return { result: normalizeAiResponse(parsed), error: null };
  } catch (err) {
    return {
      result: null,
      error: buildAiError(
        isAiTimeoutError(err) ? AI_ERROR_CODES.TIMEOUT : AI_ERROR_CODES.NETWORK_ERROR,
        safeErrorDetail(err),
        'openai'
      ),
    };
  }
}

async function classifyWithGemini(data) {
  if (!GEMINI_API_KEY) {
    console.warn('[Gemini Classify] No GEMINI_API_KEY — skipping');
    return { result: null, error: buildAiError(AI_ERROR_CODES.NO_PROVIDER, 'GEMINI_API_KEY missing', 'gemini') };
  }

  const PROMPT_STRING = `You classify cyber threats. Return strict JSON object only with keys: type, confidence, reason. type must be one of DDOS, MALWARE, SCAN, LOW. confidence must be number 0-100. Keep reason short.\n\n${JSON.stringify(data)}`;

  const body = {
    contents: [
      {
        parts: [{ text: PROMPT_STRING }]
      }
    ]
  };

  const model = getGeminiModelName();
  const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`;
  if (isGeminiRateLimited()) {
    console.warn('[Gemini Classify] Local rate-limit guard: RPM or RPD limit reached, skipping call');
    return { result: null, error: buildAiError(AI_ERROR_CODES.THROTTLED, 'gemini_local_rate_limit', 'gemini') };
  }
  recordGeminiRequest();
  console.log(`[Gemini Classify] Model: ${model} | Timeout: ${AI_TIMEOUT_MS}ms | IP: ${data?.sourceIp || 'N/A'}`);

  try {
    const response = await fetchWithTimeout(
      endpoint,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-goog-api-key': GEMINI_API_KEY,
        },
        body: JSON.stringify(body),
      },
      AI_TIMEOUT_MS
    );

    console.log(`[Gemini Classify] HTTP ${response.status}`);

    if (!response.ok) {
      const errorText = await readResponseTextSafe(response);
      if (response.status === 404) {
        console.warn(`[Gemini Classify] Invalid model (HTTP 404): ${model}`);
        return { result: null, error: buildAiError(AI_ERROR_CODES.INVALID_MODEL, `gemini_http_404_${model}`, 'gemini') };
      }
      if (response.status === 429) {
        console.warn('[Gemini Classify] Rate limit hit (429)');
        return { result: null, error: buildAiError(AI_ERROR_CODES.THROTTLED, 'gemini_rate_limited', 'gemini') };
      }
      console.warn(`[Gemini Classify] API Error: HTTP ${response.status}: ${truncateForLog(errorText, 200)}`);
      return { result: null, error: buildAiError(AI_ERROR_CODES.UPSTREAM_HTTP_ERROR, `gemini_http_${response.status}`, 'gemini') };
    }

    const json = await response.json();
    if (!json.candidates || !json.candidates[0]?.content?.parts?.length) {
      console.warn('[Gemini Classify] No candidates in response');
      return { result: null, error: buildAiError(AI_ERROR_CODES.UPSTREAM_HTTP_ERROR, 'gemini_no_candidates', 'gemini') };
    }

    const text = json.candidates[0].content.parts[0].text;
    console.log(`[Gemini Classify] Raw response (${text.length} chars): ${truncateForLog(text, 200)}`);

    let parsed;
    try {
      parsed = JSON.parse(text.replace(/```json/gi, '').replace(/```/g, '').trim());
    } catch {
      console.warn('[Gemini Classify] JSON parse failed, attempting brace extraction');
      parsed = parseAiJson(text);
      if (!parsed) {
        console.warn('[Gemini Classify] All parse attempts failed');
        return { result: null, error: buildAiError(AI_ERROR_CODES.UPSTREAM_HTTP_ERROR, 'gemini_parse_failed', 'gemini') };
      }
    }

    const normalized = normalizeAiResponse(parsed);
    if (normalized) {
      console.log(`[Gemini Classify] Result: type=${normalized.type} confidence=${normalized.confidence}`);
    } else {
      console.warn('[Gemini Classify] normalizeAiResponse returned null');
    }
    return { result: normalized, error: null };
  } catch (err) {
    console.warn(`[Gemini Classify] Fetch error: ${err.message}`);
    return {
      result: null,
      error: buildAiError(
        isAiTimeoutError(err) ? AI_ERROR_CODES.TIMEOUT : AI_ERROR_CODES.NETWORK_ERROR,
        safeErrorDetail(err),
        'gemini'
      ),
    };
  }
}

const AI_REPORT_SYSTEM_PROMPT = `You are a cybersecurity incident report generator.

You will receive a JSON object describing a network threat.

Respond ONLY with valid JSON in this exact format (no markdown, no extra text):

{
  "executive_summary": "2-3 sentences explaining the threat clearly",
  "technical_analysis": "brief explanation of signals and reasoning",
  "risk_level": "LOW | MEDIUM | HIGH | CRITICAL",
  "recommended_action": "specific mitigation steps"
}

Base your reasoning on:
- abuseConfidenceScore
- otxHits
- openPorts
- classification
- score

Keep it concise, professional, and deterministic.`;

const AI_REPORT_RISK_LEVELS = new Set(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);

function toRiskLevelFromScore(score) {
  const safeScore = clampNumber(score, 0, 100, NaN);
  if (!Number.isFinite(safeScore)) return null;
  if (safeScore >= 85) return 'CRITICAL';
  if (safeScore >= 65) return 'HIGH';
  if (safeScore >= 35) return 'MEDIUM';
  return 'LOW';
}

function normalizeAiReportRiskLevel(value) {
  const text = String(value || '').trim().toUpperCase();
  if (!text) return null;
  if (text.includes('CRIT')) return 'CRITICAL';
  if (text.includes('HIGH')) return 'HIGH';
  if (text.includes('MED')) return 'MEDIUM';
  if (text.includes('LOW')) return 'LOW';
  return null;
}

function buildAiReportSummaryFallbacks(payload) {
  const sourceCountry = String(payload?.sourceCountry || 'Unknown source');
  const classification = String(payload?.classification || 'LOW').toUpperCase();
  const score = Number.isFinite(payload?.score) ? Number(payload.score).toFixed(1) : '0.0';
  const abuseScore = Number.isFinite(payload?.abuseConfidenceScore) ? Number(payload.abuseConfidenceScore).toFixed(0) : '0';
  const otxHits = Number.isFinite(payload?.otxHits) ? Number(payload.otxHits).toFixed(0) : '0';
  const openPorts = Number.isFinite(payload?.openPorts) ? Number(payload.openPorts).toFixed(0) : '0';

  return {
    executive_summary: `Potential ${classification} activity detected from ${sourceCountry} (score ${score}).`,
    technical_analysis: `Signal snapshot: abuseScore=${abuseScore}, otxHits=${otxHits}, openPorts=${openPorts}. Review report indicators for analyst confirmation.`,
    recommended_action: 'Block or rate-limit suspicious sources, monitor related indicators, and audit exposed services for immediate hardening.',
  };
}

function normalizeAiReportSummary(parsed, payload) {
  if (!parsed || typeof parsed !== 'object') return null;

  const fallback = buildAiReportSummaryFallbacks(payload);

  const executiveSummary = String(parsed.executive_summary || parsed.executiveSummary || '').trim();
  const technicalAnalysis = String(parsed.technical_analysis || parsed.technicalAnalysis || '').trim();
  const recommendedAction = String(parsed.recommended_action || parsed.recommendedAction || '').trim();

  const explicitRisk = normalizeAiReportRiskLevel(
    parsed.risk_level || parsed.riskLevel || parsed.risk || parsed.level
  );
  const scoreRisk = toRiskLevelFromScore(parsed.score ?? parsed.threat_score ?? parsed.threatScore ?? payload?.score);
  const riskLevel = explicitRisk || scoreRisk;

  const hasNarrative = Boolean(executiveSummary || technicalAnalysis || recommendedAction);
  if (!hasNarrative || !riskLevel) {
    return null;
  }

  if (!AI_REPORT_RISK_LEVELS.has(riskLevel)) {
    return null;
  }

  return {
    executive_summary: executiveSummary || technicalAnalysis || fallback.executive_summary,
    technical_analysis: technicalAnalysis || fallback.technical_analysis,
    risk_level: riskLevel,
    recommended_action: recommendedAction || fallback.recommended_action,
  };
}

function normalizeAiReportSummaryFromContent(content, payload) {
  const parsed = parseAiJson(content);
  const normalized = normalizeAiReportSummary(parsed, payload);
  if (normalized) {
    return normalized;
  }

  const plainText = String(content || '').replace(/\s+/g, ' ').trim();
  if (plainText.length < 24) {
    return null;
  }

  const extractJsonLikeField = (key) => {
    const pattern = new RegExp(`"${key}"\\s*:\\s*"([^\\"]+)`, 'i');
    const match = plainText.match(pattern);
    return match ? String(match[1]).trim() : '';
  };

  const extractedExecutive = extractJsonLikeField('executive_summary');
  const extractedTechnical = extractJsonLikeField('technical_analysis');
  const extractedAction = extractJsonLikeField('recommended_action');
  const extractedRisk = normalizeAiReportRiskLevel(extractJsonLikeField('risk_level'));

  const fallback = buildAiReportSummaryFallbacks(payload);
  const inferredRisk = extractedRisk
    || normalizeAiReportRiskLevel(plainText)
    || toRiskLevelFromScore(payload?.score)
    || 'MEDIUM';

  const hasExtractedFields = Boolean(extractedExecutive || extractedTechnical || extractedAction);
  if (hasExtractedFields) {
    return {
      executive_summary: extractedExecutive || extractedTechnical || fallback.executive_summary,
      technical_analysis: extractedTechnical || fallback.technical_analysis,
      risk_level: AI_REPORT_RISK_LEVELS.has(inferredRisk) ? inferredRisk : 'MEDIUM',
      recommended_action: extractedAction || fallback.recommended_action,
    };
  }

  const cleanedPlain = plainText
    .replace(/^\{+\s*/, '')
    .replace(/\s*\}+$/, '')
    .trim();

  return {
    executive_summary: cleanedPlain.length > 320 ? `${cleanedPlain.slice(0, 317)}...` : cleanedPlain,
    technical_analysis: fallback.technical_analysis,
    risk_level: AI_REPORT_RISK_LEVELS.has(inferredRisk) ? inferredRisk : 'MEDIUM',
    recommended_action: fallback.recommended_action,
  };
}

function buildAiReportAttemptResult({
  summary = null,
  reasonCode = AI_REPORT_REASON_CODES.INTERNAL_ERROR,
  reasonDetail = null,
  provider = null,
} = {}) {
  return {
    summary,
    reasonCode,
    reasonDetail: reasonDetail ? String(reasonDetail).trim() : null,
    provider,
  };
}

function isAiTimeoutError(err) {
  const message = String(err?.message || '').toLowerCase();
  return message.includes('timed out') || message.includes('timeout');
}

function sanitizeIpInput(value) {
  const text = String(value || '').trim();
  return net.isIP(text) ? text : '';
}

function sanitizeCountryInput(value) {
  return String(value || '')
    .replace(/[^\p{L}\p{M}\s.,'()-]/gu, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 64);
}

function sanitizeClassificationInput(value) {
  const text = String(value || '').trim().toUpperCase();
  return Object.values(THREAT_CLASSIFICATION).includes(text) ? text : 'LOW';
}

function sanitizeCount(value, max = 1000000) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return 0;
  return Math.min(numeric, max);
}

function buildReportThreatPayload(threat) {
  const abuseConfidenceScore = clampNumber(threat?.signals?.abuseScore, 0, 100, 0);
  const otxHits = sanitizeCount(threat?.signals?.otxHits);
  const openPorts = sanitizeCount(threat?.signals?.portExposure);

  return {
    ip: sanitizeIpInput(threat?.sourceIp || threat?.ip),
    sourceCountry: sanitizeCountryInput(threat?.sourceCountry),
    abuseConfidenceScore,
    otxHits,
    openPorts,
    classification: sanitizeClassificationInput(threat?.classification),
    score: clampNumber(threat?.score, 0, 100, 0),
  };
}

function getGeminiModelName() {
  const configured = String(process.env.GEMINI_MODEL || '').trim();
  if (configured) return configured;
  return GEMINI_MODEL;
}

function buildGeminiReportRequestBodies(payload) {
  const PROMPT_STRING = `${AI_REPORT_SYSTEM_PROMPT}\n\n${JSON.stringify(payload)}`;
  return [
    {
      contents: [
        {
          role: 'user',
          parts: [{ text: PROMPT_STRING }],
        },
      ],
    }
  ];
}

async function generateReportSummaryWithOpenAI(payload) {
  if (!OPENAI_API_KEY) {
    return buildAiReportAttemptResult({
      reasonCode: AI_REPORT_REASON_CODES.NO_PROVIDER,
      reasonDetail: 'OPENAI_API_KEY is missing',
      provider: 'openai',
    });
  }

  const body = {
    model: AI_MODEL,
    temperature: 0,
    max_tokens: 280,
    messages: [
      {
        role: 'system',
        content: AI_REPORT_SYSTEM_PROMPT,
      },
      {
        role: 'user',
        content: JSON.stringify(payload),
      },
    ],
    response_format: { type: 'json_object' },
  };

  try {
    const response = await fetchWithOptionalTimeout(
      'https://api.openai.com/v1/chat/completions',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${OPENAI_API_KEY}`,
        },
        body: JSON.stringify(body),
      },
      AI_REPORT_TIMEOUT_MS
    );

    if (!response.ok) {
      const errorText = await readResponseTextSafe(response);
      console.warn(`[AI Report][openai] HTTP ${response.status}: ${truncateForLog(errorText)}`);
      return buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.UPSTREAM_HTTP_ERROR,
        reasonDetail: `openai_http_${response.status}`,
        provider: 'openai',
      });
    }

    const json = await response.json();
    const content = json?.choices?.[0]?.message?.content;
    const normalized = normalizeAiReportSummaryFromContent(content, payload);
    if (!normalized) {
      console.warn('[AI Report][openai] Response did not match expected JSON schema');
      return buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.SCHEMA_MISMATCH,
        reasonDetail: 'openai_schema_mismatch',
        provider: 'openai',
      });
    }
    return buildAiReportAttemptResult({
      summary: normalized,
      reasonCode: AI_REPORT_REASON_CODES.NONE,
      provider: 'openai',
    });
  } catch (err) {
    console.warn('[AI Report][openai] Request failed:', err.message);
    return buildAiReportAttemptResult({
      reasonCode: isAiTimeoutError(err)
        ? AI_REPORT_REASON_CODES.TIMEOUT
        : AI_REPORT_REASON_CODES.NETWORK_ERROR,
      reasonDetail: safeErrorDetail(err),
      provider: 'openai',
    });
  }
}

async function generateReportSummaryWithGemini(payload) {
  if (!GEMINI_API_KEY) {
    return buildAiReportAttemptResult({
      reasonCode: AI_REPORT_REASON_CODES.NO_PROVIDER,
      reasonDetail: 'GEMINI_API_KEY is missing',
      provider: 'gemini',
    });
  }

  const requestBodies = buildGeminiReportRequestBodies(payload);
  const model = getGeminiModelName();

  try {
    let lastFailure = buildAiReportAttemptResult({
      reasonCode: AI_REPORT_REASON_CODES.INTERNAL_ERROR,
      reasonDetail: 'gemini_unknown',
      provider: 'gemini',
    });

    for (let bodyIndex = 0; bodyIndex < requestBodies.length; bodyIndex += 1) {
      if (isGeminiRateLimited()) {
        return buildAiReportAttemptResult({
          reasonCode: AI_REPORT_REASON_CODES.THROTTLED,
          reasonDetail: 'gemini_local_rate_limit',
          provider: 'gemini',
        });
      }
      recordGeminiRequest();
      const response = await fetchWithOptionalTimeout(
        `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-goog-api-key': GEMINI_API_KEY,
          },
          body: JSON.stringify(requestBodies[bodyIndex]),
        },
        AI_REPORT_TIMEOUT_MS
      );

      if (!response.ok) {
        const errorText = await readResponseTextSafe(response);
        console.warn(`[AI Report][gemini:${model}:fmt${bodyIndex}] HTTP ${response.status}: ${truncateForLog(errorText)}`);

        if (response.status === 404) {
          return buildAiReportAttemptResult({
            reasonCode: AI_REPORT_REASON_CODES.INVALID_MODEL,
            reasonDetail: `gemini_http_404_${model}_fmt${bodyIndex}`,
            provider: 'gemini',
          });
        }

        if (response.status === 401 || response.status === 403 || response.status === 429) {
          return buildAiReportAttemptResult({
            reasonCode: AI_REPORT_REASON_CODES.UPSTREAM_HTTP_ERROR,
            reasonDetail: `gemini_http_${response.status}_${model}_fmt${bodyIndex}`,
            provider: 'gemini',
          });
        }

        lastFailure = buildAiReportAttemptResult({
          reasonCode: AI_REPORT_REASON_CODES.UPSTREAM_HTTP_ERROR,
          reasonDetail: `gemini_http_${response.status}_${model}_fmt${bodyIndex}`,
          provider: 'gemini',
        });
        continue;
      }

      const json = await response.json();
      const text = json?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!text) continue;
      const normalized = normalizeAiReportSummaryFromContent(text, payload);
      if (normalized) {
        return buildAiReportAttemptResult({
          summary: normalized,
          reasonCode: AI_REPORT_REASON_CODES.NONE,
          provider: 'gemini',
        });
      }

      console.warn(`[AI Report][gemini:${model}:fmt${bodyIndex}] Response did not match expected JSON schema`);
      lastFailure = buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.SCHEMA_MISMATCH,
        reasonDetail: `gemini_schema_mismatch_${model}_fmt${bodyIndex}`,
        provider: 'gemini',
      });
    }

    return lastFailure;
  } catch (err) {
    console.warn('[AI Report][gemini] Request failed:', err.message);
    return buildAiReportAttemptResult({
      reasonCode: isAiTimeoutError(err)
        ? AI_REPORT_REASON_CODES.TIMEOUT
        : AI_REPORT_REASON_CODES.NETWORK_ERROR,
      reasonDetail: safeErrorDetail(err),
      provider: 'gemini',
    });
  }
}

async function generateAiReportSummary(threat, mode = resolveDefaultAiProviderMode(), options = {}) {
  const explicitRequest = options?.explicitRequest !== false;

  if (!threat || typeof threat !== 'object') {
    return {
      ...buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.INTERNAL_ERROR,
        reasonDetail: 'invalid_threat_payload',
      }),
      attemptedProviders: [],
    };
  }

  const attemptedProviders = resolveAiAttemptProviders(mode);
  if (attemptedProviders.length === 0) {
    console.warn(`[AI Report] No providers available for mode=${mode}`);
    return {
      ...buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.NO_PROVIDER,
        reasonDetail: `mode=${mode}`,
      }),
      attemptedProviders,
    };
  }

  const payload = buildReportThreatPayload(threat);
  const reportCacheKey = buildAiCacheKey('report', {
    sourceIp: payload.ip,
    abuseConfidenceScore: payload.abuseConfidenceScore,
    otxHits: payload.otxHits,
    openPorts: payload.openPorts,
  });

  const cachedReport = readAiCache(reportCacheKey);
  if (cachedReport) {
    incrementAiMetric('cacheHits');
    incrementAiMetric('skippedCache');
    
    return cachedReport;
  }
  incrementAiMetric('cacheMisses');

  const now = Date.now();
  if (!explicitRequest && isAiThrottled(now)) {
    incrementAiMetric('skippedThrottle');
    
    const throttledResult = {
      ...buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.THROTTLED,
        reasonDetail: `ai_throttle_${AI_THROTTLE_MS}ms`,
        provider: null,
      }),
      attemptedProviders,
    };
    writeAiCache(reportCacheKey, throttledResult, AI_FAILURE_CACHE_TTL_MS);
    return throttledResult;
  }

  incrementAiMetric('totalCalls');
  markAiCallStart(now);

  let lastFailure = buildAiReportAttemptResult({
    reasonCode: AI_REPORT_REASON_CODES.INTERNAL_ERROR,
    reasonDetail: `mode=${mode}`,
  });

  try {
    for (let i = 0; i < attemptedProviders.length; i += 1) {
      const provider = attemptedProviders[i];
      const attempt = provider === 'openai'
        ? await generateReportSummaryWithOpenAI(payload)
        : await generateReportSummaryWithGemini(payload);

      if (attempt.summary) {
        incrementAiMetric('successCalls');
        const successResult = {
          ...attempt,
          attemptedProviders,
        };
        writeAiCache(reportCacheKey, successResult);
        return successResult;
      }

      lastFailure = attempt;
    }
  } catch (err) {
    incrementAiMetric('failedCalls');
    console.warn('[AI Report] Summary generation failed:', err.message);
    const failureResult = {
      ...buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.INTERNAL_ERROR,
        reasonDetail: safeErrorDetail(err),
      }),
      attemptedProviders,
    };
    writeAiCache(reportCacheKey, failureResult, AI_FAILURE_CACHE_TTL_MS);
    return failureResult;
  }

  console.warn(`[AI Report] No summary generated (mode=${mode}, attempted=${attemptedProviders.join(',')})`);
  incrementAiMetric('failedCalls');

  const finalFailure = {
    ...lastFailure,
    attemptedProviders,
  };
  writeAiCache(reportCacheKey, finalFailure, AI_FAILURE_CACHE_TTL_MS);
  return finalFailure;
}

function emptyAiSummary(reasonCode = AI_REPORT_REASON_CODES.NONE, reasonDetail = null, attemptedProviders = []) {
  return {
    used: false,
    executive_summary: null,
    technical_analysis: null,
    risk_level: null,
    recommended_action: null,
    reason_code: reasonCode,
    reason_detail: reasonDetail ? String(reasonDetail) : null,
    attempted_providers: Array.isArray(attemptedProviders) ? attemptedProviders.map(String) : [],
  };
}

async function applyOptionalAiLayer(ruleThreat, mode, threshold = 70, options = {}) {
  if (!ruleThreat) return null;

  const {
    eligibleForTopN = true,
    explicitRequest = false,
  } = options;

  const ruleScore = clampNumber(ruleThreat.score, 0, 100, 0);
  const attemptedProviders = resolveAiAttemptProviders(mode);
  const aiEnabled = attemptedProviders.length > 0;

  const buildFallback = (
    reasonText,
    {
      isFiltered = false,
      enabled = aiEnabled,
      fallback = true,
      provider = null,
      confidence = null,
      reasonCode = null,
    } = {}
  ) => ({
    ...ruleThreat,
    ai: {
      used: false,
      provider,
      confidence,
      reasoning: null,
      enabled,
      fallback,
      reason: reasonText,
      reasonCode,
      filtered: isFiltered,
    },
    signals: {
      ...(ruleThreat.signals || {}),
      ruleScore,
    },
  });

  const buildAppliedResult = (aiOutcome, aiResult) => {
    // The model's verdict decides the class; confidence only gates whether it is applied.
    // The evidence-based rule score is kept, clamped into the verdict's band so score and class agree.
    const finalClassification = aiResult.type;
    const band = CLASSIFICATION_SCORE_BANDS[finalClassification] || CLASSIFICATION_SCORE_BANDS[THREAT_CLASSIFICATION.LOW];
    const finalScore = clampNumber(ruleScore, band.min, band.max, ruleScore);
    const finalType = mapClassificationToType(finalClassification);

    return {
      ...ruleThreat,
      score: finalScore,
      classification: finalClassification,
      type: finalType,
      intensity: normalizeIntensity(finalScore),
      color: COLOR_MAP[finalType] || '#9fb3c8',
      signals: {
        ...(ruleThreat.signals || {}),
        ruleScore,
        aiConfidence: aiResult.confidence,
        aiVerdict: aiResult.type,
        finalScore,
      },
      ai: {
        used: true,
        provider: aiOutcome.providerUsed,
        confidence: aiResult.confidence,
        reasoning: aiResult.reason || 'AI classification applied.',
        enabled: true,
        fallback: aiOutcome.fallback,
        filtered: false,
        type: aiResult.type,
        reason: aiResult.reason || 'AI classification applied.',
      },
    };
  };

  if (!aiEnabled) {
    return buildFallback('No AI provider available', {
      enabled: false,
      fallback: false,
      reasonCode: AI_ERROR_CODES.NO_PROVIDER,
    });
  }

  // Cache reads are free, so they come before every cost gate.
  const cacheKey = buildAiCacheKey('classify', ruleThreat);
  const cachedOutcome = readAiCache(cacheKey);
  if (cachedOutcome) {
    incrementAiMetric('cacheHits');
    incrementAiMetric('skippedCache');
    
    const cachedResult = cachedOutcome.result;
    if (!cachedResult) {
      return buildFallback('Cached rule-based fallback', {
        enabled: true,
        fallback: Boolean(cachedOutcome.fallback),
      });
    }

    if (cachedResult.confidence < threshold) {
      return buildFallback(cachedResult.reason || 'Filtered due to low confidence', {
        isFiltered: true,
        enabled: true,
        fallback: Boolean(cachedOutcome.fallback),
        provider: cachedOutcome.providerUsed,
        confidence: cachedResult.confidence,
      });
    }

    return buildAppliedResult(cachedOutcome, cachedResult);
  }
  incrementAiMetric('cacheMisses');

  const aiDecision = shouldAttemptAiForThreat(ruleThreat, explicitRequest);
  if (!aiDecision.shouldCall) {
    incrementAiMetric('skippedLowScore');
    return buildFallback('AI skipped: low score', { enabled: false, fallback: true });
  }

  if (!eligibleForTopN && !explicitRequest) {
    return buildFallback(`Outside top ${AI_TOP_N} by score`, { enabled: false, fallback: true });
  }

  const now = Date.now();
  if (!explicitRequest && isAiThrottled(now)) {
    incrementAiMetric('skippedThrottle');
    return buildFallback('AI skipped: throttled', {
      enabled: true,
      fallback: true,
      reasonCode: AI_ERROR_CODES.THROTTLED,
    });
  }

  incrementAiMetric('totalCalls');
  markAiCallStart(now);
  const aiOutcome = await classifyThreatWithAI(ruleThreat, mode);
  const aiResult = aiOutcome.result;
  // Failures are cached only briefly so one transient error does not blind an IP for 10 minutes.
  writeAiCache(cacheKey, aiOutcome, aiResult ? AI_CACHE_TTL_MS : AI_FAILURE_CACHE_TTL_MS);

  if (!aiResult) {
    incrementAiMetric('failedCalls');
    const fallbackReason = aiOutcome?.error?.reason || 'Rule-based fallback';
    return buildFallback(fallbackReason, {
      enabled: aiOutcome.attemptedProviders.length > 0,
      fallback: aiOutcome.fallback,
      reasonCode: aiOutcome?.error?.code || AI_ERROR_CODES.UPSTREAM_HTTP_ERROR,
    });
  }

  incrementAiMetric('successCalls');

  if (aiResult.confidence < threshold) {
    return buildFallback(aiResult.reason || 'Filtered due to low confidence', {
      isFiltered: true,
      enabled: true,
      fallback: aiOutcome.fallback,
      provider: aiOutcome.providerUsed,
      confidence: aiResult.confidence,
    });
  }

  return buildAppliedResult(aiOutcome, aiResult);
}

function toCountryName(code) {
  if (!code || typeof code !== 'string') return null;
  const normalized = code.trim().toUpperCase();
  if (COUNTRY_CODE_MAP[normalized]) return COUNTRY_CODE_MAP[normalized];
  if (regionNameFormatter) {
    const intlName = regionNameFormatter.of(normalized);
    if (intlName && intlName !== normalized) return intlName;
  }
  return normalized;
}

function normalizeIntensity(score = 50) {
  return Math.min(10, Math.max(1, Math.round((Number(score) || 50) / 10)));
}

// Attack destinations are not observable from the feeds; every arc terminates at one neutral monitoring node.
const SENSOR_NODE = {
  country: 'Unattributed',
  lat: process.env.SENSOR_LAT && Number.isFinite(Number(process.env.SENSOR_LAT)) ? Number(process.env.SENSOR_LAT) : 20,
  lng: process.env.SENSOR_LNG && Number.isFinite(Number(process.env.SENSOR_LNG)) ? Number(process.env.SENSOR_LNG) : 0,
};

function getCountryCoords(countryName) {
  return COUNTRY_COORDS[countryName] || null;
}

function getOtxHits(otxData) {
  const pulseCount = Number(otxData?.pulse_info?.count || 0);
  const pulseListCount = Array.isArray(otxData?.pulse_info?.pulses)
    ? otxData.pulse_info.pulses.length
    : 0;
  return Math.max(toNonNegativeNumber(pulseCount), toNonNegativeNumber(pulseListCount));
}

function dedupeByIp(entries) {
  const seen = new Set();
  return entries.filter((entry) => {
    const ip = entry?.ipAddress;
    if (!ip || seen.has(ip)) return false;
    seen.add(ip);
    return true;
  });
}

function parseLoc(loc) {
  if (!loc || typeof loc !== 'string' || !loc.includes(',')) return null;
  const [latStr, lngStr] = loc.split(',');
  const lat = parseFloat(latStr);
  const lng = parseFloat(lngStr);
  if (Number.isNaN(lat) || Number.isNaN(lng)) return null;
  return { lat, lng };
}

async function fetchAbuseBlacklist(ABUSE_KEY) {
  if (!ABUSE_KEY) return { ok: false, reason: 'missing-key', entries: [] };
  if (usage.abuseipdb >= ABUSE_DAILY_SAFE_THRESHOLD) {
    return { ok: false, reason: 'daily-threshold', entries: [] };
  }

  try {
    const response = await fetchWithTimeout(
      'https://api.abuseipdb.com/api/v2/blacklist?limit=25&confidenceMinimum=65',
      {
        headers: {
          Key: ABUSE_KEY,
          Accept: 'application/json',
        },
      },
      REQUEST_TIMEOUT_MS,
      'abuseipdb'
    );

    if (!response.ok) {
      if (response.status === 429) {
        setProviderStatus('abuseipdb', SOURCE_STATUS_RATE_LIMITED);
      } else {
        setProviderStatus('abuseipdb', SOURCE_STATUS_FAILED);
      }
      logProviderFailure('abuseipdb', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        reason: 'blacklist_fetch_failed',
      });
      return {
        ok: false,
        reason: response.status === 429 ? 'rate-limited' : `http-${response.status}`,
        entries: [],
      };
    }

    const json = await response.json();
    const entries = Array.isArray(json?.data) ? json.data : [];
    setProviderStatus('abuseipdb', SOURCE_STATUS_OK);
    return { ok: entries.length > 0, reason: entries.length > 0 ? 'ok' : 'empty', entries };
  } catch (err) {
    setProviderStatus('abuseipdb', SOURCE_STATUS_FAILED);
    logProviderFailure('abuseipdb', {
      category: getProviderErrorCategory(err),
      reason: 'blacklist_fetch_exception',
      details: err?.message || '',
    });
    return { ok: false, reason: 'error', entries: [], details: err.message };
  }
}

async function fetchOtxGeneral(OTX_KEY, ipAddress) {
  if (!ipAddress || isPrivateOrBogon(ipAddress)) return null;

  try {
    const headers = {
      Accept: 'application/json',
    };
    if (OTX_KEY) {
      headers['X-OTX-API-KEY'] = OTX_KEY;
    }

    const response = await fetchWithTimeout(
      `https://otx.alienvault.com/api/v1/indicators/${net.isIP(ipAddress) === 6 ? 'IPv6' : 'IPv4'}/${encodeURIComponent(ipAddress)}/general`,
      { headers },
      REQUEST_TIMEOUT_MS,
      'otx'
    );

    if (response.status === 404) {
      setProviderStatus('otx', SOURCE_STATUS_OK);
      return null;
    }

    if (!response.ok) {
      logProviderFailure('otx', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'general_lookup_failed',
      });
      setProviderStatus('otx', SOURCE_STATUS_FAILED);
      return null;
    }
    const json = await response.json();
    setProviderStatus('otx', SOURCE_STATUS_OK);
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
    setProviderStatus('otx', SOURCE_STATUS_FAILED);
    logProviderFailure('otx', {
      category: getProviderErrorCategory(err),
      ipAddress,
      reason: 'general_lookup_exception',
      details: err?.message || '',
    });
    return null;
  }
}

async function fetchShodanHost(SHODAN_KEY, ipAddress) {
  if (!SHODAN_KEY) return null;
  if (!ipAddress || isPrivateOrBogon(ipAddress)) return null;

  try {
    const response = await fetchWithTimeout(
      `https://api.shodan.io/shodan/host/${encodeURIComponent(ipAddress)}?key=${encodeURIComponent(SHODAN_KEY)}`,
      {
        headers: {
          Accept: 'application/json',
        },
      },
      REQUEST_TIMEOUT_MS,
      'shodan'
    );
    if (response.status === 404) {
      setProviderStatus('shodan', SOURCE_STATUS_OK);
      return null;
    }
    if (!response.ok) {
      if (response.status === 403) {
        setProviderStatus('shodan', SOURCE_STATUS_UNAUTHORIZED);
      } else {
        setProviderStatus('shodan', SOURCE_STATUS_FAILED);
      }
      logProviderFailure('shodan', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'host_lookup_failed',
      });
      return null;
    }
    const json = await response.json();
    setProviderStatus('shodan', SOURCE_STATUS_OK);
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
    setProviderStatus('shodan', SOURCE_STATUS_FAILED);
    logProviderFailure('shodan', {
      category: getProviderErrorCategory(err),
      ipAddress,
      reason: 'host_lookup_exception',
      details: err?.message || '',
    });
    return null;
  }
}

async function fetchIpInfo(IPINFO_KEY, ipAddress) {
  if (!ENABLE_IPINFO) return null;
  if (!IPINFO_KEY) return null;
  if (!ipAddress || isPrivateOrBogon(ipAddress)) return null;

  try {
    const response = await fetchWithTimeout(
      `https://ipinfo.io/${encodeURIComponent(ipAddress)}/json`,
      { headers: { Authorization: `Bearer ${IPINFO_KEY}`, Accept: 'application/json' } },
      REQUEST_TIMEOUT_MS,
      'ipinfo'
    );
    if (!response.ok) {
      setProviderStatus('ipinfo', SOURCE_STATUS_FAILED);
      logProviderFailure('ipinfo', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'geo_lookup_failed',
      });
      return null;
    }
    const json = await response.json();
    setProviderStatus('ipinfo', SOURCE_STATUS_OK);
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
    setProviderStatus('ipinfo', SOURCE_STATUS_FAILED);
    logProviderFailure('ipinfo', {
      category: getProviderErrorCategory(err),
      ipAddress,
      reason: 'geo_lookup_exception',
      details: err?.message || '',
    });
    return null;
  }
}

async function resolveGeo(ipAddress, IPINFO_KEY, fallback = {}) {
  const geo = await fetchIpInfo(IPINFO_KEY, ipAddress);
  const fromIpInfo = parseLoc(geo?.loc);
  if (fromIpInfo) {
    const countryCode = String(geo.country || '').toUpperCase();
    const countryName = toCountryName(countryCode) || fallback.countryName || 'Unknown';
    return {
      sourceLat: fromIpInfo.lat,
      sourceLng: fromIpInfo.lng,
      sourceCountry: countryName,
      sourceCountryCode: countryCode || fallback.countryCode || '',
      sourceCity: geo.city || fallback.city || 'Unknown',
      sourceRegion: geo.region || fallback.region || 'Unknown',
    };
  }

  const shodanLat = fallback?.lat;
  const shodanLng = fallback?.lng;
  if (Number.isFinite(shodanLat) && Number.isFinite(shodanLng)) {
    return {
      sourceLat: shodanLat,
      sourceLng: shodanLng,
      sourceCountry: fallback.countryName || 'Unknown',
      sourceCountryCode: fallback.countryCode || '',
      sourceCity: fallback.city || 'Unknown',
      sourceRegion: fallback.region || 'Unknown',
    };
  }

  if (fallback.countryCode || fallback.countryName) {
    const countryName = fallback.countryName || toCountryName(fallback.countryCode);
    const coords = countryName ? getCountryCoords(countryName) : null;
    if (countryName && coords) {
      return {
        sourceLat: coords.lat,
        sourceLng: coords.lng,
        sourceCountry: countryName,
        sourceCountryCode: fallback.countryCode || '',
        sourceCity: fallback.city || 'Unknown',
        sourceRegion: fallback.region || 'Unknown',
      };
    }
  }

  return null;
}

function normalizeThreatRecord({
  ipAddress,
  geo,
  type,
  score,
  classification,
  signals,
  sources,
  timestamp,
  provider,
}) {
  if (!geo) return null;
  if (isPrivateOrBogon(ipAddress)) return null;
  if (!Number.isFinite(geo.sourceLat) || !Number.isFinite(geo.sourceLng)) return null;
  if (!geo.sourceCountry) return null;

  const target = SENSOR_NODE;
  const safeScore = clampNumber(score, 0, 100, 0);
  const resolvedClassification = classifyFromScore(safeScore);
  const resolvedType = type || mapClassificationToType(classification || resolvedClassification);
  const intensity = normalizeIntensity(safeScore);
  const resolvedSourceStatus = normalizeSourceStatus(
    sources || signals?.sourceStatus || {},
    signals || {}
  );
  const availableSources = getAvailableSources(resolvedSourceStatus);
  const missingSources = Object.keys(SOURCE_SIGNAL_KEYS).filter(
    (source) => !availableSources.includes(source)
  );

  const fallbackSignals = {
    abuseScore: 0,
    otxHits: 0,
    portExposure: 0,
    otxScore: 0,
    portExposureScore: 0,
    usedSources: [...availableSources],
    sourcesUsed: [...availableSources],
    availableSources: [...availableSources],
    missingSources,
    sourceStatus: resolvedSourceStatus,
    activeWeight: getActiveWeightFromSources(availableSources),
  };

  const resolvedSignals = signals
    ? {
      ...signals,
      abuseScore: clampNumber(signals.abuseScore ?? 0, 0, 100, 0),
      otxHits: toNonNegativeNumber(signals.otxHits ?? 0),
      portExposure: toNonNegativeNumber(signals.portExposure ?? 0),
      usedSources: Array.isArray(signals.usedSources) ? signals.usedSources : [...availableSources],
      sourcesUsed: Array.isArray(signals.sourcesUsed)
        ? signals.sourcesUsed
        : Array.isArray(signals.usedSources)
          ? signals.usedSources
          : [...availableSources],
      availableSources: Array.isArray(signals.availableSources) ? signals.availableSources : [...availableSources],
      missingSources: Array.isArray(signals.missingSources) ? signals.missingSources : missingSources,
      sourceStatus: resolvedSourceStatus,
      activeWeight: Number.isFinite(Number(signals.activeWeight))
        ? Number(signals.activeWeight)
        : getActiveWeightFromSources(availableSources),
    }
    : fallbackSignals;

  return {
    id: `ip-${ipAddress}`,
    sourceLat: geo.sourceLat,
    sourceLng: geo.sourceLng,
    sourceCountry: geo.sourceCountry,
    sourceCountryCode: geo.sourceCountryCode || '',
    sourceCity: geo.sourceCity || 'Unknown',
    sourceRegion: geo.sourceRegion || 'Unknown',
    sourceIp: ipAddress,
    targetLat: target.lat,
    targetLng: target.lng,
    targetCountry: target.country,
    type: resolvedType,
    score: safeScore,
    classification: resolvedClassification,
    signals: resolvedSignals,
    sources: resolvedSourceStatus,
    intensity,
    color: COLOR_MAP[resolvedType] || '#9fb3c8',
    timestamp,
    provider: provider || 'fallback',
  };
}

// ── Phase 1: Collect candidate IPs from all enabled providers ─────────

const ABUSE_REFRESH_MS = clampNumber(process.env.ABUSE_REFRESH_MS, 10 * 60 * 1000, 24 * 60 * 60 * 1000, 6 * 60 * 60 * 1000);
const ENRICHMENT_TTL_MS = 30 * 60 * 1000;
const ENRICHMENT_CONCURRENCY = 4;
const MAX_CANDIDATE_IPS = 12;
const ENRICHMENT_CACHE_MAX = 500;

let abuseBlacklistCache = { entries: [], fetchedAt: 0 };
let abuseRotationOffset = 0;
const enrichmentCache = new Map();

async function mapWithConcurrency(items, limit, worker) {
  const results = new Array(items.length);
  let cursor = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const index = cursor;
      cursor += 1;
      try {
        results[index] = { status: 'fulfilled', value: await worker(items[index], index) };
      } catch (reason) {
        results[index] = { status: 'rejected', reason };
      }
    }
  });
  await Promise.all(runners);
  return results;
}

function readEnrichmentCache(ip) {
  const entry = enrichmentCache.get(ip);
  if (!entry) return null;
  if (Date.now() - entry.at > ENRICHMENT_TTL_MS) {
    enrichmentCache.delete(ip);
    return null;
  }
  return entry;
}

function writeEnrichmentCache(ip, value) {
  enrichmentCache.delete(ip);
  enrichmentCache.set(ip, { ...value, at: Date.now() });
  while (enrichmentCache.size > ENRICHMENT_CACHE_MAX) {
    enrichmentCache.delete(enrichmentCache.keys().next().value);
  }
}

async function collectAbuseIps(abuseKey) {
  if (!ENABLE_ABUSE) return { ips: [], reason: 'disabled' };

  const cacheFresh = abuseBlacklistCache.entries.length > 0
    && (Date.now() - abuseBlacklistCache.fetchedAt) < ABUSE_REFRESH_MS;
  let reason = 'cached';

  if (!cacheFresh) {
    if (usage.abuseipdb >= ABUSE_DAILY_SAFE_THRESHOLD) {
      reason = 'daily-threshold';
    } else {
      const blacklist = await fetchAbuseBlacklist(abuseKey);
      if (blacklist.ok) {
        abuseBlacklistCache = { entries: blacklist.entries, fetchedAt: Date.now() };
        reason = 'ok';
      } else {
        reason = blacklist.reason;
      }
    }
  }

  // Stale data beats hardcoded demo IPs when the provider is exhausted or failing.
  const pool = dedupeByIp(abuseBlacklistCache.entries)
    .filter((entry) => !isPrivateOrBogon(entry?.ipAddress))
    .sort((a, b) => Number(b.abuseConfidenceScore || 0) - Number(a.abuseConfidenceScore || 0));
  if (pool.length === 0) return { ips: [], reason };

  // Slide a window over the pool so successive cycles surface different IPs without random discards.
  const size = Math.min(MAX_CANDIDATE_IPS, pool.length);
  const candidates = Array.from({ length: size }, (_, i) => pool[(abuseRotationOffset + i) % pool.length]);
  abuseRotationOffset = (abuseRotationOffset + Math.max(1, Math.floor(size / 3))) % pool.length;

  const abuseMap = {};
  for (const entry of candidates) {
    abuseMap[entry.ipAddress] = {
      abuseScore: Number(entry.abuseConfidenceScore || 0),
      countryCode: String(entry.countryCode || '').toUpperCase(),
    };
  }
  return { ips: candidates.map((e) => e.ipAddress), abuseMap, reason };
}

function collectFallbackSeedIps() {
  return OTX_FALLBACK_IPS
    .filter((ip) => ip && typeof ip === 'string' && !isPrivateOrBogon(ip))
    .slice(0, 8);
}

// ── Phase 2: Enrich each IP with all available providers ──────────────

async function enrichIpFromOtx(otxKey, ipAddress) {
  const otxData = await fetchOtxGeneral(otxKey, ipAddress);
  if (!otxData) return null;
  return {
    otxHits: getOtxHits(otxData),
    countryCode: String(otxData?.country_code || '').toUpperCase(),
  };
}

async function enrichIpFromShodan(shodanKey, ipAddress) {
  const shodanData = await fetchShodanHost(shodanKey, ipAddress);
  if (!shodanData) return null;
  return {
    portExposure: Array.isArray(shodanData?.ports) ? shodanData.ports.length : 0,
    countryCode: String(shodanData?.country_code || '').toUpperCase(),
    countryName: shodanData?.country_name || null,
    lat: Number(shodanData?.latitude),
    lng: Number(shodanData?.longitude),
    city: shodanData?.city || 'Unknown',
    region: shodanData?.region_code || 'Unknown',
  };
}

async function enrichIp(ip, abuseEntry) {
  const cached = readEnrichmentCache(ip);
  if (cached) return cached;

  const [otxSettled, shodanSettled] = await Promise.allSettled([
    ENABLE_OTX ? enrichIpFromOtx(OTX_KEY, ip) : Promise.resolve(null),
    ENABLE_SHODAN ? enrichIpFromShodan(SHODAN_KEY, ip) : Promise.resolve(null),
  ]);
  const otx = otxSettled.status === 'fulfilled' ? otxSettled.value : null;
  const shodan = shodanSettled.status === 'fulfilled' ? shodanSettled.value : null;

  const geoFallback = {};
  const abuseCode = abuseEntry?.countryCode;
  if (abuseCode) {
    geoFallback.countryCode = abuseCode;
    geoFallback.countryName = toCountryName(abuseCode);
  }
  if (otx?.countryCode && !geoFallback.countryCode) {
    geoFallback.countryCode = otx.countryCode;
    geoFallback.countryName = toCountryName(otx.countryCode);
  }
  if (shodan) {
    if (!geoFallback.countryCode && shodan.countryCode) {
      geoFallback.countryCode = shodan.countryCode;
      geoFallback.countryName = shodan.countryName || toCountryName(shodan.countryCode);
    }
    if (Number.isFinite(shodan.lat) && Number.isFinite(shodan.lng)) {
      geoFallback.lat = shodan.lat;
      geoFallback.lng = shodan.lng;
    }
    geoFallback.city = shodan.city || geoFallback.city;
    geoFallback.region = shodan.region || geoFallback.region;
  }

  const geo = await resolveGeo(ip, IPINFO_KEY, geoFallback);
  const result = { otx, shodan, geo };
  // Only remember lookups that produced geo so a transient outage is retried on the next cycle.
  if (geo) writeEnrichmentCache(ip, result);
  return result;
}

// ── Phase 3: Unified IP Map → Fusion → Threat Object ─────────────────

async function aggregateThreats(mode, threshold) {
  const abuseResult = await collectAbuseIps(ABUSE_KEY);
  const abuseMap = abuseResult.abuseMap || {};
  let allIps = (abuseResult.ips || []).filter((ip) => !isPrivateOrBogon(ip));

  let degraded = false;
  let degradedReason = null;
  if (allIps.length === 0) {
    allIps = collectFallbackSeedIps();
    degraded = true;
    degradedReason = abuseResult.reason || 'no-abuse-data';
  }

  if (allIps.length === 0) {
    return { attacks: [], sourcesUsed: [], degraded: true, degradedReason: degradedReason || 'no-candidates' };
  }

  const enrichSettled = await mapWithConcurrency(allIps, ENRICHMENT_CONCURRENCY, (ip) => enrichIp(ip, abuseMap[ip]));

  const ruleThreats = [];
  const sourcesUsedSet = new Set();
  allIps.forEach((ip, index) => {
    const settled = enrichSettled[index];
    const enrichment = settled?.status === 'fulfilled' ? settled.value : { otx: null, shodan: null, geo: null };
    const abuse = abuseMap[ip] || null;
    const { otx, shodan, geo } = enrichment;

    const sourceStatus = normalizeSourceStatus(
      {
        abuseipdb: abuse ? SOURCE_STATUS_OK : getProviderBaselineSourceStatus('abuseipdb'),
        otx: otx ? SOURCE_STATUS_OK : getProviderBaselineSourceStatus('otx'),
        shodan: shodan ? SOURCE_STATUS_OK : getProviderBaselineSourceStatus('shodan'),
      },
      {
        abuseScore: abuse ? abuse.abuseScore : null,
        otxHits: otx ? otx.otxHits : null,
        portExposure: shodan ? shodan.portExposure : null,
      }
    );

    const scoring = calculateThreatScore(
      {
        abuseScore: abuse ? abuse.abuseScore : 0,
        otxHits: otx ? otx.otxHits : 0,
        portExposure: shodan ? shodan.portExposure : 0,
      },
      sourceStatus
    );

    const providers = [];
    if (abuse) providers.push('abuseipdb');
    if (otx) providers.push('otx');
    if (shodan) providers.push('shodan');
    providers.forEach((p) => sourcesUsedSet.add(p));

    const ruleThreat = normalizeThreatRecord({
      ipAddress: ip,
      geo,
      type: mapClassificationToType(scoring.classification),
      score: scoring.score,
      classification: scoring.classification,
      signals: scoring.signals,
      sources: sourceStatus,
      timestamp: Date.now(),
      provider: providers.length > 0 ? providers.join('+') : 'seed',
    });
    if (ruleThreat) ruleThreats.push(ruleThreat);
  });

  const topThreatIndexSet = new Set(
    ruleThreats
      .map((threat, index) => ({ index, score: clampNumber(threat?.score, 0, 100, 0) }))
      .sort((a, b) => b.score - a.score)
      .slice(0, AI_TOP_N)
      .map((item) => item.index)
  );

  const attacks = [];
  for (let index = 0; index < ruleThreats.length; index += 1) {
    const threatWithAi = await applyOptionalAiLayer(ruleThreats[index], mode, threshold, {
      eligibleForTopN: topThreatIndexSet.has(index),
      explicitRequest: false,
    });
    if (threatWithAi) attacks.push(threatWithAi);
  }

  return {
    attacks: finalizeAttacks(attacks),
    sourcesUsed: [...sourcesUsedSet],
    degraded,
    degradedReason,
  };
}

function finalizeAttacks(attacks) {
  const seenIps = new Set();
  return attacks
    .filter((attack) => {
      const key = attack.sourceIp || `${attack.sourceLat}:${attack.sourceLng}`;
      if (seenIps.has(key)) return false;
      seenIps.add(key);
      return true;
    })
    .sort((a, b) => (b.score - a.score) || String(a.sourceIp).localeCompare(String(b.sourceIp)))
    .slice(0, MAX_ATTACKS);
}

function resolveActiveSources() {
  const active = [];
  if (ENABLE_ABUSE && usage.abuseipdb < ABUSE_DAILY_SAFE_THRESHOLD) active.push('abuseipdb');
  if (ENABLE_OTX) active.push('otx');
  if (ENABLE_SHODAN) active.push('shodan');
  return active;
}

app.get('/api/health', (req, res) => {
  resetUsageIfNeeded();

  const aiSelection = resolveRequestAiSelection(req);
  const activeAiMode = aiSelection.mode;
  const activeAiProvider = aiSelection.provider;

  return res.json({
    status: 'ok',
    cacheAge: latestThreatCacheAt ? (Date.now() - latestThreatCacheAt) : null,
    activeSources: resolveActiveSources(),
    ai: {
      enabled: Boolean(activeAiProvider),
      provider: activeAiProvider || 'none',
      cacheSize: aiCache.size,
      metrics: snapshotAiMetrics(),
    },
    aiProvider: {
      provider: getActiveProvider(),
      keys: {
        gemini: hasGemini,
        openai: hasOpenAI,
      },
      readiness: getActiveProvider() ? "ready" : "no_keys",
      mode: activeAiMode,
      current: activeAiProvider,
      available: AI_PROVIDER_OPTIONS,
    },
    providers: {
      abuseipdb: getProviderHealthLabel('abuseipdb'),
      ipinfo: getProviderHealthLabel('ipinfo'),
      otx: getProviderHealthLabel('otx'),
      shodan: getProviderHealthLabel('shodan')
    },
    usage: {
      abuseipdb: usage.abuseipdb,
      otx: usage.otx,
      shodan: usage.shodan,
      ipinfo: usage.ipinfo,
    },
  });
});

app.get('/api/ai/health', (req, res) => {
  const aiSelection = resolveRequestAiSelection(req);
  const provider = aiSelection.provider;
  const model = provider === 'openai'
    ? AI_MODEL
    : provider === 'gemini'
      ? getGeminiModelName()
      : 'none';

  return res.json({
    provider: provider || 'none',
    model,
    geminiConfigured: hasGemini,
    openaiConfigured: hasOpenAI,
    aiEnabled: Boolean(provider),
  });
});



//Main endpoint
async function handleThreatsRequest(req, res) {
  resetUsageIfNeeded();

  const aiSelection = resolveRequestAiSelection(req);
  const activeAiMode = aiSelection.mode;
  const cacheKey = getThreatCacheKey(activeAiMode, aiSelection.threshold);

  if (!ENABLE_ABUSE) warnMissingKeyOnce('abuseipdb', 'ABUSEIPDB_API_KEY');
  if (!ENABLE_SHODAN) warnMissingKeyOnce('shodan', 'SHODAN_API_KEY');
  if (!ENABLE_IPINFO) warnMissingKeyOnce('ipinfo', 'IPINFO_API_KEY');

  const respond = (entry, { cached, stale = false }) => res.json({
    attacks: entry.attacks,
    cached,
    stale,
    cacheAgeMs: Math.max(0, Date.now() - entry.timestamp),
    degraded: entry.degraded,
    degradedReason: entry.degradedReason,
    sourcesUsed: entry.sourcesUsed,
  });

  const fresh = readThreatCache(cacheKey);
  if (fresh) return respond(fresh, { cached: true });

  try {
    let pending = inFlightFetchPromises.get(cacheKey);
    if (!pending) {
      pending = aggregateThreats(activeAiMode, aiSelection.threshold)
        .then((aggregated) => {
          const entry = {
            attacks: aggregated.attacks,
            degraded: Boolean(aggregated.degraded),
            degradedReason: aggregated.degradedReason || null,
            sourcesUsed: aggregated.sourcesUsed || [],
            timestamp: Date.now(),
          };
          // An empty, non-degraded cycle is a real answer; only skip caching total failures.
          if (entry.attacks.length > 0) writeThreatCache(cacheKey, entry);
          return entry;
        })
        .finally(() => {
          inFlightFetchPromises.delete(cacheKey);
        });
      inFlightFetchPromises.set(cacheKey, pending);
    }

    const entry = await pending;
    return respond(entry, { cached: false });
  } catch (err) {
    console.error('[Threats] Aggregation failure:', err?.stack || err);
    const stale = peekThreatCache(cacheKey);
    if (stale) return respond(stale, { cached: true, stale: true });
    return res.status(502).json({ error: 'aggregation_failed', attacks: [] });
  }
}

app.get('/api/threats', handleThreatsRequest);
app.post('/api/threats', handleThreatsRequest);

// ── Manual AI Analysis Endpoint ────────────────────────────────
app.post('/api/analyze', aiRateLimiter, async (req, res) => {
  const startTime = Date.now();
  const { signals } = req.body || {};
  const ip = sanitizeIpInput(req.body?.ip);

  if (!ip || isPrivateOrBogon(ip)) {
    return res.status(400).json({ error: 'Missing or invalid public ip field' });
  }

  const aiSelection = resolveRequestAiSelection(req);
  const provider = aiSelection.provider;

  if (!provider) {
    console.warn('[Analyze] No AI provider available');
    return res.status(503).json({
      error: 'No AI provider available',
      type: 'LOW',
      confidence: 0,
      reasoning: AI_ERROR_LABELS[AI_ERROR_CODES.NO_PROVIDER],
      reasonCode: AI_ERROR_CODES.NO_PROVIDER,
      reasonDetail: `mode=${aiSelection.mode || 'unknown'}`,
      provider: 'none',
      latencyMs: Date.now() - startTime,
    });
  }

  // Build a normalized threat object for classification
  const abuseScore = clampNumber(signals?.abuseScore, 0, 100, 0);
  const otxHits = toNonNegativeNumber(signals?.otxHits ?? 0);
  const portExposure = toNonNegativeNumber(signals?.portExposure ?? 0);
  const country = sanitizeCountryInput(signals?.country) || 'Unknown';

  const threatPayload = {
    sourceIp: ip,
    sourceCountry: country,
    provider: 'manual',
    score: clampNumber(abuseScore, 0, 100, 0),
    intensity: 5,
    signals: { abuseScore, otxHits, portExposure },
  };

  // Check AI cache first
  const cacheKey = buildAiCacheKey('analyze', { sourceIp: ip, signals: { abuseScore, otxHits, portExposure } });
  const cached = readAiCache(cacheKey);
  if (cached?.result) {
    console.log(`[Analyze] Cache hit for ${ip}`);
    incrementAiMetric('cacheHits');
    return res.json({
      type: cached.result.type || 'LOW',
      confidence: cached.result.confidence || 0,
      reasoning: cached.result.reason || cached.result.reasoning || '',
      provider: cached.providerUsed || provider,
      latencyMs: Date.now() - startTime,
      cached: true,
    });
  }

  console.log(`[Analyze] Manual AI request for ${ip} via ${provider}`);
  incrementAiMetric('totalCalls');
  incrementAiMetric('cacheMisses');

  try {
    const aiOutcome = await classifyThreatWithAI(threatPayload, aiSelection.mode);

    if (aiOutcome.result) {
      incrementAiMetric('successCalls');
      // Cache for 5 minutes
      writeAiCache(cacheKey, aiOutcome, AI_CACHE_TTL_MS);

      console.log(`[Analyze] Success: type=${aiOutcome.result.type} confidence=${aiOutcome.result.confidence} provider=${aiOutcome.providerUsed}`);
      return res.json({
        type: aiOutcome.result.type || 'LOW',
        confidence: aiOutcome.result.confidence || 0,
        reasoning: aiOutcome.result.reason || aiOutcome.result.reasoning || '',
        provider: aiOutcome.providerUsed || provider,
        latencyMs: Date.now() - startTime,
        cached: false,
      });
    }

    incrementAiMetric('failedCalls');
    console.warn(`[Analyze] AI returned no result for ${ip} (attempted: ${aiOutcome.attemptedProviders.join(',')})`);
    return res.status(502).json({
      error: 'AI classification failed',
      type: 'LOW',
      confidence: 0,
      reasoning: aiOutcome?.error?.reason || 'AI provider did not return a valid classification.',
      reasonCode: aiOutcome?.error?.code || AI_ERROR_CODES.UPSTREAM_HTTP_ERROR,
      reasonDetail: aiOutcome?.error?.detail || null,
      provider: aiOutcome?.error?.provider || 'none',
      latencyMs: Date.now() - startTime,
      attemptedProviders: aiOutcome.attemptedProviders,
    });
  } catch (err) {
    incrementAiMetric('failedCalls');
    console.error(`[Analyze] Error for ${ip}:`, err.message);
    return res.status(500).json({
      error: 'Internal error during AI classification',
      type: 'LOW',
      confidence: 0,
      reasoning: AI_ERROR_LABELS[AI_ERROR_CODES.NETWORK_ERROR],
      reasonCode: AI_ERROR_CODES.NETWORK_ERROR,
      reasonDetail: safeErrorDetail(err),
      provider: 'none',
      latencyMs: Date.now() - startTime,
    });
  }
});

// ── Incident Report Endpoint ───────────────────────────────────
function buildReport(threat) {
  const reportSources = Array.isArray(threat.signals?.usedSources)
    ? threat.signals.usedSources
    : Array.isArray(threat.signals?.sourcesUsed)
      ? threat.signals.sourcesUsed
      : [];

  const reportSourceStatus = normalizeSourceStatus(
    threat.sources || threat.signals?.sourceStatus || {},
    threat.signals || {}
  );

  return {
    ip: sanitizeIpInput(threat.sourceIp || threat.ip),
    sourceCountry: sanitizeCountryInput(threat.sourceCountry),
    timestamp: Number.isFinite(new Date(threat.timestamp).getTime()) ? new Date(threat.timestamp).toISOString() : new Date().toISOString(),
    classification: sanitizeClassificationInput(threat.classification),
    score: clampNumber(threat.score, 0, 100, 0),
    signals: {
      abuseScore: clampNumber(threat.signals?.abuseScore, 0, 100, 0),
      otxHits: sanitizeCount(threat.signals?.otxHits),
      portExposure: sanitizeCount(threat.signals?.portExposure),
      sourceStatus: reportSourceStatus,
    },
    sources: reportSources.slice(0, 8).map((source) => String(source).slice(0, 32)),
    sources_status: reportSourceStatus,
    ai: {
      used: Boolean(threat.ai?.used),
      confidence: typeof threat.ai?.confidence === 'number' ? threat.ai.confidence : null,
      reasoning: threat.ai?.reason ? String(threat.ai.reason).slice(0, 280) : null
    },
    ai_summary: emptyAiSummary(),
  };
}

app.post('/api/report', aiRateLimiter, async (req, res) => {
  const threat = req.body && req.body.threat;
  if (!threat || typeof threat !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid threat object in request body' });
  }
  if (!sanitizeIpInput(threat.sourceIp || threat.ip)) {
    return res.status(400).json({ error: 'Threat must include a valid source IP' });
  }

  try {
    const aiSelection = resolveRequestAiSelection(req);
    const aiSummaryResult = await generateAiReportSummary(threat, aiSelection.mode);

    const report = buildReport(threat);
    report.ai_summary = aiSummaryResult?.summary
      ? {
        used: true,
        executive_summary: aiSummaryResult.summary.executive_summary,
        technical_analysis: aiSummaryResult.summary.technical_analysis,
        risk_level: aiSummaryResult.summary.risk_level,
        recommended_action: aiSummaryResult.summary.recommended_action,
        reason_code: AI_REPORT_REASON_CODES.NONE,
        reason_detail: null,
        attempted_providers: Array.isArray(aiSummaryResult.attemptedProviders)
          ? aiSummaryResult.attemptedProviders
          : [],
        provider: aiSummaryResult.provider || aiSelection.provider || null,
      }
      : emptyAiSummary(
        aiSummaryResult?.reasonCode || AI_REPORT_REASON_CODES.INTERNAL_ERROR,
        aiSummaryResult?.reasonDetail || null,
        aiSummaryResult?.attemptedProviders || []
      );

    return res.json(report);
  } catch (err) {
    console.error('[Report] generation failed:', err?.stack || err);
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

app.use((req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((err, req, res, next) => {
  if (res.headersSent) return next(err);
  if (err?.type === 'entity.parse.failed') return res.status(400).json({ error: 'invalid_json' });
  if (err?.type === 'entity.too.large') return res.status(413).json({ error: 'payload_too_large' });
  console.error('[Server] Unhandled error:', err?.stack || err);
  return res.status(500).json({ error: 'internal_error' });
});

process.on('unhandledRejection', (reason) => {
  console.error('[Server] Unhandled rejection:', reason?.stack || reason);
});

// ── Start ────────────────────────────────────────────────────
if (require.main === module) {
  const server = app.listen(PORT, () => {
    console.log(`Threat API running on http://localhost:${PORT}`);
  });

  const shutdown = (signal) => {
    console.log(`[Server] ${signal} received, shutting down`);
    server.close(() => process.exit(0));
    setTimeout(() => process.exit(1), 5000).unref();
  };
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

module.exports = { app, geminiRateLimit, scrubSecrets, safeErrorDetail, isPrivateOrBogon, calculateThreatScore, classifyFromScore, finalizeAttacks, sanitizeCountryInput, sanitizeIpInput, sanitizeClassificationInput, applyOptionalAiLayer, parseAiJson, normalizeAiResponse };
