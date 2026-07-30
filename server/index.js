require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');

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
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const OPENAI_API_KEY = process.env.OPENAI_API_KEY;
const AI_PROVIDER = process.env.AI_PROVIDER || "auto";

const hasGemini = !!GEMINI_API_KEY && !GEMINI_API_KEY.includes("your_");
const hasOpenAI = !!OPENAI_API_KEY && !OPENAI_API_KEY.includes("your_");

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
  : 0;
const GEMINI_MODEL = (process.env.GEMINI_MODEL || 'gemini-flash-latest').trim();
const AI_ENV_TOP_N = process.env.AI_TOP_N ?? process.env.AI_TOP_N_THREATS;
const AI_ENV_MIN_SCORE = process.env.AI_MIN_SCORE ?? process.env.AI_MIN_SCORE_FOR_CALL;
const AI_ENV_LIVE_SAMPLE_INTERVAL = process.env.AI_LIVE_SAMPLE_INTERVAL_MS ?? process.env.AI_LIVE_SAMPLE_WINDOW_MS;
const AI_MIN_SCORE = clampNumber(AI_ENV_MIN_SCORE, 0, 100, 40);
const AI_AMBIGUOUS_SCORE_MIN = clampNumber(process.env.AI_AMBIGUOUS_SCORE_MIN, 30, 70, 35);
const AI_AMBIGUOUS_SCORE_MAX = clampNumber(process.env.AI_AMBIGUOUS_SCORE_MAX, 35, 85, 55);
const AI_TOP_N = Math.round(clampNumber(AI_ENV_TOP_N, 1, 10, 3));
const AI_THROTTLE_MS = clampNumber(process.env.AI_THROTTLE_MS, 100, 1500, 300);
const AI_CACHE_TTL_MS = clampNumber(process.env.AI_CACHE_TTL_MS, 5 * 60 * 1000, 10 * 60 * 1000, 10 * 60 * 1000);
const AI_LIVE_SAMPLE_INTERVAL_MS = clampNumber(AI_ENV_LIVE_SAMPLE_INTERVAL, 5000, 10000, 5000);

const ENABLE_ABUSE = !!ABUSE_KEY;
const ENABLE_IPINFO = !!IPINFO_KEY;
const ENABLE_OTX = true; // allow keyless
const ENABLE_SHODAN = !!SHODAN_KEY;
const AI_PROVIDER_OPTIONS = ['openai', 'gemini', 'auto', 'off'];
const AI_REPORT_REASON_CODES = {
  NONE: 'none',
  NO_PROVIDER: 'no_provider',
  UPSTREAM_HTTP_ERROR: 'upstream_http_error',
  THROTTLED: 'throttled',
  TIMEOUT: 'timeout',
  NETWORK_ERROR: 'network_error',
  SCHEMA_MISMATCH: 'schema_mismatch',
  INTERNAL_ERROR: 'internal_error',
};

const DEBUG_PROVIDER = false;

const geminiRateLimit = {
  minuteRequests: [],
  dayRequests: [],
  MAX_RPM: Number(process.env.GEMINI_MAX_RPM) || 5,
  MAX_RPD: Number(process.env.GEMINI_MAX_RPD) || 20,
};

function isGeminiRateLimited() {
  const now = Date.now();
  geminiRateLimit.minuteRequests = geminiRateLimit.minuteRequests.filter(
    (time) => now - time < 60 * 1000
  );
  geminiRateLimit.dayRequests = geminiRateLimit.dayRequests.filter(
    (time) => now - time < 24 * 60 * 60 * 1000
  );
  return (
    geminiRateLimit.minuteRequests.length >= geminiRateLimit.MAX_RPM ||
    geminiRateLimit.dayRequests.length >= geminiRateLimit.MAX_RPD
  );
}

function recordGeminiRequest() {
  const now = Date.now();
  geminiRateLimit.minuteRequests.push(now);
  geminiRateLimit.dayRequests.push(now);
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
  return normalizeAiProviderMode(process.env.AI_PROVIDER) || normalizeAiProviderMode(AI_PROVIDER) || 'auto';
}

function resolveRequestAiSelection(req) {
  const headerMode = normalizeAiProviderMode(req?.get('X-AI-Provider'));
  const bodyMode = normalizeAiProviderMode(req?.body?.provider || req?.body?.aiProvider || req?.body?.mode);
  const queryMode = normalizeAiProviderMode(req?.query?.provider || req?.query?.aiProvider || req?.query?.mode);
  const requestedMode = headerMode || queryMode || bodyMode;
  const mode = requestedMode || resolveDefaultAiProviderMode();

  const headerThreshold = Number(req?.get('X-AI-Threshold'));
  const queryThreshold = Number(req?.query?.threshold);
  const bodyThreshold = Number(req?.body?.threshold);
  const rawThreshold = headerThreshold || queryThreshold || bodyThreshold;
  const threshold = Number.isFinite(rawThreshold) ? Math.max(0, Math.min(100, rawThreshold)) : 70;

  return {
    mode,
    requestedMode,
    provider: resolveAiProviderFromMode(mode),
    threshold,
  };
}

function getAiProviderCacheKey(mode) {
  return normalizeAiProviderMode(mode) || 'off';
}

const ACTIVE_AI_PROVIDER = getActiveProvider();
const ENABLE_AI_CLASSIFIER = ACTIVE_AI_PROVIDER !== null;



console.log("Providers:");
console.log("AbuseIPDB:", ENABLE_ABUSE ? "ON" : "OFF");
console.log("IPinfo:", ENABLE_IPINFO ? "ON" : "OFF");
console.log("OTX:", OTX_KEY ? "ON (key)" : "ON (public)");
console.log("Shodan:", ENABLE_SHODAN ? "ON" : "OFF");
console.log("AI Classifier:", ENABLE_AI_CLASSIFIER ? "ON" : "OFF");
console.log("AI Provider:", getActiveProvider());
console.log("Gemini Key Exists:", hasGemini);
console.log("AI ENABLED:", ENABLE_AI_CLASSIFIER);

// CORS — only allow the frontend origin
app.use(cors({ origin: true }));
app.use(express.json());

const CACHE_TTL_MS = 60 * 1000;
const REQUEST_TIMEOUT_MS = 4500;
const ABUSE_DAILY_SAFE_THRESHOLD = 4;
const MIN_ATTACKS = 5;
const MAX_ATTACKS = 10;

let cache = {
  data: [],
  timestamp: 0,
  aiProviderKey: 'off',
};

const aiCache = new Map();
let lastAiCallTime = 0;
let lastLiveAiWindowAt = 0;

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

let usage = {
  dayKey: getDayKey(),
  abuseipdb: 0,
  otx: 0,
  shodan: 0,
  ipinfo: 0,
};

const warnedKeys = new Set();

// ── Hardcoded target coordinates ─────────────────────────────
const TARGET_POOL = [
  { country: 'United States', lat: 38.9072, lng: -77.0369 },
  { country: 'United Kingdom', lat: 51.5074, lng: -0.1278 },
  { country: 'Germany', lat: 52.52, lng: 13.405 },
  { country: 'France', lat: 48.8566, lng: 2.3522 },
  { country: 'Japan', lat: 35.6895, lng: 139.6917 },
  { country: 'Australia', lat: -33.8688, lng: 151.2093 },
  { country: 'Canada', lat: 43.6532, lng: -79.3832 },
  { country: 'India', lat: 28.6139, lng: 77.209 },
  { country: 'Brazil', lat: -23.5505, lng: -46.6333 },
  { country: 'South Korea', lat: 37.5665, lng: 126.978 },
  { country: 'Netherlands', lat: 52.3676, lng: 4.9041 },
  { country: 'Singapore', lat: 1.3521, lng: 103.8198 },
];

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
  }
}

function incrementUsage(provider) {
  resetUsageIfNeeded();
  if (Object.prototype.hasOwnProperty.call(usage, provider)) {
    usage[provider] += 1;
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
  const message = String(err?.message || '').toLowerCase();
  return message.includes('timed out') || message.includes('timeout');
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
    parts.push(`details=${truncateForLog(details, 140)}`);
  }

  console.warn(parts.join(' | '));
}

function isCacheFresh(aiProviderKey, now = Date.now()) {
  return (
    cache.aiProviderKey === aiProviderKey &&
    Array.isArray(cache.data) &&
    cache.data.length > 0 &&
    (now - cache.timestamp) < CACHE_TTL_MS
  );
}

function isPrivateOrBogon(ip) {
  if (!ip || typeof ip !== 'string') return true;
  const parts = ip.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p))) return true;
  const [a, b] = parts;
  if (a === 0 || a === 10 || a === 127) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a >= 224) return true;
  return false;
}

function shuffle(arr) {
  const a = [...arr];
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

function fetchWithTimeout(url, options = {}, timeoutMs = 4000) {
  return Promise.race([
    fetch(url, options),
    new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Request timed out')), timeoutMs)
    ),
  ]);
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
    if (normalized === 'ok' || normalized === 'failed') return normalized;
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

function truncateForLog(value, maxLength = 180) {
  const text = String(value || '').replace(/\s+/g, ' ').trim();
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

function pruneAiCache(now = Date.now()) {
  for (const [key, entry] of aiCache.entries()) {
    if (!entry || !Number.isFinite(entry.expiresAt) || entry.expiresAt <= now) {
      aiCache.delete(key);
    }
  }
}

function readAiCache(cacheKey) {
  const now = Date.now();
  pruneAiCache(now);
  const entry = aiCache.get(cacheKey);
  if (!entry) return null;
  if (!Number.isFinite(entry.expiresAt) || entry.expiresAt <= now) {
    aiCache.delete(cacheKey);
    return null;
  }
  return entry.value;
}

function writeAiCache(cacheKey, value) {
  const now = Date.now();
  pruneAiCache(now);
  aiCache.set(cacheKey, {
    value,
    expiresAt: now + AI_CACHE_TTL_MS,
  });
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

function consumeLiveAiSamplingWindow() {
  const now = Date.now();
  if (now - lastLiveAiWindowAt < AI_LIVE_SAMPLE_INTERVAL_MS) {
    return false;
  }
  lastLiveAiWindowAt = now;
  return true;
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
    targetCountry: normalizedThreat.targetCountry,
    provider: normalizedThreat.provider,
    sourceIp: normalizedThreat.sourceIp,
    score: normalizedThreat.score,
    intensity: normalizedThreat.intensity,
    signals: normalizedThreat.signals,
  };

  for (let i = 0; i < attemptedProviders.length; i += 1) {
    const provider = attemptedProviders[i];
    const result = provider === 'openai'
      ? await classifyWithOpenAI(requestPayload)
      : await classifyWithGemini(requestPayload);

    if (result) {
      return {
        result,
        providerUsed: provider,
        fallback: i > 0,
        attemptedProviders,
      };
    }
  }

  return {
    result: null,
    providerUsed: 'none',
    fallback: attemptedProviders.length > 1,
    attemptedProviders,
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
  if (!OPENAI_API_KEY) return null;

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
    if (!response.ok) return null;

    const json = await response.json();
    const content = json?.choices?.[0]?.message?.content;
    const parsed = parseAiJson(content);
    return normalizeAiResponse(parsed);
  } catch {
    return null;
  }
}

async function classifyWithGemini(data) {
  if (!GEMINI_API_KEY) return null;

  if (isGeminiRateLimited()) {
    console.warn('[Gemini] Rate limit guard: skipping call — RPM or RPD limit reached');
    return null;
  }

  const PROMPT_STRING = `You classify cyber threats. Return strict JSON object only with keys: type, confidence, reason. type must be one of DDOS, MALWARE, SCAN, LOW. confidence must be number 0-100. Keep reason short.\n\n${JSON.stringify(data)}`;

  const body = {
    contents: [
      {
        role: 'user',
        parts: [{ text: PROMPT_STRING }]
      }
    ]
  };

  try {
    recordGeminiRequest();
    const response = await fetchWithTimeout(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(GEMINI_MODEL)}:generateContent?key=${GEMINI_API_KEY}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      },
      AI_TIMEOUT_MS
    );
    
    if (!response.ok) {
      if (response.status === 429) {
        console.warn('Gemini rate limit hit');
      } else {
        console.warn(`Gemini API Error: HTTP ${response.status}`);
      }
      return null;
    }

    const json = await response.json();
    if (!json.candidates || !json.candidates[0]?.content?.parts?.length) return null;
    
    const text = json.candidates[0].content.parts[0].text;
    let parsed;
    try {
      parsed = JSON.parse(text.replace(/```json/gi, '').replace(/```/g, '').trim());
    } catch {
      return null;
    }
    
    return normalizeAiResponse(parsed);
  } catch (err) {
    console.warn('Gemini fetch error:', err.message);
    return null;
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
  const targetCountry = String(payload?.targetCountry || 'Unknown target');
  const classification = String(payload?.classification || 'LOW').toUpperCase();
  const score = Number.isFinite(payload?.score) ? Number(payload.score).toFixed(1) : '0.0';
  const abuseScore = Number.isFinite(payload?.abuseConfidenceScore) ? Number(payload.abuseConfidenceScore).toFixed(0) : '0';
  const otxHits = Number.isFinite(payload?.otxHits) ? Number(payload.otxHits).toFixed(0) : '0';
  const openPorts = Number.isFinite(payload?.openPorts) ? Number(payload.openPorts).toFixed(0) : '0';

  return {
    executive_summary: `Potential ${classification} activity detected from ${sourceCountry} targeting ${targetCountry} (score ${score}).`,
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

function buildReportThreatPayload(threat) {
  const abuseConfidenceScore = typeof threat?.signals?.abuseScore === 'number'
    ? threat.signals.abuseScore
    : 0;
  const otxHits = typeof threat?.signals?.otxHits === 'number'
    ? threat.signals.otxHits
    : 0;
  const openPorts = typeof threat?.signals?.portExposure === 'number'
    ? threat.signals.portExposure
    : 0;

  return {
    ip: String(threat?.sourceIp || threat?.ip || ''),
    sourceCountry: String(threat?.sourceCountry || ''),
    targetCountry: String(threat?.targetCountry || ''),
    abuseConfidenceScore,
    otxHits,
    openPorts,
    classification: String(threat?.classification || 'LOW'),
    score: Number.isFinite(threat?.score) ? threat.score : 0,
  };
}

function resolveGeminiReportModel() {
  const configured = String(AI_MODEL || '').trim();
  if (configured && configured.toLowerCase().includes('gemini')) {
    return configured;
  }
  return GEMINI_MODEL;
}

function resolveGeminiReportModelCandidates() {
  const primary = resolveGeminiReportModel();
  const candidates = [
    primary,
    GEMINI_MODEL,
    'gemini-1.5-flash',
  ].filter(Boolean);
  return [...new Set(candidates)];
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
      reasonDetail: truncateForLog(err.message),
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

  try {
    const modelCandidates = resolveGeminiReportModelCandidates();
    let lastFailure = buildAiReportAttemptResult({
      reasonCode: AI_REPORT_REASON_CODES.INTERNAL_ERROR,
      reasonDetail: 'gemini_unknown',
      provider: 'gemini',
    });

    for (let i = 0; i < modelCandidates.length; i += 1) {
      const model = modelCandidates[i];
      for (let bodyIndex = 0; bodyIndex < requestBodies.length; bodyIndex += 1) {
        if (isGeminiRateLimited()) {
          return emptyAiSummary('rate_limit', 'Gemini rate limit reached', ['gemini']);
        }
        recordGeminiRequest();
        const response = await fetchWithOptionalTimeout(
          `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${GEMINI_API_KEY}`,
          {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBodies[bodyIndex]),
          },
          AI_REPORT_TIMEOUT_MS
        );

        if (!response.ok) {
          const errorText = await readResponseTextSafe(response);
          console.warn(`[AI Report][gemini:${model}:fmt${bodyIndex}] HTTP ${response.status}: ${truncateForLog(errorText)}`);

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
    }

    return lastFailure;
  } catch (err) {
    console.warn('[AI Report][gemini] Request failed:', err.message);
    return buildAiReportAttemptResult({
      reasonCode: isAiTimeoutError(err)
        ? AI_REPORT_REASON_CODES.TIMEOUT
        : AI_REPORT_REASON_CODES.NETWORK_ERROR,
      reasonDetail: truncateForLog(err.message),
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
    console.log('AI skipped: cached');
    return cachedReport;
  }
  incrementAiMetric('cacheMisses');

  const now = Date.now();
  if (!explicitRequest && isAiThrottled(now)) {
    incrementAiMetric('skippedThrottle');
    console.log('AI skipped: throttled');
    const throttledResult = {
      ...buildAiReportAttemptResult({
        reasonCode: AI_REPORT_REASON_CODES.THROTTLED,
        reasonDetail: `ai_throttle_${AI_THROTTLE_MS}ms`,
        provider: null,
      }),
      attemptedProviders,
    };
    writeAiCache(reportCacheKey, throttledResult);
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
        reasonDetail: truncateForLog(err.message),
      }),
      attemptedProviders,
    };
    writeAiCache(reportCacheKey, failureResult);
    return failureResult;
  }

  console.warn(`[AI Report] No summary generated (mode=${mode}, attempted=${attemptedProviders.join(',')})`);
  incrementAiMetric('failedCalls');

  const finalFailure = {
    ...lastFailure,
    attemptedProviders,
  };
  writeAiCache(reportCacheKey, finalFailure);
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
    liveSamplingAllowed = true,
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
      filtered: isFiltered,
    },
    signals: {
      ...(ruleThreat.signals || {}),
      ruleScore,
    },
  });

  const buildAppliedResult = (aiOutcome, aiResult) => {
    const finalScore = clampNumber(Number(((0.7 * ruleScore) + (0.3 * aiResult.confidence)).toFixed(2)), 0, 100, 0);
    const finalClassification = classifyFromScore(finalScore);
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
    return buildFallback('No AI provider available', { enabled: false, fallback: false });
  }

  const aiDecision = shouldAttemptAiForThreat(ruleThreat, explicitRequest);
  if (!aiDecision.shouldCall) {
    incrementAiMetric('skippedLowScore');
    console.log('AI skipped: low score');
    return buildFallback('AI skipped: low score', { enabled: false, fallback: true });
  }

  if (!eligibleForTopN && !explicitRequest) {
    console.log(`AI skipped: sampled (outside top ${AI_TOP_N})`);
    return buildFallback(`Outside top ${AI_TOP_N} by score`, { enabled: false, fallback: true });
  }

  if (!liveSamplingAllowed && !explicitRequest) {
    console.log('AI skipped: sampled live window');
    return buildFallback('Live stream sampling window', { enabled: false, fallback: true });
  }

  const cacheKey = buildAiCacheKey('classify', ruleThreat);
  const cachedOutcome = readAiCache(cacheKey);
  if (cachedOutcome) {
    incrementAiMetric('cacheHits');
    incrementAiMetric('skippedCache');
    console.log('AI skipped: cached');
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

  const now = Date.now();
  if (!explicitRequest && isAiThrottled(now)) {
    incrementAiMetric('skippedThrottle');
    console.log('AI skipped: throttled');
    return buildFallback('AI skipped: throttled', { enabled: true, fallback: true });
  }

  incrementAiMetric('totalCalls');
  markAiCallStart(now);
  const aiOutcome = await classifyThreatWithAI(ruleThreat, mode);
  writeAiCache(cacheKey, aiOutcome);

  const aiResult = aiOutcome.result;
  if (!aiResult) {
    incrementAiMetric('failedCalls');
    return buildFallback('Rule-based fallback', {
      enabled: aiOutcome.attemptedProviders.length > 0,
      fallback: aiOutcome.fallback,
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

function pickTarget() {
  return TARGET_POOL[Math.floor(Math.random() * TARGET_POOL.length)];
}

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
    incrementUsage('abuseipdb');
    const response = await fetchWithTimeout(
      'https://api.abuseipdb.com/api/v2/blacklist?limit=25&confidenceMinimum=65',
      {
        headers: {
          Key: ABUSE_KEY,
          Accept: 'application/json',
        },
      },
      REQUEST_TIMEOUT_MS
    );

    if (!response.ok) {
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
    return { ok: entries.length > 0, reason: entries.length > 0 ? 'ok' : 'empty', entries };
  } catch (err) {
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
    incrementUsage('otx');
    const headers = {
      Accept: 'application/json',
    };
    if (OTX_KEY) {
      headers['X-OTX-API-KEY'] = OTX_KEY;
    }

    const response = await fetchWithTimeout(
      `https://otx.alienvault.com/api/v1/indicators/IPv4/${ipAddress}/general`,
      { headers },
      REQUEST_TIMEOUT_MS
    );

    if (!response.ok) {
      logProviderFailure('otx', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'general_lookup_failed',
      });
      return null;
    }
    const json = await response.json();
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
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
    incrementUsage('shodan');
    const response = await fetchWithTimeout(
      `https://api.shodan.io/shodan/host/${ipAddress}?key=${SHODAN_KEY}`,
      {
        headers: {
          Accept: 'application/json',
        },
      },
      REQUEST_TIMEOUT_MS
    );
    if (!response.ok) {
      logProviderFailure('shodan', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'host_lookup_failed',
      });
      return null;
    }
    const json = await response.json();
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
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
    incrementUsage('ipinfo');
    const response = await fetchWithTimeout(
      `https://ipinfo.io/${ipAddress}/json?token=${IPINFO_KEY}`,
      {},
      REQUEST_TIMEOUT_MS
    );
    if (!response.ok) {
      logProviderFailure('ipinfo', {
        category: getProviderHttpFailureCategory(response.status),
        status: response.status,
        ipAddress,
        reason: 'geo_lookup_failed',
      });
      return null;
    }
    const json = await response.json();
    return json && typeof json === 'object' ? json : null;
  } catch (err) {
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

  const target = pickTarget();
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
    id: `${timestamp}-${ipAddress}`,
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

async function collectAbuseIps(abuseKey) {
  if (!ENABLE_ABUSE || usage.abuseipdb >= ABUSE_DAILY_SAFE_THRESHOLD) {
    return { ips: [], reason: !ENABLE_ABUSE ? 'disabled' : 'daily-threshold' };
  }
  const blacklist = await fetchAbuseBlacklist(abuseKey);
  if (!blacklist.ok) return { ips: [], reason: blacklist.reason };

  const candidates = dedupeByIp(blacklist.entries)
    .filter((entry) => !isPrivateOrBogon(entry?.ipAddress))
    .slice(0, 12);

  // Build a map of IP → abuse signal
  const abuseMap = {};
  for (const entry of candidates) {
    abuseMap[entry.ipAddress] = {
      abuseScore: Number(entry.abuseConfidenceScore || 0),
      countryCode: String(entry.countryCode || '').toUpperCase(),
    };
  }
  return { ips: candidates.map(e => e.ipAddress), abuseMap, reason: 'ok' };
}

function collectOtxCandidateIps(seedIps = []) {
  if (!ENABLE_OTX) return [];
  return dedupeByIp(
    shuffle(
      [...seedIps, ...OTX_FALLBACK_IPS]
        .filter((ip) => ip && typeof ip === 'string')
        .map((ipAddress) => ({ ipAddress }))
    )
  )
    .map((entry) => entry.ipAddress)
    .filter((ip) => !isPrivateOrBogon(ip))
    .slice(0, 8);
}

function collectShodanCandidateIps(seedIps = []) {
  if (!ENABLE_SHODAN) return [];
  return dedupeByIp(
    shuffle(
      [...seedIps, ...OTX_FALLBACK_IPS]
        .filter((ip) => ip && typeof ip === 'string')
        .map((ipAddress) => ({ ipAddress }))
    )
  )
    .map((entry) => entry.ipAddress)
    .filter((ip) => !isPrivateOrBogon(ip))
    .slice(0, 6);
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

// ── Phase 3: Unified IP Map → Fusion → Threat Object ─────────────────

async function aggregateThreats(mode, threshold) {
  // Step 1: Collect all candidate IPs
  const abuseResult = await collectAbuseIps(ABUSE_KEY);
  const abuseMap = abuseResult.abuseMap || {};
  const abuseIps = abuseResult.ips || [];

  const otxIps = collectOtxCandidateIps(abuseIps);
  const shodanIps = collectShodanCandidateIps(abuseIps);

  // Build unified IP set (deduplicated)
  const allIpSet = new Set([...abuseIps, ...otxIps, ...shodanIps]);
  const allIps = [...allIpSet].filter(ip => !isPrivateOrBogon(ip));

  if (allIps.length === 0) {
    return { attacks: [], sourcesUsed: [] };
  }

  // Step 2: Build the IP map — enrich each IP with all available providers in parallel
  const ipMap = {};
  for (const ip of allIps) {
    ipMap[ip] = {
      abuse: abuseMap[ip] || null,  // Already collected from blacklist
      otx: null,
      shodan: null,
      geo: null,
      sourceStatus: {
        abuseipdb: abuseMap[ip] ? 'ok' : 'failed',
        otx: 'failed',
        shodan: 'failed',
      },
    };
  }

  // Enrich with OTX and Shodan in parallel per IP
  const enrichmentPromises = allIps.map(async (ip) => {
    const tasks = [];

    // OTX enrichment (if IP is in OTX candidate set or always enrich known IPs)
    if (ENABLE_OTX) {
      tasks.push(
        enrichIpFromOtx(OTX_KEY, ip)
          .then(result => {
            if (result) {
              ipMap[ip].otx = result;
              ipMap[ip].sourceStatus.otx = 'ok';
            } else {
              ipMap[ip].sourceStatus.otx = 'failed';
            }
          })
          .catch((err) => {
            ipMap[ip].sourceStatus.otx = 'failed';
            logProviderFailure('otx', {
              category: getProviderErrorCategory(err),
              ipAddress: ip,
              reason: 'enrichment_exception',
              details: err?.message || '',
            });
          })
      );
    }

    // Shodan enrichment
    if (ENABLE_SHODAN) {
      tasks.push(
        enrichIpFromShodan(SHODAN_KEY, ip)
          .then(result => {
            if (result) {
              ipMap[ip].shodan = result;
              ipMap[ip].sourceStatus.shodan = 'ok';
            } else {
              ipMap[ip].sourceStatus.shodan = 'failed';
            }
          })
          .catch((err) => {
            ipMap[ip].sourceStatus.shodan = 'failed';
            logProviderFailure('shodan', {
              category: getProviderErrorCategory(err),
              ipAddress: ip,
              reason: 'enrichment_exception',
              details: err?.message || '',
            });
          })
      );
    }

    await Promise.allSettled(tasks);
  });

  await Promise.allSettled(enrichmentPromises);

  // Step 3: Resolve geo and build rule-based threats first
  const fusionPromises = allIps.map(async (ip) => {
    const entry = ipMap[ip];

    // Build geo fallback from best available source
    const geoFallback = {};
    if (entry.abuse?.countryCode) {
      geoFallback.countryCode = entry.abuse.countryCode;
      geoFallback.countryName = toCountryName(entry.abuse.countryCode);
    }
    if (entry.otx?.countryCode && !geoFallback.countryCode) {
      geoFallback.countryCode = entry.otx.countryCode;
      geoFallback.countryName = toCountryName(entry.otx.countryCode);
    }
    if (entry.shodan) {
      if (!geoFallback.countryCode && entry.shodan.countryCode) {
        geoFallback.countryCode = entry.shodan.countryCode;
        geoFallback.countryName = entry.shodan.countryName || toCountryName(entry.shodan.countryCode);
      }
      if (Number.isFinite(entry.shodan.lat) && Number.isFinite(entry.shodan.lng)) {
        geoFallback.lat = entry.shodan.lat;
        geoFallback.lng = entry.shodan.lng;
      }
      geoFallback.city = entry.shodan.city || geoFallback.city;
      geoFallback.region = entry.shodan.region || geoFallback.region;
    }

    const geo = await resolveGeo(ip, IPINFO_KEY, geoFallback);

    const sourceStatus = normalizeSourceStatus(entry.sourceStatus || {}, {
      abuseScore: entry.abuse ? entry.abuse.abuseScore : null,
      otxHits: entry.otx ? entry.otx.otxHits : null,
      portExposure: entry.shodan ? entry.shodan.portExposure : null,
    });

    // Fuse signals — use numeric defaults while scoring normalizes only across available weights
    const fusedSignals = {
      abuseScore: entry.abuse ? entry.abuse.abuseScore : 0,
      otxHits: entry.otx ? entry.otx.otxHits : 0,
      portExposure: entry.shodan ? entry.shodan.portExposure : 0,
    };

    const scoring = calculateThreatScore(fusedSignals, sourceStatus);

    // Determine primary provider (the one that contributed the most weight)
    const providers = [];
    if (entry.abuse) providers.push('abuseipdb');
    if (entry.otx) providers.push('otx');
    if (entry.shodan) providers.push('shodan');
    const provider = providers.length > 0 ? providers.join('+') : 'fallback';

    const ruleThreat = normalizeThreatRecord({
      ipAddress: ip,
      geo,
      type: mapClassificationToType(scoring.classification),
      score: scoring.score,
      classification: scoring.classification,
      signals: scoring.signals,
      sources: sourceStatus,
      timestamp: Date.now(),
      provider,
    });

    return ruleThreat;
  });

  const ruleResults = await Promise.allSettled(fusionPromises);
  const ruleThreats = ruleResults
    .filter(r => r.status === 'fulfilled' && r.value)
    .map(r => r.value);

  const topThreatIndexes = ruleThreats
    .map((threat, index) => ({
      index,
      score: clampNumber(threat?.score, 0, 100, 0),
    }))
    .sort((a, b) => b.score - a.score)
    .slice(0, AI_TOP_N)
    .map((item) => item.index);

  const topThreatIndexSet = new Set(topThreatIndexes);
  const liveSamplingAllowed = consumeLiveAiSamplingWindow();

  const attacks = [];
  for (let index = 0; index < ruleThreats.length; index += 1) {
    const threatWithAi = await applyOptionalAiLayer(ruleThreats[index], mode, threshold, {
      eligibleForTopN: topThreatIndexSet.has(index),
      explicitRequest: false,
      liveSamplingAllowed,
    });
    if (threatWithAi) {
      attacks.push(threatWithAi);
    }
  }

  // Determine which top-level sources contributed
  const sourcesUsed = [];
  if (Object.values(ipMap).some(e => e.abuse)) sourcesUsed.push('abuseipdb');
  if (Object.values(ipMap).some(e => e.otx)) sourcesUsed.push('otx');
  if (Object.values(ipMap).some(e => e.shodan)) sourcesUsed.push('shodan');

  return {
    attacks: finalizeAttacks(attacks),
    sourcesUsed,
  };
}

function finalizeAttacks(attacks) {
  const seenIps = new Set();
  const deduped = attacks.filter((attack) => {
    const key = attack.sourceIp || `${attack.sourceLat}:${attack.sourceLng}`;
    if (seenIps.has(key)) return false;
    seenIps.add(key);
    return true;
  });

  const shuffled = shuffle(deduped);
  const min = Math.min(MIN_ATTACKS, shuffled.length);
  const max = Math.min(MAX_ATTACKS, shuffled.length);

  if (max === 0) return [];
  const count = min === max
    ? max
    : Math.floor(Math.random() * (max - min + 1)) + min;

  return shuffled.slice(0, count);
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
  pruneAiCache(Date.now());

  const aiSelection = resolveRequestAiSelection(req);
  const activeAiMode = aiSelection.mode;
  const activeAiProvider = aiSelection.provider;
  const aiReadiness = activeAiProvider ? 'ready' : 'no_keys';

  return res.json({
    status: 'ok',
    cacheAge: cache.timestamp ? (Date.now() - cache.timestamp) : null,
    activeSources: resolveActiveSources(),
    ai: {
      enabled: Boolean(activeAiProvider),
      provider: activeAiProvider || 'none',
      cacheSize: aiCache.size,
    },
    aiMetrics: snapshotAiMetrics(),
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
      abuseipdb: ENABLE_ABUSE ? "enabled" : "missing_key",
      ipinfo: ENABLE_IPINFO ? "enabled" : "missing_key",
      otx: ENABLE_OTX ? (OTX_KEY ? "enabled_with_key" : "enabled_public") : "disabled",
      shodan: ENABLE_SHODAN ? "enabled" : "missing_key"
    },
    usage: {
      abuseipdb: usage.abuseipdb,
      otx: usage.otx,
      shodan: usage.shodan,
      ipinfo: usage.ipinfo,
    },
  });
});



// ── Main endpoint ────────────────────────────────────────────
async function handleThreatsRequest(req, res) {
  resetUsageIfNeeded();

  const aiSelection = resolveRequestAiSelection(req);
  const activeAiMode = aiSelection.mode;
  const activeAiProvider = resolveAiProviderFromMode(activeAiMode);
  const aiProviderCacheKey = getAiProviderCacheKey(activeAiMode);

  try {
    if (DEBUG_PROVIDER && aiSelection.requestedMode) {
      console.log(`[AI Provider] Request override mode=${aiSelection.requestedMode} -> resolved=${activeAiProvider || 'none'}`);
    }

    if (!ENABLE_ABUSE) warnMissingKeyOnce('abuseipdb', 'ABUSEIPDB_API_KEY');
    if (!ENABLE_SHODAN) warnMissingKeyOnce('shodan', 'SHODAN_API_KEY');
    if (!ENABLE_IPINFO) {
      warnMissingKeyOnce('ipinfo', 'IPINFO_API_KEY');
    }

    if (isCacheFresh(aiProviderCacheKey)) {
      const cachedAttacks = cache.data.map(a => ({...a, provider: 'fallback'}));
      if (DEBUG_PROVIDER) {
        cachedAttacks.forEach(a => console.log(`[DEBUG] Attack from ${a.provider}:`, a.id));
      }
      return res.json({ attacks: cachedAttacks });
    }

    const inFlightPromise = inFlightFetchPromises.get(aiProviderCacheKey);
    if (inFlightPromise) {
      const pendingResult = await inFlightPromise;
      if (DEBUG_PROVIDER) {
        pendingResult.forEach(a => console.log(`[DEBUG] Attack from ${a.provider}:`, a.id));
      }
      return res.json({ attacks: pendingResult });
    }

    const fetchPromise = (async () => {
      const aggregated = await aggregateThreats(activeAiMode, aiSelection.threshold);

      const attacks = aggregated.attacks;

      if (attacks.length > 0) {
        cache = {
          data: attacks,
          timestamp: Date.now(),
          aiProviderKey: aiProviderCacheKey,
        };
        return attacks;
      }

      if (cache.aiProviderKey === aiProviderCacheKey && cache.data.length > 0) {
        return cache.data.map(a => ({...a, provider: 'fallback'}));
      }

      return [];
    })()
      .catch((err) => {
        console.error('Aggregation failure:', err.message);
        if (cache.aiProviderKey === aiProviderCacheKey && cache.data.length > 0) {
          return cache.data.map(a => ({...a, provider: 'fallback'}));
        }
        return [];
      })
      .finally(() => {
        inFlightFetchPromises.delete(aiProviderCacheKey);
      });

    inFlightFetchPromises.set(aiProviderCacheKey, fetchPromise);

    const finalAttacks = await fetchPromise;
    if (DEBUG_PROVIDER) {
      finalAttacks.forEach(a => console.log(`[DEBUG] Attack from ${a.provider}:`, a.id));
    }
    return res.json({ attacks: finalAttacks });
  } catch (err) {
    console.error('Server error:', err.message);
    if (cache.aiProviderKey === aiProviderCacheKey && cache.data.length > 0) {
      return res.json({ attacks: cache.data.map(a => ({...a, provider: 'fallback'})) });
    }
    return res.json({ attacks: [] });
  }
}

app.get('/api/threats', handleThreatsRequest);
app.post('/api/threats', handleThreatsRequest);

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
    ip: String(threat.sourceIp || threat.ip || ''),
    sourceCountry: String(threat.sourceCountry || ''),
    targetCountry: String(threat.targetCountry || ''),
    timestamp: threat.timestamp ? new Date(threat.timestamp).toISOString() : new Date().toISOString(),
    classification: String(threat.classification || 'LOW'),
    score: Number.isFinite(threat.score) ? threat.score : 0,
    signals: {
      abuseScore: typeof threat.signals?.abuseScore === 'number' ? threat.signals.abuseScore : 0,
      otxHits: typeof threat.signals?.otxHits === 'number' ? threat.signals.otxHits : 0,
      portExposure: typeof threat.signals?.portExposure === 'number' ? threat.signals.portExposure : 0,
      sourceStatus: reportSourceStatus,
    },
    sources: reportSources.map(String),
    sources_status: reportSourceStatus,
    ai: {
      used: Boolean(threat.ai?.used),
      confidence: typeof threat.ai?.confidence === 'number' ? threat.ai.confidence : null,
      reasoning: threat.ai?.reason ? String(threat.ai.reason) : null
    },
    ai_summary: emptyAiSummary(),
  };
}

app.post('/api/report', async (req, res) => {
  const threat = req.body && req.body.threat;
  if (!threat || typeof threat !== 'object') {
    return res.status(400).json({ error: 'Missing or invalid threat object in request body' });
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
    return res.status(500).json({ error: 'Failed to generate report' });
  }
});

// ── Start ────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`⚡ Threat API running on http://localhost:${PORT}`);
});
