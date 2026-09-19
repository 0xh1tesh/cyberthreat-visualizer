import { ATTACK_TYPES, COLOR_MAP } from '../data/constants';
import { CLASS_META } from './palette';

export const NEUTRAL_ATTACK_COLOR = '#9fb3c8';

export const PORT_PROTOCOL_MAP = {
  22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
  123: 'NTP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
  1433: 'MSSQL', 3306: 'MYSQL', 3389: 'RDP', 8080: 'HTTP'
};

export const THREAT_CLASSIFICATION = {
  DDOS: 'DDOS',
  MALWARE: 'MALWARE',
  SCAN: 'SCAN',
  LOW: 'LOW'
};

export const normalizeIntensityTo10 = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 5;
  const scaled = numeric <= 1 ? numeric * 10 : numeric;
  return Math.max(1, Math.min(10, Math.round(scaled)));
};

export const toFiniteCoord = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Number(numeric.toFixed(4));
};


export const parsePort = (rawAttack) => {
  const candidates = [
    rawAttack?.port, rawAttack?.sourcePort, rawAttack?.srcPort,
    rawAttack?.destinationPort, rawAttack?.targetPort, rawAttack?.dstPort,
    Array.isArray(rawAttack?.ports) ? rawAttack.ports[0] : null
  ];
  for (const candidate of candidates) {
    const numeric = Number(candidate);
    if (Number.isInteger(numeric) && numeric > 0 && numeric <= 65535) return numeric;
  }
  return null;
};

export const inferProtocol = (rawAttack) => {
  const candidates = [
    rawAttack?.protocol, rawAttack?.transport, rawAttack?.networkProtocol,
    rawAttack?.service, rawAttack?.appProtocol, rawAttack?.layer4
  ].filter(Boolean).map((value) => String(value).toLowerCase());

  for (const candidate of candidates) {
    if (candidate.includes('https')) return 'HTTPS';
    if (candidate.includes('http')) return 'HTTP';
    if (candidate.includes('icmp')) return 'ICMP';
    if (candidate.includes('udp')) return 'UDP';
    if (candidate.includes('tcp')) return 'TCP';
    if (candidate.includes('dns')) return 'DNS';
    if (candidate.includes('ntp')) return 'NTP';
    if (candidate.includes('smb')) return 'SMB';
    if (candidate.includes('rdp')) return 'RDP';
    if (candidate.includes('ssh')) return 'SSH';
    if (candidate.includes('telnet')) return 'TELNET';
    if (candidate.includes('smtp')) return 'SMTP';
    if (candidate.includes('mysql')) return 'MYSQL';
    if (candidate.includes('mssql')) return 'MSSQL';
  }

  const port = parsePort(rawAttack);
  if (port && PORT_PROTOCOL_MAP[port]) return PORT_PROTOCOL_MAP[port];
  return null;
};

export const clampNumber = (value, min = 0, max = 100, fallback = 0) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
};

export const toNonNegativeCount = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return 0;
  return numeric;
};

export const normalizePortExposureScore = (portExposure) => clampNumber(toNonNegativeCount(portExposure) * 10, 0, 100, 0);

export const classifyThreatScore = (score) => {
  const safeScore = clampNumber(score, 0, 100, 0);
  if (safeScore >= 75) return THREAT_CLASSIFICATION.DDOS;
  if (safeScore >= 50) return THREAT_CLASSIFICATION.MALWARE;
  if (safeScore >= 30) return THREAT_CLASSIFICATION.SCAN;
  return THREAT_CLASSIFICATION.LOW;
};

export const classificationToAttackType = (classification) => {
  const normalized = String(classification || '').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return ATTACK_TYPES.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return ATTACK_TYPES.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return ATTACK_TYPES.SCAN;
  return ATTACK_TYPES.SCAN;
};

export const SIGNAL_WEIGHTS = {
  abuseScore: 0.4,
  otxHits: 0.3,
  portExposure: 0.3,
};

export const isSignalPresent = (value) => value !== null && value !== undefined;

export const calculateWeightedThreatScore = ({ abuseScore, otxHits, portExposure }) => {
  const hasAbuse = isSignalPresent(abuseScore);
  const hasOtx = isSignalPresent(otxHits);
  const hasPort = isSignalPresent(portExposure);

  const abuseNormalized = hasAbuse ? clampNumber(abuseScore, 0, 100, 0) : 0;
  const otxNormalized = hasOtx ? clampNumber(toNonNegativeCount(otxHits) * 10, 0, 100, 0) : 0;
  const portNormalized = hasPort ? normalizePortExposureScore(portExposure) : 0;

  let rawScore = 0;
  let activeWeight = 0;
  const usedSources = [];
  const missingSources = [];

  if (hasAbuse) {
    rawScore += SIGNAL_WEIGHTS.abuseScore * abuseNormalized;
    activeWeight += SIGNAL_WEIGHTS.abuseScore;
    usedSources.push('abuseipdb');
  } else {
    missingSources.push('abuseipdb');
  }

  if (hasOtx) {
    rawScore += SIGNAL_WEIGHTS.otxHits * otxNormalized;
    activeWeight += SIGNAL_WEIGHTS.otxHits;
    usedSources.push('otx');
  } else {
    missingSources.push('otx');
  }

  if (hasPort) {
    rawScore += SIGNAL_WEIGHTS.portExposure * portNormalized;
    activeWeight += SIGNAL_WEIGHTS.portExposure;
    usedSources.push('shodan');
  } else {
    missingSources.push('shodan');
  }

  const score = activeWeight > 0
    ? clampNumber(Number((rawScore / activeWeight).toFixed(2)), 0, 100, 0)
    : 0;

  return {
    score,
    classification: classifyThreatScore(score),
    signals: {
      abuseScore: hasAbuse ? abuseNormalized : null,
      otxHits: hasOtx ? toNonNegativeCount(otxHits) : null,
      portExposure: hasPort ? toNonNegativeCount(portExposure) : null,
      otxScore: otxNormalized,
      portExposureScore: portNormalized,
      usedSources,
      sourcesUsed: [...usedSources],
      missingSources,
      activeWeight: Number(activeWeight.toFixed(2)),
    }
  };
};

export const getAttackColor = (attackData) => {
  const classification = String(attackData?.classification || '').toUpperCase();
  if (CLASS_META[classification]) return CLASS_META[classification].color;
  return COLOR_MAP[attackData?.type] || NEUTRAL_ATTACK_COLOR;
};

export const normalizeClassification = (value) => {
  const normalized = String(value || '').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return THREAT_CLASSIFICATION.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return THREAT_CLASSIFICATION.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return THREAT_CLASSIFICATION.SCAN;
  if (normalized === THREAT_CLASSIFICATION.LOW) return THREAT_CLASSIFICATION.LOW;
  return null;
};

export const normalizeAttackType = (value) => {
  const text = String(value || '').toLowerCase();
  if (!text) return null;
  if (text.includes('ddos') || text === 'ddos') return ATTACK_TYPES.DDOS;
  if (text.includes('malware')) return ATTACK_TYPES.MALWARE;
  if (text.includes('scan')) return ATTACK_TYPES.SCAN;
  return null;
};

export const normalizeSeverity = (rawAttack, intensity) => {
  const fromText = String(rawAttack?.severity || rawAttack?.threatLevel || '').toLowerCase();
  if (fromText.includes('critical')) return 'critical';
  if (fromText.includes('high')) return 'high';
  if (fromText.includes('medium') || fromText.includes('moderate')) return 'medium';
  if (fromText.includes('low')) return 'low';

  const fromNumber = Number(rawAttack?.severityScore ?? rawAttack?.confidence);
  if (Number.isFinite(fromNumber)) {
    const scaled = fromNumber <= 1 ? fromNumber * 10 : (fromNumber > 10 ? fromNumber / 10 : fromNumber);
    if (scaled >= 9) return 'critical';
    if (scaled >= 7) return 'high';
    if (scaled >= 4) return 'medium';
    return 'low';
  }

  if (intensity >= 9) return 'critical';
  if (intensity >= 7) return 'high';
  if (intensity >= 4) return 'medium';
  return 'low';
};




export const normalizeAiProvider = (value) => {
  const provider = String(value || '').toLowerCase();
  if (provider === 'openai' || provider === 'gemini') return provider;
  return 'none';
};

export const getAiProviderLabel = (ai) => {
  if (ai?.provider === 'openai') return 'OpenAI';
  if (ai?.provider === 'gemini') return 'Gemini';
  return null;
};

export const formatAiModeLabel = (mode) => {
  const normalized = String(mode || '').toLowerCase();
  if (normalized === 'openai') return 'OPENAI';
  if (normalized === 'gemini') return 'GEMINI';
  if (normalized === 'off') return 'OFF';
  return 'AUTO';
};

export const getClassificationLabel = (value) => {
  const normalized = String(value || 'LOW').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return THREAT_CLASSIFICATION.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return THREAT_CLASSIFICATION.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return THREAT_CLASSIFICATION.SCAN;
  return THREAT_CLASSIFICATION.LOW;
};

export const getAiBadgeLabel = (ai) => {
  if (ai?.used) return 'AI Assisted';
  return 'Rule-Based';
};

export const getAiBadgeClass = (ai) => {
  if (ai?.used && ai?.provider === 'openai') return 'text-cyber-blue border-cyber-blue/40 bg-cyber-blue/10 shadow-[0_0_12px_rgba(87,221,255,0.25)]';
  if (ai?.used && ai?.provider === 'gemini') return 'text-violet-200 border-violet-300/40 bg-violet-500/10 shadow-[0_0_12px_rgba(160,120,255,0.25)]';
  return 'text-slate-400 border-slate-500/30 bg-slate-600/10';
};

export const getSignalValue = (value, decimals = 0) => {
  if (value === null || value === undefined) return 'N/A';
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'N/A';
  return decimals > 0 ? numeric.toFixed(decimals) : String(Math.round(numeric));
};

export const SIGNAL_SOURCE_LABELS = {
  abuseipdb: 'AbuseIPDB',
  otx: 'OTX',
  shodan: 'Shodan',
};

export const SOURCE_STATUS_VALUES = new Set(['ok', 'failed', 'rate_limited', 'unauthorized']);

export const formatSourceStatusTooltip = (sourceKey, status) => {
  const sourceLabel = SIGNAL_SOURCE_LABELS[sourceKey] || sourceKey;
  if (status === 'rate_limited') return `${sourceLabel} rate limited`;
  if (status === 'unauthorized') return `${sourceLabel} unauthorized`;
  if (status === 'failed') return `${sourceLabel} unavailable`;
  return '';
};

export const getAiErrorLabel = (reasonCode) => {
  switch (String(reasonCode || '').toLowerCase()) {
    case 'invalid_model':
      return 'Invalid Gemini model';
    case 'timeout':
      return 'AI timeout';
    case 'throttled':
      return 'AI throttled';
    default:
      return 'AI unavailable';
  }
};

export const normalizeThreatSourceStatus = (sources = {}, fallbackSignals = {}) => {
  const readStatus = (key) => {
    const direct = String(sources?.[key] || '').toLowerCase();
    if (SOURCE_STATUS_VALUES.has(direct)) return direct;

    const fallback = String(fallbackSignals?.sourceStatus?.[key] || '').toLowerCase();
    if (SOURCE_STATUS_VALUES.has(fallback)) return fallback;

    return 'failed';
  };

  return {
    abuseipdb: readStatus('abuseipdb'),
    otx: readStatus('otx'),
    shodan: readStatus('shodan'),
  };
};

export const getAvailableSourcesFromStatus = (sourceStatus = {}) =>
  Object.entries(sourceStatus)
    .filter((entry) => entry[1] === 'ok')
    .map((entry) => entry[0]);

export const getMissingSourcesFromStatus = (sourceStatus = {}) =>
  Object.entries(sourceStatus)
    .filter((entry) => entry[1] !== 'ok')
    .map((entry) => entry[0]);

export const CRITICAL_SOURCES = ['abuseipdb', 'otx'];

export const hasDegradedData = (sourceStatus = {}) => {
  const missing = getMissingSourcesFromStatus(sourceStatus);
  const criticalMissing = CRITICAL_SOURCES.every((source) => {
    const status = String(sourceStatus?.[source] || '').toLowerCase();
    return status && status !== 'ok';
  });
  // Only mark degraded if 2+ providers failed or all critical providers are unavailable
  return missing.length >= 2 || criticalMissing;
};

export const getDegradedDataTooltip = (sourceStatus = {}) => {
  const missing = Object.entries(sourceStatus)
    .filter((entry) => entry[1] !== 'ok');
  if (missing.length === 0) return '';
  const labels = missing.map(([source, status]) =>
    formatSourceStatusTooltip(source, status)
      || `${SIGNAL_SOURCE_LABELS[source] || source} unavailable`
  );
  return labels.join(', ');
};

// Only show degraded indicator on HIGH/CRITICAL threats
export const shouldShowDegradedBadge = (sourceStatus = {}, score = 0) => {
  if (!hasDegradedData(sourceStatus)) return false;
  return score >= 50; // HIGH or CRITICAL only
};

export const getSignalDisplayMeta = (value, sourceKey, sourceStatus = {}, decimals = 0) => {
  const normalizedStatus = normalizeThreatSourceStatus(sourceStatus);
  const sourceAvailable = normalizedStatus[sourceKey] === 'ok';

  if (!sourceAvailable) {
    const sourceLabel = SIGNAL_SOURCE_LABELS[sourceKey] || sourceKey;
    return {
      text: 'N/A',
      faded: true,
      tooltip: formatSourceStatusTooltip(sourceKey, normalizedStatus[sourceKey])
        || `${sourceLabel} unavailable`,
    };
  }

  const numeric = Number(value);
  const displayValue = Number.isFinite(numeric)
    ? (decimals > 0 ? numeric.toFixed(decimals) : String(Math.round(numeric)))
    : '0';

  return {
    text: displayValue,
    faded: false,
    tooltip: '',
  };
};

export const buildStableAttackId = (attack) => {
  if (attack.sourceIp) return `ip:${attack.sourceIp}`;
  const sourceKey = attack.sourceIp
    ? attack.sourceIp
    : `${attack.sourceCountry || 'unknown-src'}:${attack.sourceLat}:${attack.sourceLng}`;
  const targetKey = attack.targetCountry
    ? attack.targetCountry
    : `${attack.targetLat}:${attack.targetLng}`;
  return [sourceKey, targetKey, attack.type || ATTACK_TYPES.SCAN, attack.protocol || 'UNKNOWN'].join('|');
};

export const normalizeAttackData = (rawAttack) => {
  if (!rawAttack || typeof rawAttack !== 'object') return null;

  const sourceLat = toFiniteCoord(rawAttack.sourceLat);
  const sourceLng = toFiniteCoord(rawAttack.sourceLng);
  const targetLat = toFiniteCoord(rawAttack.targetLat);
  const targetLng = toFiniteCoord(rawAttack.targetLng);
  if (sourceLat === null || sourceLng === null || targetLat === null || targetLng === null) return null;

  const provider = String(rawAttack.provider || 'fallback').toLowerCase();
  const fallbackSignals = rawAttack?.signals && typeof rawAttack.signals === 'object' ? rawAttack.signals : {};
  const normalizedSourceStatus = normalizeThreatSourceStatus(rawAttack?.sources || {}, fallbackSignals);
  const sourceAvailable = (sourceKey) => normalizedSourceStatus[sourceKey] === 'ok';

  // Preserve null semantics: use null (not 0) for absent signals so rebalancing works
  const deriveSignal = (serverVal, rawFallback, defaultVal) => {
    if (isSignalPresent(serverVal)) return serverVal;
    if (isSignalPresent(rawFallback)) return rawFallback;
    return defaultVal;
  };

  const derivedSignals = {
    abuseScore: sourceAvailable('abuseipdb')
      ? deriveSignal(
        fallbackSignals.abuseScore,
        rawAttack.abuseScore,
        provider === 'abuseipdb' ? rawAttack.score : null
      )
      : null,
    otxHits: sourceAvailable('otx')
      ? deriveSignal(
        fallbackSignals.otxHits,
        rawAttack.otxHits,
        null
      )
      : null,
    portExposure: sourceAvailable('shodan')
      ? deriveSignal(
        fallbackSignals.portExposure,
        rawAttack.portExposure,
        Array.isArray(rawAttack.ports) ? rawAttack.ports.length : null
      )
      : null,
  };
  const weighted = calculateWeightedThreatScore(derivedSignals);
  const explicitScore = Number(rawAttack.score);
  const score = Number.isFinite(explicitScore) ? clampNumber(explicitScore, 0, 100, weighted.score) : weighted.score;
  const classification = normalizeClassification(rawAttack.classification) || classifyThreatScore(score);

  const aiRaw = rawAttack?.ai && typeof rawAttack.ai === 'object' ? rawAttack.ai : null;
  const aiProvider = normalizeAiProvider(aiRaw?.provider || rawAttack?.aiProvider);
  const ai = {
    used: Boolean(aiRaw?.used),
    provider: aiProvider,
    confidence: clampNumber(aiRaw?.confidence, 0, 100, 0),
    reason: String(aiRaw?.reason || '').trim(),
  };

  const availableSources = getAvailableSourcesFromStatus(normalizedSourceStatus);
  const missingSources = getMissingSourcesFromStatus(normalizedSourceStatus);

  const normalizedSignals = {
    abuseScore: sourceAvailable('abuseipdb')
      ? (isSignalPresent(fallbackSignals.abuseScore) ? clampNumber(fallbackSignals.abuseScore, 0, 100, 0)
        : isSignalPresent(weighted.signals.abuseScore) ? weighted.signals.abuseScore : 0)
      : 0,
    otxHits: sourceAvailable('otx')
      ? (isSignalPresent(fallbackSignals.otxHits) ? toNonNegativeCount(fallbackSignals.otxHits)
        : isSignalPresent(weighted.signals.otxHits) ? weighted.signals.otxHits : 0)
      : 0,
    portExposure: sourceAvailable('shodan')
      ? (isSignalPresent(fallbackSignals.portExposure) ? toNonNegativeCount(fallbackSignals.portExposure)
        : isSignalPresent(weighted.signals.portExposure) ? weighted.signals.portExposure : 0)
      : 0,
    ruleScore: clampNumber(fallbackSignals.ruleScore ?? weighted.score, 0, 100, weighted.score),
    aiConfidence: clampNumber(fallbackSignals.aiConfidence ?? ai.confidence, 0, 100, 0),
    finalScore: clampNumber(fallbackSignals.finalScore ?? score, 0, 100, score),
    usedSources: Array.isArray(fallbackSignals.usedSources)
      ? fallbackSignals.usedSources
      : Array.isArray(fallbackSignals.sourcesUsed)
        ? fallbackSignals.sourcesUsed
        : availableSources,
    sourcesUsed: Array.isArray(fallbackSignals.sourcesUsed)
      ? fallbackSignals.sourcesUsed
      : Array.isArray(fallbackSignals.usedSources)
        ? fallbackSignals.usedSources
        : availableSources,
    availableSources,
    missingSources,
    sourceStatus: normalizedSourceStatus,
    activeWeight: Number(
      fallbackSignals.activeWeight
      ?? weighted.signals.activeWeight
      ?? availableSources.reduce((sum, source) => {
        if (source === 'abuseipdb') return sum + SIGNAL_WEIGHTS.abuseScore;
        if (source === 'otx') return sum + SIGNAL_WEIGHTS.otxHits;
        if (source === 'shodan') return sum + SIGNAL_WEIGHTS.portExposure;
        return sum;
      }, 0)
    ),
  };

  const intensity = normalizeIntensityTo10(rawAttack.intensity ?? rawAttack.severityScore ?? rawAttack.confidence ?? (score / 10));
  const protocol = inferProtocol(rawAttack);
  const severity = normalizeSeverity(rawAttack, intensity);
  const type = normalizeAttackType(rawAttack.type || rawAttack.attackType || rawAttack.eventType) || classificationToAttackType(classification);

  const timestampRaw = Number(rawAttack.timestamp);
  const timestamp = Number.isFinite(timestampRaw) && timestampRaw > 0 ? timestampRaw : Date.now();

  const normalized = {
    sourceLat, sourceLng,
    sourceCountry: rawAttack.sourceCountry || rawAttack.originCountry || 'Unknown',
    sourceCountryCode: rawAttack.sourceCountryCode || rawAttack.countryCode || '',
    sourceCity: rawAttack.sourceCity || rawAttack.city || 'Unknown',
    sourceRegion: rawAttack.sourceRegion || rawAttack.region || 'Unknown',
    sourceIp: rawAttack.sourceIp || rawAttack.ipAddress || rawAttack.ip || '',
    targetLat, targetLng,
    targetCountry: rawAttack.targetCountry || rawAttack.destinationCountry || 'Unattributed',
    type, severity, protocol, intensity, timestamp,
    score,
    classification,
    signals: normalizedSignals,
    sources: normalizedSourceStatus,
    ai,
    provider
  };

  normalized.synthetic = Boolean(rawAttack.synthetic);
  normalized.id = normalized.synthetic && rawAttack.id ? String(rawAttack.id) : buildStableAttackId(normalized);
  normalized.color = getAttackColor(normalized);
  return normalized;
};

export const normalizeAttackBatch = (rawAttacks = []) => {
  if (!Array.isArray(rawAttacks)) return [];
  return rawAttacks.map(normalizeAttackData).filter(Boolean);
};

export const ATTACK_TTL_MS = 150 * 1000;

export const mergeAttackBuffer = (currentBuffer, incomingAttacks, maxBuffer = 24, now = Date.now()) => {
  const mergedById = new Map();
  [...currentBuffer, ...incomingAttacks].forEach((attack) => {
    if (!attack?.id) return;
    if (now - (attack.timestamp || 0) > ATTACK_TTL_MS) return;
    const existing = mergedById.get(attack.id);
    if (!existing || (attack.timestamp || 0) >= (existing.timestamp || 0)) {
      mergedById.set(attack.id, attack);
    }
  });
  return [...mergedById.values()]
    .sort((a, b) => (a.timestamp || 0) - (b.timestamp || 0))
    .slice(-maxBuffer);
};


// Adapter: flat attack new UI Threat shape


export const toNewThreat = (attack) => ({
  id: attack.id,
  type: attack.type,
  score: attack.score,
  classification: attack.classification,
  signals: attack.signals,
  sources: normalizeThreatSourceStatus(attack.sources || {}, attack.signals || {}),
  ai: attack.ai,
  origin: {
    country: attack.sourceCountry,
    lat: attack.sourceLat,
    lng: attack.sourceLng,
    ip: attack.sourceIp || '',
  },
  target: {
    country: attack.targetCountry,
    lat: attack.targetLat,
    lng: attack.targetLng,
  },
  intensity: attack.intensity,
  timestamp: new Date(attack.timestamp),
  source: attack.synthetic ? 'SIM' : attack.provider === 'seed' ? 'SEED' : 'API',
  synthetic: Boolean(attack.synthetic),
  sourceCity: attack.sourceCity,
});
