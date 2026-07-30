import React, { useState, useEffect, useRef, useMemo } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import {
  Activity,
  Shield,
  Globe as GlobeIcon,
  Terminal,
  Zap,
  AlertTriangle,
  Play,
  Pause,
  SkipForward,
  SkipBack,
  BarChart3,
  Cpu,
  Wifi,
  Database,
  Clock
} from 'lucide-react';
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  XAxis,
  YAxis,
  Tooltip,
  Legend,
  ResponsiveContainer,
  Cell,
  CartesianGrid
} from 'recharts';
import { cn } from './lib/utils';
import GlobeView from './components/GlobeView';
import ThreatReportModal from './components/ThreatReportModal';
import { wannacrySteps, miraiSteps, ATTACK_TYPES, COLOR_MAP } from './data/constants';

// ─────────────────────────────────────────────
// Data normalization pipeline (unchanged from old App)
// ─────────────────────────────────────────────

const NEUTRAL_ATTACK_COLOR = '#9fb3c8';
const DISALLOWED_SOURCE_FALLBACK_COLORS = new Set(['#9d4edd']);

const PORT_PROTOCOL_MAP = {
  22: 'SSH', 23: 'TELNET', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
  123: 'NTP', 443: 'HTTPS', 445: 'SMB', 993: 'IMAPS', 995: 'POP3S',
  1433: 'MSSQL', 3306: 'MYSQL', 3389: 'RDP', 8080: 'HTTP'
};

const THREAT_CLASSIFICATION = {
  DDOS: 'DDOS',
  MALWARE: 'MALWARE',
  SCAN: 'SCAN',
  LOW: 'LOW'
};

const normalizeIntensityTo10 = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 5;
  const scaled = numeric <= 1 ? numeric * 10 : numeric;
  return Math.max(1, Math.min(10, Math.round(scaled)));
};

const toFiniteCoord = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Number(numeric.toFixed(4));
};

const normalizeHexColor = (value) => {
  if (!value || typeof value !== 'string') return null;
  const trimmed = value.trim();
  const match = trimmed.match(/^#([a-fA-F0-9]{3}|[a-fA-F0-9]{6})$/);
  if (!match) return null;
  const hex = match[1].toLowerCase();
  if (hex.length === 3) {
    return `#${hex.split('').map((char) => `${char}${char}`).join('')}`;
  }
  return `#${hex}`;
};

const parsePort = (rawAttack) => {
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

const inferProtocol = (rawAttack) => {
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

const clampNumber = (value, min = 0, max = 100, fallback = 0) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return fallback;
  return Math.min(max, Math.max(min, numeric));
};

const toNonNegativeCount = (value) => {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric < 0) return 0;
  return numeric;
};

const normalizePortExposureScore = (portExposure) => clampNumber(toNonNegativeCount(portExposure) * 10, 0, 100, 0);

const classifyThreatScore = (score) => {
  const safeScore = clampNumber(score, 0, 100, 0);
  if (safeScore >= 75) return THREAT_CLASSIFICATION.DDOS;
  if (safeScore >= 50) return THREAT_CLASSIFICATION.MALWARE;
  if (safeScore >= 30) return THREAT_CLASSIFICATION.SCAN;
  return THREAT_CLASSIFICATION.LOW;
};

const classificationToAttackType = (classification) => {
  const normalized = String(classification || '').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return ATTACK_TYPES.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return ATTACK_TYPES.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return ATTACK_TYPES.SCAN;
  return ATTACK_TYPES.SCAN;
};

const SIGNAL_WEIGHTS = {
  abuseScore: 0.4,
  otxHits: 0.3,
  portExposure: 0.3,
};

const isSignalPresent = (value) => value !== null && value !== undefined;

const calculateWeightedThreatScore = ({ abuseScore, otxHits, portExposure }) => {
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

const normalizeClassification = (value) => {
  const normalized = String(value || '').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return THREAT_CLASSIFICATION.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return THREAT_CLASSIFICATION.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return THREAT_CLASSIFICATION.SCAN;
  if (normalized === THREAT_CLASSIFICATION.LOW) return THREAT_CLASSIFICATION.LOW;
  return null;
};

const normalizeAttackType = (value) => {
  const text = String(value || '').toLowerCase();
  if (!text) return null;
  if (text.includes('ddos') || text === 'ddos') return ATTACK_TYPES.DDOS;
  if (text.includes('malware')) return ATTACK_TYPES.MALWARE;
  if (text.includes('scan')) return ATTACK_TYPES.SCAN;
  return null;
};

const normalizeSeverity = (rawAttack, intensity) => {
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

const getAttackColor = (attackData) => {
  const typeColor = COLOR_MAP[attackData?.type];
  if (typeColor) return typeColor;

  const severity = String(attackData?.severity || '').toLowerCase();
  const severityColorMap = { critical: '#ff4757', high: '#ff4757', medium: '#ffb142', low: '#2ed573' };
  if (severityColorMap[severity]) return severityColorMap[severity];

  const protocol = String(attackData?.protocol || '').toUpperCase();
  const protocolColorMap = {
    UDP: '#ff4757', ICMP: '#ff4757', DNS: '#ff4757', NTP: '#ff4757',
    TCP: '#ffb142', SMB: '#ffb142', RDP: '#ffb142', TELNET: '#ffb142',
    HTTP: '#2ed573', HTTPS: '#2ed573', SSH: '#2ed573'
  };
  if (protocolColorMap[protocol]) return protocolColorMap[protocol];

  const providedColor = normalizeHexColor(attackData?.color);
  if (providedColor && !DISALLOWED_SOURCE_FALLBACK_COLORS.has(providedColor)) return providedColor;
  return NEUTRAL_ATTACK_COLOR;
};

const classificationAccentColor = (classification) => {
  if (classification === THREAT_CLASSIFICATION.DDOS) return '#ff4757';
  if (classification === THREAT_CLASSIFICATION.MALWARE) return '#ffb142';
  if (classification === THREAT_CLASSIFICATION.SCAN) return '#2ed573';
  return '#57ddff';
};

const hexToRgba = (hex, alpha = 1) => {
  const normalized = normalizeHexColor(hex);
  if (!normalized) return `rgba(159,179,200,${alpha})`;
  const h = normalized.slice(1);
  const r = parseInt(h.slice(0, 2), 16);
  const g = parseInt(h.slice(2, 4), 16);
  const b = parseInt(h.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
};

const normalizeAiProvider = (value) => {
  const provider = String(value || '').toLowerCase();
  if (provider === 'openai' || provider === 'gemini') return provider;
  return 'none';
};

const getAiProviderLabel = (ai) => {
  if (ai?.provider === 'openai') return 'OpenAI';
  if (ai?.provider === 'gemini') return 'Gemini';
  return null;
};

const formatAiModeLabel = (mode) => {
  const normalized = String(mode || '').toLowerCase();
  if (normalized === 'openai') return 'OPENAI';
  if (normalized === 'gemini') return 'GEMINI';
  if (normalized === 'off') return 'OFF';
  return 'AUTO';
};

const getClassificationLabel = (value) => {
  const normalized = String(value || 'LOW').toUpperCase();
  if (normalized === THREAT_CLASSIFICATION.DDOS) return THREAT_CLASSIFICATION.DDOS;
  if (normalized === THREAT_CLASSIFICATION.MALWARE) return THREAT_CLASSIFICATION.MALWARE;
  if (normalized === THREAT_CLASSIFICATION.SCAN) return THREAT_CLASSIFICATION.SCAN;
  return THREAT_CLASSIFICATION.LOW;
};

const getAiBadgeLabel = (ai) => {
  if (ai?.used) return 'AI Assisted';
  return 'Rule-Based';
};

const getAiBadgeClass = (ai) => {
  if (ai?.used && ai?.provider === 'openai') return 'text-cyber-blue border-cyber-blue/40 bg-cyber-blue/10 shadow-[0_0_12px_rgba(87,221,255,0.25)]';
  if (ai?.used && ai?.provider === 'gemini') return 'text-violet-200 border-violet-300/40 bg-violet-500/10 shadow-[0_0_12px_rgba(160,120,255,0.25)]';
  return 'text-slate-400 border-slate-500/30 bg-slate-600/10';
};

const getSignalValue = (value, decimals = 0) => {
  if (value === null || value === undefined) return 'N/A';
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return 'N/A';
  return decimals > 0 ? numeric.toFixed(decimals) : String(Math.round(numeric));
};

const SIGNAL_SOURCE_LABELS = {
  abuseipdb: 'AbuseIPDB',
  otx: 'OTX',
  shodan: 'Shodan',
};

const normalizeThreatSourceStatus = (sources = {}, fallbackSignals = {}) => {
  const readStatus = (key) => {
    const direct = String(sources?.[key] || '').toLowerCase();
    if (direct === 'ok' || direct === 'failed') return direct;

    const fallback = String(fallbackSignals?.sourceStatus?.[key] || '').toLowerCase();
    if (fallback === 'ok' || fallback === 'failed') return fallback;

    return 'failed';
  };

  return {
    abuseipdb: readStatus('abuseipdb'),
    otx: readStatus('otx'),
    shodan: readStatus('shodan'),
  };
};

const getAvailableSourcesFromStatus = (sourceStatus = {}) =>
  Object.entries(sourceStatus)
    .filter((entry) => entry[1] === 'ok')
    .map((entry) => entry[0]);

const getMissingSourcesFromStatus = (sourceStatus = {}) =>
  Object.entries(sourceStatus)
    .filter((entry) => entry[1] !== 'ok')
    .map((entry) => entry[0]);

const hasDegradedData = (sourceStatus = {}) =>
  getMissingSourcesFromStatus(sourceStatus).length > 0;

const getDegradedDataTooltip = (sourceStatus = {}) => {
  const missing = getMissingSourcesFromStatus(sourceStatus);
  if (missing.length === 0) return '';
  const labels = missing.map((source) => SIGNAL_SOURCE_LABELS[source] || source);
  return `${labels.join(', ')} unavailable`;
};

const getSignalDisplayMeta = (value, sourceKey, sourceStatus = {}, decimals = 0) => {
  const normalizedStatus = normalizeThreatSourceStatus(sourceStatus);
  const sourceAvailable = normalizedStatus[sourceKey] === 'ok';

  if (!sourceAvailable) {
    const sourceLabel = SIGNAL_SOURCE_LABELS[sourceKey] || sourceKey;
    return {
      text: '0 (no data)',
      faded: true,
      tooltip: `${sourceLabel} unavailable`,
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

const getThreatCardStyle = (score, classification, highlighted) => {
  const normalizedScore = clampNumber(score, 0, 100, 0);
  const accent = classificationAccentColor(classification);
  const borderAlpha = 0.16 + (normalizedScore / 100) * 0.4;
  const glowAlpha = (highlighted ? 0.18 : 0.08) + (normalizedScore / 100) * (highlighted ? 0.34 : 0.22);
  const glowRadius = 8 + (normalizedScore / 100) * 16;

  return {
    borderColor: hexToRgba(accent, borderAlpha),
    boxShadow: `0 0 ${glowRadius}px ${hexToRgba(accent, glowAlpha)}`,
  };
};

const buildStableAttackId = (attack) => {
  const sourceKey = attack.sourceIp
    ? attack.sourceIp
    : `${attack.sourceCountry || 'unknown-src'}:${attack.sourceLat}:${attack.sourceLng}`;
  const targetKey = attack.targetCountry
    ? attack.targetCountry
    : `${attack.targetLat}:${attack.targetLng}`;
  return [sourceKey, targetKey, attack.type || ATTACK_TYPES.SCAN, attack.protocol || 'UNKNOWN'].join('|');
};

const normalizeAttackData = (rawAttack) => {
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
    targetCountry: rawAttack.targetCountry || rawAttack.destinationCountry || 'Unknown',
    type, severity, protocol, intensity, timestamp,
    score,
    classification,
    signals: normalizedSignals,
    sources: normalizedSourceStatus,
    ai,
    provider
  };

  normalized.id = buildStableAttackId(normalized);
  normalized.color = getAttackColor({ ...rawAttack, ...normalized });
  return normalized;
};

const normalizeAttackBatch = (rawAttacks = []) => {
  if (!Array.isArray(rawAttacks)) return [];
  return rawAttacks.map(normalizeAttackData).filter(Boolean);
};

const mergeAttackBuffer = (currentBuffer, incomingAttacks, maxBuffer = 25) => {
  const mergedById = new Map();
  [...currentBuffer, ...incomingAttacks].forEach((attack) => {
    if (!attack?.id) return;
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


const toNewThreat = (attack) => ({
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
    ip: attack.sourceIp || '0.0.0.0',
  },
  target: {
    country: attack.targetCountry,
    lat: attack.targetLat,
    lng: attack.targetLng,
  },
  intensity: attack.intensity,
  timestamp: new Date(attack.timestamp),
  source: attack.provider === 'fallback' ? 'CACHE' : 'API',
});

// ─────────────────────────────────────────────
// Sub-components (from new UI, converted to JSX)
// ─────────────────────────────────────────────

const CyberPanel = ({ title, children, className, icon: Icon }) => (
  <div className={cn("cyber-panel p-3.5 sm:p-4 flex flex-col gap-2", className)}>
    <div className="flex items-center gap-2.5 pb-2 border-b border-cyber-blue/10">
      {Icon && <Icon size={15} className="text-cyber-blue/90" />}
      <h3 className="text-[11px] font-semibold uppercase tracking-[0.18em] text-cyber-blue/80 font-mono">{title}</h3>
    </div>
    <div className="flex-1 overflow-hidden pt-0.5">
      {children}
    </div>
  </div>
);

const Metric = ({ label, value, color = "blue", subValue }) => {
  const colorClass = {
    red: "text-cyber-red cyber-glow-red",
    green: "text-cyber-green cyber-glow-green",
    yellow: "text-cyber-yellow cyber-glow-yellow",
    blue: "text-cyber-blue cyber-glow-blue"
  }[color];

  return (
    <div className="flex flex-col">
      <span className="text-[10px] uppercase tracking-wide text-slate-400 font-mono">{label}</span>
      <div className="flex items-baseline gap-2">
        <span className={cn("text-lg sm:text-xl font-semibold font-mono", colorClass)}>{value}</span>
        {subValue && <span className="text-[10px] text-slate-500 font-mono">{subValue}</span>}
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────
// Main App
// ─────────────────────────────────────────────

const App = () => {
  // Live feed state
  const [liveAttacks, setLiveAttacks] = useState([]);
  const [healthStats, setHealthStats] = useState(null);

  // Simulation state
  const [simulationMode, setSimulationMode] = useState('live');
  const [currentSim, setCurrentSim] = useState('wannacry');
  const [isPlaying, setIsPlaying] = useState(false);
  const [simulationSpeed, setSimulationSpeed] = useState(1);
  const [currentStepIndex, setCurrentStepIndex] = useState(0);

  // Filter state
  const [filter, setFilter] = useState('All');

  // Report modal state
  const [selectedThreat, setSelectedThreat] = useState(null);
  const [reportModalOpen, setReportModalOpen] = useState(false);

  // UI state
  const [highlightedThreatId, setHighlightedThreatId] = useState(null);
  const [focusedCountry, setFocusedCountry] = useState(null);
  const [focusedAttack, setFocusedAttack] = useState(null);
  const [simComplete, setSimComplete] = useState(false);
  const [dataSource, setDataSource] = useState('api');
  const [liveLogs, setLiveLogs] = useState([]);
  
  // AI Provider state
  const [selectedAiProvider, setSelectedAiProvider] = useState('auto');
  const [aiThreshold, setAiThreshold] = useState(70);

  // Timer refs
  const simulationIntervalRef = useRef(null);
  const livePollRef = useRef(null);
  const liveQueueRef = useRef([]);
  const liveDrainTimerRef = useRef(null);
  const liveExpiryTimersRef = useRef(new Map());
  const liveAttackCountRef = useRef(0);

  const MAX_LIVE_ARCS = 8;
  const LIVE_ATTACK_REVEAL_MS = 1125;
  const LIVE_ATTACK_LIFETIME_MS = 9250;

  useEffect(() => {
    liveAttackCountRef.current = liveAttacks.length;
  }, [liveAttacks]);

  // Derived
  const activeSteps = currentSim === 'mirai' ? miraiSteps : wannacrySteps;
  const currentStep = simulationMode === 'simulation' ? activeSteps[currentStepIndex] : null;

  // ── Live feed: fetch from API ──
  useEffect(() => {
    if (simulationMode !== 'live') return;
    let cancelled = false;

    const clearDrainTimer = () => {
      if (liveDrainTimerRef.current) {
        clearTimeout(liveDrainTimerRef.current);
        liveDrainTimerRef.current = null;
      }
    };

    const scheduleExpiry = (attackId) => {
      if (!attackId) return;
      const existingTimer = liveExpiryTimersRef.current.get(attackId);
      if (existingTimer) {
        clearTimeout(existingTimer);
      }

      const expiryTimer = setTimeout(() => {
        if (cancelled) return;
        liveExpiryTimersRef.current.delete(attackId);
        setLiveAttacks((prev) => prev.filter((attack) => attack.id !== attackId));
      }, LIVE_ATTACK_LIFETIME_MS);

      liveExpiryTimersRef.current.set(attackId, expiryTimer);
    };

    const drainQueuedAttack = () => {
      if (cancelled || liveDrainTimerRef.current) return;

      const nextAttack = liveQueueRef.current.shift();
      if (!nextAttack) return;

      setLiveAttacks((prev) => mergeAttackBuffer(prev, [nextAttack], MAX_LIVE_ARCS));
      scheduleExpiry(nextAttack.id);

      const aiTag = nextAttack.ai?.used
        ? `${getAiProviderLabel(nextAttack.ai) || 'AI'} ${getSignalValue(nextAttack.ai?.confidence)}%`
        : 'RULE';
      setLiveLogs((prev) => [
        `[${new Date().toLocaleTimeString()}] ${nextAttack.type} from ${nextAttack.sourceCountry} → ${nextAttack.targetCountry} (${nextAttack.provider} | ${aiTag})`,
        ...prev
      ].slice(0, 20));

      liveDrainTimerRef.current = setTimeout(() => {
        liveDrainTimerRef.current = null;
        drainQueuedAttack();
      }, LIVE_ATTACK_REVEAL_MS);
    };

    const addAttacksGradually = (rawAttacks) => {
      const newAttacks = normalizeAttackBatch(rawAttacks);
      if (newAttacks.length === 0) return;

      liveQueueRef.current.push(...newAttacks);
      drainQueuedAttack();
    };
    //initial api fetch 

    const fetchThreats = async () => {
      if (liveQueueRef.current.length > 0 || liveAttackCountRef.current >= MAX_LIVE_ARCS) {
        return;
      }

      try {
        const res = await fetch(`http://localhost:5000/api/threats?provider=${selectedAiProvider}`, {
          headers: { 'X-AI-Threshold': aiThreshold.toString() }
        });
        if (!res.ok) throw new Error(`API ${res.status}`);
        const data = await res.json();
        if (!cancelled) {
          setDataSource('api');
          if (data.attacks && data.attacks.length > 0) {
            addAttacksGradually(data.attacks);
          }
        }
      } catch (err) {
        console.warn('API fetch failed:', err.message);
        if (!cancelled) setDataSource('offline');
      }
    };

    const fetchHealth = async () => {
      try {
        const res = await fetch(`http://localhost:5000/api/health?provider=${selectedAiProvider}`, {
          headers: { 'X-AI-Threshold': aiThreshold.toString() }
        });
        if (!res.ok) return;
        const data = await res.json();
        if (!cancelled) setHealthStats(data);
      } catch (err) { /* quiet fail */ }
    };

    fetchThreats();
    fetchHealth();

    const intervalId = setInterval(() => {
      fetchThreats();
      fetchHealth();
    }, 8000);
    livePollRef.current = { intervalId, _staggerIds: [] };

    return () => {
      cancelled = true;
      clearDrainTimer();
      clearInterval(intervalId);
      liveExpiryTimersRef.current.forEach((timer) => clearTimeout(timer));
      liveExpiryTimersRef.current.clear();
      liveQueueRef.current = [];
      livePollRef.current = null;
    };
  }, [simulationMode, selectedAiProvider, aiThreshold]);

  // Step simulation playback
  useEffect(() => {
    if (simulationMode === 'simulation' && isPlaying) {
      const stageDuration = 2200 / simulationSpeed;
      simulationIntervalRef.current = setInterval(() => {
        setCurrentStepIndex((prev) => {
          const nextStep = prev + 1;
          if (nextStep >= activeSteps.length) {
            setIsPlaying(false);
            setSimComplete(true);
            return prev;
          }
          return nextStep;
        });
      }, stageDuration);
      return () => {
        if (simulationIntervalRef.current) clearInterval(simulationIntervalRef.current);
      };
    }
  }, [simulationMode, isPlaying, simulationSpeed, activeSteps.length]);

  // Get current attacks based on mode
  const currentAttacks = simulationMode === 'live'
    ? liveAttacks
    : (currentStep?.arcs || []);

  const highlightedCountries = currentStep?.affectedRegions || [];

  const filteredAttacks = currentAttacks.filter((attack) => {
    if (filter === 'All') return true;
    return attack.type.toLowerCase() === filter.toLowerCase();
  });

  // Adapt flat attacks → new UI Threat shape for panels
  const threats = useMemo(() => filteredAttacks.map(toNewThreat), [filteredAttacks]);

  // Top origins for left panel
  const topOrigins = useMemo(() => {
    const counts = {};
    threats.forEach(t => {
      counts[t.origin.country] = (counts[t.origin.country] || 0) + 1;
    });
    return Object.entries(counts)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);
  }, [threats]);

  // Threat level
  const threatLevel = useMemo(() => {
    const avgIntensity = threats.reduce((acc, t) => acc + t.intensity, 0) / (threats.length || 1);
    if (avgIntensity > 7) return { label: "CRITICAL", color: "red" };
    if (avgIntensity > 4) return { label: "HIGH", color: "yellow" };
    return { label: "ELEVATED", color: "blue" };
  }, [threats]);

  // Timeline data for bar chart
  const timelineData = useMemo(() => {
    const now = Date.now();
    const buckets = [];
    for (let i = 29; i >= 0; i--) {
      const bucketStart = now - (i + 1) * 1000;
      const bucketEnd = now - i * 1000;
      const matching = currentAttacks.filter(a => {
        const ts = a.timestamp || 0;
        return ts >= bucketStart && ts < bucketEnd;
      });
      const ddos = matching.filter(a => a.type === 'DDoS').length;
      const malware = matching.filter(a => a.type === 'Malware').length;
      const scan = matching.filter(a => a.type === 'Scan').length;
      const total = matching.length;
      const dominantColor = ddos >= malware && ddos >= scan ? '#ff3131'
        : malware >= scan ? '#fefe33' : '#00ff41';
      buckets.push({
        time: `${i}s`,
        count: total,
        color: total > 0 ? dominantColor : '#00f3ff'
      });
    }
    return buckets;
  }, [currentAttacks]);

  const attackDistributionData = useMemo(() => {
    const counts = {
      DDOS: 0,
      MALWARE: 0,
      SCAN: 0,
      LOW: 0,
    };

    currentAttacks.forEach((attack) => {
      const classification = String(attack?.classification || '').toUpperCase();
      if (Object.prototype.hasOwnProperty.call(counts, classification)) {
        counts[classification] += 1;
        return;
      }

      const type = String(attack?.type || '').toLowerCase();
      if (type.includes('ddos')) {
        counts.DDOS += 1;
      } else if (type.includes('malware')) {
        counts.MALWARE += 1;
      } else if (type.includes('scan')) {
        counts.SCAN += 1;
      } else {
        counts.LOW += 1;
      }
    });

    const palette = {
      DDOS: '#ff4d4f',
      MALWARE: '#fadb14',
      SCAN: '#52c41a',
      LOW: '#00eaff',
    };

    const total = Object.values(counts).reduce((sum, value) => sum + value, 0);
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      color: palette[name],
      percentage: total > 0 ? Number(((value / total) * 100).toFixed(1)) : 0,
    }));
  }, [currentAttacks]);

  const totalDistributionAttacks = useMemo(
    () => attackDistributionData.reduce((sum, item) => sum + item.value, 0),
    [attackDistributionData]
  );

  // Provider status from health
  const providerStatus = useMemo(() => {
    if (!healthStats?.providers) return [
      { name: 'AbuseIPDB', status: 'CHECKING' },
      { name: 'OTX AlienVault', status: 'CHECKING' },
      { name: 'Shodan', status: 'CHECKING' },
      { name: 'IPinfo', status: 'CHECKING' },
    ];
    const p = healthStats.providers;
    const mapStatus = (val) => {
      if (!val) return 'OFFLINE';
      if (val.includes('enabled')) return 'ACTIVE';
      if (val === 'missing_key') return 'NO KEY';
      return 'OFFLINE';
    };
    return [
      { name: 'AbuseIPDB', status: mapStatus(p.abuseipdb) },
      { name: 'OTX AlienVault', status: mapStatus(p.otx) },
      { name: 'Shodan', status: mapStatus(p.shodan) },
      { name: 'IPinfo', status: mapStatus(p.ipinfo) },
    ];
  }, [healthStats]);

  const liveAiStats = useMemo(() => {
    const total = threats.length;
    const aiThreats = threats.filter((threat) => threat.ai?.used);
    const aiAssistedCount = aiThreats.length;
    const aiCoveragePct = total > 0 ? Math.round((aiAssistedCount / total) * 100) : 0;
    const aiAvgConfidence = aiAssistedCount > 0
      ? Math.round(
        aiThreats.reduce((sum, threat) => sum + clampNumber(threat.ai?.confidence, 0, 100, 0), 0)
        / aiAssistedCount
      )
      : 0;
    const aiOriginCounts = {};
    aiThreats.forEach((threat) => {
      const origin = threat.origin?.country || 'Unknown';
      aiOriginCounts[origin] = (aiOriginCounts[origin] || 0) + 1;
    });

    return {
      total,
      aiAssistedCount,
      aiCoveragePct,
      aiAvgConfidence,
      aiOriginCounts,
    };
  }, [threats]);

  const aiPanelStatus = useMemo(() => {
    const aiHealth = healthStats?.aiProvider || {};
    const selectedMode = String(selectedAiProvider || 'auto').toLowerCase();
    const currentProvider = aiHealth.current ? String(aiHealth.current).toUpperCase() : 'NONE';
    const readiness = String(
      aiHealth.readiness
      || (selectedMode === 'off' ? 'disabled' : currentProvider !== 'NONE' ? 'ready' : 'unknown')
    ).toUpperCase();
    const keys = aiHealth.keys || {};
    const keyLabels = [];
    if (keys.openai) keyLabels.push('OPENAI');
    if (keys.gemini) keyLabels.push('GEMINI');

    return {
      selectedMode,
      selectedLabel: formatAiModeLabel(selectedMode),
      currentProvider,
      readiness,
      keyLabel: keyLabels.length > 0 ? keyLabels.join('+') : 'NONE',
    };
  }, [healthStats, selectedAiProvider]);

  // ── Mode/sim handlers ──
  const handleModeChange = (newMode) => {
    setIsPlaying(false);
    setSimComplete(false);
    setSimulationMode(newMode);
    setFocusedCountry(null);
    setFocusedAttack(null);
    if (newMode === 'simulation') setCurrentStepIndex(0);
  };

  const handleSimChange = (sim) => {
    setCurrentSim(sim);
    setCurrentStepIndex(0);
    setIsPlaying(false);
    setSimComplete(false);
  };

  // ── System time ticker ──
  const [systemTime, setSystemTime] = useState(new Date().toLocaleTimeString());
  useEffect(() => {
    const iv = setInterval(() => setSystemTime(new Date().toLocaleTimeString()), 1000);
    return () => clearInterval(iv);
  }, []);

  // ── Handle AI Provider change ──
  const handleAiProviderChange = (mode) => {
    setSelectedAiProvider(mode);
    setLiveLogs((prev) => [
      `[${new Date().toLocaleTimeString()}] AI Provider mode set to: ${mode}`,
      ...prev
    ].slice(0, 20));
  };

  return (
    <div className="h-screen w-screen relative flex flex-col bg-cyber-bg overflow-hidden select-none">
      {/* Background Effects */}
      <div className="absolute inset-0 cyber-grid pointer-events-none" />
      <div className="scanline pointer-events-none" />

      {/* Header / Mode Switcher */}
      <header className="h-14 border-b border-cyber-blue/10 flex items-center justify-between px-5 z-20 bg-slate-950/45 backdrop-blur-xl shrink-0 relative">
        <div className="flex items-center gap-3.5 w-1/3">
          <div className="w-8 h-8 bg-cyber-blue/10 border border-cyber-blue/25 flex items-center justify-center rounded-lg shadow-[inset_0_1px_0_rgba(173,226,255,0.18)]">
            <Shield className="text-cyber-blue animate-pulse" size={16} />
          </div>
          <div>
            <h1 className="text-[11px] font-semibold tracking-[0.17em] text-slate-100 uppercase font-mono">CyberThreat Visualizer</h1>
            <p className="text-[9px] tracking-[0.12em] text-cyber-blue/65 font-mono">GLOBAL NETWORK SECURITY OPERATIONS CENTER</p>
          </div>
        </div>

        <div className="absolute left-1/2 -translate-x-1/2">
          <div className="glass-chip p-1 flex items-center gap-1.5 shadow-[0_8px_26px_rgba(0,0,0,0.35)]">
            <button
              onClick={() => handleModeChange('live')}
              className={cn(
                "relative px-4 sm:px-5 py-1.5 rounded-full text-[10px] font-semibold uppercase tracking-[0.16em] transition-all font-mono",
                simulationMode === 'live'
                  ? "bg-cyber-blue/20 text-cyber-blue shadow-[0_0_18px_rgba(87,221,255,0.35)]"
                  : "text-cyber-blue/65 hover:text-cyber-blue hover:bg-cyber-blue/10"
              )}
            >
              LIVE MONITORING
              <span className={cn(
                "pointer-events-none absolute left-4 right-4 -bottom-[3px] h-px transition-opacity duration-300",
                simulationMode === 'live' ? "opacity-100 bg-cyber-blue shadow-[0_0_8px_rgba(87,221,255,0.8)]" : "opacity-0"
              )} />
            </button>
            <button
              onClick={() => handleModeChange('simulation')}
              className={cn(
                "relative px-4 sm:px-5 py-1.5 rounded-full text-[10px] font-semibold uppercase tracking-[0.16em] transition-all font-mono",
                simulationMode === 'simulation'
                  ? "bg-cyber-blue/20 text-cyber-blue shadow-[0_0_18px_rgba(87,221,255,0.35)]"
                  : "text-cyber-blue/65 hover:text-cyber-blue hover:bg-cyber-blue/10"
              )}
            >
              SIMULATION MODE
              <span className={cn(
                "pointer-events-none absolute left-4 right-4 -bottom-[3px] h-px transition-opacity duration-300",
                simulationMode === 'simulation' ? "opacity-100 bg-cyber-blue shadow-[0_0_8px_rgba(87,221,255,0.8)]" : "opacity-0"
              )} />
            </button>
          </div>
        </div>

        <div className="flex items-center justify-end gap-5 w-1/3">
          <div className="flex flex-col items-end">
            <span className="text-[9px] tracking-[0.12em] text-slate-500 font-mono">SYSTEM TIME</span>
            <span className="text-[11px] font-semibold text-cyber-blue font-mono">{systemTime}</span>
          </div>
          <div className="w-px h-8 bg-cyber-blue/10" />
          
          {/* AI Provider Selector */}
          <div className="flex items-center gap-2.5 pl-1">
            <label className="text-[9px] tracking-[0.12em] text-slate-500 font-mono uppercase pr-1">AI:</label>
            <div className="relative min-w-[94px]">
              <select
                value={selectedAiProvider}
                onChange={(e) => handleAiProviderChange(e.target.value)}
                className={cn(
                  "pl-3 pr-3 py-1.5 rounded-lg text-[10px] font-semibold font-mono uppercase tracking-[0.12em]",
                  "bg-slate-900/80 border border-cyber-blue/30 transition-all duration-200",
                  "text-cyber-blue cursor-pointer",
                  "hover:border-cyber-blue/60 hover:shadow-[0_0_12px_rgba(87,221,255,0.25)]",
                  "focus:outline-none focus:border-cyber-blue focus:shadow-[0_0_12px_rgba(87,221,255,0.4)]",
                  selectedAiProvider === 'off' && "border-cyber-yellow/50 text-cyber-yellow shadow-[0_0_8px_rgba(254,254,51,0.15)]",
                )}
              >
                <option value="auto">Auto</option>
                <option value="openai">OpenAI</option>
                <option value="gemini">Gemini</option>
                <option value="off">Off</option>
              </select>
            </div>
          </div>
          
          <div className="w-px h-8 bg-cyber-blue/10" />

          {/* AI Threshold Slider */}
          <div className="flex items-center gap-2">
            <div className="flex flex-col items-end">
              <label className="text-[9px] tracking-[0.12em] text-slate-500 font-mono uppercase">AI FALLBACK</label>
              <span className="text-[11px] font-semibold text-cyber-blue font-mono">&lt; {aiThreshold}%</span>
            </div>
            <input 
              type="range" 
              min="0" 
              max="100" 
              value={aiThreshold}
              onChange={(e) => setAiThreshold(Number(e.target.value))}
              className="w-20 h-1 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyber-blue shadow-[0_0_8px_rgba(87,221,255,0.2)]"
            />
          </div>
          
          <div className="w-px h-8 bg-cyber-blue/10" />
          
          <div className="flex items-center gap-2">
            <div className={cn(
              "w-2 h-2 rounded-full animate-pulse",
              dataSource === 'api' ? "bg-cyber-green shadow-[0_0_8px_#00ff41]" : "bg-cyber-yellow shadow-[0_0_8px_#fefe33]"
            )} />
            <span className={cn(
              "text-[10px] font-semibold font-mono uppercase tracking-[0.12em]",
              dataSource === 'api' ? "text-cyber-green" : "text-cyber-yellow"
            )}>
              {dataSource === 'api' ? 'API: Active' : 'API: Offline'}
            </span>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="flex-1 flex overflow-hidden p-3 gap-3 z-10">

        {/* LEFT PANEL */}
        <div className="w-[22%] flex flex-col gap-3 min-w-0">
          {simulationMode === 'live' ? (
            <>
              <CyberPanel title="Live Status" icon={Activity}>
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={cn("w-2 h-2 rounded-full", dataSource === 'api' ? "bg-cyber-green animate-pulse" : "bg-cyber-yellow")} />
                    <span className={cn("text-[10px] font-mono", dataSource === 'api' ? "text-cyber-green" : "text-cyber-yellow")}>
                      {dataSource === 'api' ? 'LIVE API CONNECTED' : 'API OFFLINE'}
                    </span>
                  </div>
                    <span className="text-[9px] tracking-[0.08em] text-slate-500 font-mono">v1.0.0</span>
                </div>
                <p className="text-[9px] text-cyber-blue/60 font-mono mt-1 tracking-[0.08em]">ENDPOINT: /api/threats</p>
                <div className="mt-2 pt-2 border-t border-cyber-blue/10 flex items-center justify-between text-[9px] font-mono">
                  <span className="text-slate-500">
                    AI MODE: <span className="text-cyber-blue">{aiPanelStatus.selectedLabel}</span>
                  </span>
                  <span className={cn(
                    "font-semibold",
                    aiPanelStatus.readiness === 'READY' && "text-cyber-green",
                    (aiPanelStatus.readiness === 'NO_KEYS' || aiPanelStatus.readiness === 'DISABLED') && "text-cyber-yellow",
                    aiPanelStatus.readiness === 'MODE_UNAVAILABLE' && "text-cyber-red",
                    aiPanelStatus.readiness === 'UNKNOWN' && "text-slate-400"
                  )}>
                    {aiPanelStatus.readiness}
                  </span>
                </div>
              </CyberPanel>

              <CyberPanel title="Current Attack" icon={AlertTriangle}>
                {threats[0] ? (
                  <div className="space-y-2.5">
                    <div className="flex justify-between items-start">
                      <span className={cn(
                        "text-xs font-semibold tracking-[0.08em] font-mono",
                        threats[0].type === 'DDoS' ? "text-cyber-red" : threats[0].type === 'Malware' ? "text-cyber-yellow" : "text-cyber-green"
                      )}>
                        {threats[0].type} DETECTED
                      </span>
                      <span className="text-[10px] text-slate-500 font-mono">THREAT SCORE: {getSignalValue(threats[0].score)}/100</span>
                    </div>
                    <p className="text-sm font-semibold text-slate-100 font-mono">
                      {threats[0].origin.country} <span className="text-cyber-blue">→</span> {threats[0].target.country}
                    </p>
                    <p className="text-[10px] text-slate-400 font-mono">SRC IP: {threats[0].origin.ip}</p>
                    {getAiProviderLabel(threats[0].ai) && (
                      <p className="text-[9px] text-slate-500 font-mono">AI PROVIDER: {getAiProviderLabel(threats[0].ai)}</p>
                    )}
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[9px] text-cyber-blue font-mono uppercase">Class: {getClassificationLabel(threats[0].classification)}</span>
                      {hasDegradedData(threats[0].sources) && (
                        <span
                          title={getDegradedDataTooltip(threats[0].sources)}
                          className="px-1.5 py-[2px] rounded border border-amber-400/40 bg-amber-500/10 text-[8px] font-mono uppercase tracking-[0.08em] text-amber-300"
                        >
                          DEGRADED DATA
                        </span>
                      )}
                      <div className="relative group cursor-help">
                        <span className={cn("px-2 py-0.5 rounded-full border text-[8px] font-mono uppercase block", getAiBadgeClass(threats[0].ai))}>
                          {getAiBadgeLabel(threats[0].ai)}
                        </span>
                        {threats[0].ai?.used && threats[0].ai?.reason && (
                          <div className="pointer-events-none absolute bottom-full right-0 mb-1 w-56 p-2 rounded-lg bg-slate-900/95 backdrop-blur border border-cyber-blue/30 text-cyber-blue leading-relaxed shadow-[0_4px_20px_rgba(87,221,255,0.15)] opacity-0 group-hover:opacity-100 transition-opacity z-50">
                            <span className="block text-[8px] text-slate-500 mb-1 font-semibold uppercase tracking-wider">AI Reasoning</span>
                            <span className="text-[9px] lowercase" style={{fontVariant: 'small-caps'}}>{threats[0].ai.reason}</span>
                          </div>
                        )}
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-2 text-[8px] font-mono text-slate-400 pt-1 border-t border-cyber-blue/10">
                      <div className="flex flex-col">
                        <span className="text-slate-500">ABUSE</span>
                        {(() => {
                          const meta = getSignalDisplayMeta(threats[0].signals?.abuseScore, 'abuseipdb', threats[0].sources);
                          return (
                            <span title={meta.tooltip} className={cn(meta.faded && 'text-slate-500 italic')}>
                              {meta.text}
                            </span>
                          );
                        })()}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-slate-500">OTX HITS</span>
                        {(() => {
                          const meta = getSignalDisplayMeta(threats[0].signals?.otxHits, 'otx', threats[0].sources);
                          return (
                            <span title={meta.tooltip} className={cn(meta.faded && 'text-slate-500 italic')}>
                              {meta.text}
                            </span>
                          );
                        })()}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-slate-500">PORTS</span>
                        {(() => {
                          const meta = getSignalDisplayMeta(threats[0].signals?.portExposure, 'shodan', threats[0].sources);
                          return (
                            <span title={meta.tooltip} className={cn(meta.faded && 'text-slate-500 italic')}>
                              {meta.text}
                            </span>
                          );
                        })()}
                      </div>
                      <div className="flex flex-col">
                        <span className="text-slate-500">RULE</span>
                        <span>{getSignalValue(threats[0].signals?.ruleScore)}</span>
                      </div>
                      <div className="flex flex-col">
                        <span className="text-slate-500">AI CONF</span>
                        <span>{threats[0].ai?.used ? `${getSignalValue(threats[0].ai?.confidence)}%` : 'N/A'}</span>
                      </div>
                      <div className="flex flex-col">
                        <span className="text-slate-500">FINAL</span>
                        <span>{getSignalValue(threats[0].signals?.finalScore ?? threats[0].score)}</span>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono italic">Scanning for threats...</p>
                )}
              </CyberPanel>

              <CyberPanel title="Top Threat Origins" icon={BarChart3}>
                <div className="space-y-3.5">
                  {topOrigins.map(([country, count]) => (
                    <div key={country} className="space-y-1.5">
                      <div className="flex justify-between text-[10px] font-mono">
                        <span className="text-slate-300">{country}</span>
                        <div className="flex items-center gap-2">
                          <span className="text-cyber-blue">{count}</span>
                          <span className="text-[8px] text-cyber-blue/75 border border-cyber-blue/20 px-1 py-[1px] rounded">
                            AI {liveAiStats.aiOriginCounts[country] || 0}
                          </span>
                        </div>
                      </div>
                      <div className="h-1.5 bg-cyber-blue/10 rounded-full overflow-hidden">
                        <motion.div
                          initial={{ width: 0 }}
                          animate={{ width: `${(count / (threats.length || 1)) * 100}%` }}
                          className="h-full bg-cyber-blue shadow-[0_0_10px_rgba(87,221,255,0.42)]"
                        />
                      </div>
                    </div>
                  ))}
                </div>
                <p className="text-[9px] text-slate-500 font-mono mt-2 pt-2 border-t border-cyber-blue/10">
                  AI-ASSISTED THREATS: <span className="text-cyber-blue">{liveAiStats.aiAssistedCount}</span>
                </p>
              </CyberPanel>

              <CyberPanel title="Live Stats" icon={Activity}>
                <div className="grid grid-cols-2 gap-2">
                  <Metric label="Total Attacks" value={threats.length} color="blue" />
                  <Metric label="Most Active" value={topOrigins[0]?.[0] || 'N/A'} color="yellow" />
                  <Metric label="Threat Level" value={threatLevel.label} color={threatLevel.color} />
                  <Metric label="Data Source" value={dataSource === 'api' ? 'LIVE' : 'NONE'} color={dataSource === 'api' ? 'green' : 'red'} />
                  <Metric label="AI Coverage" value={`${liveAiStats.aiCoveragePct}%`} color="blue" />
                  <Metric
                    label="AI Avg Conf"
                    value={liveAiStats.aiAssistedCount > 0 ? `${liveAiStats.aiAvgConfidence}%` : 'N/A'}
                    color={liveAiStats.aiAssistedCount > 0 ? 'green' : 'yellow'}
                  />
                </div>
              </CyberPanel>

              <CyberPanel title="Recent Activity Log" icon={Terminal} className="flex-1">
                <div className="mb-2 px-2 py-1 rounded border border-cyber-blue/15 bg-cyber-blue/5 flex items-center justify-between text-[8px] font-mono text-slate-400">
                  <span>AI COVERAGE: <span className="text-cyber-blue">{liveAiStats.aiCoveragePct}%</span></span>
                  <span>PROVIDER: <span className="text-cyber-blue">{aiPanelStatus.currentProvider}</span></span>
                </div>
                <div className="font-mono text-[10px] space-y-1 h-full overflow-y-auto scrollbar-hide">
                  <AnimatePresence mode="popLayout">
                    {liveLogs.map((log, i) => (
                      <motion.div
                        key={log + i}
                        initial={{ opacity: 0, x: -10 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0 }}
                        className="text-cyber-green/80 border-l border-cyber-green/18 pl-2"
                      >
                        {log}
                      </motion.div>
                    ))}
                  </AnimatePresence>
                </div>
              </CyberPanel>

              <CyberPanel title="System Intelligence" icon={Database}>
                <div className="space-y-1">
                  {providerStatus.map((p) => (
                    <div key={p.name} className="flex justify-between items-center bg-black/25 rounded-md px-2.5 py-2 border border-cyber-blue/10">
                      <span className="text-[10px] text-slate-400 font-mono">{p.name}</span>
                      <span className={cn("text-[9px] font-bold", {
                        'text-cyber-green': p.status === 'ACTIVE',
                        'text-cyber-yellow': p.status === 'CHECKING' || p.status === 'NO KEY',
                        'text-cyber-red': p.status === 'OFFLINE',
                      })}>{p.status}</span>
                    </div>
                  ))}
                  <div className="flex justify-between items-center bg-black/25 rounded-md px-2.5 py-2 border border-cyber-blue/10">
                    <span className="text-[10px] text-slate-400 font-mono">AI Engine</span>
                    <span className={cn("text-[9px] font-bold", {
                      'text-cyber-green': aiPanelStatus.readiness === 'READY',
                      'text-cyber-yellow': aiPanelStatus.readiness === 'DISABLED' || aiPanelStatus.readiness === 'NO_KEYS',
                      'text-cyber-red': aiPanelStatus.readiness === 'MODE_UNAVAILABLE',
                      'text-slate-400': aiPanelStatus.readiness === 'UNKNOWN',
                    })}>{aiPanelStatus.readiness}</span>
                  </div>
                  <div className="text-[8px] text-slate-500 font-mono px-1 pt-1">
                    MODE: {aiPanelStatus.selectedLabel} | ACTIVE: {aiPanelStatus.currentProvider} | KEYS: {aiPanelStatus.keyLabel}
                  </div>
                  {healthStats?.usage && (
                    <div className="flex justify-between text-[8px] text-slate-500 font-mono mt-2 pt-2 border-t border-cyber-blue/10">
                      <span>API CALLS: {Object.values(healthStats.usage).reduce((a, b) => a + b, 0)}</span>
                      <span>CACHE: {healthStats.cacheAge ? `${Math.round(healthStats.cacheAge / 1000)}s` : 'N/A'}</span>
                    </div>
                  )}
                </div>
              </CyberPanel>
            </>
          ) : (
            <>
              <CyberPanel title="Scenario Details" icon={GlobeIcon}>
                <div className="flex gap-2 mb-2">
                  <button
                    onClick={() => handleSimChange('wannacry')}
                    className={cn(
                      "flex-1 py-1.5 text-[10px] font-bold font-mono border transition-all",
                      currentSim === 'wannacry' ? "bg-cyber-red/15 border-cyber-red/80 text-cyber-red" : "border-cyber-blue/10 text-slate-500 hover:border-cyber-blue/30"
                    )}
                  >WannaCry</button>
                  <button
                    onClick={() => handleSimChange('mirai')}
                    className={cn(
                      "flex-1 py-1.5 text-[10px] font-bold font-mono border transition-all",
                      currentSim === 'mirai' ? "bg-cyber-blue/15 border-cyber-blue text-cyber-blue" : "border-cyber-blue/10 text-slate-500 hover:border-cyber-blue/30"
                    )}
                  >Mirai</button>
                </div>
                <h2 className="text-lg font-bold text-cyber-blue cyber-glow-blue font-mono mb-2">
                  {currentSim === 'wannacry' ? 'WannaCry Ransomware' : 'Mirai Botnet'}
                </h2>
                {currentStep && (
                  <div className="space-y-2.5">
                    <div className="p-3 bg-cyber-red/10 border border-cyber-red/20 rounded-lg">
                      <span className="text-[10px] font-bold text-cyber-red uppercase mb-1 block">Estimated Impact</span>
                      <p className="text-sm font-bold text-white font-mono">{currentStep.impactStat}</p>
                    </div>
                    {currentStep.focusRegion?.primary && (
                      <div className="p-2.5 bg-cyber-blue/10 border border-cyber-blue/20 rounded-lg">
                        <span className="text-[10px] font-bold text-cyber-blue uppercase block">Primary Globe Focus</span>
                        <p className="text-xs font-semibold text-white font-mono mt-1">{currentStep.focusRegion.primary}</p>
                        <p className="text-[10px] text-slate-300 mt-1 leading-relaxed">{currentStep.focusRegion.why}</p>
                      </div>
                    )}
                  </div>
                )}
              </CyberPanel>

              <CyberPanel title="Technical Insight" icon={Terminal}>
                {currentStep ? (
                  <div className="space-y-3.5">
                    <div>
                      <span className="text-[10px] text-slate-500 uppercase font-mono">Phase: {currentStep.title}</span>
                      <p className="text-xs text-slate-300 mt-1 leading-relaxed">{currentStep.description}</p>
                    </div>

                    <div className="p-2.5 bg-cyber-blue/8 border border-cyber-blue/15 rounded-lg">
                      <span className="text-[10px] text-cyber-blue font-mono block mb-1 uppercase">On The Globe</span>
                      <p className="text-[10px] text-slate-200 leading-relaxed">
                        {currentStep.visualPattern || 'Watch the highlighted routes to follow how this phase unfolds geographically.'}
                      </p>
                      {currentStep.arcNarrativeSummary && (
                        <p className="text-[10px] text-slate-300 mt-1 leading-relaxed">
                          {currentStep.arcNarrativeSummary}
                        </p>
                      )}
                      {currentStep.intensityMeaning && (
                        <p className="text-[10px] text-cyber-yellow mt-1 leading-relaxed">
                          Intensity meaning: {currentStep.intensityMeaning}
                        </p>
                      )}
                    </div>

                    <div className="p-2.5 bg-black/30 border border-cyber-blue/10 rounded-lg">
                      <span className="text-[10px] text-cyber-blue font-mono block mb-1">KEY TECH (SIMPLIFIED):</span>
                      <p className="text-[10px] text-cyber-green font-mono leading-tight">{currentStep.technicalInsight}</p>
                    </div>

                    {Array.isArray(currentStep.exploitBreakdown) && currentStep.exploitBreakdown.length > 0 && (
                      <div className="p-2.5 bg-black/25 border border-cyber-blue/10 rounded-lg">
                        <span className="text-[10px] text-cyber-blue font-mono block mb-1 uppercase">How It Works</span>
                        <ul className="space-y-1">
                          {currentStep.exploitBreakdown.map((item, idx) => (
                            <li key={`${currentStep.id}-exploit-${idx}`} className="text-[10px] text-slate-300 leading-relaxed">
                              • {item}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    {currentStep.analystTakeaway && (
                      <div className="p-2.5 bg-cyber-yellow/8 border border-cyber-yellow/20 rounded-lg">
                        <span className="text-[10px] text-cyber-yellow font-mono block mb-1 uppercase">Analyst Takeaway</span>
                        <p className="text-[10px] text-slate-200 leading-relaxed">{currentStep.analystTakeaway}</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-slate-500 font-mono italic">No active phase data...</p>
                )}
              </CyberPanel>

              <CyberPanel title="Countries Involved" icon={Activity} className="flex-1">
                <div className="flex flex-wrap gap-2">
                  {currentStep?.affectedRegions?.map(c => (
                    <span key={c} className="px-2.5 py-1 bg-cyber-blue/10 border border-cyber-blue/20 rounded-full text-[10px] font-mono text-cyber-blue">
                      {c}
                    </span>
                  ))}
                </div>
              </CyberPanel>
            </>
          )}
        </div>

        {/* CENTER PANEL */}
        <div className="flex-1 flex flex-col gap-3 relative min-w-0">
          {/* Top Overlay */}
          <div className="absolute top-4 left-1/2 -translate-x-1/2 z-20 flex flex-col items-center pointer-events-none">
            <div className={cn(
              "px-6 py-2.5 border rounded-xl backdrop-blur-lg flex flex-col items-center transition-all duration-500 bg-slate-950/45",
              threatLevel.color === 'red' ? "border-cyber-red/60 shadow-[0_0_22px_rgba(255,95,102,0.18)]" :
              threatLevel.color === 'yellow' ? "border-cyber-yellow/65 shadow-[0_0_20px_rgba(246,204,99,0.2)]" :
              "border-cyber-blue/65 shadow-[0_0_22px_rgba(87,221,255,0.22)]"
            )}>
              <span className={cn(
                "text-[10px] font-semibold tracking-[0.24em] font-mono",
                threatLevel.color === 'red' ? "text-cyber-red" : threatLevel.color === 'yellow' ? "text-cyber-yellow" : "text-cyber-blue"
              )}>
                THREAT LEVEL: {threatLevel.label}
              </span>
              <span className="text-xl font-semibold text-slate-100 font-mono mt-0.5">
                {threats.length} <span className="text-[9px] text-slate-500 tracking-normal">ACTIVE THREATS</span>
              </span>
              {simulationMode === 'live' && (
                <span className="text-[9px] text-slate-400 font-mono mt-0.5 tracking-[0.08em]">
                  AI COVERAGE: <span className="text-cyber-blue">{liveAiStats.aiCoveragePct}%</span> |
                  MODE: <span className="text-cyber-blue">{aiPanelStatus.selectedLabel}</span>
                </span>
              )}
            </div>
          </div>

          {/* Globe Container */}
          <div className="flex-1 relative overflow-hidden bg-transparent">
            <GlobeView
              attacks={filteredAttacks}
              currentStep={currentStep}
              highlightedCountries={highlightedCountries}
              currentSim={currentSim}
              isPlaying={isPlaying}
              onCountryClick={(country) => {
                setFocusedCountry(country?.name || null);
                setFocusedAttack(null);
              }}
              onAttackClick={(attack) => {
                setFocusedCountry(null);
                setFocusedAttack(attack || null);
                if (attack) {
                  setSelectedThreat(toNewThreat(attack));
                  setReportModalOpen(true);
                }
              }}
              selectedCountry={focusedCountry}
              selectedAttack={focusedAttack}
            />
          </div>

          {/* Simulation complete overlay */}
          {simComplete && simulationMode === 'simulation' && (
            <div className="absolute inset-0 z-30 flex items-center justify-center bg-black/70 backdrop-blur-sm">
              <div className="text-center p-8 border border-cyber-blue/25 rounded-xl bg-slate-950/70 max-w-md">
                <h2 className="text-xl font-bold text-cyber-blue font-mono mb-2 cyber-glow-blue">
                  SIMULATION COMPLETE
                </h2>
                <p className="text-sm text-slate-400 mb-4">
                  {currentSim === 'wannacry' ? 'WannaCry' : 'Mirai'} scenario completed — {activeSteps.length} phases analyzed
                </p>
                <div className="flex gap-3 justify-center">
                  <button
                    onClick={() => { setCurrentStepIndex(0); setSimComplete(false); setIsPlaying(false); }}
                    className="px-4 py-2 rounded-full bg-cyber-blue text-black text-[10px] font-semibold font-mono uppercase"
                  >Restart</button>
                  <button
                    onClick={() => { handleSimChange(currentSim === 'wannacry' ? 'mirai' : 'wannacry'); }}
                    className="px-4 py-2 rounded-full border border-cyber-blue/35 text-cyber-blue text-[10px] font-semibold font-mono uppercase"
                  >Switch Scenario</button>
                </div>
              </div>
            </div>
          )}

          {/* Bottom Analytics */}
          <div className="shrink-0 h-auto sm:h-36 flex flex-col sm:flex-row gap-3">
            <div className="sm:w-[70%] cyber-panel p-3 flex flex-col min-h-[9rem] sm:min-h-0">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <BarChart3 size={14} className="text-cyber-blue" />
                  <span className="text-[10px] font-semibold text-cyber-blue uppercase tracking-[0.15em] font-mono">Attack Rate Timeline (Last 30s)</span>
                </div>
                <div className="flex gap-4 text-[10px] font-mono">
                  <div className="flex items-center gap-1"><div className="w-2 h-2 bg-cyber-red" /><span className="text-slate-500">DDoS</span></div>
                  <div className="flex items-center gap-1"><div className="w-2 h-2 bg-cyber-yellow" /><span className="text-slate-500">MALWARE</span></div>
                  <div className="flex items-center gap-1"><div className="w-2 h-2 bg-cyber-green" /><span className="text-slate-500">SCAN</span></div>
                  {simulationMode === 'live' && (
                    <div className="flex items-center gap-1 text-cyber-blue">
                      <Cpu size={10} />
                      <span>{liveAiStats.aiCoveragePct}% AI</span>
                    </div>
                  )}
                </div>
              </div>
              <div className="flex-1 w-full min-h-0">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={timelineData} margin={{ top: 5, right: 5, left: -25, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="2 2" stroke="#00f3ff" opacity={0.1} vertical={false} />
                    <XAxis dataKey="time" stroke="#00f3ff" opacity={0.5} tick={{ fill: '#00f3ff', fontSize: 8 }} tickMargin={5} />
                    <YAxis allowDecimals={false} stroke="#00f3ff" opacity={0.5} tick={{ fill: '#00f3ff', fontSize: 8 }} />
                    <Tooltip
                      contentStyle={{ backgroundColor: '#050d17', border: '1px solid rgba(87,221,255,0.55)', fontSize: '10px', fontFamily: 'Rajdhani' }}
                      cursor={{ fill: 'rgba(0, 243, 255, 0.1)' }}
                      formatter={(value) => [value, 'Attacks']}
                      labelStyle={{ color: '#aaa' }}
                    />
                    <Bar dataKey="count" animationDuration={300}>
                      {timelineData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} fillOpacity={0.8} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            <div className="sm:w-[30%] cyber-panel p-3 flex flex-col min-h-[9rem] sm:min-h-0">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Activity size={14} className="text-cyber-blue" />
                  <span className="text-[10px] font-semibold text-cyber-blue uppercase tracking-[0.15em] font-mono">Attack Distribution</span>
                </div>
                <span className="text-[9px] text-slate-500 font-mono">{totalDistributionAttacks} total</span>
              </div>

              <div className="flex-1 w-full min-h-0">
                {totalDistributionAttacks === 0 ? (
                  <div className="h-full flex items-center justify-center text-[10px] text-slate-500 font-mono uppercase tracking-[0.12em]">
                    No active attacks
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie
                        data={attackDistributionData.filter((item) => item.value > 0)}
                        dataKey="value"
                        nameKey="name"
                        innerRadius={24}
                        outerRadius={50}
                        paddingAngle={2}
                        stroke="rgba(5, 13, 23, 0.85)"
                        strokeWidth={1}
                      >
                        {attackDistributionData.filter((item) => item.value > 0).map((entry) => (
                          <Cell key={`dist-${entry.name}`} fill={entry.color} style={{ filter: `drop-shadow(0 0 5px ${entry.color})` }} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{ backgroundColor: '#050d17', border: '1px solid rgba(87,221,255,0.55)', fontSize: '10px', fontFamily: 'Rajdhani' }}
                        formatter={(value, name, item) => {
                          const pct = item?.payload?.percentage ?? 0;
                          return [`${value} (${pct}%)`, name];
                        }}
                        labelStyle={{ color: '#aaa' }}
                      />
                      <Legend
                        verticalAlign="bottom"
                        height={18}
                        iconType="circle"
                        formatter={(value) => (
                          <span className="text-[9px] text-slate-400 font-mono tracking-[0.08em]">{value}</span>
                        )}
                      />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </div>
            </div>
          </div>
        </div>

        {/* RIGHT PANEL */}
        <div className="w-[22%] flex flex-col gap-3 min-w-0">
          {simulationMode === 'live' ? (
            (() => {
              // Sort threats by highest score first
              const sortedThreats = [...threats].sort((a, b) => (b.score || 0) - (a.score || 0));
              const criticalThreats = sortedThreats.filter(t => t.score >= 75);
              const highThreats = sortedThreats.filter(t => t.score >= 50 && t.score < 75);
              const lowThreats = sortedThreats.filter(t => t.score < 50);
              const activeCount = sortedThreats.length;

              const getScoreColor = (score) => {
                if (score >= 70) return { bar: '#ff4757', glow: 'rgba(255,71,87,0.6)', text: 'text-red-400', bg: 'bg-red-500' };
                if (score >= 30) return { bar: '#ffb142', glow: 'rgba(255,177,66,0.5)', text: 'text-amber-400', bg: 'bg-amber-500' };
                return { bar: '#2ed573', glow: 'rgba(46,213,115,0.4)', text: 'text-emerald-400', bg: 'bg-emerald-500' };
              };

              const getTypeBadgeStyle = (type) => {
                if (type === 'DDoS') return { bg: 'rgba(255,71,87,0.15)', border: 'rgba(255,71,87,0.5)', color: '#ff4757', label: 'DDOS' };
                if (type === 'Malware') return { bg: 'rgba(255,177,66,0.15)', border: 'rgba(255,177,66,0.5)', color: '#ffb142', label: 'MALWARE' };
                return { bg: 'rgba(46,213,115,0.15)', border: 'rgba(46,213,115,0.5)', color: '#2ed573', label: 'SCAN' };
              };

              const getTypeAccentBorder = (type) => {
                if (type === 'DDoS') return '#ff4757';
                if (type === 'Malware') return '#ffb142';
                return '#2ed573';
              };

              const getSeverityLabel = (score) => {
                if (score >= 75) return { label: 'CRITICAL', color: '#ff4757' };
                if (score >= 50) return { label: 'HIGH', color: '#ffb142' };
                if (score >= 30) return { label: 'MED', color: '#f6cc63' };
                return { label: 'LOW', color: '#2ed573' };
              };

              const renderThreatCard = (threat, index) => {
                const isHovered = threat.id === highlightedThreatId;
                const scoreColor = getScoreColor(threat.score);
                const typeBadge = getTypeBadgeStyle(threat.type);
                const severity = getSeverityLabel(threat.score);
                const accentBorder = getTypeAccentBorder(threat.type);
                const scoreVal = clampNumber(threat.score, 0, 100, 0);
                const degradedData = hasDegradedData(threat.sources);
                const degradedTooltip = getDegradedDataTooltip(threat.sources);
                const timeLabel = threat.timestamp.toLocaleTimeString([], {
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                  hour12: false,
                });

                return (
                  <motion.div
                    key={threat.id}
                    initial={{ opacity: 0, x: 20 }}
                    animate={{ opacity: 1, x: 0 }}
                    exit={{ opacity: 0, scale: 0.95 }}
                    transition={{ duration: 0.25 }}
                    onMouseEnter={() => setHighlightedThreatId(threat.id)}
                    onMouseLeave={() => setHighlightedThreatId(null)}
                    onClick={() => setHighlightedThreatId(threat.id === highlightedThreatId ? null : threat.id)}
                    className="cursor-crosshair"
                    style={{
                      transform: isHovered ? 'scale(1.02)' : 'scale(1)',
                      transition: 'transform 0.2s ease, box-shadow 0.2s ease',
                    }}
                  >
                    <div
                      className="rounded-lg overflow-hidden transition-all duration-200"
                      style={{
                        background: isHovered ? 'rgba(87,221,255,0.06)' : 'rgba(0,0,0,0.25)',
                        border: `1px solid ${isHovered ? 'rgba(87,221,255,0.25)' : 'rgba(87,221,255,0.08)'}`,
                        borderLeft: `3px solid ${accentBorder}`,
                        boxShadow: isHovered
                          ? `0 0 ${12 + (scoreVal / 100) * 20}px ${scoreColor.glow}, inset 0 1px 0 rgba(255,255,255,0.04)`
                          : `0 0 ${4 + (scoreVal / 100) * 8}px ${scoreColor.glow.replace(/[\d.]+\)$/, '0.15)')}, inset 0 1px 0 rgba(255,255,255,0.02)`,
                      }}
                    >
                      <div className="px-2.5 py-2">
                        {/* Top Row: Attack Type Badge + Timestamp */}
                        <div className="flex items-center justify-between mb-1.5">
                          <div
                            className="px-1.5 py-[1px] rounded text-[8px] font-bold font-mono uppercase tracking-wider"
                            style={{
                              background: typeBadge.bg,
                              border: `1px solid ${typeBadge.border}`,
                              color: typeBadge.color,
                              textShadow: `0 0 8px ${typeBadge.color}`,
                            }}
                          >
                            {typeBadge.label}
                          </div>
                          <span className="text-[8px] text-slate-500 font-mono tracking-wider">{timeLabel}</span>
                        </div>

                        {/* Middle Row: Countries + IP */}
                        <p className="text-[11px] font-bold text-slate-100 font-mono leading-tight tracking-wide">
                          {threat.origin.country}
                          <span className="text-cyber-blue mx-1" style={{ textShadow: '0 0 6px rgba(87,221,255,0.6)' }}>→</span>
                          {threat.target.country}
                        </p>
                        <p className="text-[8px] text-slate-500 font-mono mt-0.5 tracking-wider" style={{ fontFamily: "'Courier New', monospace" }}>
                          {threat.origin.ip}
                        </p>

                        {/* Bottom Row: Score Bar + Classification + AI Badge */}
                        <div className="flex items-center gap-2 mt-1.5">
                          {/* Score Bar */}
                          <div className="flex-1 flex items-center gap-1.5">
                            <span className={cn("text-[9px] font-bold font-mono tabular-nums", scoreColor.text)}>
                              {getSignalValue(threat.score)}
                            </span>
                            <div className="flex-1 h-[4px] bg-slate-800/80 rounded-full overflow-hidden relative">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${scoreVal}%` }}
                                transition={{ duration: 0.6, ease: 'easeOut' }}
                                className="h-full rounded-full"
                                style={{
                                  background: `linear-gradient(90deg, ${scoreColor.bar}88, ${scoreColor.bar})`,
                                  boxShadow: `0 0 6px ${scoreColor.glow}`,
                                }}
                              />
                            </div>
                          </div>

                          {/* Classification Label */}
                          <span
                            className="text-[7px] font-bold font-mono uppercase tracking-wider px-1 py-[1px] rounded"
                            style={{
                              color: severity.color,
                              background: `${severity.color}18`,
                              border: `1px solid ${severity.color}40`,
                            }}
                          >
                            {severity.label}
                          </span>

                          {/* AI/RULE Badge */}
                          <span
                            className="text-[7px] font-bold font-mono uppercase tracking-wider px-1 py-[1px] rounded"
                            style={{
                              color: threat.ai?.used ? '#57ddff' : '#64748b',
                              background: threat.ai?.used ? 'rgba(87,221,255,0.1)' : 'rgba(100,116,139,0.1)',
                              border: `1px solid ${threat.ai?.used ? 'rgba(87,221,255,0.3)' : 'rgba(100,116,139,0.2)'}`,
                            }}
                          >
                            {threat.ai?.used ? `AI ${getSignalValue(threat.ai?.confidence)}%` : 'RULE'}
                          </span>

                          {degradedData && (
                            <span
                              title={degradedTooltip}
                              className="text-[7px] font-bold font-mono uppercase tracking-wider px-1 py-[1px] rounded border border-amber-400/40 bg-amber-500/10 text-amber-300"
                            >
                              DEGRADED DATA
                            </span>
                          )}

                          {/* Report Button */}
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedThreat(threat);
                              setReportModalOpen(true);
                            }}
                            className="ml-1 p-1 rounded hover:bg-slate-700/50 transition-colors group"
                            title="View detailed report"
                          >
                            <AlertTriangle className="w-3.5 h-3.5 text-amber-400 group-hover:text-amber-300" />
                          </button>
                        </div>
                      </div>

                      {/* Hover Expand: Signal Breakdown */}
                      <AnimatePresence>
                        {isHovered && (
                          <motion.div
                            initial={{ height: 0, opacity: 0 }}
                            animate={{ height: 'auto', opacity: 1 }}
                            exit={{ height: 0, opacity: 0 }}
                            transition={{ duration: 0.2 }}
                            className="overflow-hidden"
                          >
                            <div className="px-2.5 pb-2 pt-1.5 border-t border-slate-700/40">
                              {degradedData && (
                                <div className="mb-1.5 text-[7px] font-mono uppercase tracking-[0.08em] text-amber-300" title={degradedTooltip}>
                                  DEGRADED DATA: {degradedTooltip}
                                </div>
                              )}
                              <div className="grid grid-cols-3 gap-x-2 gap-y-1">
                                {(() => {
                                  const abuseMeta = getSignalDisplayMeta(threat.signals?.abuseScore, 'abuseipdb', threat.sources);
                                  const otxMeta = getSignalDisplayMeta(threat.signals?.otxHits, 'otx', threat.sources);
                                  const portsMeta = getSignalDisplayMeta(threat.signals?.portExposure, 'shodan', threat.sources);

                                  return [
                                    { label: 'ABUSE', value: abuseMeta.text, color: '#ff4757', faded: abuseMeta.faded, tooltip: abuseMeta.tooltip },
                                    { label: 'OTX', value: otxMeta.text, color: '#57ddff', faded: otxMeta.faded, tooltip: otxMeta.tooltip },
                                    { label: 'PORTS', value: portsMeta.text, color: '#2ed573', faded: portsMeta.faded, tooltip: portsMeta.tooltip },
                                    { label: 'RULE', value: getSignalValue(threat.signals?.ruleScore), color: '#f6cc63', faded: false, tooltip: '' },
                                    { label: 'FINAL', value: getSignalValue(threat.signals?.finalScore ?? threat.score), color: '#ff9ff3', faded: false, tooltip: '' },
                                    { label: 'AI CONF', value: threat.ai?.used ? `${getSignalValue(threat.ai?.confidence)}%` : 'N/A', color: '#57ddff', faded: false, tooltip: '' },
                                  ];
                                })().map((sig) => (
                                  <div key={sig.label} className="flex flex-col">
                                    <span className="text-[7px] text-slate-600 font-mono uppercase tracking-wider">{sig.label}</span>
                                    <span
                                      title={sig.tooltip}
                                      className="text-[9px] font-semibold font-mono"
                                      style={{ color: sig.faded || sig.value === 'N/A' ? '#475569' : sig.color }}
                                    >
                                      {sig.value}
                                    </span>
                                  </div>
                                ))}
                              </div>
                              {threat.ai?.used && threat.ai?.reason && (
                                <div className="mt-1.5 pt-1.5 border-t border-slate-700/30">
                                  <span className="text-[7px] text-slate-600 font-mono uppercase tracking-wider block mb-0.5">AI REASONING</span>
                                  <p className="text-[8px] text-cyber-blue/80 font-mono leading-relaxed">{threat.ai.reason}</p>
                                </div>
                              )}
                              {getAiProviderLabel(threat.ai) && (
                                <span className="text-[7px] text-slate-600 font-mono mt-1 block">
                                  PROVIDER: <span className="text-slate-400">{getAiProviderLabel(threat.ai)}</span>
                                </span>
                              )}
                            </div>
                          </motion.div>
                        )}
                      </AnimatePresence>
                    </div>
                  </motion.div>
                );
              };

              const renderSectionLabel = (label, count, color, key) => (
                <motion.div 
                  key={key}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-2 py-1"
                >
                  <div className="w-1.5 h-1.5 rounded-full" style={{ background: color, boxShadow: `0 0 6px ${color}` }} />
                  <span className="text-[8px] font-bold font-mono uppercase tracking-[0.2em]" style={{ color }}>{label}</span>
                  <span className="text-[8px] font-mono text-slate-600">({count})</span>
                  <div className="flex-1 h-px" style={{ background: `linear-gradient(90deg, ${color}30, transparent)` }} />
                </motion.div>
              );

              return (
                <>
                  <div className="cyber-panel p-1.5 flex gap-1.5 shrink-0">
                    {['All', 'DDoS', 'Malware', 'Scan'].map((tab) => {
                      const isActive = filter === tab;
                      let activeClass = "border-cyber-blue text-cyber-blue bg-cyber-blue/10";
                      if (tab === 'DDoS') activeClass = "border-cyber-red text-cyber-red bg-cyber-red/10";
                      if (tab === 'Malware') activeClass = "border-cyber-yellow text-cyber-yellow bg-cyber-yellow/10";
                      if (tab === 'Scan') activeClass = "border-cyber-green text-cyber-green bg-cyber-green/10";

                      return (
                        <button
                          key={tab}
                          onClick={() => setFilter(tab)}
                          className={cn(
                            "flex-1 py-1 text-[10px] font-bold font-mono border-b-2 transition-all duration-200 rounded-t",
                            isActive 
                              ? activeClass
                              : "border-transparent text-slate-500 hover:text-slate-300 hover:bg-slate-800/50"
                          )}
                        >
                          {tab}
                        </button>
                      );
                    })}
                  </div>

                  <div className="flex-1 flex flex-col cyber-panel overflow-hidden">
                    {/* SOC-style Header */}
                  <div className="px-3.5 py-2.5 border-b border-cyber-blue/10 shrink-0">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Activity size={13} className="text-cyber-blue/90" />
                        <h3 className="text-[10px] font-semibold uppercase tracking-[0.18em] text-cyber-blue/80 font-mono">
                          Live Threat Feed
                        </h3>
                        <div className="relative flex items-center justify-center w-2 h-2">
                          <div className="absolute inset-0 bg-cyber-green rounded-full animate-ping opacity-40" />
                          <div className="w-1.5 h-1.5 bg-cyber-green rounded-full shadow-[0_0_6px_#42dca3]" />
                        </div>
                      </div>
                      <span className="text-[9px] font-mono text-slate-500">
                        <span className="text-cyber-blue font-semibold">{sortedThreats.length}</span> total
                      </span>
                    </div>
                    <div className="flex items-center gap-3 mt-1.5">
                      <div className="flex items-center gap-1.5 px-2 py-0.5 rounded bg-cyber-blue/8 border border-cyber-blue/15">
                        <Zap size={9} className="text-cyber-blue" />
                        <span className="text-[8px] font-mono text-cyber-blue font-semibold">{activeCount} Active</span>
                      </div>
                      <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-cyber-blue/10 border border-cyber-blue/25">
                        <Cpu size={8} className="text-cyber-blue" />
                        <span className="text-[8px] font-mono text-cyber-blue font-semibold">
                          AI {liveAiStats.aiCoveragePct}%
                        </span>
                      </div>
                      {criticalThreats.length > 0 && (
                        <div className="flex items-center gap-1 px-2 py-0.5 rounded bg-red-500/10 border border-red-500/25">
                          <AlertTriangle size={8} className="text-red-400" />
                          <span className="text-[8px] font-mono text-red-400 font-semibold">{criticalThreats.length} Critical</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Scrollable Feed */}
                  <div className="flex-1 overflow-y-auto px-2 py-1.5 space-y-1.5 scrollbar-hide">
                    <AnimatePresence>
                      {criticalThreats.length > 0 && renderSectionLabel('CRITICAL', criticalThreats.length, '#ff4757', 'lbl-critical')}
                      {criticalThreats.map((threat, i) => renderThreatCard(threat, i))}
                      {highThreats.length > 0 && renderSectionLabel('HIGH', highThreats.length, '#ffb142', 'lbl-high')}
                      {highThreats.map((threat, i) => renderThreatCard(threat, i))}
                      {lowThreats.length > 0 && renderSectionLabel('LOW', lowThreats.length, '#2ed573', 'lbl-low')}
                      {lowThreats.map((threat, i) => renderThreatCard(threat, i))}
                    </AnimatePresence>
                  </div>
                </div>
              </>
            );
          })()
          ) : (
            <>
              <CyberPanel title="Simulation Controls" icon={Zap}>
                <div className="space-y-3">
                  <div className="flex items-center justify-center gap-4">
                    <button
                      onClick={() => setCurrentStepIndex(prev => Math.max(0, prev - 1))}
                      className="p-2.5 hover:bg-cyber-blue/10 border border-cyber-blue/20 rounded-lg text-cyber-blue transition-colors"
                    >
                      <SkipBack size={16} />
                    </button>
                    <button
                      onClick={() => { setIsPlaying(!isPlaying); if (simComplete) { setSimComplete(false); setCurrentStepIndex(0); } }}
                      className="w-12 h-12 flex items-center justify-center bg-cyber-blue text-black rounded-full hover:shadow-[0_0_15px_rgba(87,221,255,0.55)] transition-all"
                    >
                      {isPlaying ? <Pause size={24} /> : <Play size={24} className="ml-1" />}
                    </button>
                    <button
                      onClick={() => {
                        const next = Math.min(activeSteps.length - 1, currentStepIndex + 1);
                        if (next === currentStepIndex && currentStepIndex === activeSteps.length - 1) setSimComplete(true);
                        setCurrentStepIndex(next);
                      }}
                      className="p-2.5 hover:bg-cyber-blue/10 border border-cyber-blue/20 rounded-lg text-cyber-blue transition-colors"
                    >
                      <SkipForward size={16} />
                    </button>
                  </div>

                  <div className="space-y-2">
                    <div className="flex justify-between text-[10px] font-mono">
                      <span className="text-slate-500">SPEED</span>
                      <span className="text-cyber-blue">{simulationSpeed}X</span>
                    </div>
                    <div className="flex gap-1">
                      {[1, 2, 5].map(s => (
                        <button
                          key={s}
                          onClick={() => setSimulationSpeed(s)}
                          className={cn(
                            "flex-1 py-1 text-[10px] font-mono border transition-all",
                            simulationSpeed === s ? "bg-cyber-blue/20 border-cyber-blue text-cyber-blue" : "border-cyber-blue/10 text-slate-500 hover:border-cyber-blue/30"
                          )}
                        >{s}X</button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-cyber-blue/10">
                    <div className="flex justify-between text-[10px] font-mono">
                      <span className="text-slate-500">PROGRESS</span>
                      <span className="text-cyber-blue">STEP {currentStepIndex + 1} OF {activeSteps.length}</span>
                    </div>
                    <div className="h-1 bg-cyber-blue/10 rounded-full overflow-hidden">
                      <motion.div
                        animate={{ width: `${((currentStepIndex + 1) / activeSteps.length) * 100}%` }}
                        className="h-full bg-cyber-blue"
                      />
                    </div>
                  </div>
                </div>
              </CyberPanel>

              <CyberPanel title="Simulated Events" icon={Terminal} className="flex-1">
                <div className="space-y-3 h-full overflow-y-auto pr-2 scrollbar-hide">
                  {activeSteps.slice(0, currentStepIndex + 1).reverse().map((step) => (
                    <div key={step.id} className="p-2.5 border border-cyber-blue/10 bg-black/25 rounded-lg">
                      <div className="flex justify-between items-center mb-1">
                        <span className="text-[10px] font-bold text-cyber-blue font-mono">PHASE {step.id}</span>
                        <span className="text-[9px] text-slate-500 font-mono">COMPLETED</span>
                      </div>
                      <p className="text-[10px] text-slate-300 font-mono leading-tight">{step.title}</p>
                    </div>
                  ))}
                </div>
              </CyberPanel>
            </>
          )}
        </div>
      </main>

      {/* Footer / Status Bar */}
      <footer className="h-7 border-t border-cyber-blue/10 bg-slate-950/50 backdrop-blur-md flex items-center justify-between px-5 z-20 shrink-0">
        <div className="flex items-center gap-4 text-[9px] font-mono text-slate-500">
          <div className="flex items-center gap-1">
            <Wifi size={10} className="text-cyber-green" />
            <span>CONNECTION: SECURE</span>
          </div>
          <div className="flex items-center gap-1">
            <Database size={10} className="text-cyber-blue" />
            <span>BACKEND: {dataSource === 'api' ? 'CONNECTED' : 'OFFLINE'}</span>
          </div>
        </div>
        <div className="flex items-center gap-4 text-[9px] font-mono text-slate-500">
          <span>ATTACKS: {currentAttacks.length} | MODE: {simulationMode.toUpperCase()}</span>
          <div className="flex items-center gap-1">
            <Clock size={10} />
            <span>UTC: {new Date().toISOString().slice(0, 19)}</span>
          </div>
        </div>
      </footer>

      {/* Threat Report Modal */}
      <ThreatReportModal
        threat={selectedThreat}
        isOpen={reportModalOpen}
        aiProvider={selectedAiProvider}
        onClose={() => {
          setReportModalOpen(false);
          setSelectedThreat(null);
        }}
      />
    </div>
  );
};

export default App;
