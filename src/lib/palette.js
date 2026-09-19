// Single source of truth for threat colours and tones. Tailwind needs literal class names,
// so tone classes are spelled out here rather than composed at runtime.

export const CLASS_META = {
  DDOS: { key: 'DDOS', label: 'DDoS', severity: 'Critical', color: '#ff6b6b', tone: 'crit', rank: 3 },
  MALWARE: { key: 'MALWARE', label: 'Malware', severity: 'High', color: '#ffb454', tone: 'warn', rank: 2 },
  SCAN: { key: 'SCAN', label: 'Scan', severity: 'Medium', color: '#5fd4a0', tone: 'ok', rank: 1 },
  LOW: { key: 'LOW', label: 'Low risk', severity: 'Low', color: '#8f9ab3', tone: 'low', rank: 0 },
};

export const CLASS_ORDER = ['DDOS', 'MALWARE', 'SCAN', 'LOW'];

export const classMeta = (classification) =>
  CLASS_META[String(classification || '').toUpperCase()] || CLASS_META.LOW;

export const TONE = {
  crit: { text: 'text-crit', soft: 'bg-crit/10', border: 'border-crit/30', solid: 'bg-crit', rule: 'border-l-crit' },
  warn: { text: 'text-warn', soft: 'bg-warn/10', border: 'border-warn/30', solid: 'bg-warn', rule: 'border-l-warn' },
  ok: { text: 'text-ok', soft: 'bg-ok/10', border: 'border-ok/30', solid: 'bg-ok', rule: 'border-l-ok' },
  info: { text: 'text-info', soft: 'bg-info/10', border: 'border-info/30', solid: 'bg-info', rule: 'border-l-info' },
  ai: { text: 'text-ai', soft: 'bg-ai/10', border: 'border-ai/30', solid: 'bg-ai', rule: 'border-l-ai' },
  low: { text: 'text-low', soft: 'bg-low/10', border: 'border-low/30', solid: 'bg-low', rule: 'border-l-low' },
  neutral: { text: 'text-ink-muted', soft: 'bg-raised', border: 'border-line', solid: 'bg-ink-faint', rule: 'border-l-line-strong' },
};

export const toneFor = (classification) => TONE[classMeta(classification).tone];

// Hex → rgba string for canvas / WebGL consumers.
export const withAlpha = (hex, alpha = 1) => {
  const match = /^#([a-f\d]{6})$/i.exec(String(hex || ''));
  if (!match) return `rgba(143,154,179,${alpha})`;
  const value = match[1];
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
};
