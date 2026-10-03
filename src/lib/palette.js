// Single source of truth for threat classes. Severity is ordinal, so the four classes share one
// vermilion hue stepped from light (low) to dark (critical); validated per mode for monotone
// lightness and a visible light end. Tailwind needs literal class names, so they are spelled out.

export const CLASS_META = {
  DDOS: { key: 'DDOS', label: 'DDoS', severity: 'Critical', tone: 'crit', rank: 3, color: '#a62407' },
  MALWARE: { key: 'MALWARE', label: 'Malware', severity: 'High', tone: 'high', rank: 2, color: '#c6442b' },
  SCAN: { key: 'SCAN', label: 'Scan', severity: 'Medium', tone: 'med', rank: 1, color: '#d4705b' },
  LOW: { key: 'LOW', label: 'Low risk', severity: 'Low', tone: 'low', rank: 0, color: '#d79b8e' },
};

export const CLASS_ORDER = ['DDOS', 'MALWARE', 'SCAN', 'LOW'];

export const classMeta = (classification) =>
  CLASS_META[String(classification || '').toUpperCase()] || CLASS_META.LOW;

export const SEVERITY_BG = { crit: 'bg-crit', high: 'bg-high', med: 'bg-med', low: 'bg-low' };

// Mirrors the CSS tokens in global.css for canvas / SVG / WebGL consumers that cannot read them.
export const THEMES = {
  light: {
    paper: '#f3f3f0', ink: '#161615', inkSoft: '#55554f', inkMute: '#6b6b65', rule: '#d6d6d0',
    sea: '#e2e3df', land: '#f9f9f6', coast: 'rgba(22,22,21,0.42)', grid: 'rgba(22,22,21,0.08)',
    crit: '#a62407', high: '#c6442b', med: '#d4705b', low: '#d79b8e',
  },
  dark: {
    paper: '#141413', ink: '#ecebe6', inkSoft: '#b3b2ab', inkMute: '#8e8d86', rule: '#33332f',
    sea: '#1a1a18', land: '#272725', coast: 'rgba(236,235,230,0.34)', grid: 'rgba(236,235,230,0.07)',
    crit: '#ff9077', high: '#ef755c', med: '#c76c58', low: '#91655b',
  },
};

export const classColor = (classification, colors) => colors[classMeta(classification).tone];

// Hex → rgba string for canvas / WebGL consumers.
export const withAlpha = (hex, alpha = 1) => {
  const match = /^#([a-f\d]{6})$/i.exec(String(hex || ''));
  if (!match) return `rgba(124,124,118,${alpha})`;
  const value = match[1];
  const r = parseInt(value.slice(0, 2), 16);
  const g = parseInt(value.slice(2, 4), 16);
  const b = parseInt(value.slice(4, 6), 16);
  return `rgba(${r},${g},${b},${alpha})`;
};
