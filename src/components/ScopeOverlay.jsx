import React from 'react';
import { CHROME } from '../lib/palette';

const C = 100;
const polar = (r, deg) => {
  const rad = ((deg - 90) * Math.PI) / 180;
  return [C + r * Math.cos(rad), C + r * Math.sin(rad)];
};

// Static geometry, computed once: a bearing ring with 5° minor and 30° major graduations.
const TICKS = Array.from({ length: 72 }, (_, i) => {
  const deg = i * 5;
  const major = deg % 30 === 0;
  const [x1, y1] = polar(96, deg);
  const [x2, y2] = polar(major ? 92 : 94.4, deg);
  return { deg, major, x1, y1, x2, y2 };
});

const LABELS = TICKS.filter((tick) => tick.major).map(({ deg }) => {
  const [x, y] = polar(88.6, deg);
  return { deg, x, y, text: String(deg).padStart(3, '0') };
});

/** Decorative scope bezel drawn around the globe. Sized to the stage's shorter side. */
const ScopeOverlay = () => (
  <svg
    viewBox="0 0 200 200"
    aria-hidden="true"
    className="pointer-events-none absolute top-1/2 left-1/2 aspect-square -translate-x-1/2 -translate-y-1/2"
    style={{ width: 'min(96cqw, 96cqh)' }}
  >
    <circle cx={C} cy={C} r="96" fill="none" stroke={CHROME.lineStrong} strokeWidth="0.35" />
    <circle cx={C} cy={C} r="98.6" fill="none" stroke={CHROME.line} strokeWidth="0.3" strokeDasharray="0.6 1.4" />
    {TICKS.map((tick) => (
      <line
        key={tick.deg}
        x1={tick.x1}
        y1={tick.y1}
        x2={tick.x2}
        y2={tick.y2}
        stroke={tick.major ? CHROME.info : CHROME.lineStrong}
        strokeOpacity={tick.major ? 0.75 : 1}
        strokeWidth={tick.major ? 0.45 : 0.3}
      />
    ))}
    {LABELS.map((label) => (
      <text
        key={label.deg}
        x={label.x}
        y={label.y}
        fill={CHROME.inkFaint}
        fontSize="3"
        fontFamily="JetBrains Mono Variable, monospace"
        textAnchor="middle"
        dominantBaseline="central"
      >
        {label.text}
      </text>
    ))}
    {/* Cardinal crosshair stubs crossing the ring. */}
    {[0, 90, 180, 270].map((deg) => {
      const [x1, y1] = polar(100, deg);
      const [x2, y2] = polar(90.8, deg);
      return <line key={deg} x1={x1} y1={y1} x2={x2} y2={y2} stroke={CHROME.info} strokeWidth="0.5" />;
    })}
  </svg>
);

export default ScopeOverlay;
