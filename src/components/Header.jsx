import React, { useEffect, useState } from 'react';
import { Radio, PlayCircle } from 'lucide-react';
import { Segmented, StatusDot } from './ui';
import { cn } from '../lib/utils';

const MODE_OPTIONS = [
  { value: 'live', label: 'Live', icon: Radio },
  { value: 'simulation', label: 'Simulation', icon: PlayCircle },
];

const AI_OPTIONS = [
  { value: 'auto', label: 'Auto' },
  { value: 'gemini', label: 'Gemini' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'off', label: 'Off (rules only)' },
];

const STATUS_META = {
  connecting: { label: 'Connecting', tone: 'warn', pulse: true },
  live: { label: 'Live', tone: 'ok', pulse: true },
  degraded: { label: 'Limited data', tone: 'warn', pulse: false },
  offline: { label: 'Offline', tone: 'crit', pulse: false },
  simulation: { label: 'Simulation', tone: 'info', pulse: false },
};

const Clock = () => {
  const [now, setNow] = useState(() => new Date());
  useEffect(() => {
    const timer = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(timer);
  }, []);
  return (
    <div className="hidden flex-col items-end leading-none lg:flex">
      <span className="readout text-[10px]!">{now.toISOString().slice(0, 10)}</span>
      <time dateTime={now.toISOString()} className="mt-1 font-mono text-sm tabular text-ink">
        {now.toISOString().slice(11, 19)}<span className="ml-1 text-ink-faint">UTC</span>
      </time>
    </div>
  );
};

export const ConnectionPill = ({ status, className }) => {
  const meta = STATUS_META[status] || STATUS_META.connecting;
  return (
    <span
      role="status"
      className={cn('inline-flex items-center gap-2 border border-line-strong bg-canvas px-2.5 py-1 font-mono text-xs uppercase tracking-wider text-ink', className)}
    >
      <StatusDot tone={meta.tone} pulse={meta.pulse} />
      {meta.label}
    </span>
  );
};

/** Wordmark glyph: a scope reticle with one hostile contact. */
const Mark = () => (
  <span className="hud grid size-9 shrink-0 place-items-center border border-line-strong bg-canvas" aria-hidden="true">
    <svg viewBox="0 0 24 24" className="size-6" fill="none" strokeWidth="1.2">
      <circle cx="12" cy="12" r="9" stroke="#253957" />
      <circle cx="12" cy="12" r="5" stroke="#253957" />
      <path d="M12 1.5v4M12 18.5v4M1.5 12h4M18.5 12h4" stroke="#5cf2e6" />
      <path d="M12 12 18.4 5.6" stroke="#5cf2e6" strokeOpacity="0.6" />
      <rect x="15.4" y="6.1" width="3" height="3" transform="rotate(45 16.9 7.6)" fill="#ff3d6e" />
    </svg>
  </span>
);

const Header = ({ mode, onModeChange, provider, onProviderChange, status }) => (
  <header className="relative flex h-16 shrink-0 items-center justify-between gap-3 border-b border-line bg-canvas/95 px-3 sm:px-5">
    <div className="flex min-w-0 items-center gap-3">
      <Mark />
      <div className="min-w-0 leading-tight">
        <h1 className="sr-only truncate text-lg font-bold uppercase tracking-[0.14em] text-ink sm:not-sr-only">
          Threat<span className="text-info">/</span>Globe
        </h1>
        <p className="readout hidden truncate sm:block">OSINT intercept console</p>
      </div>
    </div>

    <Segmented label="Data mode" options={MODE_OPTIONS} value={mode} onChange={onModeChange} size="sm" />

    <div className="flex items-center justify-end gap-3 sm:gap-4">
      <label className="hidden items-center gap-2 md:flex">
        <span className="readout">AI classifier</span>
        <select
          value={provider}
          onChange={(event) => onProviderChange(event.target.value)}
          className="border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink transition-colors hover:border-info/60"
        >
          {AI_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
      </label>
      <span className="hidden h-8 w-px bg-line lg:block" aria-hidden="true" />
      <Clock />
      <ConnectionPill status={status} className="hidden sm:inline-flex" />
      <span className="sm:hidden"><StatusDot tone={(STATUS_META[status] || STATUS_META.connecting).tone} /></span>
    </div>

    {/* Hazard strip under the command bar. */}
    <span className="hatch pointer-events-none absolute inset-x-0 -bottom-[5px] h-1 opacity-60" aria-hidden="true" />
  </header>
);

export { AI_OPTIONS };
export default Header;
