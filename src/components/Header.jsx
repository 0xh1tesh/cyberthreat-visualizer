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
    <time dateTime={now.toISOString()} className="hidden font-mono text-xs tabular text-ink-muted lg:block">
      {now.toISOString().slice(11, 19)} UTC
    </time>
  );
};

export const ConnectionPill = ({ status, className }) => {
  const meta = STATUS_META[status] || STATUS_META.connecting;
  return (
    <span
      role="status"
      className={cn('inline-flex items-center gap-2 rounded-full border border-line bg-surface px-3 py-1 text-xs font-medium text-ink', className)}
    >
      <StatusDot tone={meta.tone} pulse={meta.pulse} />
      {meta.label}
    </span>
  );
};

const Header = ({ mode, onModeChange, provider, onProviderChange, status }) => (
  <header className="flex h-14 shrink-0 items-center justify-between gap-3 border-b border-line bg-canvas px-3 sm:px-5">
    <div className="flex min-w-0 items-center gap-3">
      <span className="grid size-8 shrink-0 place-items-center rounded-lg border border-line bg-surface" aria-hidden="true">
        <svg viewBox="0 0 24 24" className="size-[18px]" fill="none" stroke="currentColor" strokeWidth="1.6">
          <circle cx="12" cy="12" r="8" className="text-ink-muted" />
          <path d="M4 12h16M12 4c2.6 2.4 2.6 13.6 0 16M12 4c-2.6 2.4-2.6 13.6 0 16" className="text-ink-faint" />
          <circle cx="18" cy="6" r="2.4" fill="#ff6b6b" stroke="none" />
        </svg>
      </span>
      <div className="min-w-0 leading-tight">
        <h1 className="truncate text-sm font-semibold text-ink">Threat Globe</h1>
        <p className="hidden truncate text-2xs text-ink-muted sm:block">Open-source threat intelligence</p>
      </div>
    </div>

    <Segmented
      label="Data mode"
      options={MODE_OPTIONS}
      value={mode}
      onChange={onModeChange}
      size="sm"
    />

    <div className="flex items-center justify-end gap-2.5 sm:gap-3.5">
      <label className="hidden items-center gap-2 text-xs text-ink-muted md:flex">
        <span>AI classifier</span>
        <select
          value={provider}
          onChange={(event) => onProviderChange(event.target.value)}
          className="rounded-lg border border-line bg-surface px-2.5 py-1.5 text-xs text-ink transition-colors hover:border-line-strong"
        >
          {AI_OPTIONS.map((option) => (
            <option key={option.value} value={option.value}>{option.label}</option>
          ))}
        </select>
      </label>
      <Clock />
      <ConnectionPill status={status} className="hidden sm:inline-flex" />
      <span className="sm:hidden"><StatusDot tone={(STATUS_META[status] || STATUS_META.connecting).tone} /></span>
    </div>
  </header>
);

export { AI_OPTIONS };
export default Header;
