import React from 'react';
import { MoonIcon, SunIcon } from '@phosphor-icons/react';
import { IconButton, LiveDot, Tabs } from './ui';
import { useNow } from '../hooks/useNow';
import { cn } from '../lib/utils';

const MODE_OPTIONS = [
  { value: 'live', label: 'Live' },
  { value: 'simulation', label: 'Simulation' },
];

const AI_OPTIONS = [
  { value: 'auto', label: 'Auto' },
  { value: 'gemini', label: 'Gemini' },
  { value: 'openai', label: 'OpenAI' },
  { value: 'off', label: 'Off (rules only)' },
];

const STATUS_META = {
  connecting: { label: 'Connecting', live: false, tone: 'text-ink-mute' },
  live: { label: 'Live', live: true, tone: 'text-ink' },
  degraded: { label: 'Limited data', live: true, tone: 'text-high' },
  offline: { label: 'Offline', live: false, tone: 'text-crit' },
  simulation: { label: 'Replay', live: false, tone: 'text-ink-mute' },
};

const dateline = new Intl.DateTimeFormat('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });

const Clock = () => {
  const now = new Date(useNow(1000));
  return (
    <p className="hidden items-baseline gap-2 lg:flex">
      <span className="text-xs text-ink-mute">{dateline.format(now)}</span>
      <time dateTime={now.toISOString()} className="text-[13px] font-medium tabular text-ink">
        {now.toISOString().slice(11, 19)} UTC
      </time>
    </p>
  );
};

export const ConnectionStatus = ({ status, className }) => {
  const meta = STATUS_META[status] || STATUS_META.connecting;
  return (
    <span role="status" className={cn('inline-flex items-center gap-2 text-[13px] font-semibold', meta.tone, className)}>
      <LiveDot active={meta.live} />
      <span className="max-sm:sr-only">{meta.label}</span>
    </span>
  );
};

const Header = ({ mode, onModeChange, provider, onProviderChange, status, theme, onToggleTheme }) => (
  <header className="shrink-0 border-b-[3px] border-double border-ink px-4 sm:px-5">
    <div className="flex h-14 items-center gap-4 sm:gap-8">
      <h1 className="condensed shrink-0 text-[23px] leading-none sm:text-[26px] font-extrabold tracking-[-0.01em] text-ink">
        Threat Globe
      </h1>

      <Tabs label="Data mode" options={MODE_OPTIONS} value={mode} onChange={onModeChange} bare className="self-stretch [&>button]:pt-4" />

      <div className="ml-auto flex items-center gap-2 sm:gap-5">
        <Clock />
        <label className="hidden items-center gap-2 text-xs text-ink-mute md:flex">
          AI classifier
          <select
            value={provider}
            onChange={(event) => onProviderChange(event.target.value)}
            className="h-7 border border-rule bg-paper px-1.5 text-[13px] text-ink transition-colors hover:border-ink"
          >
            {AI_OPTIONS.map((option) => (
              <option key={option.value} value={option.value}>{option.label}</option>
            ))}
          </select>
        </label>
        <ConnectionStatus status={status} />
        <IconButton label={theme === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'} onClick={onToggleTheme}>
          {theme === 'dark' ? <SunIcon size={17} /> : <MoonIcon size={17} />}
        </IconButton>
      </div>
    </div>
  </header>
);

export { AI_OPTIONS };
export default Header;
