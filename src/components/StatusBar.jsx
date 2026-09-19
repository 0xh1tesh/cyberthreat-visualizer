import React from 'react';
import { StatusDot } from './ui';
import { useNow } from '../hooks/useNow';

const formatAge = (ms) => {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.round(seconds / 60)}m ago`;
};

const StatusBar = ({ mode, status, lastUpdated, meta, count }) => {
  const now = useNow();
  const live = mode === 'live';

  return (
    <footer className="hidden h-8 shrink-0 items-center justify-between gap-4 border-t border-line px-5 text-xs text-ink-muted md:flex">
      <div className="flex min-w-0 items-center gap-2">
        <StatusDot tone={live ? (status === 'offline' ? 'crit' : status === 'live' ? 'ok' : 'warn') : 'info'} />
        {live ? (
          <span className="truncate">
            {status === 'offline' ? 'Disconnected' : lastUpdated ? `Updated ${formatAge(now - lastUpdated)}` : 'Waiting for first update'}
            {meta.cached && status !== 'offline' ? ' · served from cache' : ''}
          </span>
        ) : (
          <span>Simulation · synthetic data</span>
        )}
      </div>
      <span className="tabular">{count} {count === 1 ? 'threat' : 'threats'} on screen</span>
    </footer>
  );
};

export default StatusBar;
