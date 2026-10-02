import React from 'react';
import { StatusDot } from './ui';
import { useNow } from '../hooks/useNow';

const formatAge = (ms) => {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 5) return 'just now';
  if (seconds < 60) return `${seconds}s ago`;
  return `${Math.round(seconds / 60)}m ago`;
};

const Field = ({ label, children }) => (
  <span className="flex items-center gap-2 border-l border-line pl-3 first:border-l-0 first:pl-0">
    <span className="text-ink-faint">{label}</span>
    <span className="text-ink-muted">{children}</span>
  </span>
);

const StatusBar = ({ mode, status, lastUpdated, meta, count }) => {
  const now = useNow();
  const live = mode === 'live';
  const linkTone = live ? (status === 'offline' ? 'crit' : status === 'live' ? 'ok' : 'warn') : 'info';

  return (
    <footer className="hidden h-8 shrink-0 items-center justify-between gap-4 border-t border-line bg-canvas/95 px-5 font-mono text-[11px] uppercase tracking-wider md:flex">
      <div className="flex min-w-0 items-center gap-3">
        <StatusDot tone={linkTone} />
        {live ? (
          <>
            <Field label="Link">{status === 'offline' ? 'Disconnected' : status}</Field>
            <Field label="Sync">{lastUpdated ? formatAge(now - lastUpdated) : 'Pending'}</Field>
            {meta.cached && status !== 'offline' && <Field label="Source">Cache</Field>}
          </>
        ) : (
          <Field label="Feed">Synthetic replay</Field>
        )}
      </div>
      <Field label="Tracks">{String(count).padStart(2, '0')}</Field>
    </footer>
  );
};

export default StatusBar;
