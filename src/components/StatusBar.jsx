import React from 'react';
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

  let note = 'Synthetic replay of a historical incident.';
  if (live && status === 'offline') note = 'Disconnected from the API.';
  else if (live) {
    note = lastUpdated ? `Updated ${formatAge(now - lastUpdated)}.` : 'Waiting for the first refresh.';
    if (meta.cached) note += ' Served from cache.';
  }

  return (
    <footer className="hidden h-8 shrink-0 items-center justify-between gap-4 border-t border-rule px-5 text-xs text-ink-mute md:flex">
      <p className="truncate">{note}</p>
      <p className="shrink-0 tabular">{count} {count === 1 ? 'route' : 'routes'} on the globe</p>
    </footer>
  );
};

export default StatusBar;
