import React, { useMemo } from 'react';
import { Radar, RefreshCw, WifiOff } from 'lucide-react';
import ThreatCard from './ThreatCard';
import { EmptyState, Panel, Segmented, Skeleton } from './ui';
import { CLASS_META } from '../lib/palette';

export const FILTER_OPTIONS = [
  { value: 'ALL', label: 'All' },
  { value: 'DDOS', label: CLASS_META.DDOS.severity },
  { value: 'MALWARE', label: CLASS_META.MALWARE.severity },
  { value: 'SCAN', label: CLASS_META.SCAN.severity },
  { value: 'LOW', label: CLASS_META.LOW.severity },
];

const ThreatFeed = ({
  threats,
  status,
  filter,
  onFilterChange,
  selectedId,
  hoveredId,
  analysisStates,
  onSelect,
  onHover,
  onReport,
  onAnalyze,
  onRetry,
  className,
}) => {
  const counts = useMemo(() => {
    const result = { ALL: threats.length, DDOS: 0, MALWARE: 0, SCAN: 0, LOW: 0 };
    threats.forEach((threat) => {
      const key = String(threat.classification || 'LOW').toUpperCase();
      if (key in result) result[key] += 1;
    });
    return result;
  }, [threats]);

  const visible = useMemo(() => {
    const filtered = filter === 'ALL' ? threats : threats.filter((t) => String(t.classification).toUpperCase() === filter);
    return [...filtered].sort((a, b) => (b.score || 0) - (a.score || 0));
  }, [threats, filter]);

  const options = FILTER_OPTIONS.map((option) => ({ ...option, count: counts[option.value] }));
  const connecting = status === 'connecting' && threats.length === 0;
  const offlineEmpty = status === 'offline' && threats.length === 0;

  return (
    <Panel
      title="Threat feed"
      icon={Radar}
      className={className}
      bodyClassName="flex min-h-0 flex-1 flex-col gap-3 pb-3!"
      action={<span className="text-xs tabular text-ink-muted" aria-live="polite">{visible.length} shown</span>}
    >
      <div className="-mx-1 overflow-x-auto px-1 scroll-thin">
        <Segmented label="Filter by severity" options={options} value={filter} onChange={onFilterChange} size="sm" />
      </div>

      <div className="scroll-thin -mr-2 min-h-0 flex-1 overflow-y-auto pr-2">
        {connecting && (
          <ul className="space-y-2" aria-label="Loading threats">
            {[0, 1, 2, 3].map((i) => <li key={i}><Skeleton className="h-[108px]" /></li>)}
          </ul>
        )}

        {offlineEmpty && (
          <EmptyState
            icon={WifiOff}
            title="Cannot reach the API"
            action={(
              <button
                type="button"
                onClick={onRetry}
                className="mt-1 inline-flex items-center gap-1.5 rounded-lg border border-line bg-raised px-3 py-1.5 text-xs font-medium text-ink hover:border-line-strong"
              >
                <RefreshCw size={12} aria-hidden="true" /> Retry now
              </button>
            )}
          >
            Start the server with <code className="font-mono text-ink">npm start</code> in <code className="font-mono text-ink">server/</code>.
          </EmptyState>
        )}

        {!connecting && !offlineEmpty && visible.length === 0 && (
          <EmptyState icon={Radar} title={filter === 'ALL' ? 'No threats yet' : 'Nothing in this category'}>
            {filter === 'ALL'
              ? 'New threats appear after the next refresh.'
              : 'Try a different severity filter.'}
          </EmptyState>
        )}

        {visible.length > 0 && (
          <ul className="space-y-2" aria-label="Threats">
            {visible.map((threat) => (
              <ThreatCard
                key={threat.id}
                threat={threat}
                selected={threat.id === selectedId}
                hovered={threat.id === hoveredId}
                analysis={analysisStates[threat.id]}
                onSelect={onSelect}
                onHover={onHover}
                onReport={onReport}
                onAnalyze={onAnalyze}
              />
            ))}
          </ul>
        )}
      </div>
    </Panel>
  );
};

export default ThreatFeed;
