import React, { useMemo } from 'react';
import { AnimatePresence } from 'motion/react';
import { ArrowClockwiseIcon } from '@phosphor-icons/react';
import ThreatCard from './ThreatCard';
import { Button, EmptyState, Section, Skeleton, Tabs } from './ui';
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
    <Section
      title="Threat feed"
      className={className}
      bodyClassName="flex min-h-0 flex-1 flex-col"
      action={<span className="text-xs text-ink-mute tabular" aria-live="polite">{visible.length} shown, by score</span>}
    >
      <div className="scroll-thin overflow-x-auto">
        <Tabs label="Filter by severity" options={options} value={filter} onChange={onFilterChange} />
      </div>

      <div className="scroll-thin -mr-2 min-h-0 flex-1 overflow-y-auto pr-2">
        {connecting && (
          <ul className="divide-y divide-rule" aria-label="Loading threats">
            {[0, 1, 2, 3, 4].map((i) => (
              <li key={i} className="grid grid-cols-[3rem_1fr] gap-3 px-2 py-3">
                <Skeleton className="h-8" />
                <div className="space-y-1.5"><Skeleton className="h-4 w-2/3" /><Skeleton className="h-3 w-1/2" /></div>
              </li>
            ))}
          </ul>
        )}

        {offlineEmpty && (
          <EmptyState
            title="Cannot reach the API"
            action={(
              <Button onClick={onRetry}>
                <ArrowClockwiseIcon size={13} aria-hidden="true" /> Retry now
              </Button>
            )}
          >
            Start the server with <code className="font-mono text-ink">npm start</code> in <code className="font-mono text-ink">server/</code>.
          </EmptyState>
        )}

        {!connecting && !offlineEmpty && visible.length === 0 && (
          <EmptyState title={filter === 'ALL' ? 'No threats yet' : 'Nothing in this category'}>
            {filter === 'ALL' ? 'New threats appear after the next refresh.' : 'Try a different severity filter.'}
          </EmptyState>
        )}

        {visible.length > 0 && (
          <ul className="divide-y divide-rule" aria-label="Threats">
            <AnimatePresence initial={false}>
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
            </AnimatePresence>
          </ul>
        )}
      </div>
    </Section>
  );
};

export default ThreatFeed;
