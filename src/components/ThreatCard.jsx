import React, { memo } from 'react';
import { motion } from 'motion/react';
import { CircleNotchIcon } from '@phosphor-icons/react';
import { Button, Swatch, Tag } from './ui';
import { cn } from '../lib/utils';
import { classMeta } from '../lib/palette';
import {
  getAiProviderLabel,
  getSignalDisplayMeta,
  getSignalValue,
  hasDegradedData,
  getDegradedDataTooltip,
} from '../lib/threat-normalize';

const timeFormat = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };

const SignalCell = ({ label, meta }) => (
  <div title={meta.tooltip || undefined} className="min-w-0">
    <dt className="text-[11.5px] text-ink-mute">{label}</dt>
    <dd className={cn('condensed text-xl font-semibold tabular', meta.faded ? 'text-ink-mute' : 'text-ink')}>{meta.text}</dd>
  </div>
);

const ThreatCard = ({
  threat,
  selected,
  hovered,
  analysis,
  onSelect,
  onHover,
  onReport,
  onAnalyze,
}) => {
  const meta = classMeta(threat.classification);
  const partial = !threat.synthetic && hasDegradedData(threat.sources) && threat.score >= 50;
  const loading = analysis?.status === 'loading';
  const coolingDown = Number(analysis?.cooldownUntil || 0) > 0;
  const canAnalyze = Boolean(threat.origin.ip) && !threat.synthetic;
  const aiLabel = getAiProviderLabel(threat.ai);
  const abuse = getSignalDisplayMeta(threat.signals?.abuseScore, 'abuseipdb', threat.sources);
  const otx = getSignalDisplayMeta(threat.signals?.otxHits, 'otx', threat.sources);
  const ports = getSignalDisplayMeta(threat.signals?.portExposure, 'shodan', threat.sources);
  const city = threat.sourceCity && threat.sourceCity !== 'Unknown' ? threat.sourceCity : null;

  return (
    <motion.li
      layout="position"
      initial={{ opacity: 0, y: -6 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0 }}
      transition={{ type: 'spring', stiffness: 380, damping: 34 }}
      onMouseEnter={() => onHover(threat.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(threat.id)}
      onBlur={() => onHover(null)}
      className={cn('transition-colors duration-150', selected ? 'bg-wash' : hovered && 'bg-wash/55')}
    >
      <button
        type="button"
        onClick={() => onSelect(threat.id)}
        aria-expanded={selected}
        className="grid w-full grid-cols-[3rem_minmax(0,1fr)_auto] items-start gap-x-3 px-2 py-2.5 text-left"
      >
        <span className={cn('condensed text-[30px] leading-8 font-semibold tabular', meta.rank === 3 ? 'text-crit' : 'text-ink')}>
          {getSignalValue(threat.score)}
        </span>
        <span className="min-w-0">
          <span className="block truncate text-[14.5px] leading-5 font-semibold text-ink">{threat.origin.country}</span>
          <span className="mt-0.5 flex min-w-0 items-baseline gap-2 text-xs text-ink-mute">
            <span className="truncate font-mono text-[11.5px] text-ink-soft">{threat.origin.ip || 'IP unavailable'}</span>
            {city && <span className="truncate">{city}</span>}
          </span>
        </span>
        <span className="flex flex-col items-end gap-1 pt-0.5">
          <span className="inline-flex items-center gap-1.5 text-[12.5px] text-ink">
            <Swatch classification={threat.classification} />
            {meta.label}
          </span>
          <time className="text-[11.5px] tabular text-ink-mute" dateTime={threat.timestamp.toISOString()}>
            {threat.timestamp.toLocaleTimeString([], timeFormat)}
          </time>
        </span>
      </button>

      {(threat.synthetic || threat.source === 'SEED' || partial) && (
        <div className="-mt-1 flex flex-wrap gap-1.5 pr-2 pb-2.5 pl-[4.25rem]">
          {threat.synthetic && <Tag>Simulated</Tag>}
          {threat.source === 'SEED' && <Tag tone="alert" title="Fallback sample IP, not from the live blacklist">Sample</Tag>}
          {partial && <Tag tone="alert" title={getDegradedDataTooltip(threat.sources)}>Partial data</Tag>}
        </div>
      )}

      {selected && (
        <div className="space-y-3 pr-2 pb-3 pl-[4.25rem]">
          <dl className="grid grid-cols-3 divide-x divide-rule border-y border-rule py-2 [&>div]:px-3 [&>div:first-child]:pl-0">
            <SignalCell label="Abuse score" meta={abuse} />
            <SignalCell label="OTX hits" meta={otx} />
            <SignalCell label="Open ports" meta={ports} />
          </dl>

          <p className="text-[12.5px] leading-5 text-ink-soft">
            {threat.ai?.used
              ? <>Classified by {aiLabel || 'the AI model'} at {getSignalValue(threat.ai.confidence)}% confidence.{threat.ai.reason ? ` ${threat.ai.reason}` : ''}</>
              : 'Classified by the rule engine.'}
          </p>

          {analysis?.status === 'done' && analysis.result && (
            <p className="border-l-2 border-ink pl-3 text-[12.5px] leading-5 text-ink">
              <span className="font-semibold">
                Manual analysis: {classMeta(analysis.result.type).label}, {Math.round(analysis.result.confidence)}% ({analysis.result.provider})
              </span>
              {analysis.result.reasoning && <span className="block text-ink-soft">{analysis.result.reasoning}</span>}
            </p>
          )}
          {analysis?.status === 'error' && (
            <p role="alert" className="text-[12.5px] text-crit">{analysis.error}</p>
          )}

          <div className="flex gap-2">
            <Button variant="solid" onClick={() => onReport(threat)}>Open report</Button>
            {canAnalyze && (
              <Button onClick={() => onAnalyze(threat)} disabled={loading || coolingDown}>
                {loading && <CircleNotchIcon size={13} className="animate-spin" aria-hidden="true" />}
                {loading ? 'Analyzing' : 'Run AI analysis'}
              </Button>
            )}
          </div>
        </div>
      )}
    </motion.li>
  );
};

export default memo(ThreatCard);
