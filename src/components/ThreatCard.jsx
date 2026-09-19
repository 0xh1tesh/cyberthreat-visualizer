import React, { memo } from 'react';
import { FileText, Loader2, Sparkles } from 'lucide-react';
import { Badge } from './ui';
import { cn } from '../lib/utils';
import { classMeta, toneFor, TONE } from '../lib/palette';
import {
  getAiProviderLabel,
  getSignalDisplayMeta,
  getSignalValue,
  hasDegradedData,
  getDegradedDataTooltip,
} from '../lib/threat-normalize';

const timeFormat = { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false };

const SignalCell = ({ label, meta }) => (
  <div title={meta.tooltip || undefined}>
    <dt className="text-2xs uppercase tracking-wide text-ink-faint">{label}</dt>
    <dd className={cn('text-[13px] font-medium tabular', meta.faded ? 'text-ink-faint' : 'text-ink')}>{meta.text}</dd>
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
  const tone = toneFor(threat.classification);
  const partial = !threat.synthetic && hasDegradedData(threat.sources) && threat.score >= 50;
  const loading = analysis?.status === 'loading';
  const coolingDown = Number(analysis?.cooldownUntil || 0) > 0;
  const canAnalyze = Boolean(threat.origin.ip) && !threat.synthetic;
  const aiLabel = getAiProviderLabel(threat.ai);
  const abuse = getSignalDisplayMeta(threat.signals?.abuseScore, 'abuseipdb', threat.sources);
  const otx = getSignalDisplayMeta(threat.signals?.otxHits, 'otx', threat.sources);
  const ports = getSignalDisplayMeta(threat.signals?.portExposure, 'shodan', threat.sources);

  return (
    <li
      onMouseEnter={() => onHover(threat.id)}
      onMouseLeave={() => onHover(null)}
      onFocus={() => onHover(threat.id)}
      onBlur={() => onHover(null)}
      className={cn(
        'animate-fade-up rounded-lg border border-l-2 bg-surface transition-colors duration-150',
        tone.rule,
        selected || hovered ? 'border-line-strong bg-raised' : 'border-line',
      )}
    >
      <button
        type="button"
        onClick={() => onSelect(threat.id)}
        aria-expanded={selected}
        className="w-full rounded-t-lg p-3 text-left"
      >
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <Badge tone={meta.tone}>{meta.label}</Badge>
              <time className="text-2xs tabular text-ink-faint" dateTime={threat.timestamp.toISOString()}>
                {threat.timestamp.toLocaleTimeString([], timeFormat)}
              </time>
              {threat.synthetic && <Badge tone="info">Simulated</Badge>}
              {threat.source === 'SEED' && <Badge tone="warn" title="Fallback sample IP, not from the live blacklist">Sample</Badge>}
            </div>
            <p className="mt-1.5 truncate text-sm font-medium text-ink">{threat.origin.country}</p>
            <p className="truncate font-mono text-xs text-ink-muted">
              {threat.origin.ip || 'IP unavailable'}
              {threat.sourceCity && threat.sourceCity !== 'Unknown' ? ` · ${threat.sourceCity}` : ''}
            </p>
          </div>
          <div className="shrink-0 text-right">
            <p className={cn('text-xl font-semibold leading-6 tabular', tone.text)}>{getSignalValue(threat.score)}</p>
            <p className="text-2xs text-ink-faint">of 100</p>
          </div>
        </div>
      </button>

      <div className="flex items-center gap-1.5 border-t border-line px-3 py-2">
        {threat.ai?.used ? (
          <Badge tone="ai" title={aiLabel ? `Classified by ${aiLabel}` : 'AI-assisted'}>
            <Sparkles size={11} aria-hidden="true" />
            AI {getSignalValue(threat.ai.confidence)}%
          </Badge>
        ) : (
          <Badge tone="neutral" title="Classified by the rule engine">Rules</Badge>
        )}
        {partial && <Badge tone="warn" title={getDegradedDataTooltip(threat.sources)}>Partial data</Badge>}
        <span className="flex-1" />
        {canAnalyze && (
          <button
            type="button"
            onClick={() => onAnalyze(threat)}
            disabled={loading || coolingDown}
            className="inline-flex items-center gap-1.5 rounded-md border border-line px-2 py-1 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:text-ink disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? <Loader2 size={12} className="animate-spin" aria-hidden="true" /> : <Sparkles size={12} aria-hidden="true" />}
            {loading ? 'Analyzing' : 'Analyze'}
          </button>
        )}
        <button
          type="button"
          onClick={() => onReport(threat)}
          className="inline-flex items-center gap-1.5 rounded-md border border-line px-2 py-1 text-xs font-medium text-ink-muted transition-colors hover:border-line-strong hover:text-ink"
        >
          <FileText size={12} aria-hidden="true" />
          Report
        </button>
      </div>

      {selected && (
        <div className="space-y-3 border-t border-line px-3 py-3">
          <dl className="grid grid-cols-3 gap-3">
            <SignalCell label="Abuse" meta={abuse} />
            <SignalCell label="OTX hits" meta={otx} />
            <SignalCell label="Open ports" meta={ports} />
          </dl>
          {threat.ai?.used && threat.ai.reason && (
            <p className="text-xs leading-5 text-ink-muted">
              <span className={cn('font-medium', TONE.ai.text)}>{aiLabel || 'AI'} · </span>
              {threat.ai.reason}
            </p>
          )}
          {analysis?.status === 'done' && analysis.result && (
            <div className={cn('rounded-md border p-2.5 text-xs leading-5', TONE.ai.border, TONE.ai.soft)}>
              <p className="font-medium text-ink">
                Manual analysis: {classMeta(analysis.result.type).label} · {Math.round(analysis.result.confidence)}% · {analysis.result.provider}
              </p>
              {analysis.result.reasoning && <p className="mt-0.5 text-ink-muted">{analysis.result.reasoning}</p>}
            </div>
          )}
          {analysis?.status === 'error' && (
            <p role="alert" className="text-xs text-warn">{analysis.error}</p>
          )}
        </div>
      )}
    </li>
  );
};

export default memo(ThreatCard);
