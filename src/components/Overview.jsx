import React, { useMemo } from 'react';
import { Database, Globe2, ShieldAlert } from 'lucide-react';
import { Badge, EmptyState, Panel, Stat, StatusDot } from './ui';
import { AI_OPTIONS } from './Header';
import { cn } from '../lib/utils';
import { CLASS_META, TONE } from '../lib/palette';

const PROVIDERS = [
  { key: 'abuseipdb', name: 'AbuseIPDB', role: 'IP reputation' },
  { key: 'otx', name: 'AlienVault OTX', role: 'Threat pulses' },
  { key: 'shodan', name: 'Shodan', role: 'Open ports' },
  { key: 'ipinfo', name: 'IPinfo', role: 'Geolocation' },
];

const providerState = (value) => {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('enabled')) return { label: 'Active', tone: 'ok' };
  if (normalized === 'rate_limited') return { label: 'Rate limited', tone: 'warn' };
  if (normalized === 'unauthorized') return { label: 'Key rejected', tone: 'crit' };
  if (normalized === 'missing_key') return { label: 'No key', tone: 'neutral' };
  if (normalized === 'offline') return { label: 'Unreachable', tone: 'crit' };
  return { label: 'Unknown', tone: 'neutral' };
};

const aiState = (health, aiHealth, provider) => {
  if (provider === 'off') return { label: 'Disabled', tone: 'neutral' };
  const enabled = typeof aiHealth?.aiEnabled === 'boolean' ? aiHealth.aiEnabled : health?.ai?.enabled;
  if (enabled === undefined) return { label: 'Checking', tone: 'neutral' };
  return enabled ? { label: 'Ready', tone: 'ok' } : { label: 'No API key', tone: 'warn' };
};

const highestClass = (threats) => {
  let best = null;
  threats.forEach((threat) => {
    const meta = CLASS_META[String(threat.classification).toUpperCase()] || CLASS_META.LOW;
    if (!best || meta.rank > best.rank) best = meta;
  });
  return best;
};

const Overview = ({ threats, health, aiHealth, provider, onProviderChange, status }) => {
  const summary = useMemo(() => {
    const originCounts = new Map();
    let scoreSum = 0;
    let critical = 0;
    threats.forEach((threat) => {
      scoreSum += threat.score || 0;
      if (String(threat.classification).toUpperCase() === 'DDOS') critical += 1;
      originCounts.set(threat.origin.country, (originCounts.get(threat.origin.country) || 0) + 1);
    });
    const origins = [...originCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    return {
      top: highestClass(threats),
      critical,
      average: threats.length ? Math.round(scoreSum / threats.length) : 0,
      origins,
    };
  }, [threats]);

  const ai = aiState(health, aiHealth, provider);
  const aiModel = aiHealth?.model && aiHealth.model !== 'none' ? aiHealth.model : null;
  const level = summary.top;
  const levelTone = level ? TONE[level.tone] : TONE.neutral;
  const usageTotal = health?.usage ? Object.values(health.usage).reduce((a, b) => a + b, 0) : null;
  const maxOrigin = summary.origins[0]?.[1] || 1;

  return (
    <div className="flex min-h-0 flex-col gap-3">
      <Panel title="Threat level" icon={ShieldAlert}>
        {level ? (
          <>
            <div className="flex items-center gap-3">
              <span className={cn('size-2.5 rounded-full', levelTone.solid)} aria-hidden="true" />
              <p className={cn('text-2xl font-semibold', levelTone.text)}>{level.severity}</p>
            </div>
            <p className="mt-1 text-xs text-ink-muted">Highest severity currently observed</p>
            <dl className="mt-4 grid grid-cols-3 gap-3 border-t border-line pt-3">
              <Stat label="Active" value={threats.length} />
              <Stat label="Critical" value={summary.critical} tone={summary.critical ? 'crit' : undefined} />
              <Stat label="Avg score" value={summary.average} />
            </dl>
          </>
        ) : (
          <EmptyState title={status === 'offline' ? 'No data' : 'Waiting for data'} className="py-4">
            {status === 'offline' ? 'The API is unreachable.' : 'The first results arrive shortly.'}
          </EmptyState>
        )}
      </Panel>

      <Panel title="Top origins" icon={Globe2}>
        {summary.origins.length > 0 ? (
          <ol className="space-y-3">
            {summary.origins.map(([country, count]) => (
              <li key={country}>
                <div className="flex items-center justify-between gap-3 text-[13px]">
                  <span className="truncate text-ink">{country}</span>
                  <span className="tabular text-ink-muted">{count}</span>
                </div>
                <div className="mt-1.5 h-1 overflow-hidden rounded-full bg-raised" aria-hidden="true">
                  <div
                    className="h-full rounded-full bg-info transition-[width] duration-300"
                    style={{ width: `${(count / maxOrigin) * 100}%` }}
                  />
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <p className="py-2 text-[13px] text-ink-muted">No origins to rank yet.</p>
        )}
      </Panel>

      <Panel title="Data sources" icon={Database}>
        <ul className="divide-y divide-line">
          {PROVIDERS.map((item) => {
            const state = providerState(health?.providers?.[item.key]);
            return (
              <li key={item.key} className="flex items-center justify-between gap-3 py-2 first:pt-0">
                <div className="min-w-0">
                  <p className="truncate text-[13px] text-ink">{item.name}</p>
                  <p className="truncate text-2xs text-ink-faint">{item.role}</p>
                </div>
                <Badge tone={state.tone} dot>{health ? state.label : 'Checking'}</Badge>
              </li>
            );
          })}
          <li className="flex items-center justify-between gap-3 py-2 last:pb-0">
            <div className="min-w-0">
              <p className="text-[13px] text-ink">AI classifier</p>
              <p className="truncate text-2xs text-ink-faint">{aiModel || 'Rule engine only'}</p>
            </div>
            <Badge tone={ai.tone} dot>{ai.label}</Badge>
          </li>
        </ul>

        <label className="mt-3 flex items-center justify-between gap-3 border-t border-line pt-3 text-xs text-ink-muted md:hidden">
          AI classifier
          <select
            value={provider}
            onChange={(event) => onProviderChange(event.target.value)}
            className="rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs text-ink"
          >
            {AI_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>

        {health && (
          <p className="mt-3 flex items-center gap-2 border-t border-line pt-3 text-2xs text-ink-faint">
            <StatusDot tone={status === 'offline' ? 'crit' : 'ok'} />
            {usageTotal !== null && <span className="tabular">{usageTotal} provider calls today</span>}
            {health.cacheAge ? <span className="tabular">· cache {Math.round(health.cacheAge / 1000)}s old</span> : null}
          </p>
        )}
      </Panel>
    </div>
  );
};

export default Overview;
