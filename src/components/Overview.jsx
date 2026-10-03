import React, { useMemo } from 'react';
import { WarningIcon } from '@phosphor-icons/react';
import { EmptyState, Section, Stat } from './ui';
import { AI_OPTIONS } from './Header';
import { cn } from '../lib/utils';
import { CLASS_META, CLASS_ORDER, SEVERITY_BG } from '../lib/palette';

const PROVIDERS = [
  { key: 'abuseipdb', name: 'AbuseIPDB', role: 'IP reputation' },
  { key: 'otx', name: 'AlienVault OTX', role: 'Threat pulses' },
  { key: 'shodan', name: 'Shodan', role: 'Open ports' },
  { key: 'ipinfo', name: 'IPinfo', role: 'Geolocation' },
];

// Colour is reserved for problems: a healthy source reads quietly.
const providerState = (value) => {
  const normalized = String(value || '').toLowerCase();
  if (normalized.includes('enabled')) return { label: 'Active' };
  if (normalized === 'rate_limited') return { label: 'Rate limited', issue: 'text-high' };
  if (normalized === 'unauthorized') return { label: 'Key rejected', issue: 'text-crit' };
  if (normalized === 'missing_key') return { label: 'No key' };
  if (normalized === 'offline') return { label: 'Unreachable', issue: 'text-crit' };
  return { label: 'Unknown' };
};

const aiState = (health, aiHealth, provider) => {
  if (provider === 'off') return { label: 'Disabled' };
  const enabled = typeof aiHealth?.aiEnabled === 'boolean' ? aiHealth.aiEnabled : health?.ai?.enabled;
  if (enabled === undefined) return { label: 'Checking' };
  return enabled ? { label: 'Ready' } : { label: 'No API key', issue: 'text-high' };
};

const plural = (count, one, many) => `${count} ${count === 1 ? one : many}`;

/** The opening paragraph of the briefing, written from the data rather than templated around it. */
const writeLede = ({ total, critical, origins }) => {
  const parts = [`${plural(total, 'hostile source', 'hostile sources')} in the latest refresh.`];
  parts.push(critical ? `${critical} ${critical === 1 ? 'is' : 'are'} rated critical.` : 'None are rated critical.');
  if (origins[0]) {
    const [first, second] = origins;
    parts.push(`${first[0]} accounts for ${first[1]}${second ? `, followed by ${second[0]} with ${second[1]}` : ''}.`);
  }
  return parts.join(' ');
};

const ConditionScale = ({ level }) => (
  <ol className="mt-4 grid grid-cols-4 gap-0.5" aria-label={`Threat condition: ${level.severity}, ${level.rank + 1} of 4`}>
    {[...CLASS_ORDER].reverse().map((key) => {
      const step = CLASS_META[key];
      const current = step.rank === level.rank;
      return (
        <li key={key} aria-current={current ? 'step' : undefined}>
          <span className="flex h-2.5 items-end" aria-hidden="true">
            <span className={cn('block w-full transition-[height] duration-300', SEVERITY_BG[step.tone], current ? 'h-2.5' : 'h-1')} />
          </span>
          <span className={cn('mt-1.5 block text-[11.5px]', current ? 'font-semibold text-ink' : 'text-ink-mute')}>{step.severity}</span>
        </li>
      );
    })}
  </ol>
);

const Overview = ({ threats, health, aiHealth, provider, onProviderChange, status }) => {
  const summary = useMemo(() => {
    const originCounts = new Map();
    let scoreSum = 0;
    let critical = 0;
    let top = null;
    threats.forEach((threat) => {
      const meta = CLASS_META[String(threat.classification).toUpperCase()] || CLASS_META.LOW;
      if (!top || meta.rank > top.rank) top = meta;
      if (meta.key === 'DDOS') critical += 1;
      scoreSum += threat.score || 0;
      originCounts.set(threat.origin.country, (originCounts.get(threat.origin.country) || 0) + 1);
    });
    const origins = [...originCounts.entries()].sort((a, b) => b[1] - a[1]).slice(0, 5);
    return { top, critical, total: threats.length, average: threats.length ? Math.round(scoreSum / threats.length) : 0, origins };
  }, [threats]);

  const ai = aiState(health, aiHealth, provider);
  const aiModel = aiHealth?.model && aiHealth.model !== 'none' ? aiHealth.model : null;
  const usageTotal = health?.usage ? Object.values(health.usage).reduce((a, b) => a + b, 0) : null;
  const maxOrigin = summary.origins[0]?.[1] || 1;
  const level = summary.top;

  return (
    <div className="flex min-h-0 flex-col gap-7">
      <section aria-labelledby="condition-heading">
        <p className="text-xs text-ink-mute">Threat condition</p>
        {level ? (
          <>
            <h2 id="condition-heading" className={cn('condensed mt-0.5 text-[52px] leading-[0.95] font-extrabold tracking-[-0.015em]', level.rank === 3 ? 'text-crit' : 'text-ink')}>
              {level.severity}
            </h2>
            <p className="mt-3 text-[14.5px] leading-[1.55] text-ink-soft">{writeLede(summary)}</p>
            <ConditionScale level={level} />
            <dl className="mt-6 grid grid-cols-3 divide-x divide-rule border-y border-rule py-3 [&>div]:px-3 [&>div:first-child]:pl-0">
              <Stat label="Active" value={summary.total} />
              <Stat label="Critical" value={summary.critical} emphasis={summary.critical > 0} />
              <Stat label="Mean score" value={summary.average} />
            </dl>
          </>
        ) : (
          <>
            <h2 id="condition-heading" className="sr-only">Threat condition</h2>
            <EmptyState title={status === 'offline' ? 'No data' : 'Waiting for data'} className="py-3">
              {status === 'offline' ? 'The API is unreachable.' : 'The first results arrive shortly.'}
            </EmptyState>
          </>
        )}
      </section>

      <Section title="Top origins">
        {summary.origins.length > 0 ? (
          <ol className="space-y-2 pt-1">
            {summary.origins.map(([country, count]) => (
              <li key={country} className="grid grid-cols-[minmax(0,7.5rem)_minmax(0,1fr)_2ch] items-center gap-3 text-[13.5px]">
                <span className="truncate text-ink">{country}</span>
                <span className="h-2 bg-ink-soft transition-[width] duration-300" style={{ width: `${(count / maxOrigin) * 100}%` }} aria-hidden="true" />
                <span className="text-right tabular text-ink">{count}</span>
              </li>
            ))}
          </ol>
        ) : (
          <p className="py-1 text-[13px] text-ink-mute">No origins to rank yet.</p>
        )}
      </Section>

      <Section title="Data sources">
        <ul className="divide-y divide-rule">
          {PROVIDERS.map((item) => {
            const state = health ? providerState(health.providers?.[item.key]) : { label: 'Checking' };
            return (
              <li key={item.key} className="flex items-baseline justify-between gap-3 py-2 first:pt-1">
                <p className="min-w-0 truncate text-[13.5px] text-ink">
                  {item.name} <span className="text-ink-mute">{item.role}</span>
                </p>
                <span className={cn('inline-flex shrink-0 items-center gap-1 text-[12.5px]', state.issue || 'text-ink-mute')}>
                  {state.issue && <WarningIcon size={13} weight="bold" aria-hidden="true" />}
                  {state.label}
                </span>
              </li>
            );
          })}
          <li className="flex items-baseline justify-between gap-3 py-2">
            <p className="min-w-0 truncate text-[13.5px] text-ink">
              AI classifier <span className="text-ink-mute">{aiModel || 'Rule engine only'}</span>
            </p>
            <span className={cn('inline-flex shrink-0 items-center gap-1 text-[12.5px]', ai.issue || 'text-ink-mute')}>
              {ai.issue && <WarningIcon size={13} weight="bold" aria-hidden="true" />}
              {ai.label}
            </span>
          </li>
        </ul>

        <label className="mt-2 flex items-center justify-between gap-3 border-t border-rule pt-3 text-[13px] text-ink md:hidden">
          AI classifier
          <select
            value={provider}
            onChange={(event) => onProviderChange(event.target.value)}
            className="h-8 border border-rule bg-paper px-2 text-[13px] text-ink"
          >
            {AI_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
          </select>
        </label>

        {health && (usageTotal !== null || health.cacheAge) && (
          <p className="mt-2 border-t border-rule pt-2 text-xs text-ink-mute tabular">
            {usageTotal !== null && `${plural(usageTotal, 'provider call', 'provider calls')} today.`}
            {health.cacheAge ? ` Cache is ${Math.round(health.cacheAge / 1000)}s old.` : ''}
          </p>
        )}
      </Section>
    </div>
  );
};

export default Overview;
