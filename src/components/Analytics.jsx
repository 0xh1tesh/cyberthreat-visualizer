import React, { useMemo } from 'react';
import { Bar, BarChart, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { EmptyState, Section, Swatch } from './ui';
import { useNow } from '../hooks/useNow';
import { CLASS_META, CLASS_ORDER } from '../lib/palette';

const BUCKET_MS = 30 * 1000;
const BUCKET_COUNT = 20;

const axisTick = (colors) => ({ fill: colors.inkMute, fontSize: 11, fontFamily: 'Archivo Variable, sans-serif' });

const ChartTooltip = ({ active, payload, label, unit = 'observations' }) => {
  if (!active || !payload?.length) return null;
  const rows = payload.filter((item) => item.value > 0);
  return (
    <div className="min-w-36 border border-ink bg-sheet px-3 py-2 text-xs shadow-[0_10px_28px_-12px_rgb(0_0_0/0.35)]">
      <p className="condensed mb-1 text-sm font-bold text-ink">{label}</p>
      {rows.length === 0 && <p className="text-ink-mute">No {unit}</p>}
      {rows.map((item) => (
        <p key={item.dataKey} className="flex items-center justify-between gap-4 text-ink-soft">
          <span className="flex items-center gap-1.5">
            {CLASS_META[item.dataKey] && <Swatch classification={item.dataKey} />}
            {item.name}
          </span>
          <span className="tabular text-ink">{item.value}</span>
        </p>
      ))}
    </div>
  );
};

const Legend = () => (
  <ul className="flex flex-wrap items-center gap-x-3 gap-y-1" aria-label="Severity key">
    {[...CLASS_ORDER].reverse().map((key) => (
      <li key={key} className="inline-flex items-center gap-1.5 text-[11.5px] text-ink-soft">
        <Swatch classification={key} />
        {CLASS_META[key].severity}
      </li>
    ))}
  </ul>
);

export const ObservationsTimeline = ({ observations, colors, className }) => {
  const now = useNow(15000);
  const data = useMemo(() => {
    const buckets = Array.from({ length: BUCKET_COUNT }, (_, index) => {
      const minutesAgo = ((BUCKET_COUNT - 1 - index) * BUCKET_MS) / 60000;
      return {
        label: index === BUCKET_COUNT - 1 ? 'Now' : `${minutesAgo % 1 === 0 ? minutesAgo : minutesAgo.toFixed(1)} min ago`,
        tick: index === BUCKET_COUNT - 1 ? 'now' : `-${Math.round(minutesAgo)}m`,
        DDOS: 0, MALWARE: 0, SCAN: 0, LOW: 0,
      };
    });
    observations.forEach((observation) => {
      const age = now - observation.timestamp;
      const index = BUCKET_COUNT - 1 - Math.floor(age / BUCKET_MS);
      const key = String(observation.classification).toUpperCase();
      if (index >= 0 && index < BUCKET_COUNT && key in buckets[index]) buckets[index][key] += 1;
    });
    return buckets;
  }, [observations, now]);

  const total = data.reduce((sum, bucket) => sum + bucket.DDOS + bucket.MALWARE + bucket.SCAN + bucket.LOW, 0);

  return (
    <Section
      title="Observations, last 10 minutes"
      action={<Legend />}
      className={className}
      bodyClassName="h-[calc(100%-42px)] min-h-[110px]"
    >
      {total === 0 ? (
        <EmptyState title="No observations yet" className="h-full justify-center py-0">Results appear here as threats are refreshed.</EmptyState>
      ) : (
        <div role="img" aria-label={`${total} threat observations in the last 10 minutes, stacked by severity`} className="h-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 6, right: 0, left: -26, bottom: 0 }} barCategoryGap={2}>
              <XAxis dataKey="tick" tick={axisTick(colors)} tickLine={false} axisLine={{ stroke: colors.ink }} interval={3} />
              <YAxis allowDecimals={false} tick={axisTick(colors)} tickLine={false} axisLine={false} tickCount={3} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: colors.rule, fillOpacity: 0.45 }} />
              {[...CLASS_ORDER].reverse().map((key) => (
                <Bar key={key} dataKey={key} name={CLASS_META[key].label} stackId="a" fill={colors[CLASS_META[key].tone]} stroke={colors.paper} strokeWidth={1} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Section>
  );
};

export const ClassMix = ({ threats, className }) => {
  const counts = useMemo(() => {
    const result = { DDOS: 0, MALWARE: 0, SCAN: 0, LOW: 0 };
    threats.forEach((threat) => {
      const key = String(threat.classification).toUpperCase();
      if (key in result) result[key] += 1;
    });
    return result;
  }, [threats]);
  const total = threats.length;

  return (
    <Section title="Severity mix" className={className}>
      {total === 0 ? (
        <p className="py-1 text-[13px] text-ink-mute">No active threats.</p>
      ) : (
        <>
          <div
            className="flex h-3 gap-0.5"
            role="img"
            aria-label={CLASS_ORDER.map((key) => `${CLASS_META[key].label} ${counts[key]}`).join(', ')}
          >
            {CLASS_ORDER.map((key) => counts[key] > 0 && (
              <Swatch key={key} classification={key} className="h-full transition-[width] duration-300" style={{ width: `${(counts[key] / total) * 100}%` }} />
            ))}
          </div>
          <dl className="mt-3 space-y-1.5">
            {CLASS_ORDER.map((key) => (
              <div key={key} className="flex items-baseline justify-between text-[13px]">
                <dt className="flex items-center gap-2 text-ink-soft">
                  <Swatch classification={key} />
                  {CLASS_META[key].label}
                </dt>
                <dd className="tabular text-ink">
                  {counts[key]}
                  <span className="ml-2 inline-block w-9 text-right text-ink-mute">{Math.round((counts[key] / total) * 100)}%</span>
                </dd>
              </div>
            ))}
          </dl>
        </>
      )}
    </Section>
  );
};

export const PhaseIntensity = ({ steps, stepIndex, onSelect, colors, className }) => {
  const data = useMemo(() => steps.map((step, index) => {
    const arcs = step.arcs || [];
    const mean = arcs.length ? arcs.reduce((sum, arc) => sum + (arc.score || 0), 0) / arcs.length : 0;
    return { index, title: step.title, score: Math.round(mean) };
  }), [steps]);

  return (
    <Section title="Mean threat score by phase" className={className} bodyClassName="h-[calc(100%-42px)] min-h-[110px]">
      <div role="img" aria-label="Average simulated threat score for each scenario phase; select a bar to jump to that phase" className="h-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 6, right: 0, left: -26, bottom: 0 }} barCategoryGap={6}>
            <XAxis dataKey="index" tickFormatter={(value) => value + 1} tick={axisTick(colors)} tickLine={false} axisLine={{ stroke: colors.ink }} />
            <YAxis domain={[0, 100]} ticks={[0, 50, 100]} tick={axisTick(colors)} tickLine={false} axisLine={false} />
            <Tooltip content={<ChartTooltip unit="data" />} labelFormatter={(value) => data[value]?.title} cursor={{ fill: colors.rule, fillOpacity: 0.45 }} />
            <Bar dataKey="score" name="Mean score" isAnimationActive={false} onClick={(entry) => onSelect(entry.index)}>
              {data.map((entry) => (
                <Cell key={entry.index} fill={entry.index === stepIndex ? colors.ink : colors.rule} cursor="pointer" />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Section>
  );
};
