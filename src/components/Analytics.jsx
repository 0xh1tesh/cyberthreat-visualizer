import React, { useMemo } from 'react';
import { Bar, BarChart, CartesianGrid, Cell, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts';
import { Activity, BarChart3 } from 'lucide-react';
import { EmptyState, Panel } from './ui';
import { useNow } from '../hooks/useNow';
import { CLASS_META, CLASS_ORDER } from '../lib/palette';

const BUCKET_MS = 30 * 1000;
const BUCKET_COUNT = 20;
const AXIS_TICK = { fill: '#a0a0ab', fontSize: 11 };

const ChartTooltip = ({ active, payload, label, unit = 'observations' }) => {
  if (!active || !payload?.length) return null;
  const rows = payload.filter((item) => item.value > 0);
  return (
    <div className="rounded-lg border border-line-strong bg-overlay px-3 py-2 text-xs shadow-none">
      <p className="mb-1 font-medium text-ink">{label}</p>
      {rows.length === 0 && <p className="text-ink-muted">No {unit}</p>}
      {rows.map((item) => (
        <p key={item.dataKey} className="flex items-center justify-between gap-4 text-ink-muted">
          <span className="flex items-center gap-1.5">
            <span className="size-2 rounded-full" style={{ background: item.color || item.fill }} aria-hidden="true" />
            {item.name}
          </span>
          <span className="tabular text-ink">{item.value}</span>
        </p>
      ))}
    </div>
  );
};

export const ObservationsTimeline = ({ observations, className }) => {
  const now = useNow(15000);
  const data = useMemo(() => {
    const buckets = Array.from({ length: BUCKET_COUNT }, (_, index) => {
      const minutesAgo = ((BUCKET_COUNT - 1 - index) * BUCKET_MS) / 60000;
      return {
        label: index === BUCKET_COUNT - 1 ? 'now' : `${minutesAgo % 1 === 0 ? minutesAgo : minutesAgo.toFixed(1)}m ago`,
        tick: index === BUCKET_COUNT - 1 ? 'now' : `${Math.round(minutesAgo)}m`,
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
    <Panel
      title="Observations, last 10 minutes"
      icon={BarChart3}
      className={className}
      bodyClassName="h-[calc(100%-44px)] min-h-[120px]"
    >
      {total === 0 ? (
        <EmptyState title="No observations yet" className="h-full py-2">Results appear here as threats are refreshed.</EmptyState>
      ) : (
        <div role="img" aria-label={`${total} threat observations in the last 10 minutes, grouped by severity`} className="h-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data} margin={{ top: 4, right: 4, left: -22, bottom: 0 }} barCategoryGap={3}>
              <CartesianGrid stroke="#26262b" vertical={false} />
              <XAxis dataKey="tick" tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: '#26262b' }} interval={3} />
              <YAxis allowDecimals={false} tick={AXIS_TICK} tickLine={false} axisLine={false} />
              <Tooltip content={<ChartTooltip />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
              {[...CLASS_ORDER].reverse().map((key) => (
                <Bar key={key} dataKey={key} name={CLASS_META[key].label} stackId="a" fill={CLASS_META[key].color} isAnimationActive={false} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Panel>
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
    <Panel title="Severity mix" icon={Activity} className={className}>
      {total === 0 ? (
        <p className="py-2 text-[13px] text-ink-muted">No active threats.</p>
      ) : (
        <>
          <div
            className="flex h-2 overflow-hidden rounded-full bg-raised"
            role="img"
            aria-label={CLASS_ORDER.map((key) => `${CLASS_META[key].label} ${counts[key]}`).join(', ')}
          >
            {CLASS_ORDER.map((key) => counts[key] > 0 && (
              <div key={key} style={{ width: `${(counts[key] / total) * 100}%`, background: CLASS_META[key].color }} />
            ))}
          </div>
          <ul className="mt-3 space-y-1.5">
            {CLASS_ORDER.map((key) => (
              <li key={key} className="flex items-center justify-between text-[13px]">
                <span className="flex items-center gap-2 text-ink-muted">
                  <span className="size-2 rounded-full" style={{ background: CLASS_META[key].color }} aria-hidden="true" />
                  {CLASS_META[key].label}
                </span>
                <span className="tabular text-ink">
                  {counts[key]}
                  <span className="ml-1.5 text-ink-faint">{Math.round((counts[key] / total) * 100)}%</span>
                </span>
              </li>
            ))}
          </ul>
        </>
      )}
    </Panel>
  );
};

export const PhaseIntensity = ({ steps, stepIndex, onSelect, className }) => {
  const data = useMemo(() => steps.map((step, index) => {
    const arcs = step.arcs || [];
    const mean = arcs.length ? arcs.reduce((sum, arc) => sum + (arc.score || 0), 0) / arcs.length : 0;
    return { index, name: `Phase ${index + 1}`, title: step.title, score: Math.round(mean) };
  }), [steps]);

  return (
    <Panel title="Intensity by phase" icon={BarChart3} className={className} bodyClassName="h-[calc(100%-44px)] min-h-[120px]">
      <div role="img" aria-label="Average simulated threat score for each scenario phase" className="h-full">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} margin={{ top: 4, right: 4, left: -22, bottom: 0 }}>
            <CartesianGrid stroke="#26262b" vertical={false} />
            <XAxis dataKey="index" tickFormatter={(value) => value + 1} tick={AXIS_TICK} tickLine={false} axisLine={{ stroke: '#26262b' }} />
            <YAxis domain={[0, 100]} tick={AXIS_TICK} tickLine={false} axisLine={false} />
            <Tooltip content={<ChartTooltip unit="data" />} labelFormatter={(value) => `Phase ${value + 1}`} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
            <Bar dataKey="score" name="Avg score" radius={[3, 3, 0, 0]} isAnimationActive={false} onClick={(entry) => onSelect(entry.index)}>
              {data.map((entry) => (
                <Cell key={entry.index} fill={entry.index === stepIndex ? '#6cb6ff' : '#383840'} cursor="pointer" />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Panel>
  );
};
