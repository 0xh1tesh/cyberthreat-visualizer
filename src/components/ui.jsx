import React, { useId, useRef } from 'react';
import { cn } from '../lib/utils';
import { TONE } from '../lib/palette';

/** Framed instrument panel: hairline hull, corner ticks, and a header plate. */
export const Panel = ({ title, icon: Icon, action, children, className, bodyClassName, as: Tag = 'section' }) => {
  const headingId = useId();
  return (
    <Tag aria-labelledby={title ? headingId : undefined} className={cn('hud border border-line bg-surface/90', className)}>
      {(title || action) && (
        <header className="flex h-10 items-center justify-between gap-3 border-b border-line px-3.5">
          <h2 id={headingId} className="flex min-w-0 items-center gap-2 text-[13px] font-semibold uppercase tracking-[0.08em] text-ink">
            {Icon && <Icon size={14} className="shrink-0 text-info" aria-hidden="true" />}
            <span className="truncate">{title}</span>
          </h2>
          {action}
        </header>
      )}
      <div className={cn('px-3.5 py-3', bodyClassName)}>{children}</div>
    </Tag>
  );
};

export const Badge = ({ tone = 'neutral', children, title, className, dot = false }) => {
  const t = TONE[tone] || TONE.neutral;
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 border px-1.5 py-px font-mono text-2xs font-medium uppercase tracking-wide',
        t.text, t.soft, t.border, className,
      )}
    >
      {dot && <span className={cn('size-1.5', t.solid)} aria-hidden="true" />}
      {children}
    </span>
  );
};

export const StatusDot = ({ tone = 'neutral', pulse = false, className }) => (
  <span
    aria-hidden="true"
    className={cn('inline-block size-2 rotate-45', (TONE[tone] || TONE.neutral).solid, pulse && 'animate-live-dot', className)}
  />
);

/** Segmented LED bar. `value` is 0–1; colour comes from a tone or an explicit hex. */
export const Meter = ({ value, tone = 'info', color, className, label }) => {
  const pct = `${Math.max(0, Math.min(1, value || 0)) * 100}%`;
  return (
    <div
      className={cn('meter meter-track relative h-1.5', className)}
      role={label ? 'meter' : undefined}
      aria-label={label}
      aria-valuemin={label ? 0 : undefined}
      aria-valuemax={label ? 100 : undefined}
      aria-valuenow={label ? Math.round((value || 0) * 100) : undefined}
      aria-hidden={label ? undefined : 'true'}
    >
      <div
        className={cn('absolute inset-y-0 left-0 transition-[width] duration-300', !color && (TONE[tone] || TONE.info).solid)}
        style={{ width: pct, background: color }}
      />
    </div>
  );
};

export const Stat = ({ label, value, hint, tone }) => (
  <div className="min-w-0">
    <dt className="readout">{label}</dt>
    <dd className={cn('mt-0.5 truncate font-mono text-xl font-semibold tabular text-ink', tone && (TONE[tone] || TONE.neutral).text)}>{value}</dd>
    {hint && <p className="truncate text-2xs text-ink-faint">{hint}</p>}
  </div>
);

/** Single-choice switcher (radio-group pattern) with arrow-key navigation. */
export const Segmented = ({ options, value, onChange, label, size = 'md', className }) => {
  const refs = useRef([]);

  const onKeyDown = (event, index) => {
    let next = null;
    if (event.key === 'ArrowRight') next = (index + 1) % options.length;
    if (event.key === 'ArrowLeft') next = (index - 1 + options.length) % options.length;
    if (event.key === 'Home') next = 0;
    if (event.key === 'End') next = options.length - 1;
    if (next === null) return;
    event.preventDefault();
    onChange(options[next].value);
    refs.current[next]?.focus();
  };

  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn('inline-flex border border-line bg-canvas/80 p-0.5', className)}
    >
      {options.map((option, index) => {
        const selected = option.value === value;
        return (
          <button
            key={option.value}
            ref={(node) => { refs.current[index] = node; }}
            role="radio"
            type="button"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(option.value)}
            onKeyDown={(event) => onKeyDown(event, index)}
            className={cn(
              'inline-flex items-center gap-1.5 border font-semibold uppercase tracking-[0.06em] transition-colors duration-150',
              size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3.5 py-1.5 text-[13px]',
              selected ? 'border-info/50 bg-info/10 text-info' : 'border-transparent text-ink-muted hover:text-ink',
            )}
          >
            {option.icon && <option.icon size={14} aria-hidden="true" />}
            {option.label}
            {option.count !== undefined && (
              <span className={cn('font-mono tabular font-normal', selected ? 'text-info/80' : 'text-ink-faint')}>{option.count}</span>
            )}
          </button>
        );
      })}
    </div>
  );
};

export const EmptyState = ({ icon: Icon, title, children, action, className }) => (
  <div className={cn('flex flex-col items-center justify-center gap-2 px-6 py-8 text-center', className)}>
    {Icon && (
      <span className="grid size-10 place-items-center border border-dashed border-line-strong">
        <Icon size={16} className="text-info" aria-hidden="true" />
      </span>
    )}
    <p className="text-sm font-semibold uppercase tracking-[0.06em] text-ink">{title}</p>
    {children && <p className="max-w-[30ch] text-[13px] leading-5 text-ink-muted">{children}</p>}
    {action}
  </div>
);

export const Skeleton = ({ className }) => (
  <div aria-hidden="true" className={cn('hatch animate-pulse border border-line', className)} />
);

export const IconButton = ({ label, children, className, ...rest }) => (
  <button
    type="button"
    aria-label={label}
    title={label}
    className={cn(
      'inline-grid size-9 place-items-center border border-line bg-raised text-ink-muted transition-colors duration-150 hover:border-info/50 hover:text-info disabled:cursor-not-allowed disabled:opacity-40',
      className,
    )}
    {...rest}
  >
    {children}
  </button>
);

/** Secondary command button used across cards, dialogs and banners. */
export const CommandButton = ({ className, tone, children, ...rest }) => (
  <button
    type="button"
    className={cn(
      'inline-flex items-center gap-1.5 border px-2.5 py-1 text-xs font-semibold uppercase tracking-[0.06em] transition-colors duration-150 disabled:cursor-not-allowed disabled:opacity-50',
      tone === 'crit'
        ? 'border-crit/40 text-crit hover:bg-crit/10'
        : tone === 'warn'
          ? 'border-warn/40 text-warn hover:bg-warn/10'
          : 'border-line-strong text-ink-muted hover:border-info/60 hover:text-info',
      className,
    )}
    {...rest}
  >
    {children}
  </button>
);
