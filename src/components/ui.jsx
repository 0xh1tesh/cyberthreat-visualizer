import React, { useId, useRef } from 'react';
import { cn } from '../lib/utils';
import { TONE } from '../lib/palette';

export const Panel = ({ title, icon: Icon, action, children, className, bodyClassName, as: Tag = 'section' }) => {
  const headingId = useId();
  return (
    <Tag aria-labelledby={title ? headingId : undefined} className={cn('rounded-xl border border-line bg-surface', className)}>
      {(title || action) && (
        <header className="flex items-center justify-between gap-3 px-4 pt-3.5 pb-2.5">
          <h2 id={headingId} className="flex items-center gap-2 text-[13px] font-semibold text-ink">
            {Icon && <Icon size={15} className="text-ink-muted" aria-hidden="true" />}
            {title}
          </h2>
          {action}
        </header>
      )}
      <div className={cn('px-4 pb-4', !title && !action && 'pt-4', bodyClassName)}>{children}</div>
    </Tag>
  );
};

export const Badge = ({ tone = 'neutral', children, title, className, dot = false }) => {
  const t = TONE[tone] || TONE.neutral;
  return (
    <span
      title={title}
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-1.5 py-0.5 text-2xs font-medium leading-4',
        t.text, t.soft, t.border, className,
      )}
    >
      {dot && <span className={cn('size-1.5 rounded-full', t.solid)} aria-hidden="true" />}
      {children}
    </span>
  );
};

export const StatusDot = ({ tone = 'neutral', pulse = false, className }) => (
  <span
    aria-hidden="true"
    className={cn('inline-block size-2 rounded-full', (TONE[tone] || TONE.neutral).solid, pulse && 'animate-live-dot', className)}
  />
);

export const Stat = ({ label, value, hint, tone }) => (
  <div className="min-w-0">
    <dt className="text-2xs font-medium uppercase tracking-wide text-ink-muted">{label}</dt>
    <dd className={cn('mt-0.5 truncate text-lg font-semibold tabular text-ink', tone && (TONE[tone] || TONE.neutral).text)}>{value}</dd>
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
      className={cn('inline-flex rounded-lg border border-line bg-canvas p-0.5', className)}
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
              'inline-flex items-center gap-1.5 rounded-md font-medium transition-colors duration-150',
              size === 'sm' ? 'px-2.5 py-1 text-xs' : 'px-3.5 py-1.5 text-[13px]',
              selected ? 'bg-overlay text-ink' : 'text-ink-muted hover:text-ink',
            )}
          >
            {option.icon && <option.icon size={14} aria-hidden="true" />}
            {option.label}
            {option.count !== undefined && (
              <span className="tabular text-ink-faint">{option.count}</span>
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
      <span className="grid size-9 place-items-center rounded-full border border-line bg-raised">
        <Icon size={16} className="text-ink-muted" aria-hidden="true" />
      </span>
    )}
    <p className="text-sm font-medium text-ink">{title}</p>
    {children && <p className="max-w-[28ch] text-[13px] leading-5 text-ink-muted">{children}</p>}
    {action}
  </div>
);

export const Skeleton = ({ className }) => (
  <div aria-hidden="true" className={cn('animate-pulse rounded-md bg-raised', className)} />
);

export const IconButton = ({ label, children, className, ...rest }) => (
  <button
    type="button"
    aria-label={label}
    title={label}
    className={cn(
      'inline-grid size-8 place-items-center rounded-lg border border-line bg-raised text-ink-muted transition-colors duration-150 hover:border-line-strong hover:text-ink disabled:cursor-not-allowed disabled:opacity-40',
      className,
    )}
    {...rest}
  >
    {children}
  </button>
);
