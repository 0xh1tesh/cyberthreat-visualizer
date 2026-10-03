import React, { useId, useRef } from 'react';
import { cn } from '../lib/utils';
import { SEVERITY_BG, classMeta } from '../lib/palette';

/** A newspaper-style section: heavy ink rule, a condensed head, then content. No box. */
export const Section = ({ title, action, children, className, bodyClassName, as: Tag = 'section' }) => {
  const headingId = useId();
  return (
    <Tag aria-labelledby={title ? headingId : undefined} className={cn('border-t-2 border-ink', className)}>
      {(title || action) && (
        <header className="flex min-h-10 flex-wrap items-center justify-between gap-x-3 gap-y-1 py-2">
          <h2 id={headingId} className="condensed truncate text-[17px] font-bold leading-6 text-ink">{title}</h2>
          {action}
        </header>
      )}
      <div className={bodyClassName}>{children}</div>
    </Tag>
  );
};

/** Square severity key. Identity lives in the label next to it; the colour only reinforces it. */
export const Swatch = ({ classification, className, style }) => (
  <span aria-hidden="true" style={style} className={cn('inline-block size-2.5 shrink-0', SEVERITY_BG[classMeta(classification).tone], className)} />
);

export const Tag = ({ tone = 'neutral', children, title, className }) => (
  <span
    title={title}
    className={cn(
      'inline-flex items-center gap-1 border px-1.5 text-[11.5px] font-medium leading-[18px] whitespace-nowrap',
      tone === 'alert' ? 'border-crit/50 text-crit' : 'border-rule text-ink-soft',
      className,
    )}
  >
    {children}
  </span>
);

/** The page's one circle: a real live-connection indicator. */
export const LiveDot = ({ active = true, className }) => (
  <span aria-hidden="true" className={cn('inline-block size-2 shrink-0 rounded-full', active ? 'animate-live bg-crit' : 'bg-ink-mute', className)} />
);

export const Stat = ({ label, value, emphasis = false }) => (
  <div className="min-w-0">
    <dt className="text-xs text-ink-mute">{label}</dt>
    <dd className={cn('condensed mt-0.5 truncate text-[30px] font-semibold leading-8 tabular', emphasis ? 'text-crit' : 'text-ink')}>{value}</dd>
  </div>
);

/** Single-choice tabs (radio-group pattern) with arrow-key navigation and an ink underline. */
export const Tabs = ({ options, value, onChange, label, bare = false, className }) => {
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
    <div role="radiogroup" aria-label={label} className={cn('flex items-end gap-4', !bare && 'border-b border-rule', className)}>
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
              '-mb-px inline-flex shrink-0 items-baseline gap-1.5 border-b-2 pt-1 pb-1.5 text-[13.5px] font-medium whitespace-nowrap transition-colors duration-150',
              selected ? 'border-ink text-ink' : 'border-transparent text-ink-mute hover:text-ink',
            )}
          >
            {option.label}
            {option.count !== undefined && <span className="text-xs tabular text-ink-mute">{option.count}</span>}
          </button>
        );
      })}
    </div>
  );
};

export const EmptyState = ({ title, children, action, className }) => (
  <div className={cn('flex flex-col items-start gap-1.5 py-6', className)}>
    <p className="condensed text-lg font-bold text-ink">{title}</p>
    {children && <p className="max-w-[36ch] text-[13px] leading-5 text-ink-mute">{children}</p>}
    {action && <div className="mt-2">{action}</div>}
  </div>
);

export const Skeleton = ({ className }) => (
  <div aria-hidden="true" className={cn('animate-pulse bg-wash', className)} />
);

export const Button = ({ variant = 'outline', size = 'sm', className, children, ...rest }) => (
  <button
    type="button"
    className={cn(
      'inline-flex shrink-0 items-center justify-center gap-1.5 font-medium whitespace-nowrap transition-[background-color,border-color,color,transform] duration-150 active:translate-y-px disabled:cursor-not-allowed disabled:opacity-45 disabled:active:translate-y-0',
      size === 'sm' ? 'h-7 px-2.5 text-[12.5px]' : 'h-9 px-3.5 text-[13.5px]',
      variant === 'solid' && 'bg-ink text-paper hover:bg-ink/85',
      variant === 'outline' && 'border border-ink/30 text-ink hover:border-ink',
      variant === 'alert' && 'border border-crit/50 text-crit hover:border-crit',
      className,
    )}
    {...rest}
  >
    {children}
  </button>
);

export const IconButton = ({ label, children, className, ...rest }) => (
  <button
    type="button"
    aria-label={label}
    title={label}
    className={cn(
      'inline-grid size-8 shrink-0 place-items-center text-ink-soft transition-colors duration-150 hover:bg-wash hover:text-ink disabled:cursor-not-allowed disabled:opacity-35 disabled:hover:bg-transparent',
      className,
    )}
    {...rest}
  >
    {children}
  </button>
);
