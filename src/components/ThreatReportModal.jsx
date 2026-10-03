import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { ArrowUpRightIcon, CheckIcon, CircleNotchIcon, CopyIcon, PrinterIcon, WarningIcon, XIcon } from '@phosphor-icons/react';
import { Button, IconButton, Swatch, Tag } from './ui';
import { cn } from '../lib/utils';
import { apiFetch, describeApiError, isAbortError } from '../lib/api';
import { classMeta } from '../lib/palette';
import { getSignalDisplayMeta } from '../lib/threat-normalize';

const SUMMARY_TTL_MS = 7 * 60 * 1000;
const summaryCache = new Map();

const MITRE_MAP = {
  DDOS: { id: 'T1499', name: 'Endpoint Denial of Service' },
  MALWARE: { id: 'T1204', name: 'User Execution' },
  SCAN: { id: 'T1595', name: 'Active Scanning' },
  LOW: { id: 'T1595', name: 'Active Scanning' },
};

const RISK_LABEL = { HIGH: 'High risk', MEDIUM: 'Medium risk', LOW: 'Low risk' };

const cacheKey = (ip, provider) => `${ip}|${provider}`;

const readSummary = (key) => {
  const entry = summaryCache.get(key);
  if (!entry) return null;
  if (entry.expiresAt <= Date.now()) {
    summaryCache.delete(key);
    return null;
  }
  return entry.value;
};

const buildRuleReasoning = (classification, signals, sources) => {
  const parts = [];
  const ok = (key) => String(sources?.[key] || '').toLowerCase() === 'ok';
  if (ok('otx')) parts.push(Number(signals?.otxHits) > 0 ? `${signals.otxHits} OTX pulse hits` : 'no OTX pulse hits');
  if (ok('abuseipdb')) parts.push(`AbuseIPDB confidence ${Math.round(Number(signals?.abuseScore) || 0)}`);
  else parts.push('AbuseIPDB data unavailable');
  if (ok('shodan')) parts.push(`${Number(signals?.portExposure) || 0} exposed ports`);
  else parts.push('port data unavailable');
  return `Classified as ${classMeta(classification).label} from ${parts.join(', ')}.`;
};

const Block = ({ title, children, action }) => (
  <section className="border-t border-ink pt-3">
    <div className="mb-3 flex min-h-7 items-center justify-between gap-3">
      <h3 className="condensed text-[17px] font-bold text-ink">{title}</h3>
      {action}
    </div>
    {children}
  </section>
);

const SignalFigure = ({ label, meta }) => (
  <div className="min-w-0" title={meta.tooltip || undefined}>
    <dt className="text-xs text-ink-mute">{label}</dt>
    <dd className={cn('condensed mt-0.5 font-semibold tabular', meta.faded ? 'text-lg text-ink-mute' : 'text-[30px] leading-8 text-ink')}>
      {meta.faded ? 'Unavailable' : meta.text}
    </dd>
  </div>
);

const FOCUSABLE = 'a[href],button:not([disabled]),select,textarea,input,[tabindex]:not([tabindex="-1"])';

const ReportDialog = ({ threat, onClose, aiProvider }) => {
  const titleId = useId();
  const ip = threat.origin?.ip || '';
  const dialogRef = useRef(null);
  const requestRef = useRef(null);
  const [status, setStatus] = useState('idle');
  const [summary, setSummary] = useState(() => (ip ? readSummary(cacheKey(ip, aiProvider)) : null));
  const [error, setError] = useState(null);
  const [copied, setCopied] = useState(false);

  const canSummarize = Boolean(ip) && !threat.synthetic;
  const meta = classMeta(threat.classification);

  const abortRequest = useCallback(() => {
    requestRef.current?.abort();
    requestRef.current = null;
  }, []);

  // A late response must never land after the dialog closes.
  useEffect(() => abortRequest, [abortRequest]);

  // Focus management + Escape + Tab trap.
  useEffect(() => {
    const previous = document.activeElement;
    const dialog = dialogRef.current;
    dialog?.querySelector('[data-autofocus]')?.focus();

    const onKeyDown = (event) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        onClose();
        return;
      }
      if (event.key !== 'Tab' || !dialog) return;
      const items = [...dialog.querySelectorAll(FOCUSABLE)].filter((el) => el.offsetParent !== null);
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && document.activeElement === last) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('keydown', onKeyDown);
      if (previous instanceof HTMLElement) previous.focus();
    };
  }, [onClose]);

  const generate = async () => {
    if (!canSummarize || status === 'loading') return;
    abortRequest();
    const controller = new AbortController();
    requestRef.current = controller;
    setStatus('loading');
    setError(null);

    try {
      const data = await apiFetch('/report', {
        method: 'POST',
        signal: controller.signal,
        headers: { 'X-AI-Provider': aiProvider },
        body: {
          provider: aiProvider,
          threat: {
            sourceIp: ip,
            sourceCountry: threat.origin.country,
            classification: threat.classification,
            score: threat.score,
            timestamp: threat.timestamp?.getTime?.() ?? Date.now(),
            signals: {
              abuseScore: threat.signals?.abuseScore ?? 0,
              otxHits: threat.signals?.otxHits ?? 0,
              portExposure: threat.signals?.portExposure ?? 0,
            },
            sources: threat.sources,
            ai: { used: Boolean(threat.ai?.used), confidence: threat.ai?.confidence, reason: threat.ai?.reason },
          },
        },
      });

      const ai = data?.ai_summary;
      if (!ai?.used) {
        setError(describeApiError({ code: ai?.reason_code }));
        setStatus('error');
        return;
      }
      const result = {
        assessment: String(ai.executive_summary || ''),
        technical: String(ai.technical_analysis || ''),
        action: String(ai.recommended_action || ''),
        risk: String(ai.risk_level || 'MEDIUM').toUpperCase(),
        provider: String(ai.provider || aiProvider).toUpperCase(),
      };
      summaryCache.set(cacheKey(ip, aiProvider), { value: result, expiresAt: Date.now() + SUMMARY_TTL_MS });
      setSummary(result);
      setStatus('idle');
    } catch (err) {
      if (isAbortError(err)) return;
      setError(describeApiError(err));
      setStatus('error');
    }
  };

  const copyIp = async () => {
    try {
      await navigator.clipboard.writeText(ip);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  };

  const reasoning = useMemo(() => {
    if (threat.ai?.used && threat.ai.reason) return threat.ai.reason;
    return buildRuleReasoning(threat.classification, threat.signals, threat.sources);
  }, [threat]);

  const mitre = MITRE_MAP[meta.key] || MITRE_MAP.LOW;
  const abuse = getSignalDisplayMeta(threat.signals?.abuseScore, 'abuseipdb', threat.sources);
  const otx = getSignalDisplayMeta(threat.signals?.otxHits, 'otx', threat.sources);
  const ports = getSignalDisplayMeta(threat.signals?.portExposure, 'shodan', threat.sources);

  return (
    <motion.div
      className="fixed inset-0 z-50 grid place-items-end bg-ink/45 sm:place-items-center sm:p-6 print:static print:block print:bg-transparent"
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      transition={{ duration: 0.15 }}
      onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}
    >
      <motion.div
        ref={dialogRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        data-print
        initial={{ opacity: 0, y: 24 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: 24 }}
        transition={{ type: 'spring', stiffness: 420, damping: 38 }}
        className="flex max-h-[100dvh] w-full flex-col overflow-hidden border-t-[6px] border-ink bg-sheet shadow-[0_32px_80px_-24px_rgb(0_0_0/0.45)] sm:max-h-[88vh] sm:max-w-2xl"
      >
        <header className="px-6 pt-4 sm:px-8">
          <div className="flex items-center justify-between gap-3">
            <p className="text-xs text-ink-mute">
              Threat report, <time className="tabular" dateTime={threat.timestamp.toISOString()}>{threat.timestamp.toLocaleString()}</time>
            </p>
            <div className="-mr-2 flex items-center" data-print-hide>
              <IconButton label="Print report" onClick={() => window.print()}>
                <PrinterIcon size={17} aria-hidden="true" />
              </IconButton>
              <IconButton label="Close report" onClick={onClose} data-autofocus>
                <XIcon size={17} aria-hidden="true" />
              </IconButton>
            </div>
          </div>

          <div className="mt-2 flex items-end justify-between gap-6 border-b border-ink pb-5">
            <div className="min-w-0">
              <h2 id={titleId} className="condensed text-[44px] leading-[0.95] font-extrabold tracking-[-0.015em] text-ink">
                <span className="sr-only">Threat report: </span>{threat.origin.country}
              </h2>
              <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1.5">
                <span className="inline-flex items-center gap-1.5 text-[13px] font-medium text-ink">
                  <Swatch classification={threat.classification} />
                  {meta.label}, {meta.severity.toLowerCase()} severity
                </span>
                {ip && (
                  <button
                    type="button"
                    onClick={copyIp}
                    className="inline-flex items-center gap-1.5 font-mono text-[12.5px] text-ink-soft transition-colors hover:text-ink"
                    aria-label={`Copy IP address ${ip}`}
                  >
                    {ip}
                    {copied ? <CheckIcon size={13} weight="bold" aria-hidden="true" /> : <CopyIcon size={13} aria-hidden="true" />}
                  </button>
                )}
                {threat.synthetic && <Tag>Simulated</Tag>}
              </div>
            </div>
            <div className="shrink-0 text-right">
              <p className={cn('condensed text-[72px] leading-[0.8] font-extrabold tabular', meta.rank === 3 ? 'text-crit' : 'text-ink')}>
                {Math.round(threat.score)}
              </p>
              <p className="mt-1.5 text-xs text-ink-mute">score out of 100</p>
            </div>
          </div>
        </header>

        <div className="scroll-thin min-h-0 flex-1 space-y-7 overflow-y-auto px-6 pt-5 pb-7 sm:px-8 print:overflow-visible">
          <dl className="grid grid-cols-3 divide-x divide-rule [&>div]:px-4 [&>div:first-child]:pl-0">
            <SignalFigure label="AbuseIPDB score" meta={abuse} />
            <SignalFigure label="OTX pulse hits" meta={otx} />
            <SignalFigure label="Open ports" meta={ports} />
          </dl>

          <Block
            title="Incident summary"
            action={canSummarize && !summary && status !== 'error' && (
              <span data-print-hide>
                <Button variant="solid" onClick={generate} disabled={status === 'loading'}>
                  {status === 'loading' && <CircleNotchIcon size={13} className="animate-spin" aria-hidden="true" />}
                  {status === 'loading' ? 'Generating' : 'Generate summary'}
                </Button>
              </span>
            )}
          >
            {!canSummarize && (
              <p className="text-[13.5px] text-ink-mute">
                AI summaries are only available for live threats with a real source IP.
              </p>
            )}

            {canSummarize && !summary && status !== 'error' && (
              <p className="text-[13.5px] text-ink-mute" aria-live="polite">
                {status === 'loading' ? 'Asking the model for an incident summary.' : 'No summary generated yet.'}
              </p>
            )}

            {status === 'error' && (
              <div role="alert" className="flex items-center justify-between gap-3 bg-wash px-3 py-2.5">
                <span className="flex items-center gap-2 text-[13px] text-crit">
                  <WarningIcon size={15} weight="bold" aria-hidden="true" /> {error}
                </span>
                <Button variant="alert" onClick={generate}>Retry</Button>
              </div>
            )}

            {summary && (
              <div className="space-y-4">
                <p className="text-xs text-ink-mute">
                  Written by {summary.provider}. <span className="font-semibold text-ink">{RISK_LABEL[summary.risk] || `${summary.risk} risk`}</span>
                </p>
                {[['Assessment', summary.assessment], ['Technical analysis', summary.technical], ['Recommended action', summary.action]]
                  .filter(([, text]) => text)
                  .map(([label, text], index) => (
                    <div key={label}>
                      <h4 className="text-[13px] font-semibold text-ink">{label}</h4>
                      <p className={cn('mt-1 max-w-[65ch] leading-[1.6] text-ink', index === 0 ? 'text-[15px]' : 'text-[13.5px]')}>{text}</p>
                    </div>
                  ))}
              </div>
            )}
          </Block>

          <Block title="Classification">
            <p className="text-[13.5px] text-ink">
              {threat.ai?.used ? 'AI-assisted' : 'Rule engine'}
              {threat.ai?.used && threat.ai.confidence > 0 && <span className="text-ink-mute">, model confidence {Math.round(threat.ai.confidence)}%</span>}
            </p>
            <p className="mt-2 max-w-[65ch] text-[13.5px] leading-[1.6] text-ink-soft">{reasoning}</p>
          </Block>

          <p className="border-t border-rule pt-3 text-xs text-ink-mute">
            Maps to{' '}
            <a
              href={`https://attack.mitre.org/techniques/${mitre.id}/`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-0.5 font-medium text-ink underline decoration-rule underline-offset-[3px] transition-colors hover:decoration-ink"
            >
              MITRE ATT&amp;CK {mitre.id}, {mitre.name}
              <ArrowUpRightIcon size={12} aria-hidden="true" />
            </a>
          </p>
        </div>
      </motion.div>
    </motion.div>
  );
};

const ThreatReportModal = ({ threat, isOpen, onClose, aiProvider = 'auto' }) => (
  <AnimatePresence>
    {isOpen && threat && (
      <ReportDialog key={`${threat.id}|${aiProvider}`} threat={threat} onClose={onClose} aiProvider={aiProvider} />
    )}
  </AnimatePresence>
);

export default ThreatReportModal;
