import React, { useCallback, useEffect, useId, useMemo, useRef, useState } from 'react';
import { AnimatePresence, motion } from 'motion/react';
import { AlertCircle, Check, Copy, ExternalLink, Loader2, Sparkles, X } from 'lucide-react';
import { Badge, IconButton } from './ui';
import { cn } from '../lib/utils';
import { apiFetch, describeApiError, isAbortError } from '../lib/api';
import { classMeta, TONE } from '../lib/palette';
import { getSignalDisplayMeta } from '../lib/threat-normalize';

const SUMMARY_TTL_MS = 7 * 60 * 1000;
const summaryCache = new Map();

const MITRE_MAP = {
  DDOS: { id: 'T1499', name: 'Endpoint Denial of Service' },
  MALWARE: { id: 'T1204', name: 'User Execution' },
  SCAN: { id: 'T1595', name: 'Active Scanning' },
  LOW: { id: 'T1595', name: 'Active Scanning' },
};

const RISK_TONE = { HIGH: 'text-crit', MEDIUM: 'text-warn', LOW: 'text-ok' };

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

const Section = ({ title, children, action }) => (
  <section className="space-y-3">
    <div className="flex items-center justify-between gap-3">
      <h3 className="text-[13px] font-semibold text-ink">{title}</h3>
      {action}
    </div>
    {children}
  </section>
);

const SignalTile = ({ label, meta }) => (
  <div className="rounded-lg border border-line bg-canvas p-3" title={meta.tooltip || undefined}>
    <p className="text-2xs font-medium uppercase tracking-wide text-ink-faint">{label}</p>
    <p className={cn('mt-1 text-lg font-semibold tabular', meta.faded ? 'text-ink-faint' : 'text-ink')}>
      {meta.faded ? 'Unavailable' : meta.text}
    </p>
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
  const tone = TONE[meta.tone];

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
          className="fixed inset-0 z-50 grid place-items-end bg-black/70 sm:place-items-center sm:p-4"
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
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: 16 }}
            transition={{ duration: 0.18, ease: 'easeOut' }}
            className="flex max-h-[100dvh] w-full flex-col overflow-hidden rounded-t-2xl border border-line bg-surface sm:max-h-[86vh] sm:max-w-2xl sm:rounded-2xl"
          >
            <header className="flex items-start justify-between gap-4 border-b border-line px-5 py-4">
              <div className="min-w-0">
                <div className="flex flex-wrap items-center gap-2">
                  <h2 id={titleId} className="text-base font-semibold text-ink">Threat report</h2>
                  <Badge tone={meta.tone}>{meta.label}</Badge>
                  {threat.synthetic && <Badge tone="info">Simulated</Badge>}
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-ink-muted">
                  <span>{threat.origin.country}</span>
                  {ip && (
                    <button
                      type="button"
                      onClick={copyIp}
                      className="inline-flex items-center gap-1.5 font-mono text-ink hover:text-info"
                      aria-label={`Copy IP address ${ip}`}
                    >
                      {ip}
                      {copied ? <Check size={12} className="text-ok" aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                    </button>
                  )}
                  <time className="tabular" dateTime={threat.timestamp.toISOString()}>{threat.timestamp.toLocaleString()}</time>
                </div>
              </div>
              <div className="flex shrink-0 items-start gap-3">
                <div className="text-right">
                  <p className={cn('text-3xl font-semibold leading-8 tabular', tone.text)}>{Math.round(threat.score)}</p>
                  <p className="text-2xs text-ink-faint">threat score</p>
                </div>
                <IconButton label="Close report" onClick={onClose} data-autofocus>
                  <X size={15} aria-hidden="true" />
                </IconButton>
              </div>
            </header>

            <div className="scroll-thin min-h-0 flex-1 space-y-6 overflow-y-auto px-5 py-5">
              <Section title="Signals">
                <div className="grid grid-cols-3 gap-3">
                  <SignalTile label="Abuse score" meta={abuse} />
                  <SignalTile label="OTX hits" meta={otx} />
                  <SignalTile label="Open ports" meta={ports} />
                </div>
              </Section>

              <Section
                title="AI incident summary"
                action={canSummarize && !summary && status !== 'error' && (
                  <button
                    type="button"
                    onClick={generate}
                    disabled={status === 'loading'}
                    className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-raised px-3 py-1.5 text-xs font-medium text-ink transition-colors hover:border-line-strong disabled:cursor-not-allowed disabled:opacity-60"
                  >
                    {status === 'loading' ? <Loader2 size={13} className="animate-spin" aria-hidden="true" /> : <Sparkles size={13} className="text-ai" aria-hidden="true" />}
                    {status === 'loading' ? 'Generating' : 'Generate summary'}
                  </button>
                )}
              >
                {!canSummarize && (
                  <p className="rounded-lg border border-line bg-canvas p-4 text-[13px] text-ink-muted">
                    AI summaries are only available for live threats with a real source IP.
                  </p>
                )}

                {canSummarize && !summary && status !== 'error' && (
                  <p className="rounded-lg border border-line bg-canvas p-4 text-[13px] text-ink-muted" aria-live="polite">
                    {status === 'loading' ? 'Asking the model for an incident summary…' : 'No summary generated yet.'}
                  </p>
                )}

                {status === 'error' && (
                  <div role="alert" className="flex items-center justify-between gap-3 rounded-lg border border-warn/30 bg-warn/10 p-4">
                    <span className="flex items-center gap-2 text-[13px] text-warn">
                      <AlertCircle size={15} aria-hidden="true" /> {error}
                    </span>
                    <button type="button" onClick={generate} className="rounded-md border border-warn/40 px-2.5 py-1 text-xs font-medium text-warn hover:bg-warn/10">
                      Retry
                    </button>
                  </div>
                )}

                {summary && (
                  <div className="space-y-4 rounded-lg border border-ai/30 bg-ai/5 p-4">
                    <div className="flex items-center gap-2">
                      <Badge tone="ai"><Sparkles size={11} aria-hidden="true" /> {summary.provider}</Badge>
                      <span className={cn('text-xs font-medium', RISK_TONE[summary.risk] || 'text-warn')}>{summary.risk} risk</span>
                    </div>
                    {[['Assessment', summary.assessment], ['Technical analysis', summary.technical], ['Recommended action', summary.action]]
                      .filter(([, text]) => text)
                      .map(([label, text]) => (
                        <div key={label}>
                          <p className="text-2xs font-medium uppercase tracking-wide text-ink-faint">{label}</p>
                          <p className="mt-1 text-[13px] leading-6 text-ink">{text}</p>
                        </div>
                      ))}
                  </div>
                )}
              </Section>

              <Section title="Classification">
                <div className="space-y-3 rounded-lg border border-line bg-canvas p-4 text-[13px]">
                  <div className="flex items-center justify-between">
                    <span className="text-ink-muted">Method</span>
                    <span className="text-ink">{threat.ai?.used ? 'AI-assisted' : 'Rule engine'}</span>
                  </div>
                  {threat.ai?.used && threat.ai.confidence > 0 && (
                    <div className="flex items-center justify-between">
                      <span className="text-ink-muted">Model confidence</span>
                      <span className="tabular text-ink">{Math.round(threat.ai.confidence)}%</span>
                    </div>
                  )}
                  <p className="border-t border-line pt-3 leading-6 text-ink-muted">{reasoning}</p>
                </div>
                <a
                  href={`https://attack.mitre.org/techniques/${mitre.id}/`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-2 rounded-md border border-line px-2.5 py-1.5 font-mono text-xs text-ink-muted transition-colors hover:border-line-strong hover:text-ink"
                >
                  MITRE ATT&amp;CK {mitre.id} · {mitre.name}
                  <ExternalLink size={12} aria-hidden="true" />
                </a>
              </Section>
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
