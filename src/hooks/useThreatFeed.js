import { useCallback, useEffect, useState } from 'react';
import { apiFetch, isAbortError } from '../lib/api';
import { mergeAttackBuffer, normalizeAttackBatch } from '../lib/threat-normalize';

export const POLL_INTERVAL_MS = 8000;
const MAX_BACKOFF_MS = 60000;
export const AI_CONFIDENCE_THRESHOLD = 70;
export const HISTORY_WINDOW_MS = 10 * 60 * 1000;

/**
 * Polls the threat API. Requests never overlap, are aborted on change/unmount, back off
 * after failures, and pause while the tab is hidden.
 * status: 'connecting' | 'live' | 'degraded' | 'offline'
 */
export function useThreatFeed({ enabled, provider }) {
  const [attacks, setAttacks] = useState([]);
  const [health, setHealth] = useState(null);
  const [aiHealth, setAiHealth] = useState(null);
  const [status, setStatus] = useState('connecting');
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [history, setHistory] = useState([]);
  const [meta, setMeta] = useState({ cached: false, degraded: false, degradedReason: null });
  const [refreshToken, setRefreshToken] = useState(0);

  const refresh = useCallback(() => setRefreshToken((value) => value + 1), []);

  useEffect(() => {
    if (!enabled) return undefined;

    const controller = new AbortController();
    const { signal } = controller;
    const headers = {
      'X-AI-Provider': provider,
      'X-AI-Threshold': String(AI_CONFIDENCE_THRESHOLD),
    };

    let timer = null;
    let failures = 0;
    let inFlight = false;
    let disposed = false;

    const schedule = (delay) => {
      if (disposed) return;
      clearTimeout(timer);
      timer = setTimeout(tick, delay);
    };

    async function tick() {
      if (disposed || inFlight) return;
      if (document.hidden) {
        schedule(POLL_INTERVAL_MS);
        return;
      }

      inFlight = true;
      try {
        const [threatsResult, healthResult, aiResult] = await Promise.allSettled([
          apiFetch('/threats', { signal, headers }),
          apiFetch('/health', { signal, headers }),
          apiFetch('/ai/health', { signal, headers }),
        ]);
        if (disposed) return;

        if (healthResult.status === 'fulfilled') setHealth(healthResult.value);
        if (aiResult.status === 'fulfilled') setAiHealth(aiResult.value);

        if (threatsResult.status === 'fulfilled') {
          const data = threatsResult.value;
          const incoming = normalizeAttackBatch(data?.attacks);
          setAttacks((previous) => mergeAttackBuffer(previous, incoming));
          // Cached replies repeat the previous cycle, so only fresh cycles count as new observations.
          if (!data?.cached) {
            const observedAt = Date.now();
            setHistory((previous) => [
              ...previous.filter((item) => observedAt - item.timestamp <= HISTORY_WINDOW_MS),
              ...incoming.map((attack) => ({ timestamp: observedAt, classification: attack.classification })),
            ]);
          }
          setMeta({
            cached: Boolean(data?.cached),
            degraded: Boolean(data?.degraded),
            degradedReason: data?.degradedReason || null,
          });
          setStatus(data?.degraded ? 'degraded' : 'live');
          setError(null);
          setLastUpdated(Date.now());
          failures = 0;
        } else {
          const reason = threatsResult.reason;
          if (isAbortError(reason)) return;
          failures += 1;
          setStatus('offline');
          setError(reason);
          // Expire stale data even while offline so old arcs do not linger forever.
          setAttacks((previous) => mergeAttackBuffer(previous, []));
        }
      } finally {
        inFlight = false;
        const delay = failures === 0
          ? POLL_INTERVAL_MS
          : Math.min(MAX_BACKOFF_MS, POLL_INTERVAL_MS * 2 ** Math.min(failures, 4));
        schedule(delay);
      }
    }

    const onVisibility = () => {
      if (!document.hidden && !inFlight) schedule(0);
    };
    document.addEventListener('visibilitychange', onVisibility);

    tick();

    return () => {
      disposed = true;
      controller.abort();
      clearTimeout(timer);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [enabled, provider, refreshToken]);

  return { attacks, history, health, aiHealth, status, error, lastUpdated, meta, refresh };
}
