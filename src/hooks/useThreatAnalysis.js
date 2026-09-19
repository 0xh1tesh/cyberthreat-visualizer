import { useCallback, useEffect, useRef, useState } from 'react';
import { apiFetch, describeApiError, isAbortError } from '../lib/api';
import { AI_CONFIDENCE_THRESHOLD } from './useThreatFeed';

const COOLDOWN_MS = 3000;

const clamp = (value, min, max) => Math.min(max, Math.max(min, Number(value) || 0));

/** Manual, per-threat AI classification. One request per threat at a time, with a short cooldown. */
export function useThreatAnalysis(provider) {
  const [states, setStates] = useState({});
  const controllers = useRef(new Map());
  const timers = useRef(new Set());

  useEffect(() => () => {
    controllers.current.forEach((controller) => controller.abort());
    timers.current.forEach((timer) => clearTimeout(timer));
  }, []);

  const patch = useCallback((id, next) => {
    setStates((previous) => ({ ...previous, [id]: { ...previous[id], ...next } }));
  }, []);

  const analyze = useCallback(async (threat) => {
    const id = threat?.id;
    if (!id || threat.synthetic || !threat.origin?.ip) return;
    if (controllers.current.has(id)) return;

    const controller = new AbortController();
    controllers.current.set(id, controller);
    patch(id, { status: 'loading', error: null });

    try {
      const data = await apiFetch('/analyze', {
        method: 'POST',
        signal: controller.signal,
        headers: {
          'X-AI-Provider': provider,
          'X-AI-Threshold': String(AI_CONFIDENCE_THRESHOLD),
        },
        body: {
          ip: threat.origin.ip,
          signals: {
            abuseScore: Number(threat.signals?.abuseScore ?? 0),
            otxHits: Number(threat.signals?.otxHits ?? 0),
            portExposure: Number(threat.signals?.portExposure ?? 0),
            country: threat.origin.country,
          },
        },
      });
      patch(id, {
        status: 'done',
        result: {
          type: String(data?.type || 'LOW').toUpperCase(),
          confidence: clamp(data?.confidence, 0, 100),
          reasoning: String(data?.reasoning || '').trim(),
          provider: String(data?.provider || 'ai'),
          latencyMs: Number(data?.latencyMs) || 0,
        },
      });
    } catch (err) {
      if (isAbortError(err)) return;
      patch(id, { status: 'error', error: describeApiError(err) });
    } finally {
      controllers.current.delete(id);
      const until = Date.now() + COOLDOWN_MS;
      patch(id, { cooldownUntil: until });
      const timer = setTimeout(() => {
        timers.current.delete(timer);
        patch(id, { cooldownUntil: 0 });
      }, COOLDOWN_MS);
      timers.current.add(timer);
    }
  }, [provider, patch]);

  return { states, analyze };
}
