// @vitest-environment jsdom
import React from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { act, cleanup, fireEvent, render, screen } from '@testing-library/react';
import ThreatReportModal from './ThreatReportModal';

const baseThreat = (overrides = {}) => ({
  id: 'ip:8.8.4.4',
  type: 'DDoS',
  score: 88,
  classification: 'DDOS',
  signals: { abuseScore: 90, otxHits: 5, portExposure: 2 },
  sources: { abuseipdb: 'ok', otx: 'ok', shodan: 'ok' },
  ai: { used: false },
  origin: { country: 'Poland', ip: '8.8.4.4' },
  timestamp: new Date('2026-01-01T12:00:00Z'),
  synthetic: false,
  ...overrides,
});

const summaryResponse = () => ({
  ok: true,
  status: 200,
  json: async () => ({
    ai_summary: {
      used: true,
      executive_summary: 'Assessment text',
      technical_analysis: 'Technical text',
      recommended_action: 'Block the source',
      risk_level: 'HIGH',
      provider: 'gemini',
    },
  }),
});

afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('ThreatReportModal', () => {
  it('does not offer AI summaries for simulated threats', () => {
    render(<ThreatReportModal threat={baseThreat({ synthetic: true, origin: { country: 'Ukraine', ip: '' } })} isOpen onClose={() => {}} />);
    expect(screen.getByText(/only available for live threats/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /generate summary/i })).toBeNull();
  });

  it('closes on Escape and exposes an accessible dialog', () => {
    const onClose = vi.fn();
    render(<ThreatReportModal threat={baseThreat()} isOpen onClose={onClose} />);
    const dialog = screen.getByRole('dialog');
    expect(dialog.getAttribute('aria-modal')).toBe('true');
    expect(dialog.getAttribute('aria-labelledby')).toBeTruthy();
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(onClose).toHaveBeenCalled();
  });

  it('aborts the in-flight request when the dialog closes, so a late reply cannot land on another threat', async () => {
    let resolveFetch;
    let capturedSignal;
    vi.stubGlobal('fetch', vi.fn((url, options) => {
      capturedSignal = options.signal;
      return new Promise((resolve) => { resolveFetch = resolve; });
    }));

    const { rerender } = render(<ThreatReportModal threat={baseThreat()} isOpen onClose={() => {}} />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /generate summary/i }));
    });
    expect(capturedSignal.aborted).toBe(false);

    rerender(<ThreatReportModal threat={null} isOpen={false} onClose={() => {}} />);
    await act(async () => {});
    expect(capturedSignal.aborted).toBe(true);

    // The late response is ignored and nothing from threat A shows up for threat B.
    rerender(<ThreatReportModal threat={baseThreat({ id: 'ip:1.1.1.1', origin: { country: 'France', ip: '1.1.1.1' } })} isOpen onClose={() => {}} />);
    await act(async () => { resolveFetch(summaryResponse()); });
    expect(screen.queryByText('Assessment text')).toBeNull();
    expect(screen.getByText(/no summary generated yet/i)).toBeTruthy();
  });

  it('shows a readable error when no AI provider is configured', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ ai_summary: { used: false, reason_code: 'no_provider' } }),
    }));
    render(<ThreatReportModal threat={baseThreat({ id: 'ip:9.9.9.9', origin: { country: 'Spain', ip: '9.9.9.9' } })} isOpen onClose={() => {}} />);
    await act(async () => {
      fireEvent.click(screen.getByRole('button', { name: /generate summary/i }));
    });
    expect((await screen.findByRole('alert')).textContent).toMatch(/no ai provider/i);
  });
});
