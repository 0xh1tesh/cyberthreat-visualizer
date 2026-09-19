import { describe, expect, it } from 'vitest';
import {
  ATTACK_TTL_MS,
  mergeAttackBuffer,
  normalizeAttackBatch,
  normalizeAttackData,
  toNewThreat,
} from './threat-normalize';
import { CLASS_META, classMeta } from './palette';
import { describeApiError, ApiError } from './api';

const raw = (overrides = {}) => ({
  id: 'ip-8.8.4.4',
  sourceIp: '8.8.4.4',
  sourceLat: 52.2,
  sourceLng: 21,
  sourceCountry: 'Poland',
  targetLat: 20,
  targetLng: 0,
  targetCountry: 'Unattributed',
  score: 82,
  classification: 'DDOS',
  type: 'DDoS',
  timestamp: Date.now(),
  signals: { abuseScore: 90, otxHits: 8, portExposure: 2 },
  sources: { abuseipdb: 'ok', otx: 'ok', shodan: 'ok' },
  provider: 'abuseipdb+otx+shodan',
  ...overrides,
});

describe('normalizeAttackData', () => {
  it('rejects records without usable coordinates', () => {
    expect(normalizeAttackData(raw({ sourceLat: 'x' }))).toBeNull();
    expect(normalizeAttackData(null)).toBeNull();
    expect(normalizeAttackBatch('nope')).toEqual([]);
  });

  it('keys identity on the source IP so a re-classified threat replaces itself', () => {
    const before = normalizeAttackData(raw({ classification: 'MALWARE', type: 'Malware', score: 60 }));
    const after = normalizeAttackData(raw());
    expect(before.id).toBe('ip:8.8.4.4');
    expect(after.id).toBe(before.id);
  });

  it('colours by classification from the single shared palette', () => {
    expect(normalizeAttackData(raw()).color).toBe(CLASS_META.DDOS.color);
    expect(normalizeAttackData(raw({ classification: 'LOW', score: 5 })).color).toBe(CLASS_META.LOW.color);
  });

  it('keeps simulation arcs distinct and marks them synthetic', () => {
    const a = normalizeAttackData({ ...raw({ sourceIp: '' }), id: 'sim-1', synthetic: true });
    const b = normalizeAttackData({ ...raw({ sourceIp: '' }), id: 'sim-2', synthetic: true });
    expect(a.synthetic).toBe(true);
    expect(a.id).toBe('sim-1');
    expect(a.id).not.toBe(b.id);
    expect(toNewThreat(a).origin.ip).toBe('');
    expect(toNewThreat(a).source).toBe('SIM');
  });
});

describe('mergeAttackBuffer', () => {
  const attack = (ip, timestamp, score = 50) => normalizeAttackData(raw({ id: `ip-${ip}`, sourceIp: ip, timestamp, score }));

  it('replaces an entry with the same id instead of duplicating it', () => {
    const now = Date.now();
    const merged = mergeAttackBuffer([attack('1.1.1.1', now - 5000, 40)], [attack('1.1.1.1', now, 90)], 24, now);
    expect(merged).toHaveLength(1);
    expect(merged[0].score).toBe(90);
  });

  it('expires threats that have not been re-observed', () => {
    const now = Date.now();
    const stale = attack('2.2.2.2', now - ATTACK_TTL_MS - 1000);
    const fresh = attack('3.3.3.3', now - 1000);
    const merged = mergeAttackBuffer([stale, fresh], [], 24, now);
    expect(merged.map((a) => a.sourceIp)).toEqual(['3.3.3.3']);
  });

  it('caps the buffer and keeps the newest entries', () => {
    const now = Date.now();
    const many = Array.from({ length: 30 }, (_, i) => attack(`4.4.4.${i}`, now - (30 - i) * 100));
    const merged = mergeAttackBuffer([], many, 24, now);
    expect(merged).toHaveLength(24);
    expect(merged.at(-1).sourceIp).toBe('4.4.4.29');
  });
});

describe('palette and api helpers', () => {
  it('falls back to the low-risk class for unknown values', () => {
    expect(classMeta('nonsense').key).toBe('LOW');
    expect(classMeta('ddos').key).toBe('DDOS');
  });

  it('describes API failures in plain language', () => {
    expect(describeApiError(new ApiError('x', { status: 429 }))).toMatch(/too many/i);
    expect(describeApiError(new ApiError('x', { code: 'network_error' }))).toMatch(/reach/i);
    expect(describeApiError({ code: 'no_provider' })).toMatch(/no ai provider/i);
    expect(describeApiError(new ApiError('x', { status: 503 }))).toMatch(/server/i);
  });
});
