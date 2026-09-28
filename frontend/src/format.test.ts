import { describe, expect, it } from 'vitest';
import { bytes, clockTime, count, evidenceValue, humanizeKey } from './format';

describe('format', () => {
  it('scales byte counts to the unit an analyst reads at a glance', () => {
    expect(bytes(0)).toBe('');
    expect(bytes(512)).toBe('512 B');
    expect(bytes(1024 * 1024)).toBe('1.0 MiB');
    expect(bytes(2.5 * 1024 * 1024 * 1024)).toBe('2.5 GiB');
    expect(bytes(64 * 1024 * 1024 * 1024)).toBe('64 GiB');
  });

  it('turns evidence keys into readable labels', () => {
    expect(humanizeKey('impliedSpeedKmh')).toBe('Implied Speed Kmh');
    expect(humanizeKey('bucket')).toBe('Bucket');
  });

  it('renders evidence values without leaking null into the panel', () => {
    expect(evidenceValue(null)).toBe('');
    expect(evidenceValue(undefined)).toBe('');
    expect(evidenceValue(false)).toBe('false');
    expect(evidenceValue(0)).toBe('0');
    expect(evidenceValue({ a: 1 })).toBe('{"a":1}');
  });

  it('falls back rather than printing Invalid Date', () => {
    expect(clockTime('nonsense')).toBe('--:--:--');
  });

  it('shows an em dash when a counter has not arrived yet', () => {
    expect(count(null)).toBe('—');
    expect(count(1234)).toBe('1,234');
  });
});
