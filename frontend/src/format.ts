const NUMBER = new Intl.NumberFormat('en-US');
const BYTE_UNITS = ['B', 'KiB', 'MiB', 'GiB', 'TiB'] as const;

export function count(value: number | null | undefined): string {
  return value == null ? '—' : NUMBER.format(value);
}

/** Wall-clock time to hundredths, so two events in the same second stay distinguishable. */
export function clockTime(iso?: string | null): string {
  const date = iso ? new Date(iso) : new Date();
  if (Number.isNaN(date.getTime())) {
    return '--:--:--';
  }
  const hundredths = String(Math.floor(date.getMilliseconds() / 10)).padStart(2, '0');
  return `${date.toLocaleTimeString('en-GB', { hour12: false })}.${hundredths}`;
}

export function bytes(value: number): string {
  if (!value) {
    return '';
  }
  let size = value;
  let unit = 0;
  while (size >= 1024 && unit < BYTE_UNITS.length - 1) {
    size /= 1024;
    unit += 1;
  }
  return `${size.toFixed(size < 10 && unit > 0 ? 1 : 0)} ${BYTE_UNITS[unit]}`;
}

/** `impliedSpeedKmh` reads better as `Implied Speed Kmh` than as a raw evidence key. */
export function humanizeKey(key: string): string {
  const spaced = key.replace(/([a-z0-9])([A-Z])/g, '$1 $2');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
}

export function evidenceValue(value: unknown): string {
  if (value === null || value === undefined) {
    return '';
  }
  return typeof value === 'object' ? JSON.stringify(value) : String(value);
}

export function titleCase(severity: string): string {
  return severity.charAt(0) + severity.slice(1).toLowerCase();
}
