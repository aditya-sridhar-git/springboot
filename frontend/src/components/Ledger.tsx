import { count } from '../format';
import type { Severity } from '../types';

export interface LedgerRow {
  key: string;
  label: string;
  value: number;
  severity?: Severity;
}

interface Props {
  rows: LedgerRow[];
  emptyText: string;
  plain?: boolean;
}

/** A label, a number, and a bar showing its share of the largest row. */
export function Ledger({ rows, emptyText, plain = false }: Props) {
  if (rows.length === 0) {
    return (
      <ul className={plain ? 'ledger ledger-plain' : 'ledger'}>
        <li className="quiet">{emptyText}</li>
      </ul>
    );
  }

  const peak = Math.max(...rows.map((row) => row.value), 1);

  return (
    <ul className={plain ? 'ledger ledger-plain' : 'ledger'}>
      {rows.map((row) => (
        <li key={row.key} data-severity={row.severity}>
          <span className="label">{row.label}</span>
          <span className="count">{count(row.value)}</span>
          <span className="bar">
            <span style={{ width: `${Math.max(2, (row.value / peak) * 100)}%` }} />
          </span>
        </li>
      ))}
    </ul>
  );
}
