import { useMemo, useState } from 'react';
import type { AlertStatus, AlertView, SeverityFilter } from '../types';
import { AlertStrip } from './AlertStrip';

interface Props {
  alerts: AlertView[];
  freshAlertIds: ReadonlySet<string>;
  error: string | null;
  onSettled: (id: string) => void;
  onStatusChange: (id: string, status: AlertStatus) => Promise<void>;
}

const FILTERS: Array<[SeverityFilter, string]> = [
  ['ALL', 'All'],
  ['CRITICAL', 'Critical'],
  ['HIGH', 'High'],
  ['MEDIUM', 'Medium'],
];

export function ThreatBoard({ alerts, freshAlertIds, error, onSettled, onStatusChange }: Props) {
  const [filter, setFilter] = useState<SeverityFilter>('ALL');

  const visible = useMemo(
    () => (filter === 'ALL' ? alerts : alerts.filter((alert) => alert.severity === filter)),
    [alerts, filter],
  );

  return (
    <section className="board" aria-labelledby="board-heading">
      <div className="board-head">
        <h2 id="board-heading">Threat board</h2>
        <div className="filters" role="group" aria-label="Filter alerts by severity">
          {FILTERS.map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={filter === value ? 'filter is-on' : 'filter'}
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>

      {visible.length === 0 ? (
        <p className="empty">
          {error
            ? `Cannot reach the analyzer: ${error}`
            : filter === 'ALL'
              ? 'Nothing detected yet. The analyzer is watching the stream — start a drill below to see it work.'
              : `No ${filter.toLowerCase()} alerts on the board.`}
        </p>
      ) : (
        <ol className="strips">
          {visible.map((alert) => (
            <AlertStrip
              key={alert.id}
              alert={alert}
              isFresh={freshAlertIds.has(alert.id)}
              onSettled={onSettled}
              onStatusChange={onStatusChange}
            />
          ))}
        </ol>
      )}
    </section>
  );
}
