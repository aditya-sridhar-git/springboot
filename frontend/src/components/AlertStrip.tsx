import { Fragment, useEffect, useRef, useState } from 'react';
import { clockTime, evidenceValue, humanizeKey } from '../format';
import type { AlertStatus, AlertView } from '../types';

interface Props {
  alert: AlertView;
  isFresh: boolean;
  onSettled: (id: string) => void;
  onStatusChange: (id: string, status: AlertStatus) => Promise<void>;
}

const TRIAGE: Array<[string, AlertStatus]> = [
  ['Acknowledge', 'ACKNOWLEDGED'],
  ['Resolve', 'RESOLVED'],
  ['Mark false positive', 'FALSE_POSITIVE'],
];

const FLASH_MS = 2000;

export function AlertStrip({ alert, isFresh, onSettled, onStatusChange }: Props) {
  const [pending, setPending] = useState<AlertStatus | null>(null);
  const [failed, setFailed] = useState(false);
  const settledRef = useRef(onSettled);
  settledRef.current = onSettled;

  useEffect(() => {
    if (!isFresh) {
      return;
    }
    const timer = window.setTimeout(() => settledRef.current(alert.id), FLASH_MS);
    return () => window.clearTimeout(timer);
  }, [isFresh, alert.id]);

  const triage = async (status: AlertStatus) => {
    setPending(status);
    setFailed(false);
    try {
      await onStatusChange(alert.id, status);
    } catch {
      setFailed(true);
    } finally {
      setPending(null);
    }
  };

  const meta = [
    alert.severity,
    clockTime(alert.detectedAt),
    alert.ruleId,
    alert.region ?? 'global',
    alert.sourceIp ?? 'no source ip',
    alert.mitreTechnique ?? '',
  ];

  const evidence = Object.entries(alert.evidence ?? {});

  return (
    <li
      className={isFresh ? 'strip is-new' : 'strip'}
      data-severity={alert.severity}
      data-status={alert.status}
    >
      <div className="keel" />

      <div className="strip-body">
        <p className="strip-line">
          {meta.filter(Boolean).map((part, index) => (
            <span key={part} className={index === 0 ? 'sev' : undefined}>
              {part}
            </span>
          ))}
        </p>
        <h3 className="strip-title">{alert.title}</h3>

        <details>
          <summary>Why this fired</summary>
          <div className="detail">
            <p>{alert.description}</p>

            {evidence.length > 0 && (
              <dl className="evidence">
                {evidence.map(([key, value]) => (
                  <Fragment key={key}>
                    <dt>{humanizeKey(key)}</dt>
                    <dd>{evidenceValue(value)}</dd>
                  </Fragment>
                ))}
              </dl>
            )}

            <div className="triage">
              {TRIAGE.map(([label, status]) => (
                <button
                  key={status}
                  type="button"
                  disabled={pending !== null || alert.status === status}
                  onClick={() => void triage(status)}
                >
                  {pending === status ? 'Saving…' : label}
                </button>
              ))}
            </div>
            {failed && <p className="triage-error">That did not save. Try again.</p>}
          </div>
        </details>
      </div>

      <div className="strip-score">
        {alert.riskScore}
        <small>risk</small>
      </div>
    </li>
  );
}
