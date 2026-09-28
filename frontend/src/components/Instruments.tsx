import { titleCase } from '../format';
import { SEVERITIES } from '../types';
import type { StatsSnapshot } from '../types';
import { Ledger, type LedgerRow } from './Ledger';
import { Sparkline } from './Sparkline';

interface Props {
  stats: StatsSnapshot | null;
}

export function Instruments({ stats }: Props) {
  const severityRows: LedgerRow[] = SEVERITIES.flatMap((severity) => {
    const value = stats?.alertsBySeverity[severity];
    return value ? [{ key: severity, label: titleCase(severity), value, severity }] : [];
  });

  const ruleRows: LedgerRow[] = (stats?.topRules ?? []).map((rule) => ({
    key: rule.ruleId,
    label: rule.ruleName,
    value: rule.count,
  }));

  const sourceRows: LedgerRow[] = (stats?.topSourceIps ?? []).map((source) => ({
    key: source.sourceIp,
    label: source.sourceIp,
    value: source.count,
  }));

  return (
    <aside className="instruments" aria-label="Pipeline instruments">
      <section className="instrument">
        <h2>Last five minutes</h2>
        <Sparkline timeline={stats?.ingestTimeline ?? []} />
      </section>

      <section className="instrument">
        <h2>Severity ledger</h2>
        <Ledger rows={severityRows} emptyText="No alerts raised yet." />
      </section>

      <section className="instrument">
        <h2>Rules firing today</h2>
        <Ledger rows={ruleRows} emptyText="No rule has fired in the last 24 hours." plain />
      </section>

      <section className="instrument">
        <h2>Loudest source addresses</h2>
        <Ledger rows={sourceRows} emptyText="No source address has drawn an alert yet." plain />
      </section>
    </aside>
  );
}
