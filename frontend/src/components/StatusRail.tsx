import { count } from '../format';
import type { LinkState, StatsSnapshot } from '../types';

interface Props {
  stats: StatsSnapshot | null;
  link: LinkState;
}

const LINK_LABEL: Record<LinkState, string> = {
  connecting: 'Connecting',
  live: 'Live',
  lost: 'Reconnecting',
};

export function StatusRail({ stats, link }: Props) {
  const readouts: Array<[string, string]> = [
    ['Ingest', stats ? `${stats.eventsPerSecond.toFixed(1)}/s` : '—'],
    ['Events seen', count(stats?.eventsIngested)],
    ['Alerts raised', count(stats?.alertsRaised)],
    ['Open', count(stats?.openAlerts)],
    ['Suppressed', count(stats?.alertsSuppressed)],
  ];

  return (
    <header className="rail">
      <div className="rail-identity">
        <span className="mark" aria-hidden="true" />
        <h1>Sentinel</h1>
        <p>Cloud audit analyzer</p>
      </div>

      <dl className="rail-readout">
        {readouts.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{value}</dd>
          </div>
        ))}
      </dl>

      <p className="rail-link" data-state={link}>
        <span className="beacon" aria-hidden="true" />
        <span>{LINK_LABEL[link]}</span>
      </p>
    </header>
  );
}
