import { useEffect, useState } from 'react';
import { api } from '../api';
import type { Scenario } from '../types';

type DrillState = { status: 'idle' } | { status: 'running' } | { status: 'sent'; events: number } | { status: 'failed' };

const RESET_MS = 2500;

export function Drills() {
  const [scenarios, setScenarios] = useState<Scenario[]>([]);
  const [unavailable, setUnavailable] = useState(false);
  const [drillStates, setDrillStates] = useState<Record<string, DrillState>>({});

  useEffect(() => {
    let cancelled = false;
    void api
      .scenarios()
      .then((list) => {
        if (!cancelled) setScenarios(list);
      })
      .catch(() => {
        if (!cancelled) setUnavailable(true);
      });
    return () => {
      cancelled = true;
    };
  }, []);

  const run = async (scenario: Scenario) => {
    setDrillStates((current) => ({ ...current, [scenario.id]: { status: 'running' } }));
    try {
      const events = await api.runDrill(scenario.id);
      setDrillStates((current) => ({ ...current, [scenario.id]: { status: 'sent', events } }));
    } catch {
      setDrillStates((current) => ({ ...current, [scenario.id]: { status: 'failed' } }));
    }
    window.setTimeout(
      () => setDrillStates((current) => ({ ...current, [scenario.id]: { status: 'idle' } })),
      RESET_MS,
    );
  };

  const labelFor = (scenario: Scenario) => {
    const state = drillStates[scenario.id] ?? { status: 'idle' };
    switch (state.status) {
      case 'running':
        return `${scenario.label} · sending`;
      case 'sent':
        return `${scenario.label} · ${state.events} sent`;
      case 'failed':
        return `${scenario.label} · failed`;
      default:
        return scenario.label;
    }
  };

  return (
    <section className="drills" aria-labelledby="drills-heading">
      <div className="drills-head">
        <h2 id="drills-heading">Run a drill</h2>
        <p>
          Replays a real attack sequence through Kafka. The rules see it exactly as they would see the
          real thing.
        </p>
      </div>

      {unavailable ? (
        <p className="empty">
          Drills are unavailable — this analyzer is reading a live audit feed.
        </p>
      ) : (
        <div className="drill-set">
          {scenarios.map((scenario) => {
            const state = drillStates[scenario.id] ?? { status: 'idle' };
            return (
              <button
                key={scenario.id}
                type="button"
                className={state.status === 'sent' ? 'drill is-sent' : 'drill'}
                title={scenario.description}
                disabled={state.status === 'running'}
                onClick={() => void run(scenario)}
              >
                {labelFor(scenario)}
              </button>
            );
          })}
        </div>
      )}
    </section>
  );
}
