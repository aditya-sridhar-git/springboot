import { Drills } from './components/Drills';
import { EventTape } from './components/EventTape';
import { Instruments } from './components/Instruments';
import { StatusRail } from './components/StatusRail';
import { ThreatBoard } from './components/ThreatBoard';
import { useDashboard } from './hooks/useDashboard';

export function App() {
  const { state, setAlertStatus, markSettled } = useDashboard();

  return (
    <>
      <StatusRail stats={state.stats} link={state.link} />
      <main>
        <ThreatBoard
          alerts={state.alerts}
          freshAlertIds={state.freshAlertIds}
          error={state.error}
          onSettled={markSettled}
          onStatusChange={setAlertStatus}
        />
        <Instruments stats={state.stats} />
        <Drills />
        <EventTape events={state.events} />
      </main>
    </>
  );
}
