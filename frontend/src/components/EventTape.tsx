import { bytes, clockTime } from '../format';
import type { EventView } from '../types';

interface Props {
  events: EventView[];
}

function detailOf(event: EventView): string {
  if (event.bytesTransferred) {
    return `${event.resource ?? ''} ${bytes(event.bytesTransferred)}`.trim();
  }
  return event.resource ?? event.eventSource ?? '';
}

/** The raw audit stream as it arrives, unfiltered. */
export function EventTape({ events }: Props) {
  return (
    <section className="tape" aria-labelledby="tape-heading">
      <h2 id="tape-heading">Event tape</h2>
      <ol aria-live="off">
        {events.map((event) => (
          <li key={event.eventId} data-outcome={event.outcome}>
            <span className="t-time">{clockTime(event.eventTime)}</span>
            <span className="t-region">{event.region ?? '—'}</span>
            <span className="t-actor">
              {event.actor} {event.eventName}
            </span>
            <span className="t-detail">{detailOf(event)}</span>
            <span className="t-outcome">
              {event.outcome === 'FAILURE' ? (event.errorCode ?? 'FAILURE') : 'ok'}
            </span>
          </li>
        ))}
      </ol>
    </section>
  );
}
