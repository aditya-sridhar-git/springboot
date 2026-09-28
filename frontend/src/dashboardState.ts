import type { AlertView, EventView, LinkState, SocketFrame, StatsSnapshot } from './types';

/** How much history the browser keeps. The server holds the rest. */
export const MAX_ALERTS = 60;
export const MAX_EVENTS = 40;

export interface DashboardState {
  alerts: AlertView[];
  events: EventView[];
  stats: StatsSnapshot | null;
  link: LinkState;
  /** Ids that arrived over the socket rather than in the initial load, so they can flash once. */
  freshAlertIds: ReadonlySet<string>;
  error: string | null;
}

export const initialState: DashboardState = {
  alerts: [],
  events: [],
  stats: null,
  link: 'connecting',
  freshAlertIds: new Set(),
  error: null,
};

export type DashboardAction =
  | { type: 'seed'; alerts: AlertView[]; events: EventView[]; stats: StatsSnapshot }
  | { type: 'seed-failed'; message: string }
  | { type: 'frame'; frame: SocketFrame }
  | { type: 'link'; link: LinkState }
  | { type: 'settled'; id: string };

function prependAlert(alerts: AlertView[], incoming: AlertView): AlertView[] {
  if (alerts.some((alert) => alert.id === incoming.id)) {
    return alerts;
  }
  return [incoming, ...alerts].slice(0, MAX_ALERTS);
}

export function dashboardReducer(state: DashboardState, action: DashboardAction): DashboardState {
  switch (action.type) {
    case 'seed':
      return {
        ...state,
        // The REST snapshot is oldest-first from the cache; the board reads newest-first.
        alerts: action.alerts.slice(0, MAX_ALERTS),
        events: action.events.slice(0, MAX_EVENTS),
        stats: action.stats,
        error: null,
      };

    case 'seed-failed':
      return { ...state, error: action.message };

    case 'link':
      return { ...state, link: action.link };

    case 'settled': {
      if (!state.freshAlertIds.has(action.id)) {
        return state;
      }
      const fresh = new Set(state.freshAlertIds);
      fresh.delete(action.id);
      return { ...state, freshAlertIds: fresh };
    }

    case 'frame':
      switch (action.frame.type) {
        case 'alert': {
          const alert = action.frame.data;
          const alerts = prependAlert(state.alerts, alert);
          if (alerts === state.alerts) {
            return state;
          }
          return { ...state, alerts, freshAlertIds: new Set(state.freshAlertIds).add(alert.id) };
        }

        case 'alert-updated': {
          const updated = action.frame.data;
          return {
            ...state,
            alerts: state.alerts.map((alert) => (alert.id === updated.id ? updated : alert)),
          };
        }

        case 'events': {
          const arriving = [...action.frame.data].reverse();
          return { ...state, events: [...arriving, ...state.events].slice(0, MAX_EVENTS) };
        }

        case 'stats':
          return { ...state, stats: action.frame.data };

        default:
          return state;
      }

    default:
      return state;
  }
}

/** Narrows an untrusted socket payload to a frame the reducer understands. */
export function parseFrame(raw: string): SocketFrame | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (
      typeof parsed === 'object' &&
      parsed !== null &&
      'type' in parsed &&
      typeof (parsed as { type: unknown }).type === 'string'
    ) {
      return parsed as SocketFrame;
    }
  } catch {
    // A frame we cannot read is dropped rather than allowed to break the board.
  }
  return null;
}
