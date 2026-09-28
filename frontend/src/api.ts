import type { AlertStatus, AlertView, EventView, Scenario, StatsSnapshot } from './types';

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(path, { headers: { Accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`${path} responded ${response.status}`);
  }
  return (await response.json()) as T;
}

export const api = {
  /** Served from the Redis hot cache, so a fresh dashboard paints without touching SQL. */
  recentAlerts: (limit = 40) => getJson<AlertView[]>(`/api/alerts/recent?limit=${limit}`),

  recentEvents: (limit = 25) => getJson<EventView[]>(`/api/events/recent?limit=${limit}`),

  stats: () => getJson<StatsSnapshot>('/api/stats'),

  scenarios: () => getJson<Scenario[]>('/api/simulator/scenarios'),

  async setAlertStatus(id: string, status: AlertStatus): Promise<AlertView> {
    const response = await fetch(`/api/alerts/${id}/status?status=${status}`, { method: 'POST' });
    if (!response.ok) {
      throw new Error(`Could not set status: ${response.status}`);
    }
    return (await response.json()) as AlertView;
  },

  async runDrill(scenarioId: string): Promise<number> {
    const response = await fetch(`/api/simulator/scenarios/${scenarioId}`, { method: 'POST' });
    const body = (await response.json()) as { eventsPublished?: number; error?: string };
    if (!response.ok) {
      throw new Error(body.error ?? `Drill failed: ${response.status}`);
    }
    return body.eventsPublished ?? 0;
  },
};

export function socketUrl(): string {
  const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
  return `${protocol}://${window.location.host}/ws/dashboard`;
}
