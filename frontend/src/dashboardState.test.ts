import { describe, expect, it } from 'vitest';
import { MAX_ALERTS, MAX_EVENTS, dashboardReducer, initialState, parseFrame } from './dashboardState';
import type { DashboardState as State } from './dashboardState';
import type { AlertView, EventView } from './types';

function alert(id: string, overrides: Partial<AlertView> = {}): AlertView {
  return {
    id,
    ruleId: 'brute-force-login',
    ruleName: 'Brute force console login',
    severity: 'HIGH',
    riskScore: 75,
    title: `Alert ${id}`,
    description: 'why',
    mitreTechnique: 'T1110',
    accountId: '123456789012',
    principalId: 'AIDA1',
    userName: 'alice.chen',
    sourceIp: '203.0.113.9',
    region: 'us-east-1',
    eventName: 'ConsoleLogin',
    resource: null,
    triggerEventId: 'e1',
    eventTime: '2026-09-11T00:00:00Z',
    detectedAt: '2026-09-11T00:00:01Z',
    status: 'OPEN',
    evidence: { failureCount: 5 },
    ...overrides,
  };
}

function event(id: string): EventView {
  return {
    eventId: id,
    eventTime: '2026-09-11T00:00:00Z',
    provider: 'AWS',
    eventName: 'DescribeInstances',
    eventSource: 'ec2.amazonaws.com',
    region: 'us-east-1',
    actor: 'deploy-bot',
    principalType: 'AssumedRole',
    sourceIp: '10.0.0.4',
    outcome: 'SUCCESS',
    errorCode: null,
    resource: 'i-abc',
    bytesTransferred: 0,
  };
}

const push = (state: State, frames: Parameters<typeof dashboardReducer>[1][]): State =>
  frames.reduce(dashboardReducer, state);

describe('dashboardReducer', () => {
  it('puts a newly raised alert at the top and marks it fresh', () => {
    const state = push(initialState, [
      { type: 'frame', frame: { type: 'alert', data: alert('a') } },
      { type: 'frame', frame: { type: 'alert', data: alert('b') } },
    ]);

    expect(state.alerts.map((a) => a.id)).toEqual(['b', 'a']);
    expect([...state.freshAlertIds]).toEqual(['a', 'b']);
  });

  it('ignores an alert it has already shown', () => {
    const once = dashboardReducer(initialState, { type: 'frame', frame: { type: 'alert', data: alert('a') } });
    const twice = dashboardReducer(once, { type: 'frame', frame: { type: 'alert', data: alert('a') } });

    expect(twice).toBe(once);
    expect(twice.alerts).toHaveLength(1);
  });

  it('caps the board so a long shift cannot grow the DOM without bound', () => {
    const state = push(
      initialState,
      Array.from({ length: MAX_ALERTS + 25 }, (_, i) => ({
        type: 'frame' as const,
        frame: { type: 'alert' as const, data: alert(`a${i}`) },
      })),
    );

    expect(state.alerts).toHaveLength(MAX_ALERTS);
    expect(state.alerts[0]?.id).toBe(`a${MAX_ALERTS + 24}`);
  });

  it('applies a triage update in place without reordering the board', () => {
    const seeded = push(initialState, [
      { type: 'frame', frame: { type: 'alert', data: alert('a') } },
      { type: 'frame', frame: { type: 'alert', data: alert('b') } },
    ]);

    const state = dashboardReducer(seeded, {
      type: 'frame',
      frame: { type: 'alert-updated', data: alert('a', { status: 'RESOLVED' }) },
    });

    expect(state.alerts.map((a) => a.id)).toEqual(['b', 'a']);
    expect(state.alerts[1]?.status).toBe('RESOLVED');
  });

  it('shows the newest event first and caps the tape', () => {
    const state = dashboardReducer(initialState, {
      type: 'frame',
      frame: { type: 'events', data: Array.from({ length: MAX_EVENTS + 10 }, (_, i) => event(`e${i}`)) },
    });

    expect(state.events).toHaveLength(MAX_EVENTS);
    expect(state.events[0]?.eventId).toBe(`e${MAX_EVENTS + 9}`);
  });

  it('clears the fresh flag once a strip has finished flashing', () => {
    const raised = dashboardReducer(initialState, { type: 'frame', frame: { type: 'alert', data: alert('a') } });
    const settled = dashboardReducer(raised, { type: 'settled', id: 'a' });

    expect(settled.freshAlertIds.has('a')).toBe(false);
  });

  it('tracks the link state so the rail can report a dropped connection', () => {
    expect(dashboardReducer(initialState, { type: 'link', link: 'lost' }).link).toBe('lost');
  });
});

describe('parseFrame', () => {
  it('accepts a well-formed frame', () => {
    expect(parseFrame('{"type":"stats","data":{}}')).toEqual({ type: 'stats', data: {} });
  });

  it('drops anything it cannot read rather than throwing', () => {
    expect(parseFrame('not json')).toBeNull();
    expect(parseFrame('{"nope":1}')).toBeNull();
    expect(parseFrame('[]')).toBeNull();
  });
});
