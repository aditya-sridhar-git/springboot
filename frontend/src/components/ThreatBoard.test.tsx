import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { ThreatBoard } from './ThreatBoard';
import type { AlertView, Severity } from '../types';

function alert(id: string, severity: Severity, title: string): AlertView {
  return {
    id,
    ruleId: 'rule-' + id,
    ruleName: 'Rule ' + id,
    severity,
    riskScore: 80,
    title,
    description: 'Because the rule said so.',
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
    evidence: { failureCount: 5, grantee: null },
    ...{},
  };
}

const ALERTS = [
  alert('1', 'CRITICAL', 'Bucket made publicly readable'),
  alert('2', 'HIGH', 'Five failed sign-ins'),
  alert('3', 'MEDIUM', 'First resource in af-south-1'),
];

function renderBoard(overrides: Partial<Parameters<typeof ThreatBoard>[0]> = {}) {
  const onStatusChange = vi.fn().mockResolvedValue(undefined);
  render(
    <ThreatBoard
      alerts={ALERTS}
      freshAlertIds={new Set()}
      error={null}
      onSettled={vi.fn()}
      onStatusChange={onStatusChange}
      {...overrides}
    />,
  );
  return { onStatusChange };
}

describe('ThreatBoard', () => {
  it('lists every alert until a severity filter is chosen', async () => {
    renderBoard();
    expect(screen.getAllByRole('listitem')).toHaveLength(3);

    await userEvent.click(screen.getByRole('button', { name: 'Critical' }));

    const remaining = screen.getAllByRole('listitem');
    expect(remaining).toHaveLength(1);
    expect(within(remaining[0]!).getByText('Bucket made publicly readable')).toBeTruthy();
  });

  it('explains an empty filter instead of showing a blank board', async () => {
    render(
      <ThreatBoard
        alerts={[alert('1', 'CRITICAL', 'Only a critical one')]}
        freshAlertIds={new Set()}
        error={null}
        onSettled={vi.fn()}
        onStatusChange={vi.fn()}
      />,
    );

    await userEvent.click(screen.getByRole('button', { name: 'High' }));
    expect(screen.getByText('No high alerts on the board.')).toBeTruthy();
  });

  it('surfaces a connection failure rather than pretending the account is quiet', () => {
    render(
      <ThreatBoard
        alerts={[]}
        freshAlertIds={new Set()}
        error="Failed to fetch"
        onSettled={vi.fn()}
        onStatusChange={vi.fn()}
      />,
    );
    expect(screen.getByText(/Cannot reach the analyzer: Failed to fetch/)).toBeTruthy();
  });

  it('sends the triage decision for the alert that was acted on', async () => {
    const { onStatusChange } = renderBoard();

    await userEvent.click(screen.getAllByText('Why this fired')[1]!);
    await userEvent.click(screen.getAllByRole('button', { name: 'Acknowledge' })[1]!);

    expect(onStatusChange).toHaveBeenCalledWith('2', 'ACKNOWLEDGED');
  });
});
