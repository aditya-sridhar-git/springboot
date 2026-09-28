/** Mirrors the DTOs in com.cloudsec.web.dto. */

export const SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'] as const;
export type Severity = (typeof SEVERITIES)[number];

export type AlertStatus = 'OPEN' | 'ACKNOWLEDGED' | 'RESOLVED' | 'FALSE_POSITIVE';
export type Outcome = 'SUCCESS' | 'FAILURE';

export interface AlertView {
  id: string;
  ruleId: string;
  ruleName: string;
  severity: Severity;
  riskScore: number;
  title: string;
  description: string;
  mitreTechnique: string | null;
  accountId: string | null;
  principalId: string | null;
  userName: string | null;
  sourceIp: string | null;
  region: string | null;
  eventName: string | null;
  resource: string | null;
  triggerEventId: string | null;
  eventTime: string | null;
  detectedAt: string;
  status: AlertStatus;
  evidence: Record<string, unknown>;
}

export interface EventView {
  eventId: string;
  eventTime: string;
  provider: string;
  eventName: string;
  eventSource: string | null;
  region: string | null;
  actor: string;
  principalType: string | null;
  sourceIp: string | null;
  outcome: Outcome;
  errorCode: string | null;
  resource: string | null;
  bytesTransferred: number;
}

export interface RuleCount {
  ruleId: string;
  ruleName: string;
  count: number;
}

export interface SourceCount {
  sourceIp: string;
  count: number;
}

export interface TimelineBucket {
  epochSecond: number;
  events: number;
  alerts: number;
}

export interface StatsSnapshot {
  generatedAt: string;
  eventsIngested: number;
  eventsLastHour: number;
  eventsPerSecond: number;
  alertsRaised: number;
  alertsSuppressed: number;
  openAlerts: number;
  alertsBySeverity: Partial<Record<Severity, number>>;
  topRules: RuleCount[];
  topSourceIps: SourceCount[];
  ingestTimeline: TimelineBucket[];
  connectedDashboards: number;
  pipelineHealth: Record<string, unknown>;
}

export interface Scenario {
  id: string;
  label: string;
  description: string;
}

/** Frames pushed by DashboardSocketHandler. */
export type SocketFrame =
  | { type: 'alert'; data: AlertView }
  | { type: 'alert-updated'; data: AlertView }
  | { type: 'events'; data: EventView[] }
  | { type: 'stats'; data: StatsSnapshot }
  | { type: 'pong'; data: unknown };

export type LinkState = 'connecting' | 'live' | 'lost';

export type SeverityFilter = Severity | 'ALL';
