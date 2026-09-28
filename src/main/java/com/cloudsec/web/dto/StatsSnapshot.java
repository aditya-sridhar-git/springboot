package com.cloudsec.web.dto;

import java.time.Instant;
import java.util.List;
import java.util.Map;

/** Everything the dashboard header and charts need, refreshed on a fixed cadence. */
public record StatsSnapshot(
        Instant generatedAt,
        long eventsIngested,
        long eventsLastHour,
        double eventsPerSecond,
        long alertsRaised,
        long alertsSuppressed,
        long openAlerts,
        Map<String, Long> alertsBySeverity,
        List<RuleCount> topRules,
        List<SourceCount> topSourceIps,
        List<Bucket> ingestTimeline,
        int connectedDashboards,
        Map<String, Object> pipelineHealth) {

    public record RuleCount(String ruleId, String ruleName, long count) {
    }

    public record SourceCount(String sourceIp, long count) {
    }

    /** One slot of the rolling ingest/alert sparkline. */
    public record Bucket(long epochSecond, long events, long alerts) {
    }
}
