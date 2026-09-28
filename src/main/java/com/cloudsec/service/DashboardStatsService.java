package com.cloudsec.service;

import com.cloudsec.config.SimulatorProperties;
import com.cloudsec.engine.DetectionEngine;
import com.cloudsec.model.AlertStatus;
import com.cloudsec.repository.AuditEventRepository;
import com.cloudsec.repository.SecurityAlertRepository;
import com.cloudsec.state.AnalyzerStateStore;
import com.cloudsec.web.DashboardSocketHandler;
import com.cloudsec.web.dto.StatsSnapshot;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

/**
 * Aggregates the numbers behind the dashboard.
 *
 * <p>Counters and the sparkline come from Redis so they are cheap to read at 2 Hz. The heavier
 * grouped queries hit PostgreSQL, so they are refreshed on a slower cadence and cached in between.
 */
@Service
public class DashboardStatsService {

    private static final Logger log = LoggerFactory.getLogger(DashboardStatsService.class);
    private static final Duration SLOW_STATS_TTL = Duration.ofSeconds(10);
    private static final int TIMELINE_BUCKETS = 60;
    private static final String COUNTERS_KEY = "counters";

    /** Query results that are too expensive to recompute on every push. */
    private record SlowStats(Instant computedAt, long openAlerts, long eventsLastHour,
                             List<StatsSnapshot.RuleCount> topRules,
                             List<StatsSnapshot.SourceCount> topSourceIps) {
    }

    private final AnalyzerStateStore state;
    private final SecurityAlertRepository alertRepository;
    private final AuditEventRepository eventRepository;
    private final DashboardSocketHandler socket;
    private final DetectionEngine engine;
    private final SimulatorProperties simulatorProperties;
    private final AtomicReference<SlowStats> slowStats =
            new AtomicReference<>(new SlowStats(Instant.EPOCH, 0, 0, List.of(), List.of()));
    private final AtomicLong openAlertsGauge = new AtomicLong();

    public DashboardStatsService(AnalyzerStateStore state,
                                 SecurityAlertRepository alertRepository,
                                 AuditEventRepository eventRepository,
                                 DashboardSocketHandler socket,
                                 DetectionEngine engine,
                                 SimulatorProperties simulatorProperties,
                                 MeterRegistry meters) {
        this.state = state;
        this.alertRepository = alertRepository;
        this.eventRepository = eventRepository;
        this.socket = socket;
        this.engine = engine;
        this.simulatorProperties = simulatorProperties;
        Gauge.builder("cloudsec.alerts.open", openAlertsGauge, AtomicLong::doubleValue)
                .description("Alerts still awaiting triage")
                .register(meters);
        Gauge.builder("cloudsec.dashboard.clients", socket, DashboardSocketHandler::connectedClients)
                .description("Dashboards currently attached over WebSocket")
                .register(meters);
    }

    public StatsSnapshot snapshot() {
        Instant now = Instant.now();
        Map<String, Long> counters = state.counters(COUNTERS_KEY);
        SlowStats slow = refreshSlowStats(now);
        openAlertsGauge.set(slow.openAlerts());

        List<StatsSnapshot.Bucket> timeline = timeline(now);
        int recentBuckets = Math.min(12, timeline.size());
        long recentEvents = timeline.stream()
                .skip(timeline.size() - recentBuckets)
                .mapToLong(StatsSnapshot.Bucket::events)
                .sum();
        double perSecond = recentEvents / (double) (recentBuckets * EventIngestService.BUCKET_SECONDS);

        Map<String, Long> bySeverity = new LinkedHashMap<>();
        counters.forEach((key, value) -> {
            if (key.startsWith("alerts.severity.")) {
                bySeverity.put(key.substring("alerts.severity.".length()), value);
            }
        });

        Map<String, Object> health = new LinkedHashMap<>();
        health.put("activeRules", engine.activeRules().size());
        health.put("simulatorEnabled", simulatorProperties.enabled());
        health.put("simulatedEventsPerSecond", simulatorProperties.eventsPerSecond());
        health.put("socketMessagesSent", socket.messagesSent());

        return new StatsSnapshot(
                now,
                counters.getOrDefault("events.ingested", 0L),
                slow.eventsLastHour(),
                Math.round(perSecond * 10) / 10.0,
                counters.getOrDefault("alerts.raised", 0L),
                counters.getOrDefault("alerts.suppressed", 0L),
                slow.openAlerts(),
                bySeverity,
                slow.topRules(),
                slow.topSourceIps(),
                timeline,
                socket.connectedClients(),
                health);
    }

    private List<StatsSnapshot.Bucket> timeline(Instant now) {
        long current = now.getEpochSecond() / EventIngestService.BUCKET_SECONDS;
        List<Long> buckets = new ArrayList<>(TIMELINE_BUCKETS);
        for (int i = TIMELINE_BUCKETS - 1; i >= 0; i--) {
            buckets.add(current - i);
        }
        List<Long> events = state.readTimeSeries(EventIngestService.TIMELINE_EVENTS, buckets);
        List<Long> alerts = state.readTimeSeries(EventIngestService.TIMELINE_ALERTS, buckets);
        List<StatsSnapshot.Bucket> out = new ArrayList<>(TIMELINE_BUCKETS);
        for (int i = 0; i < buckets.size(); i++) {
            out.add(new StatsSnapshot.Bucket(
                    buckets.get(i) * EventIngestService.BUCKET_SECONDS,
                    events.get(i),
                    alerts.get(i)));
        }
        return out;
    }

    private SlowStats computeSlowStats(Instant now) {
        Instant since = now.minus(Duration.ofHours(24));
        List<StatsSnapshot.RuleCount> rules = alertRepository.countByRuleSince(since).stream()
                .limit(8)
                .map(r -> new StatsSnapshot.RuleCount(r.getRuleId(), r.getRuleName(), r.getTotal()))
                .toList();
        List<StatsSnapshot.SourceCount> sources =
                alertRepository.topSourceIpsSince(since, PageRequest.of(0, 8)).stream()
                        .map(s -> new StatsSnapshot.SourceCount(s.getSourceIp(), s.getTotal()))
                        .toList();
        return new SlowStats(now,
                alertRepository.countByStatus(AlertStatus.OPEN),
                eventRepository.countByEventTimeAfter(now.minus(Duration.ofHours(1))),
                rules,
                sources);
    }

    private SlowStats refreshSlowStats(Instant now) {
        SlowStats current = slowStats.get();
        if (Duration.between(current.computedAt(), now).compareTo(SLOW_STATS_TTL) < 0) {
            return current;
        }
        try {
            SlowStats fresh = computeSlowStats(now);
            slowStats.set(fresh);
            return fresh;
        } catch (RuntimeException ex) {
            // A slow or unavailable database degrades the dashboard, it does not break it.
            log.warn("Falling back to cached statistics: {}", ex.toString());
            return current;
        }
    }

    public void pushSnapshot() {
        socket.broadcast("stats", snapshot());
    }

    public void pushSnapshotTo(String sessionId) {
        socket.sendTo(sessionId, "stats", snapshot());
    }
}
