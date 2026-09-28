package com.cloudsec.service;

import com.cloudsec.config.AnalyzerProperties;
import com.cloudsec.config.DetectionProperties;
import com.cloudsec.engine.Detection;
import com.cloudsec.engine.DetectionEngine;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.state.AnalyzerStateStore;
import com.cloudsec.web.DashboardSocketHandler;
import com.cloudsec.web.dto.AlertView;
import com.cloudsec.web.dto.EventView;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * The hot path: normalise, archive, detect, notify.
 *
 * <p>Called once per Kafka batch. Archiving is best effort - a database hiccup must never stop
 * detection, because a missed alert is far more expensive than a missed archive row.
 */
@Service
public class EventIngestService {

    private static final Logger log = LoggerFactory.getLogger(EventIngestService.class);

    public static final String TIMELINE_EVENTS = "events";
    public static final String TIMELINE_ALERTS = "alerts";
    /** Sparkline resolution. Buckets live long enough to fill the dashboard window twice over. */
    public static final int BUCKET_SECONDS = 5;
    private static final Duration BUCKET_TTL = Duration.ofMinutes(20);
    private static final String RECENT_EVENTS_KEY = "recent:events";
    private static final String COUNTERS_KEY = "counters";

    private final DetectionEngine engine;
    private final AlertService alertService;
    private final AuditArchiveService archive;
    private final AnalyzerStateStore state;
    private final DashboardSocketHandler socket;
    private final ObjectMapper objectMapper;
    private final AnalyzerProperties properties;
    private final DetectionProperties detectionProperties;
    private final Counter ingested;
    private final Timer pipelineTimer;

    public EventIngestService(DetectionEngine engine,
                              AlertService alertService,
                              AuditArchiveService archive,
                              AnalyzerStateStore state,
                              DashboardSocketHandler socket,
                              ObjectMapper objectMapper,
                              AnalyzerProperties properties,
                              DetectionProperties detectionProperties,
                              MeterRegistry meters) {
        this.engine = engine;
        this.alertService = alertService;
        this.archive = archive;
        this.state = state;
        this.socket = socket;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.detectionProperties = detectionProperties;
        this.ingested = Counter.builder("cloudsec.events.ingested")
                .description("Cloud audit events accepted by the analyzer")
                .register(meters);
        this.pipelineTimer = Timer.builder("cloudsec.pipeline.batch")
                .description("End to end time to process one Kafka batch")
                .publishPercentileHistogram()
                .register(meters);
    }

    public void ingest(List<CloudAuditEvent> batch) {
        pipelineTimer.record(() -> process(batch));
    }

    private void process(List<CloudAuditEvent> batch) {
        List<CloudAuditEvent> events = batch.stream().filter(java.util.Objects::nonNull).toList();
        if (events.isEmpty()) {
            return;
        }

        List<Detection> detections = new ArrayList<>();
        for (CloudAuditEvent event : events) {
            ingested.increment();
            state.incrementCounter(COUNTERS_KEY, "events.ingested", 1);
            recordTimeline(TIMELINE_EVENTS, event.eventTime(), 1);
            cacheRecent(event);
            detections.addAll(engine.analyze(event));
        }

        socket.broadcast("events", events.stream().map(EventView::of).toList());

        if (detectionProperties.persistEvents()) {
            archive.archive(events);
        }

        if (!detections.isEmpty()) {
            List<AlertView> raised = alertService.handle(detections);
            if (!raised.isEmpty()) {
                recordTimeline(TIMELINE_ALERTS, Instant.now(), raised.size());
            }
        }
    }

    private void recordTimeline(String series, Instant at, long delta) {
        state.incrementTimeSeries(series, at.getEpochSecond() / BUCKET_SECONDS, delta, BUCKET_TTL);
    }

    private void cacheRecent(CloudAuditEvent event) {
        String json = writeJson(EventView.of(event));
        if (json != null) {
            state.pushRecent(RECENT_EVENTS_KEY, json, properties.recentEventCacheSize());
        }
    }

    public List<EventView> recentEvents(int limit) {
        return state.recent(RECENT_EVENTS_KEY, limit).stream()
                .map(json -> {
                    try {
                        return Optional.of(objectMapper.readValue(json, EventView.class));
                    } catch (Exception ex) {
                        return Optional.<EventView>empty();
                    }
                })
                .flatMap(Optional::stream)
                .toList();
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            log.debug("Could not serialise payload: {}", ex.toString());
            return null;
        }
    }
}
