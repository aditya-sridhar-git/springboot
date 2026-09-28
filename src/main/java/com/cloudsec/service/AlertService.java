package com.cloudsec.service;

import com.cloudsec.config.AnalyzerProperties;
import com.cloudsec.engine.Detection;
import com.cloudsec.model.AlertStatus;
import com.cloudsec.model.SecurityAlert;
import com.cloudsec.model.Severity;
import com.cloudsec.repository.SecurityAlertRepository;
import com.cloudsec.state.AnalyzerStateStore;
import com.cloudsec.web.DashboardSocketHandler;
import com.cloudsec.web.dto.AlertView;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Turns rule firings into durable alerts.
 *
 * <p>Order matters here: claim the de-duplication key in Redis first so that two analyzer replicas
 * consuming different partitions cannot both write the same alert, then persist, then notify.
 */
@Service
public class AlertService {

    private static final Logger log = LoggerFactory.getLogger(AlertService.class);
    private static final String RECENT_ALERTS_KEY = "recent:alerts";
    private static final String COUNTERS_KEY = "counters";

    private final SecurityAlertRepository repository;
    private final AnalyzerStateStore state;
    private final DashboardSocketHandler socket;
    private final KafkaTemplate<String, Object> kafka;
    private final ObjectMapper objectMapper;
    private final MeterRegistry meters;
    private final AnalyzerProperties properties;

    public AlertService(SecurityAlertRepository repository,
                        AnalyzerStateStore state,
                        DashboardSocketHandler socket,
                        KafkaTemplate<String, Object> kafka,
                        ObjectMapper objectMapper,
                        MeterRegistry meters,
                        AnalyzerProperties properties) {
        this.repository = repository;
        this.state = state;
        this.socket = socket;
        this.kafka = kafka;
        this.objectMapper = objectMapper;
        this.meters = meters;
        this.properties = properties;
    }

    /** @return the alerts that were actually raised, i.e. excluding suppressed duplicates */
    public List<AlertView> handle(List<Detection> detections) {
        return detections.stream()
                .map(this::raise)
                .flatMap(Optional::stream)
                .toList();
    }

    private Optional<AlertView> raise(Detection detection) {
        String dedupKey = detection.draft().dedupKey();
        if (!state.claim(dedupKey, detection.rule().suppressionWindow())) {
            meters.counter("cloudsec.alerts.suppressed", "rule", detection.rule().id()).increment();
            state.incrementCounter(COUNTERS_KEY, "alerts.suppressed", 1);
            log.debug("Suppressed duplicate detection {} within {}", dedupKey, detection.rule().suppressionWindow());
            return Optional.empty();
        }

        SecurityAlert alert = persist(detection);
        AlertView view = AlertView.of(alert, objectMapper);

        meters.counter("cloudsec.alerts.raised",
                "rule", detection.rule().id(),
                "severity", alert.getSeverity().name()).increment();
        state.incrementCounter(COUNTERS_KEY, "alerts.raised", 1);
        state.incrementCounter(COUNTERS_KEY, "alerts.severity." + alert.getSeverity().name(), 1);
        cacheRecent(view);
        publishDownstream(view);
        socket.broadcast("alert", view);

        log.warn("ALERT [{}] {} - {} (risk {}, rule {})", alert.getSeverity(), alert.getTitle(),
                alert.getUserName(), alert.getRiskScore(), alert.getRuleId());
        return Optional.of(view);
    }

    private SecurityAlert persist(Detection detection) {
        SecurityAlert alert = new SecurityAlert(UUID.randomUUID());
        alert.setRuleId(detection.rule().id());
        alert.setRuleName(detection.rule().name());
        alert.setSeverity(detection.draft().severity());
        alert.setRiskScore(detection.draft().riskScore());
        alert.setTitle(truncate(detection.draft().title(), 256));
        alert.setDescription(truncate(detection.draft().description(), 2048));
        alert.setMitreTechnique(detection.rule().mitreTechnique());
        alert.setAccountId(detection.event().accountId());
        alert.setPrincipalId(detection.event().principalId());
        alert.setUserName(detection.event().actor());
        alert.setSourceIp(detection.event().sourceIp());
        alert.setRegion(detection.event().region());
        alert.setEventName(detection.event().eventName());
        alert.setResource(truncate(detection.event().resource(), 512));
        alert.setTriggerEventId(detection.event().eventId());
        alert.setEventTime(detection.event().eventTime());
        alert.setDetectedAt(Instant.now());
        alert.setStatus(AlertStatus.OPEN);
        alert.setEvidenceJson(writeJson(detection.draft().evidence()));
        return repository.save(alert);
    }

    private void cacheRecent(AlertView view) {
        String json = writeJson(view);
        if (json != null) {
            state.pushRecent(RECENT_ALERTS_KEY, json, properties.recentAlertCacheSize());
        }
    }

    private void publishDownstream(AlertView view) {
        // Alerts go back onto Kafka so SOAR, ticketing or a SIEM can subscribe without touching this service.
        kafka.send(properties.alertsTopic(), view.ruleId(), view)
                .whenComplete((result, ex) -> {
                    if (ex != null) {
                        log.warn("Could not publish alert {} to {}: {}", view.id(), properties.alertsTopic(), ex.toString());
                    }
                });
    }

    public List<AlertView> recentFromCache(int limit) {
        return state.recent(RECENT_ALERTS_KEY, limit).stream()
                .map(json -> readJson(json, AlertView.class))
                .flatMap(Optional::stream)
                .toList();
    }

    @Transactional
    public Optional<AlertView> updateStatus(UUID id, AlertStatus status) {
        return repository.findById(id).map(alert -> {
            alert.setStatus(status);
            SecurityAlert saved = repository.save(alert);
            AlertView view = AlertView.of(saved, objectMapper);
            socket.broadcast("alert-updated", view);
            return view;
        });
    }

    public long countOpen() {
        return repository.countByStatus(AlertStatus.OPEN);
    }

    public long countBySeverity(Severity severity) {
        return repository.countBySeverity(severity);
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            log.warn("Could not serialise {}: {}", value.getClass().getSimpleName(), ex.toString());
            return null;
        }
    }

    private <T> Optional<T> readJson(String json, Class<T> type) {
        try {
            return Optional.of(objectMapper.readValue(json, type));
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    private static String truncate(String value, int max) {
        if (value == null) {
            return null;
        }
        return value.length() <= max ? value : value.substring(0, max - 3) + "...";
    }
}
