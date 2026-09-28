package com.cloudsec.service;

import com.cloudsec.config.AnalyzerProperties;
import com.cloudsec.model.AuditEventRecord;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.repository.AuditEventRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Durable archive of ingested events, kept separate from the ingest hot path so the batch insert
 * gets a real transaction and a database problem cannot take detection down with it.
 */
@Service
public class AuditArchiveService {

    private static final Logger log = LoggerFactory.getLogger(AuditArchiveService.class);

    private final AuditEventRepository repository;
    private final ObjectMapper objectMapper;
    private final AnalyzerProperties properties;
    private final Counter failures;

    public AuditArchiveService(AuditEventRepository repository,
                               ObjectMapper objectMapper,
                               AnalyzerProperties properties,
                               MeterRegistry meters) {
        this.repository = repository;
        this.objectMapper = objectMapper;
        this.properties = properties;
        this.failures = Counter.builder("cloudsec.events.archive.failures")
                .description("Events that could not be written to PostgreSQL")
                .register(meters);
    }

    @Transactional
    public void archive(List<CloudAuditEvent> events) {
        List<AuditEventRecord> rows = events.stream()
                .map(e -> AuditEventRecord.from(e, writeJson(e.requestParameters())))
                .toList();
        try {
            repository.saveAll(rows);
        } catch (DataIntegrityViolationException ex) {
            // Re-delivery after a consumer rebalance replays events we already stored; expected.
            log.debug("Skipping {} already archived events", rows.size());
        } catch (RuntimeException ex) {
            failures.increment(rows.size());
            log.warn("Could not archive {} events: {}", rows.size(), ex.toString());
        }
    }

    /** Keeps the archive from growing without bound in a long running demo or lab environment. */
    @Scheduled(initialDelayString = "PT5M", fixedDelayString = "PT1H")
    @Transactional
    public void pruneOldEvents() {
        Instant cutoff = Instant.now().minus(properties.eventRetention());
        int removed = repository.deleteOlderThan(cutoff);
        if (removed > 0) {
            log.info("Pruned {} audit events older than {}", removed, cutoff);
        }
    }

    private String writeJson(Object value) {
        try {
            return objectMapper.writeValueAsString(value);
        } catch (Exception ex) {
            return null;
        }
    }
}
