package com.cloudsec.ingest;

import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.service.EventIngestService;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.kafka.annotation.KafkaListener;
import org.springframework.stereotype.Component;

/**
 * Entry point of the pipeline. Consumes the raw cloud audit stream in batches, which amortises the
 * per-record cost of the Redis round trips the stateful rules make.
 */
@Component
public class SecurityEventConsumer {

    private static final Logger log = LoggerFactory.getLogger(SecurityEventConsumer.class);

    private final EventIngestService ingestService;

    public SecurityEventConsumer(EventIngestService ingestService) {
        this.ingestService = ingestService;
    }

    @KafkaListener(
            topics = "${cloudsec.events-topic:cloud.security.events}",
            groupId = "${spring.kafka.consumer.group-id:cloud-security-analyzer}",
            containerFactory = "kafkaListenerContainerFactory")
    public void onSecurityEvents(List<CloudAuditEvent> events) {
        log.debug("Received batch of {} cloud audit events", events.size());
        ingestService.ingest(events);
    }
}
