package com.cloudsec.web.dto;

import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Outcome;
import java.time.Instant;

/** Compact projection of an audit event for the live ingest ticker. */
public record EventView(
        String eventId,
        Instant eventTime,
        String provider,
        String eventName,
        String eventSource,
        String region,
        String actor,
        String principalType,
        String sourceIp,
        Outcome outcome,
        String errorCode,
        String resource,
        long bytesTransferred) {

    public static EventView of(CloudAuditEvent e) {
        return new EventView(e.eventId(), e.eventTime(), e.provider(), e.eventName(), e.eventSource(),
                e.region(), e.actor(), e.principalType(), e.sourceIp(), e.outcome(), e.errorCode(),
                e.resource(), e.bytesTransferred());
    }
}
