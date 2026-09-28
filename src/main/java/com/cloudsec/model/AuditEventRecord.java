package com.cloudsec.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;

/** Durable copy of every ingested audit event, used for investigation and rule back-testing. */
@Entity
@Table(name = "audit_event", indexes = {
        @Index(name = "idx_event_time", columnList = "event_time"),
        @Index(name = "idx_event_principal", columnList = "principal_id"),
        @Index(name = "idx_event_name", columnList = "event_name")
})
public class AuditEventRecord {

    @Id
    @Column(name = "event_id", nullable = false, length = 64)
    private String eventId;

    @Column(name = "event_time", nullable = false)
    private Instant eventTime;

    @Column(name = "ingested_at", nullable = false)
    private Instant ingestedAt;

    @Column(name = "provider", length = 16)
    private String provider;

    @Column(name = "event_source", length = 128)
    private String eventSource;

    @Column(name = "event_name", length = 128)
    private String eventName;

    @Column(name = "region", length = 32)
    private String region;

    @Column(name = "account_id", length = 64)
    private String accountId;

    @Column(name = "principal_id", length = 128)
    private String principalId;

    @Column(name = "principal_type", length = 32)
    private String principalType;

    @Column(name = "user_name", length = 128)
    private String userName;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Enumerated(EnumType.STRING)
    @Column(name = "outcome", length = 16)
    private Outcome outcome;

    @Column(name = "error_code", length = 64)
    private String errorCode;

    @Column(name = "resource", length = 512)
    private String resource;

    @Column(name = "bytes_transferred")
    private long bytesTransferred;

    @Column(name = "mfa_used")
    private boolean mfaUsed;

    @Column(name = "request_parameters", columnDefinition = "text")
    private String requestParametersJson;

    protected AuditEventRecord() {
    }

    public static AuditEventRecord from(CloudAuditEvent event, String requestParametersJson) {
        AuditEventRecord r = new AuditEventRecord();
        r.eventId = event.eventId();
        r.eventTime = event.eventTime();
        r.ingestedAt = Instant.now();
        r.provider = event.provider();
        r.eventSource = event.eventSource();
        r.eventName = event.eventName();
        r.region = event.region();
        r.accountId = event.accountId();
        r.principalId = event.principalId();
        r.principalType = event.principalType();
        r.userName = event.userName();
        r.sourceIp = event.sourceIp();
        r.outcome = event.outcome();
        r.errorCode = event.errorCode();
        r.resource = event.resource();
        r.bytesTransferred = event.bytesTransferred();
        r.mfaUsed = event.mfaUsed();
        r.requestParametersJson = requestParametersJson;
        return r;
    }

    public String getEventId() { return eventId; }
    public Instant getEventTime() { return eventTime; }
    public Instant getIngestedAt() { return ingestedAt; }
    public String getProvider() { return provider; }
    public String getEventSource() { return eventSource; }
    public String getEventName() { return eventName; }
    public String getRegion() { return region; }
    public String getAccountId() { return accountId; }
    public String getPrincipalId() { return principalId; }
    public String getPrincipalType() { return principalType; }
    public String getUserName() { return userName; }
    public String getSourceIp() { return sourceIp; }
    public Outcome getOutcome() { return outcome; }
    public String getErrorCode() { return errorCode; }
    public String getResource() { return resource; }
    public long getBytesTransferred() { return bytesTransferred; }
    public boolean isMfaUsed() { return mfaUsed; }
    public String getRequestParametersJson() { return requestParametersJson; }
}
