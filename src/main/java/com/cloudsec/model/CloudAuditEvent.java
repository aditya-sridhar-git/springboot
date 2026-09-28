package com.cloudsec.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

/**
 * A normalised cloud control-plane audit record.
 *
 * <p>The shape follows AWS CloudTrail closely (that is the richest of the three major providers)
 * but the field names are provider neutral so Azure Activity Log and GCP Cloud Audit Log records
 * can be mapped onto the same structure.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public record CloudAuditEvent(
        String eventId,
        Instant eventTime,
        String provider,
        String eventSource,
        String eventName,
        String region,
        String accountId,
        String principalId,
        String principalType,
        String userName,
        String sourceIp,
        String userAgent,
        Outcome outcome,
        String errorCode,
        String resource,
        long bytesTransferred,
        boolean mfaUsed,
        Map<String, Object> requestParameters) {

    public CloudAuditEvent {
        requestParameters = requestParameters == null ? Map.of() : Map.copyOf(requestParameters);
        outcome = outcome == null ? Outcome.SUCCESS : outcome;
    }

    public boolean failed() {
        return outcome == Outcome.FAILURE;
    }

    public boolean succeeded() {
        return outcome == Outcome.SUCCESS;
    }

    public boolean isRootPrincipal() {
        return "Root".equalsIgnoreCase(principalType);
    }

    /** Case-insensitive match against any of the supplied event names. */
    public boolean eventNameIn(String... names) {
        for (String name : names) {
            if (name.equalsIgnoreCase(eventName)) {
                return true;
            }
        }
        return false;
    }

    public String param(String key) {
        Object value = requestParameters.get(key);
        return value == null ? null : String.valueOf(value);
    }

    /** Best-effort actor label used for grouping and display. */
    public String actor() {
        if (userName != null && !userName.isBlank()) {
            return userName;
        }
        return principalId == null ? "unknown" : principalId;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String eventId = UUID.randomUUID().toString();
        private Instant eventTime = Instant.now();
        private String provider = "AWS";
        private String eventSource;
        private String eventName;
        private String region;
        private String accountId;
        private String principalId;
        private String principalType = "IAMUser";
        private String userName;
        private String sourceIp;
        private String userAgent = "aws-cli/2.15.0";
        private Outcome outcome = Outcome.SUCCESS;
        private String errorCode;
        private String resource;
        private long bytesTransferred;
        private boolean mfaUsed;
        private final Map<String, Object> requestParameters = new LinkedHashMap<>();

        public Builder eventId(String v) { this.eventId = v; return this; }
        public Builder eventTime(Instant v) { this.eventTime = v; return this; }
        public Builder provider(String v) { this.provider = v; return this; }
        public Builder eventSource(String v) { this.eventSource = v; return this; }
        public Builder eventName(String v) { this.eventName = v; return this; }
        public Builder region(String v) { this.region = v; return this; }
        public Builder accountId(String v) { this.accountId = v; return this; }
        public Builder principalId(String v) { this.principalId = v; return this; }
        public Builder principalType(String v) { this.principalType = v; return this; }
        public Builder userName(String v) { this.userName = v; return this; }
        public Builder sourceIp(String v) { this.sourceIp = v; return this; }
        public Builder userAgent(String v) { this.userAgent = v; return this; }
        public Builder outcome(Outcome v) { this.outcome = v; return this; }
        public Builder errorCode(String v) { this.errorCode = v; return this; }
        public Builder resource(String v) { this.resource = v; return this; }
        public Builder bytesTransferred(long v) { this.bytesTransferred = v; return this; }
        public Builder mfaUsed(boolean v) { this.mfaUsed = v; return this; }

        public Builder param(String key, Object value) {
            this.requestParameters.put(key, value);
            return this;
        }

        public CloudAuditEvent build() {
            return new CloudAuditEvent(eventId, eventTime, provider, eventSource, eventName, region,
                    accountId, principalId, principalType, userName, sourceIp, userAgent, outcome,
                    errorCode, resource, bytesTransferred, mfaUsed, requestParameters);
        }
    }
}
