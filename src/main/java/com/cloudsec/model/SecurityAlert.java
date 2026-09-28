package com.cloudsec.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;

/** A detection produced by the rules engine. Persisted in PostgreSQL and pushed to the dashboard. */
@Entity
@Table(name = "security_alert", indexes = {
        @Index(name = "idx_alert_detected_at", columnList = "detected_at"),
        @Index(name = "idx_alert_severity", columnList = "severity"),
        @Index(name = "idx_alert_status", columnList = "status"),
        @Index(name = "idx_alert_rule_id", columnList = "rule_id")
})
public class SecurityAlert {

    @Id
    @Column(name = "id", nullable = false)
    private UUID id;

    @Column(name = "rule_id", nullable = false, length = 64)
    private String ruleId;

    @Column(name = "rule_name", nullable = false, length = 128)
    private String ruleName;

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 16)
    private Severity severity;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "title", nullable = false, length = 256)
    private String title;

    @Column(name = "description", nullable = false, length = 2048)
    private String description;

    @Column(name = "mitre_technique", length = 64)
    private String mitreTechnique;

    @Column(name = "account_id", length = 64)
    private String accountId;

    @Column(name = "principal_id", length = 128)
    private String principalId;

    @Column(name = "user_name", length = 128)
    private String userName;

    @Column(name = "source_ip", length = 64)
    private String sourceIp;

    @Column(name = "region", length = 32)
    private String region;

    @Column(name = "event_name", length = 128)
    private String eventName;

    @Column(name = "resource", length = 512)
    private String resource;

    @Column(name = "trigger_event_id", length = 64)
    private String triggerEventId;

    @Column(name = "event_time")
    private Instant eventTime;

    @Column(name = "detected_at", nullable = false)
    private Instant detectedAt;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    private AlertStatus status = AlertStatus.OPEN;

    @Column(name = "evidence", columnDefinition = "text")
    private String evidenceJson;

    protected SecurityAlert() {
    }

    public SecurityAlert(UUID id) {
        this.id = id;
    }

    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }

    public String getRuleId() { return ruleId; }
    public void setRuleId(String ruleId) { this.ruleId = ruleId; }

    public String getRuleName() { return ruleName; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }

    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }

    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }

    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }

    public String getMitreTechnique() { return mitreTechnique; }
    public void setMitreTechnique(String mitreTechnique) { this.mitreTechnique = mitreTechnique; }

    public String getAccountId() { return accountId; }
    public void setAccountId(String accountId) { this.accountId = accountId; }

    public String getPrincipalId() { return principalId; }
    public void setPrincipalId(String principalId) { this.principalId = principalId; }

    public String getUserName() { return userName; }
    public void setUserName(String userName) { this.userName = userName; }

    public String getSourceIp() { return sourceIp; }
    public void setSourceIp(String sourceIp) { this.sourceIp = sourceIp; }

    public String getRegion() { return region; }
    public void setRegion(String region) { this.region = region; }

    public String getEventName() { return eventName; }
    public void setEventName(String eventName) { this.eventName = eventName; }

    public String getResource() { return resource; }
    public void setResource(String resource) { this.resource = resource; }

    public String getTriggerEventId() { return triggerEventId; }
    public void setTriggerEventId(String triggerEventId) { this.triggerEventId = triggerEventId; }

    public Instant getEventTime() { return eventTime; }
    public void setEventTime(Instant eventTime) { this.eventTime = eventTime; }

    public Instant getDetectedAt() { return detectedAt; }
    public void setDetectedAt(Instant detectedAt) { this.detectedAt = detectedAt; }

    public AlertStatus getStatus() { return status; }
    public void setStatus(AlertStatus status) { this.status = status; }

    public String getEvidenceJson() { return evidenceJson; }
    public void setEvidenceJson(String evidenceJson) { this.evidenceJson = evidenceJson; }
}
