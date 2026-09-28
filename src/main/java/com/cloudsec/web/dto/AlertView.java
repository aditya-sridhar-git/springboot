package com.cloudsec.web.dto;

import com.cloudsec.model.AlertStatus;
import com.cloudsec.model.SecurityAlert;
import com.cloudsec.model.Severity;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;

/** Wire shape of an alert, with the evidence blob rehydrated into a real JSON object. */
public record AlertView(
        UUID id,
        String ruleId,
        String ruleName,
        Severity severity,
        int riskScore,
        String title,
        String description,
        String mitreTechnique,
        String accountId,
        String principalId,
        String userName,
        String sourceIp,
        String region,
        String eventName,
        String resource,
        String triggerEventId,
        Instant eventTime,
        Instant detectedAt,
        AlertStatus status,
        Map<String, Object> evidence) {

    private static final TypeReference<Map<String, Object>> EVIDENCE_TYPE = new TypeReference<>() {
    };

    public static AlertView of(SecurityAlert alert, ObjectMapper mapper) {
        Map<String, Object> evidence = Map.of();
        if (alert.getEvidenceJson() != null && !alert.getEvidenceJson().isBlank()) {
            try {
                evidence = mapper.readValue(alert.getEvidenceJson(), EVIDENCE_TYPE);
            } catch (Exception ex) {
                evidence = Map.of("raw", alert.getEvidenceJson());
            }
        }
        return new AlertView(
                alert.getId(), alert.getRuleId(), alert.getRuleName(), alert.getSeverity(),
                alert.getRiskScore(), alert.getTitle(), alert.getDescription(), alert.getMitreTechnique(),
                alert.getAccountId(), alert.getPrincipalId(), alert.getUserName(), alert.getSourceIp(),
                alert.getRegion(), alert.getEventName(), alert.getResource(), alert.getTriggerEventId(),
                alert.getEventTime(), alert.getDetectedAt(), alert.getStatus(), evidence);
    }
}
