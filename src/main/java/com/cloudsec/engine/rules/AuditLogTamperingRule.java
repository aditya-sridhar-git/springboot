package com.cloudsec.engine.rules;

import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Someone turning off the very telemetry this analyzer runs on. Almost always either an attacker
 * covering their tracks or a change that will blind the security team by accident.
 */
@Component
public class AuditLogTamperingRule implements DetectionRule {

    @Override
    public String id() {
        return "audit-log-tampering";
    }

    @Override
    public String name() {
        return "Audit logging disabled or deleted";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1562.008";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded() && event.eventNameIn(
                "StopLogging", "DeleteTrail", "UpdateTrail", "DeleteFlowLogs",
                "DeleteLogGroup", "PutEventSelectors", "DeleteDetector", "DisableSecurityHub");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        // UpdateTrail is only interesting when it narrows what gets logged.
        if ("UpdateTrail".equalsIgnoreCase(event.eventName())
                && !"false".equalsIgnoreCase(event.param("isMultiRegionTrail"))
                && !"false".equalsIgnoreCase(event.param("includeGlobalServiceEvents"))) {
            return Optional.empty();
        }

        String target = event.resource() == null ? event.accountId() : event.resource();
        return Optional.of(AlertDraft.builder(id() + ":" + target + ":" + event.eventName())
                .title("Audit logging tampered: %s on %s".formatted(event.eventName(), target))
                .description(("%s called %s against %s. Detection coverage for account %s is now degraded, "
                        + "so treat subsequent activity in this account as unmonitored until logging is restored.")
                        .formatted(event.actor(), event.eventName(), target, event.accountId()))
                .evidence("eventName", event.eventName())
                .evidence("target", target)
                .evidence("actor", event.actor())
                .evidence("principalType", event.principalType())
                .evidence("sourceIp", event.sourceIp())
                .evidence("region", event.region())
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(10);
    }
}
