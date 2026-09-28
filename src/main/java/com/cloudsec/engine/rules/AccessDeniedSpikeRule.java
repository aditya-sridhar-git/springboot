package com.cloudsec.engine.rules;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * A burst of AccessDenied responses for one principal, which is what permission enumeration looks
 * like once an attacker holds a credential but does not know what it can do.
 */
@Component
public class AccessDeniedSpikeRule implements DetectionRule {

    private static final Set<String> DENIAL_CODES = Set.of(
            "AccessDenied", "AccessDeniedException", "UnauthorizedOperation", "Forbidden", "Client.UnauthorizedOperation");

    private final DetectionProperties.AccessDenied config;

    public AccessDeniedSpikeRule(DetectionProperties properties) {
        this.config = properties.accessDenied();
    }

    @Override
    public String id() {
        return "access-denied-spike";
    }

    @Override
    public String name() {
        return "Permission enumeration";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public String mitreTechnique() {
        return "T1087";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.failed() && event.errorCode() != null && DENIAL_CODES.contains(event.errorCode());
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String key = event.accountId() + "|" + event.principalId();
        long denials = state.recordAndCount(id(), key, event.eventId(), event.eventTime(), config.window());
        if (denials < config.threshold()) {
            return Optional.empty();
        }

        Severity effective = denials >= config.threshold() * 3 ? Severity.HIGH : Severity.MEDIUM;
        return Optional.of(AlertDraft.builder(id() + ":" + key)
                .title("%d access denials for %s".formatted(denials, event.actor()))
                .description(("Principal %s received %d authorisation failures across the API within %d minutes. "
                        + "That pattern is characteristic of an attacker mapping what a stolen credential can reach. "
                        + "Most recent call: %s.")
                        .formatted(event.actor(), denials, config.window().toMinutes(), event.eventName()))
                .severity(effective)
                .evidence("denialCount", denials)
                .evidence("threshold", config.threshold())
                .evidence("windowMinutes", config.window().toMinutes())
                .evidence("actor", event.actor())
                .evidence("lastEventName", event.eventName())
                .evidence("lastErrorCode", event.errorCode())
                .evidence("sourceIp", event.sourceIp())
                .build(effective));
    }

    @Override
    public Duration suppressionWindow() {
        return config.window();
    }
}
