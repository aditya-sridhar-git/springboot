package com.cloudsec.engine.rules;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** Repeated failed console logins from one source IP inside a short window. */
@Component
public class BruteForceLoginRule implements DetectionRule {

    private final DetectionProperties.BruteForce config;

    public BruteForceLoginRule(DetectionProperties properties) {
        this.config = properties.bruteForce();
    }

    @Override
    public String id() {
        return "brute-force-login";
    }

    @Override
    public String name() {
        return "Brute force console login";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1110";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.failed() && event.eventNameIn("ConsoleLogin", "AssumeRole", "GetSessionToken");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String key = event.accountId() + "|" + event.sourceIp();
        long failures = state.recordAndCount(id(), key, event.eventId(), event.eventTime(), config.window());
        if (failures < config.failureThreshold()) {
            return Optional.empty();
        }

        // Every extra failure past the threshold nudges the score, capped by the builder at 100.
        int score = severity().baseRiskScore() + (int) Math.min(20, failures - config.failureThreshold());
        return Optional.of(AlertDraft.builder(id() + ":" + key)
                .title("%d failed sign-ins from %s".formatted(failures, event.sourceIp()))
                .description(("Source IP %s produced %d failed authentication attempts against account %s "
                        + "within %s. Most recent target principal: %s.")
                        .formatted(event.sourceIp(), failures, event.accountId(),
                                humanize(config.window()), event.actor()))
                .riskScore(score)
                .evidence("failureCount", failures)
                .evidence("threshold", config.failureThreshold())
                .evidence("windowSeconds", config.window().toSeconds())
                .evidence("sourceIp", event.sourceIp())
                .evidence("lastErrorCode", event.errorCode())
                .evidence("targetPrincipal", event.actor())
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return config.window();
    }

    private static String humanize(Duration duration) {
        return duration.toMinutes() + " minutes";
    }
}
