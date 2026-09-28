package com.cloudsec.engine;

import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;

/**
 * One detection. Rules are Spring beans, so adding a detection means adding a class and nothing
 * else: the engine discovers every {@code DetectionRule} on the classpath at startup.
 */
public interface DetectionRule {

    /** Stable machine identifier, e.g. {@code brute-force-login}. Used in metrics and dedup keys. */
    String id();

    String name();

    Severity severity();

    /** MITRE ATT&CK technique this detection maps to, e.g. {@code T1110}. */
    String mitreTechnique();

    /** Cheap pre-filter so irrelevant events never reach {@link #evaluate}. */
    boolean supports(CloudAuditEvent event);

    Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state);

    /** How long an identical detection stays suppressed after firing. */
    default Duration suppressionWindow() {
        return Duration.ofMinutes(10);
    }

    default boolean enabled() {
        return true;
    }
}
