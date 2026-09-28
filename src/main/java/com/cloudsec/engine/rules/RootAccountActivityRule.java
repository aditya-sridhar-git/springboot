package com.cloudsec.engine.rules;

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
 * Use of the account root credential. Root should be locked away after bootstrap, so any activity
 * is worth a look, and root activity without MFA is worse.
 */
@Component
public class RootAccountActivityRule implements DetectionRule {

    /** Root doing these is close to a guaranteed incident rather than an admin being lazy. */
    private static final Set<String> DESTRUCTIVE = Set.of(
            "DeleteTrail", "StopLogging", "DeleteBucket", "PutUserPolicy", "CreateAccessKey",
            "DeleteFlowLogs", "UpdateAccountPasswordPolicy", "DeactivateMFADevice");

    @Override
    public String id() {
        return "root-account-activity";
    }

    @Override
    public String name() {
        return "Root account activity";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1078.004";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.isRootPrincipal();
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        boolean destructive = DESTRUCTIVE.contains(event.eventName());
        Severity effective = destructive || !event.mfaUsed() ? Severity.CRITICAL : Severity.HIGH;

        String qualifier = event.mfaUsed() ? "with MFA" : "without MFA";
        return Optional.of(AlertDraft.builder(id() + ":" + event.accountId() + ":" + event.eventName())
                .title("Root credential used for %s".formatted(event.eventName()))
                .description(("The root user of account %s called %s from %s (%s) %s. Root should only be "
                        + "used for the handful of tasks that require it, and never for day to day work.")
                        .formatted(event.accountId(), event.eventName(), event.sourceIp(),
                                event.region(), qualifier))
                .severity(effective)
                .evidence("eventName", event.eventName())
                .evidence("eventSource", event.eventSource())
                .evidence("sourceIp", event.sourceIp())
                .evidence("region", event.region())
                .evidence("mfaUsed", event.mfaUsed())
                .evidence("destructiveAction", destructive)
                .build(effective));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(15);
    }
}
