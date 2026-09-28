package com.cloudsec.engine.rules;

import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.engine.GeoRegions;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * First ever activity in a region. Crypto-mining and staging infrastructure tends to appear in a
 * region the account has never touched, because nobody is watching there.
 */
@Component
public class UnusualRegionRule implements DetectionRule {

    @Override
    public String id() {
        return "unusual-region";
    }

    @Override
    public String name() {
        return "Activity in a never-used region";
    }

    @Override
    public Severity severity() {
        return Severity.MEDIUM;
    }

    @Override
    public String mitreTechnique() {
        return "T1078.004";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded()
                && event.region() != null
                && event.eventNameIn("RunInstances", "CreateFunction", "CreateCluster",
                        "CreateBucket", "StartInstances", "RequestSpotInstances");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String setKey = "regions:" + event.accountId();
        if (!state.isFirstTimeSeen(setKey, event.region())) {
            return Optional.empty();
        }

        String label = GeoRegions.of(event.region()).map(GeoRegions.Coordinates::label).orElse(event.region());
        return Optional.of(AlertDraft.builder(id() + ":" + event.accountId() + ":" + event.region())
                .title("First resource created in %s".formatted(event.region()))
                .description(("%s called %s in %s (%s), a region account %s has never used before. "
                        + "Verify this is a deliberate expansion and not resource hijacking.")
                        .formatted(event.actor(), event.eventName(), event.region(), label, event.accountId()))
                .evidence("region", event.region())
                .evidence("regionLabel", label)
                .evidence("eventName", event.eventName())
                .evidence("actor", event.actor())
                .evidence("resource", event.resource())
                .evidence("instanceType", event.param("instanceType"))
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofHours(6);
    }
}
