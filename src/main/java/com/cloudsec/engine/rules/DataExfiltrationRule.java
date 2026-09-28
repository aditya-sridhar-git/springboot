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

/** An unusual volume of data pulled out of object storage by a single principal. */
@Component
public class DataExfiltrationRule implements DetectionRule {

    private static final long GIB = 1024L * 1024L * 1024L;

    private final DetectionProperties.Exfiltration config;

    public DataExfiltrationRule(DetectionProperties properties) {
        this.config = properties.exfiltration();
    }

    @Override
    public String id() {
        return "data-exfiltration-volume";
    }

    @Override
    public String name() {
        return "Bulk data egress";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1530";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded()
                && event.bytesTransferred() > 0
                && event.eventNameIn("GetObject", "CopyObject", "SelectObjectContent",
                        "CreateSnapshot", "ExportImage", "DownloadBlob");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String key = event.accountId() + "|" + event.principalId();
        long total = state.recordAndSum(id(), key, event.eventId(), event.bytesTransferred(),
                event.eventTime(), config.window());
        if (total < config.bytesThreshold()) {
            return Optional.empty();
        }

        double gib = total / (double) GIB;
        Severity effective = total >= config.bytesThreshold() * 4 ? Severity.CRITICAL : Severity.HIGH;

        return Optional.of(AlertDraft.builder(id() + ":" + key)
                .title("%.1f GiB egress by %s in %d minutes".formatted(gib, event.actor(), config.window().toMinutes()))
                .description(("Principal %s transferred %.1f GiB out of storage in account %s within %d minutes, "
                        + "against a threshold of %.1f GiB. Most recent object: %s.")
                        .formatted(event.actor(), gib, event.accountId(), config.window().toMinutes(),
                                config.bytesThreshold() / (double) GIB, event.resource()))
                .severity(effective)
                .evidence("bytesTransferred", total)
                .evidence("gibTransferred", Math.round(gib * 10) / 10.0)
                .evidence("thresholdBytes", config.bytesThreshold())
                .evidence("windowMinutes", config.window().toMinutes())
                .evidence("actor", event.actor())
                .evidence("lastResource", event.resource())
                .evidence("sourceIp", event.sourceIp())
                .build(effective));
    }

    @Override
    public Duration suppressionWindow() {
        return config.window();
    }
}
