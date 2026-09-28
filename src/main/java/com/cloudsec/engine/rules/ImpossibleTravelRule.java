package com.cloudsec.engine.rules;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.engine.GeoRegions;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import com.cloudsec.state.Sighting;
import java.time.Duration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/**
 * Two successful sign-ins for one principal that are too far apart to be the same human travelling.
 */
@Component
public class ImpossibleTravelRule implements DetectionRule {

    private final DetectionProperties.ImpossibleTravel config;

    public ImpossibleTravelRule(DetectionProperties properties) {
        this.config = properties.impossibleTravel();
    }

    @Override
    public String id() {
        return "impossible-travel";
    }

    @Override
    public String name() {
        return "Impossible travel";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1078";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded()
                && event.eventNameIn("ConsoleLogin", "AssumeRole", "GetSessionToken")
                && event.principalId() != null;
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        Optional<GeoRegions.Coordinates> here = GeoRegions.of(event.region());
        if (here.isEmpty()) {
            return Optional.empty();
        }
        GeoRegions.Coordinates now = here.get();
        Optional<Sighting> previous = state.lastSighting(event.principalId());

        state.recordSighting(event.principalId(),
                new Sighting(event.region(), now.latitude(), now.longitude(), event.sourceIp(), event.eventTime()),
                config.sightingTtl());

        if (previous.isEmpty()) {
            return Optional.empty();
        }
        Sighting last = previous.get();
        if (last.region().equals(event.region())) {
            return Optional.empty();
        }

        double km = GeoRegions.distanceKm(last.latitude(), last.longitude(), now.latitude(), now.longitude());
        if (km < config.minDistanceKm()) {
            return Optional.empty();
        }

        long elapsedSeconds = Math.max(1L, event.eventTime().getEpochSecond() - last.at().getEpochSecond());
        if (elapsedSeconds <= 0) {
            return Optional.empty();
        }
        double hours = elapsedSeconds / 3600.0;
        double speedKmh = km / hours;
        if (speedKmh <= config.maxSpeedKmh()) {
            return Optional.empty();
        }

        // Keyed on the identity, not the pair of regions: once an account is flagged, its next few
        // hops are the same incident, and a separate alert per hop only buries the first one.
        return Optional.of(AlertDraft.builder(id() + ":" + event.principalId())
                .title("Impossible travel for %s: %s to %s".formatted(event.actor(), last.region(), event.region()))
                .description(("Principal %s signed in from %s and then from %s %d seconds later. "
                        + "That is %.0f km at an implied %.0f km/h, well beyond the %.0f km/h threshold, "
                        + "so the two sessions cannot belong to the same person.")
                        .formatted(event.actor(), last.region(), event.region(), elapsedSeconds,
                                km, speedKmh, config.maxSpeedKmh()))
                .evidence("previousRegion", last.region())
                .evidence("previousIp", last.sourceIp())
                .evidence("previousLoginAt", last.at().toString())
                .evidence("currentRegion", event.region())
                .evidence("currentIp", event.sourceIp())
                .evidence("distanceKm", Math.round(km))
                .evidence("elapsedSeconds", elapsedSeconds)
                .evidence("impliedSpeedKmh", Math.round(speedKmh))
                .evidence("mfaUsed", event.mfaUsed())
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(30);
    }
}
