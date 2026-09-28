package com.cloudsec.config;

import java.time.Duration;
import java.util.List;
import java.util.Set;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Tunable thresholds for the detection rules, all overridable from configuration. */
@ConfigurationProperties(prefix = "cloudsec.detection")
public record DetectionProperties(
        @DefaultValue BruteForce bruteForce,
        @DefaultValue ImpossibleTravel impossibleTravel,
        @DefaultValue Exfiltration exfiltration,
        @DefaultValue AccessDenied accessDenied,
        @DefaultValue OpenIngress openIngress,
        /** Rule ids that should never fire, e.g. because they are noisy in this account. */
        @DefaultValue Set<String> disabledRules,
        /** Persist every ingested event to PostgreSQL as well as analysing it. */
        @DefaultValue("true") boolean persistEvents) {

    public record BruteForce(
            @DefaultValue("5") int failureThreshold,
            @DefaultValue("5m") Duration window) {
    }

    public record ImpossibleTravel(
            /** Above this implied ground speed the two logins cannot belong to one human. */
            @DefaultValue("900") double maxSpeedKmh,
            @DefaultValue("100") double minDistanceKm,
            @DefaultValue("24h") Duration sightingTtl) {
    }

    public record Exfiltration(
            @DefaultValue("2147483648") long bytesThreshold,
            @DefaultValue("10m") Duration window) {
    }

    public record AccessDenied(
            @DefaultValue("12") int threshold,
            @DefaultValue("5m") Duration window) {
    }

    public record OpenIngress(
            @DefaultValue({"22", "3389", "3306", "5432", "6379", "27017", "9200"}) List<Integer> sensitivePorts,
            @DefaultValue({"0.0.0.0/0", "::/0"}) List<String> wildcardCidrs) {
    }

    public boolean isDisabled(String ruleId) {
        return disabledRules.contains(ruleId);
    }
}
