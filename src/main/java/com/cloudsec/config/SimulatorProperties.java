package com.cloudsec.config;

import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Settings for the synthetic cloud environment.
 *
 * <p>Point the analyzer at a real CloudTrail-to-Kafka bridge and this whole component switches off
 * with {@code cloudsec.simulator.enabled=false}; nothing downstream changes.
 */
@ConfigurationProperties(prefix = "cloudsec.simulator")
public record SimulatorProperties(
        @DefaultValue("true") boolean enabled,
        /** Baseline benign traffic rate. */
        @DefaultValue("6") int eventsPerSecond,
        /** How often a random attack scenario is injected into the benign stream. */
        @DefaultValue("45") int attackIntervalSeconds,
        @DefaultValue({"123456789012", "210987654321"}) List<String> accountIds,
        /** Regions the simulated organisation legitimately operates in. */
        @DefaultValue({"us-east-1", "eu-west-1", "ap-south-1"}) List<String> homeRegions,
        @DefaultValue({"alice.chen", "bob.martins", "priya.nair", "sam.okafor", "deploy-bot",
                "terraform-ci", "analytics-etl", "backup-agent"}) List<String> principals,
        /** Fixed seed keeps demos reproducible; set to 0 for a fresh stream every run. */
        @DefaultValue("1337") long randomSeed) {
}
