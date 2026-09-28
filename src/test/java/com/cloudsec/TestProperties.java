package com.cloudsec;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.config.SimulatorProperties;
import java.time.Duration;
import java.util.List;
import java.util.Set;

/** The production defaults, spelled out so rule tests assert against real thresholds. */
public final class TestProperties {

    private TestProperties() {
    }

    public static DetectionProperties detection() {
        return new DetectionProperties(
                new DetectionProperties.BruteForce(5, Duration.ofMinutes(5)),
                new DetectionProperties.ImpossibleTravel(900, 100, Duration.ofHours(24)),
                new DetectionProperties.Exfiltration(2L * 1024 * 1024 * 1024, Duration.ofMinutes(10)),
                new DetectionProperties.AccessDenied(12, Duration.ofMinutes(5)),
                new DetectionProperties.OpenIngress(List.of(22, 3389, 3306, 5432, 6379, 27017, 9200),
                        List.of("0.0.0.0/0", "::/0")),
                Set.of(),
                true);
    }

    public static SimulatorProperties simulator() {
        return new SimulatorProperties(true, 6, 45,
                List.of("123456789012", "210987654321"),
                List.of("us-east-1", "eu-west-1", "ap-south-1"),
                List.of("alice.chen", "bob.martins", "priya.nair", "sam.okafor", "deploy-bot",
                        "terraform-ci", "analytics-etl", "backup-agent"),
                1337L);
    }
}
