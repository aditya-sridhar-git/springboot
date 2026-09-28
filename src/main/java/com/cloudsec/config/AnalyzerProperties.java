package com.cloudsec.config;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/** Wiring level configuration: topic names, retention and dashboard cadence. */
@ConfigurationProperties(prefix = "cloudsec")
public record AnalyzerProperties(
        @DefaultValue("cloud.security.events") String eventsTopic,
        @DefaultValue("cloud.security.alerts") String alertsTopic,
        @DefaultValue("6") int topicPartitions,
        @DefaultValue("1") short topicReplicas,
        /** How many alerts the Redis hot cache keeps for instant dashboard loads. */
        @DefaultValue("200") int recentAlertCacheSize,
        @DefaultValue("100") int recentEventCacheSize,
        /** How often the aggregated stats frame is pushed to connected dashboards. */
        @DefaultValue("2s") Duration statsPushInterval,
        /** Audit events older than this are pruned from PostgreSQL. */
        @DefaultValue("7d") Duration eventRetention) {
}
