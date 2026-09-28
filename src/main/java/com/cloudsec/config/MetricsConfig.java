package com.cloudsec.config;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.config.MeterFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Metric hygiene for the Datadog export: every series is tagged with service and environment, and
 * the high-cardinality HTTP URI tag is capped so a scanner hitting random paths cannot blow up the
 * custom-metric bill.
 */
@Configuration
public class MetricsConfig {

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> commonTags(
            @Value("${spring.application.name:cloud-security-analyzer}") String service,
            @Value("${cloudsec.environment:local}") String environment) {
        return registry -> registry.config()
                .commonTags("service", service, "env", environment)
                .meterFilter(MeterFilter.maximumAllowableTags("http.server.requests", "uri", 100,
                        MeterFilter.deny()));
    }
}
