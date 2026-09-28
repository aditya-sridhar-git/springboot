package com.cloudsec.config;

import com.cloudsec.service.DashboardStatsService;
import com.cloudsec.web.DashboardSocketHandler;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.EnableScheduling;
import org.springframework.scheduling.annotation.SchedulingConfigurer;
import org.springframework.scheduling.config.ScheduledTaskRegistrar;

/**
 * Registers the dashboard push loop programmatically so its cadence can come straight from
 * {@link AnalyzerProperties} as a real {@code Duration}.
 */
@Configuration
@EnableScheduling
public class SchedulingConfig implements SchedulingConfigurer {

    private final DashboardStatsService statsService;
    private final AnalyzerProperties properties;

    public SchedulingConfig(DashboardStatsService statsService, AnalyzerProperties properties) {
        this.statsService = statsService;
        this.properties = properties;
    }

    @Override
    public void configureTasks(ScheduledTaskRegistrar registrar) {
        registrar.addFixedDelayTask(statsService::pushSnapshot, properties.statsPushInterval());
    }

    /** A dashboard that has just connected should not wait a full cycle for its first numbers. */
    @EventListener
    public void onDashboardConnected(DashboardSocketHandler.DashboardClientConnected event) {
        statsService.pushSnapshotTo(event.sessionId());
    }
}
