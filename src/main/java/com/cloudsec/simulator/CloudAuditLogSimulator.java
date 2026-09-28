package com.cloudsec.simulator;

import com.cloudsec.config.AnalyzerProperties;
import com.cloudsec.config.SimulatorProperties;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.state.AnalyzerStateStore;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

/**
 * Stands in for the cloud provider.
 *
 * <p>Publishes a steady stream of ordinary control-plane activity onto the events topic and slips a
 * full attack sequence into it every so often, so the pipeline always has something real to detect.
 * Switch it off with {@code cloudsec.simulator.enabled=false} and point Kafka at a real audit feed.
 */
@Component
@ConditionalOnProperty(prefix = "cloudsec.simulator", name = "enabled", havingValue = "true", matchIfMissing = true)
public class CloudAuditLogSimulator {

    private static final Logger log = LoggerFactory.getLogger(CloudAuditLogSimulator.class);

    private final CloudEventFactory factory;
    private final ScenarioLibrary scenarios;
    private final KafkaTemplate<String, Object> kafka;
    private final SimulatorProperties properties;
    private final AnalyzerProperties analyzerProperties;
    private final AnalyzerStateStore state;
    private final Counter published;
    private final AtomicLong tick = new AtomicLong();

    public CloudAuditLogSimulator(CloudEventFactory factory,
                                  ScenarioLibrary scenarios,
                                  KafkaTemplate<String, Object> kafka,
                                  SimulatorProperties properties,
                                  AnalyzerProperties analyzerProperties,
                                  AnalyzerStateStore state,
                                  MeterRegistry meters) {
        this.factory = factory;
        this.scenarios = scenarios;
        this.kafka = kafka;
        this.properties = properties;
        this.analyzerProperties = analyzerProperties;
        this.state = state;
        this.published = Counter.builder("cloudsec.simulator.events.published")
                .description("Synthetic cloud audit events written to Kafka")
                .register(meters);
    }

    @PostConstruct
    void seedRegionBaseline() {
        // Teach the unusual-region rule which regions are normal, the way a real deployment would
        // learn them over its first days. Without this every home region alerts once on startup.
        for (String account : properties.accountIds()) {
            for (String region : properties.homeRegions()) {
                state.isFirstTimeSeen("regions:" + account, region);
            }
        }
        log.info("Simulator active: {} events/s across accounts {}, attack every {}s",
                properties.eventsPerSecond(), properties.accountIds(), properties.attackIntervalSeconds());
    }

    @Scheduled(fixedRate = 1000)
    void emitBaselineTraffic() {
        long second = tick.incrementAndGet();
        for (int i = 0; i < properties.eventsPerSecond(); i++) {
            // Roughly one sign-in for every twenty API calls.
            publish(factory.nextDouble() < 0.05 ? factory.benignLogin() : factory.benignEvent());
        }
        if (properties.attackIntervalSeconds() > 0 && second % properties.attackIntervalSeconds() == 0) {
            AttackScenario scenario = AttackScenario.values()[factory.nextInt(AttackScenario.values().length)];
            inject(scenario);
        }
    }

    /** Replays one scenario immediately. Wired to the dashboard buttons and the REST API. */
    public int inject(AttackScenario scenario) {
        List<CloudAuditEvent> events = scenarios.generate(scenario);
        events.forEach(this::publish);
        log.info("Injected scenario {} ({} events): {}", scenario, events.size(), scenario.description());
        return events.size();
    }

    private void publish(CloudAuditEvent event) {
        // Keying by principal keeps one identity on one partition, which is what the stateful rules
        // need to see login sequences in the order they happened.
        kafka.send(analyzerProperties.eventsTopic(), event.principalId(), event);
        published.increment();
    }
}
