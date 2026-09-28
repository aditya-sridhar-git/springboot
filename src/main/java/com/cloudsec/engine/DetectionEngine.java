package com.cloudsec.engine;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.state.AnalyzerStateStore;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Timer;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Runs every enabled rule against each event.
 *
 * <p>The engine is deliberately dumb: it owns ordering, timing, isolation and nothing else. A rule
 * that throws is logged and skipped so one bad detection cannot stall the whole pipeline.
 */
@Component
public class DetectionEngine {

    private static final Logger log = LoggerFactory.getLogger(DetectionEngine.class);

    private final List<DetectionRule> rules;
    private final AnalyzerStateStore state;
    private final DetectionProperties properties;
    private final MeterRegistry meters;
    private final Map<String, Timer> ruleTimers = new ConcurrentHashMap<>();

    public DetectionEngine(List<DetectionRule> rules,
                           AnalyzerStateStore state,
                           DetectionProperties properties,
                           MeterRegistry meters) {
        this.rules = rules.stream()
                .filter(DetectionRule::enabled)
                .filter(r -> !properties.isDisabled(r.id()))
                .sorted(Comparator.comparing(DetectionRule::id))
                .toList();
        this.state = state;
        this.properties = properties;
        this.meters = meters;
        log.info("Detection engine loaded {} rules: {}", this.rules.size(), this.rules.stream().map(DetectionRule::id).toList());
    }

    public List<Detection> analyze(CloudAuditEvent event) {
        List<Detection> detections = new ArrayList<>();
        for (DetectionRule rule : rules) {
            if (!rule.supports(event)) {
                continue;
            }
            Timer timer = ruleTimers.computeIfAbsent(rule.id(), id -> Timer.builder("cloudsec.rule.evaluation")
                    .description("Time spent evaluating a single detection rule")
                    .tag("rule", id)
                    .publishPercentileHistogram()
                    .register(meters));
            long started = System.nanoTime();
            try {
                Optional<AlertDraft> draft = rule.evaluate(event, state);
                draft.ifPresent(d -> detections.add(new Detection(rule, d, event)));
            } catch (RuntimeException ex) {
                meters.counter("cloudsec.rule.errors", "rule", rule.id()).increment();
                log.error("Rule {} failed on event {}", rule.id(), event.eventId(), ex);
            } finally {
                timer.record(System.nanoTime() - started, java.util.concurrent.TimeUnit.NANOSECONDS);
            }
        }
        return detections;
    }

    public List<DetectionRule> activeRules() {
        return rules;
    }

    public DetectionProperties properties() {
        return properties;
    }
}
