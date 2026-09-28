package com.cloudsec.engine;

import static org.assertj.core.api.Assertions.assertThat;

import com.cloudsec.TestProperties;
import com.cloudsec.config.DetectionProperties;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import com.cloudsec.state.InMemoryAnalyzerStateStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class DetectionEngineTest {

    private final InMemoryAnalyzerStateStore state = new InMemoryAnalyzerStateStore();
    private final SimpleMeterRegistry meters = new SimpleMeterRegistry();

    private static final CloudAuditEvent EVENT = CloudAuditEvent.builder()
            .eventName("DescribeInstances").accountId("123456789012").userName("alice.chen").build();

    /** A rule that always fires, so dispatch is easy to assert. */
    private static class AlwaysFires implements DetectionRule {
        private final String id;

        AlwaysFires(String id) {
            this.id = id;
        }

        public String id() { return id; }
        public String name() { return "Always " + id; }
        public Severity severity() { return Severity.LOW; }
        public String mitreTechnique() { return "T0000"; }
        public boolean supports(CloudAuditEvent event) { return true; }

        public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
            return Optional.of(AlertDraft.builder(id + ":fixed").title("fired").build(severity()));
        }
    }

    private static class Explodes extends AlwaysFires {
        Explodes() {
            super("explodes");
        }

        @Override
        public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
            throw new IllegalStateException("rule is broken");
        }
    }

    @Test
    @DisplayName("every supporting rule gets a chance to fire")
    void runsAllRules() {
        DetectionEngine engine = new DetectionEngine(
                List.of(new AlwaysFires("one"), new AlwaysFires("two")),
                state, TestProperties.detection(), meters);

        assertThat(engine.analyze(EVENT)).hasSize(2)
                .extracting(d -> d.rule().id())
                .containsExactly("one", "two");
    }

    @Test
    @DisplayName("one broken rule does not stop the others")
    void isolatesFailingRules() {
        DetectionEngine engine = new DetectionEngine(
                List.of(new Explodes(), new AlwaysFires("healthy")),
                state, TestProperties.detection(), meters);

        assertThat(engine.analyze(EVENT)).hasSize(1)
                .first().extracting(d -> d.rule().id()).isEqualTo("healthy");
        assertThat(meters.counter("cloudsec.rule.errors", "rule", "explodes").count()).isEqualTo(1.0);
    }

    @Test
    @DisplayName("rules named in the disabled list never load")
    void honoursDisabledRules() {
        DetectionProperties base = TestProperties.detection();
        DetectionProperties withDisabled = new DetectionProperties(base.bruteForce(), base.impossibleTravel(),
                base.exfiltration(), base.accessDenied(), base.openIngress(), Set.of("two"), true);

        DetectionEngine engine = new DetectionEngine(
                List.of(new AlwaysFires("one"), new AlwaysFires("two")),
                state, withDisabled, meters);

        assertThat(engine.activeRules()).extracting(DetectionRule::id).containsExactly("one");
        assertThat(engine.analyze(EVENT)).hasSize(1);
    }

    @Test
    @DisplayName("each rule evaluation is timed for the metrics export")
    void recordsRuleTimings() {
        DetectionEngine engine = new DetectionEngine(
                List.of(new AlwaysFires("one")), state, TestProperties.detection(), meters);
        engine.analyze(EVENT);

        assertThat(meters.timer("cloudsec.rule.evaluation", "rule", "one").count()).isEqualTo(1L);
    }
}
