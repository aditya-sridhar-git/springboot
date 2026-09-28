package com.cloudsec.simulator;

import static org.assertj.core.api.Assertions.assertThat;

import com.cloudsec.TestProperties;
import com.cloudsec.engine.Detection;
import com.cloudsec.engine.DetectionEngine;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.engine.rules.AccessDeniedSpikeRule;
import com.cloudsec.engine.rules.AuditLogTamperingRule;
import com.cloudsec.engine.rules.BruteForceLoginRule;
import com.cloudsec.engine.rules.DataExfiltrationRule;
import com.cloudsec.engine.rules.ImpossibleTravelRule;
import com.cloudsec.engine.rules.OpenSecurityGroupRule;
import com.cloudsec.engine.rules.PrivilegeEscalationRule;
import com.cloudsec.engine.rules.PublicStorageExposureRule;
import com.cloudsec.engine.rules.RootAccountActivityRule;
import com.cloudsec.engine.rules.UnusualRegionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.state.InMemoryAnalyzerStateStore;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * The end to end contract of the demo: every scripted attack the simulated cloud can produce is
 * caught by the rule it was written for. If a threshold drifts, this is the test that fails.
 */
class ScenarioDetectionTest {

    private final CloudEventFactory factory = new CloudEventFactory(TestProperties.simulator());
    private final ScenarioLibrary scenarios = new ScenarioLibrary(factory);

    private DetectionEngine newEngine() {
        List<DetectionRule> rules = List.of(
                new BruteForceLoginRule(TestProperties.detection()),
                new ImpossibleTravelRule(TestProperties.detection()),
                new RootAccountActivityRule(),
                new PublicStorageExposureRule(),
                new OpenSecurityGroupRule(TestProperties.detection()),
                new PrivilegeEscalationRule(),
                new AuditLogTamperingRule(),
                new DataExfiltrationRule(TestProperties.detection()),
                new UnusualRegionRule(),
                new AccessDeniedSpikeRule(TestProperties.detection()));
        return new DetectionEngine(rules, new InMemoryAnalyzerStateStore(),
                TestProperties.detection(), new SimpleMeterRegistry());
    }

    static Stream<Arguments> scenarioExpectations() {
        return Stream.of(
                Arguments.of(AttackScenario.BRUTE_FORCE, "brute-force-login"),
                Arguments.of(AttackScenario.IMPOSSIBLE_TRAVEL, "impossible-travel"),
                Arguments.of(AttackScenario.PUBLIC_BUCKET, "public-storage-exposure"),
                Arguments.of(AttackScenario.OPEN_SECURITY_GROUP, "open-security-group"),
                Arguments.of(AttackScenario.PRIVILEGE_ESCALATION, "privilege-escalation"),
                Arguments.of(AttackScenario.LOG_TAMPERING, "audit-log-tampering"),
                Arguments.of(AttackScenario.DATA_EXFILTRATION, "data-exfiltration-volume"),
                Arguments.of(AttackScenario.CRYPTO_MINING, "unusual-region"),
                Arguments.of(AttackScenario.CREDENTIAL_ENUMERATION, "access-denied-spike"));
    }

    @ParameterizedTest(name = "{0} is caught by {1}")
    @MethodSource("scenarioExpectations")
    void everyScenarioIsDetected(AttackScenario scenario, String expectedRuleId) {
        DetectionEngine engine = newEngine();
        List<String> firedRules = scenarios.generate(scenario).stream()
                .map(engine::analyze)
                .flatMap(List::stream)
                .map(Detection::rule)
                .map(DetectionRule::id)
                .distinct()
                .toList();

        assertThat(firedRules).contains(expectedRuleId);
    }

    @Test
    @DisplayName("root activity in the log tampering scenario raises a second, separate alert")
    void logTamperingAlsoFlagsRootUsage() {
        DetectionEngine engine = newEngine();
        List<String> fired = scenarios.generate(AttackScenario.LOG_TAMPERING).stream()
                .map(engine::analyze)
                .flatMap(List::stream)
                .map(d -> d.rule().id())
                .toList();

        assertThat(fired).contains("audit-log-tampering", "root-account-activity");
    }

    @Test
    @DisplayName("ordinary background traffic does not trip any rule")
    void benignTrafficIsQuiet() {
        // Seed the regions the organisation legitimately uses, exactly as the running simulator does.
        InMemoryAnalyzerStateStore seeded = new InMemoryAnalyzerStateStore();
        for (String account : TestProperties.simulator().accountIds()) {
            for (String region : TestProperties.simulator().homeRegions()) {
                seeded.isFirstTimeSeen("regions:" + account, region);
            }
        }
        DetectionEngine engine = new DetectionEngine(
                List.of(new BruteForceLoginRule(TestProperties.detection()),
                        new ImpossibleTravelRule(TestProperties.detection()),
                        new RootAccountActivityRule(),
                        new PublicStorageExposureRule(),
                        new OpenSecurityGroupRule(TestProperties.detection()),
                        new PrivilegeEscalationRule(),
                        new AuditLogTamperingRule(),
                        new DataExfiltrationRule(TestProperties.detection()),
                        new AccessDeniedSpikeRule(TestProperties.detection()),
                        new UnusualRegionRule()),
                seeded, TestProperties.detection(), new SimpleMeterRegistry());

        // Mix sign-ins into the API traffic: an identity that appears to hop regions between calls
        // is the classic way a synthetic feed manufactures impossible-travel false positives.
        List<Detection> detections = Stream.generate(
                        () -> factory.nextDouble() < 0.05 ? factory.benignLogin() : factory.benignEvent())
                .limit(3000)
                .map(engine::analyze)
                .flatMap(List::stream)
                .toList();

        assertThat(detections)
                .describedAs("benign traffic should raise no alerts, got %s",
                        detections.stream().map(d -> d.rule().id()).distinct().toList())
                .isEmpty();
    }

    @Test
    @DisplayName("simulated events carry the fields every rule and the archive depend on")
    void generatedEventsAreWellFormed() {
        for (AttackScenario scenario : AttackScenario.values()) {
            for (CloudAuditEvent event : scenarios.generate(scenario)) {
                assertThat(event.eventId()).as("%s eventId", scenario).isNotBlank();
                assertThat(event.eventTime()).as("%s eventTime", scenario).isNotNull();
                assertThat(event.eventName()).as("%s eventName", scenario).isNotBlank();
                assertThat(event.accountId()).as("%s accountId", scenario).isNotBlank();
                assertThat(event.principalId()).as("%s principalId", scenario).isNotBlank();
                assertThat(event.sourceIp()).as("%s sourceIp", scenario).isNotBlank();
            }
        }
    }
}
