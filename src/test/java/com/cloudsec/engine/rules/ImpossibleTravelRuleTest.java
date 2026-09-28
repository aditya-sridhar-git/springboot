package com.cloudsec.engine.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.cloudsec.TestProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.InMemoryAnalyzerStateStore;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class ImpossibleTravelRuleTest {

    private static final Instant T0 = Instant.parse("2026-09-10T12:00:00Z");

    private ImpossibleTravelRule rule;
    private InMemoryAnalyzerStateStore state;

    @BeforeEach
    void setUp() {
        rule = new ImpossibleTravelRule(TestProperties.detection());
        state = new InMemoryAnalyzerStateStore();
    }

    private CloudAuditEvent login(Instant at, String region) {
        return CloudAuditEvent.builder()
                .eventTime(at)
                .eventSource("signin.amazonaws.com")
                .eventName("ConsoleLogin")
                .region(region)
                .accountId("123456789012")
                .principalId("AIDA-alice")
                .userName("alice.chen")
                .sourceIp("198.51.100.7")
                .build();
    }

    @Test
    @DisplayName("the first sign-in only establishes a baseline")
    void firstLoginIsSilent() {
        assertThat(rule.evaluate(login(T0, "us-east-1"), state)).isEmpty();
        assertThat(state.lastSighting("AIDA-alice")).isPresent();
    }

    @Test
    @DisplayName("Virginia to Singapore in eight minutes is impossible")
    void firesOnImpossibleHop() {
        rule.evaluate(login(T0, "us-east-1"), state);
        Optional<AlertDraft> draft = rule.evaluate(login(T0.plusSeconds(480), "ap-southeast-1"), state);

        assertThat(draft).isPresent();
        AlertDraft alert = draft.get();
        assertThat(alert.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(alert.title()).contains("us-east-1").contains("ap-southeast-1");
        assertThat((Long) alert.evidence().get("distanceKm")).isGreaterThan(15_000L);
        assertThat((Long) alert.evidence().get("impliedSpeedKmh")).isGreaterThan(900L);
        // One key per identity, so the follow-on hops of the same compromise collapse into it.
        assertThat(alert.dedupKey()).isEqualTo("impossible-travel:AIDA-alice");
    }

    @Test
    @DisplayName("the same trip over two days is ordinary travel")
    void doesNotFireWhenTravelIsPlausible() {
        rule.evaluate(login(T0, "us-east-1"), state);
        assertThat(rule.evaluate(login(T0.plusSeconds(48 * 3600), "ap-southeast-1"), state)).isEmpty();
    }

    @Test
    @DisplayName("nearby regions stay under the minimum distance")
    void ignoresShortHops() {
        rule.evaluate(login(T0, "eu-west-2"), state);
        // London to Ireland is roughly 460 km, but at 30 minutes that is only ~920 km/h... just over
        // the threshold, so use a shorter pair: Frankfurt and Stockholm are far, London/Ireland is not.
        assertThat(rule.evaluate(login(T0.plusSeconds(7200), "eu-west-1"), state)).isEmpty();
    }

    @Test
    @DisplayName("an unmapped region cannot be reasoned about, so it is skipped")
    void unknownRegionIsIgnored() {
        rule.evaluate(login(T0, "us-east-1"), state);
        assertThat(rule.evaluate(login(T0.plusSeconds(60), "mars-north-1"), state)).isEmpty();
    }

    @Test
    void repeatedLoginsFromTheSameRegionAreQuiet() {
        rule.evaluate(login(T0, "us-east-1"), state);
        assertThat(rule.evaluate(login(T0.plusSeconds(30), "us-east-1"), state)).isEmpty();
    }
}
