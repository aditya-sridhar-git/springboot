package com.cloudsec.engine.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.cloudsec.TestProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Outcome;
import com.cloudsec.model.Severity;
import com.cloudsec.state.InMemoryAnalyzerStateStore;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class BruteForceLoginRuleTest {

    private static final Instant T0 = Instant.parse("2026-09-10T12:00:00Z");

    private BruteForceLoginRule rule;
    private InMemoryAnalyzerStateStore state;

    @BeforeEach
    void setUp() {
        rule = new BruteForceLoginRule(TestProperties.detection());
        state = new InMemoryAnalyzerStateStore();
    }

    private CloudAuditEvent failedLogin(Instant at, String sourceIp) {
        return CloudAuditEvent.builder()
                .eventTime(at)
                .eventSource("signin.amazonaws.com")
                .eventName("ConsoleLogin")
                .region("us-east-1")
                .accountId("123456789012")
                .principalId("AIDA1")
                .userName("alice.chen")
                .sourceIp(sourceIp)
                .outcome(Outcome.FAILURE)
                .errorCode("Failed authentication")
                .build();
    }

    @Test
    @DisplayName("stays quiet below the failure threshold")
    void doesNotFireBelowThreshold() {
        for (int i = 0; i < 4; i++) {
            assertThat(rule.evaluate(failedLogin(T0.plusSeconds(i * 10L), "203.0.113.9"), state)).isEmpty();
        }
    }

    @Test
    @DisplayName("fires on the fifth failure from one address")
    void firesAtThreshold() {
        Optional<AlertDraft> draft = Optional.empty();
        for (int i = 0; i < 5; i++) {
            draft = rule.evaluate(failedLogin(T0.plusSeconds(i * 10L), "203.0.113.9"), state);
        }
        assertThat(draft).isPresent();
        AlertDraft alert = draft.get();
        assertThat(alert.severity()).isEqualTo(Severity.HIGH);
        assertThat(alert.title()).contains("5 failed sign-ins from 203.0.113.9");
        assertThat(alert.evidence()).containsEntry("failureCount", 5L).containsEntry("threshold", 5);
        assertThat(alert.dedupKey()).isEqualTo("brute-force-login:123456789012|203.0.113.9");
    }

    @Test
    @DisplayName("failures that fall outside the window stop counting")
    void oldFailuresLeaveTheWindow() {
        for (int i = 0; i < 4; i++) {
            rule.evaluate(failedLogin(T0.plusSeconds(i * 10L), "203.0.113.9"), state);
        }
        // Six minutes later the earlier burst has aged out, so this is failure number one again.
        assertThat(rule.evaluate(failedLogin(T0.plusSeconds(360), "203.0.113.9"), state)).isEmpty();
    }

    @Test
    @DisplayName("failures from different addresses are counted separately")
    void separateSourcesDoNotCombine() {
        for (int i = 0; i < 4; i++) {
            rule.evaluate(failedLogin(T0.plusSeconds(i * 10L), "203.0.113.9"), state);
        }
        assertThat(rule.evaluate(failedLogin(T0.plusSeconds(50), "198.51.100.4"), state)).isEmpty();
    }

    @Test
    void ignoresSuccessfulLogins() {
        CloudAuditEvent success = CloudAuditEvent.builder()
                .eventName("ConsoleLogin").outcome(Outcome.SUCCESS).build();
        assertThat(rule.supports(success)).isFalse();
    }
}
