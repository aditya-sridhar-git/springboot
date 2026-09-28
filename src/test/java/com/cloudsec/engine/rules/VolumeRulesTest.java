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

/** Rules that accumulate a quantity over a window: egress volume, denials, first-seen regions. */
class VolumeRulesTest {

    private static final Instant T0 = Instant.parse("2026-09-10T12:00:00Z");
    private static final long MIB = 1024L * 1024L;

    private InMemoryAnalyzerStateStore state;

    @BeforeEach
    void setUp() {
        state = new InMemoryAnalyzerStateStore();
    }

    private CloudAuditEvent download(Instant at, long bytes) {
        return CloudAuditEvent.builder()
                .eventTime(at)
                .eventName("GetObject")
                .eventSource("s3.amazonaws.com")
                .accountId("123456789012")
                .principalId("AIDA-etl")
                .userName("analytics-etl")
                .sourceIp("203.0.113.44")
                .resource("arn:aws:s3:::data-lake/exports/part-0001.parquet")
                .bytesTransferred(bytes)
                .build();
    }

    @Test
    @DisplayName("ordinary downloads never reach the egress threshold")
    void quietBelowThreshold() {
        DataExfiltrationRule rule = new DataExfiltrationRule(TestProperties.detection());
        for (int i = 0; i < 7; i++) {
            assertThat(rule.evaluate(download(T0.plusSeconds(i * 10L), 250 * MIB), state)).isEmpty();
        }
    }

    @Test
    @DisplayName("more than 2 GiB in ten minutes fires")
    void firesOnBulkEgress() {
        DataExfiltrationRule rule = new DataExfiltrationRule(TestProperties.detection());
        Optional<AlertDraft> draft = Optional.empty();
        for (int i = 0; i < 9; i++) {
            draft = rule.evaluate(download(T0.plusSeconds(i * 10L), 250 * MIB), state);
        }
        assertThat(draft).isPresent();
        assertThat(draft.get().severity()).isEqualTo(Severity.HIGH);
        assertThat((Long) draft.get().evidence().get("bytesTransferred")).isGreaterThan(2L * 1024 * MIB);
    }

    @Test
    @DisplayName("four times the threshold escalates to critical")
    void escalatesOnExtremeVolume() {
        DataExfiltrationRule rule = new DataExfiltrationRule(TestProperties.detection());
        Optional<AlertDraft> draft = Optional.empty();
        for (int i = 0; i < 34; i++) {
            draft = rule.evaluate(download(T0.plusSeconds(i * 10L), 250 * MIB), state);
        }
        assertThat(draft).isPresent();
        assertThat(draft.get().severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    @DisplayName("volume that falls outside the window stops counting")
    void windowExpires() {
        DataExfiltrationRule rule = new DataExfiltrationRule(TestProperties.detection());
        for (int i = 0; i < 7; i++) {
            rule.evaluate(download(T0.plusSeconds(i * 10L), 250 * MIB), state);
        }
        // Twenty minutes on, the earlier transfers have aged out of the ten minute window.
        assertThat(rule.evaluate(download(T0.plusSeconds(1200), 250 * MIB), state)).isEmpty();
    }

    @Test
    @DisplayName("a burst of denials looks like permission enumeration")
    void firesOnDenialSpike() {
        AccessDeniedSpikeRule rule = new AccessDeniedSpikeRule(TestProperties.detection());
        Optional<AlertDraft> draft = Optional.empty();
        for (int i = 0; i < 12; i++) {
            draft = rule.evaluate(denied(T0.plusSeconds(i * 4L)), state);
        }
        assertThat(draft).isPresent();
        assertThat(draft.get().severity()).isEqualTo(Severity.MEDIUM);
        assertThat(draft.get().evidence()).containsEntry("denialCount", 12L);
    }

    @Test
    @DisplayName("three times the denial threshold escalates")
    void denialSpikeEscalates() {
        AccessDeniedSpikeRule rule = new AccessDeniedSpikeRule(TestProperties.detection());
        Optional<AlertDraft> draft = Optional.empty();
        for (int i = 0; i < 36; i++) {
            draft = rule.evaluate(denied(T0.plusSeconds(i * 4L)), state);
        }
        assertThat(draft).get().extracting(AlertDraft::severity).isEqualTo(Severity.HIGH);
    }

    private CloudAuditEvent denied(Instant at) {
        return CloudAuditEvent.builder()
                .eventTime(at)
                .eventName("ListUsers")
                .eventSource("iam.amazonaws.com")
                .accountId("123456789012")
                .principalId("AIDA-stolen")
                .userName("svc-stolen")
                .sourceIp("203.0.113.44")
                .outcome(Outcome.FAILURE)
                .errorCode("AccessDenied")
                .build();
    }

    @Test
    @DisplayName("a region is only new once")
    void unusualRegionFiresOnceThenLearnsIt() {
        UnusualRegionRule rule = new UnusualRegionRule();
        CloudAuditEvent launch = CloudAuditEvent.builder()
                .eventTime(T0)
                .eventName("RunInstances")
                .eventSource("ec2.amazonaws.com")
                .accountId("123456789012")
                .userName("deploy-bot")
                .region("af-south-1")
                .resource("i-0abc")
                .param("instanceType", "p4d.24xlarge")
                .build();

        assertThat(rule.evaluate(launch, state)).isPresent();
        assertThat(rule.evaluate(launch, state)).isEmpty();
    }
}
