package com.cloudsec.engine.rules;

import static org.assertj.core.api.Assertions.assertThat;

import com.cloudsec.TestProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Outcome;
import com.cloudsec.model.Severity;
import com.cloudsec.state.InMemoryAnalyzerStateStore;
import java.util.Optional;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/** The stateless posture rules: storage exposure, firewall openings, IAM changes, log tampering. */
class PostureRulesTest {

    private final InMemoryAnalyzerStateStore state = new InMemoryAnalyzerStateStore();

    @Nested
    class PublicStorage {

        private final PublicStorageExposureRule rule = new PublicStorageExposureRule();

        @Test
        @DisplayName("granting AllUsers on a bucket is critical")
        void firesOnAnonymousGrant() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("PutBucketAcl")
                    .eventSource("s3.amazonaws.com")
                    .accountId("123456789012")
                    .userName("deploy-bot")
                    .resource("arn:aws:s3:::customer-exports")
                    .param("grantee", "http://acs.amazonaws.com/groups/global/AllUsers")
                    .param("acl", "public-read")
                    .build();

            Optional<AlertDraft> draft = rule.evaluate(event, state);
            assertThat(draft).isPresent();
            assertThat(draft.get().severity()).isEqualTo(Severity.CRITICAL);
            assertThat(draft.get().evidence()).containsEntry("grantee", "AllUsers (anonymous)");
        }

        @Test
        @DisplayName("a private ACL change is routine")
        void ignoresPrivateAcl() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("PutBucketAcl")
                    .resource("arn:aws:s3:::internal-logs")
                    .param("grantee", "arn:aws:iam::123456789012:root")
                    .param("acl", "private")
                    .build();
            assertThat(rule.evaluate(event, state)).isEmpty();
        }

        @Test
        @DisplayName("evidence omits fields the event never carried instead of printing null")
        void evidenceSkipsAbsentFields() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("DeletePublicAccessBlock")
                    .resource("arn:aws:s3:::customer-exports")
                    .param("blockPublicAcls", "false")
                    .build();

            Optional<AlertDraft> draft = rule.evaluate(event, state);
            assertThat(draft).isPresent();
            assertThat(draft.get().evidence())
                    .doesNotContainKeys("acl", "grantee", "bucketPolicy")
                    .containsEntry("publicAccessBlockRemoved", true);
        }

        @Test
        void removingThePublicAccessBlockAlsoFires() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("DeletePublicAccessBlock")
                    .resource("arn:aws:s3:::customer-exports")
                    .param("blockPublicAcls", "false")
                    .build();
            assertThat(rule.evaluate(event, state)).isPresent();
        }
    }

    @Nested
    class OpenIngress {

        private final OpenSecurityGroupRule rule = new OpenSecurityGroupRule(TestProperties.detection());

        @Test
        @DisplayName("SSH open to the world fires")
        void firesOnOpenSsh() {
            Optional<AlertDraft> draft = rule.evaluate(ingress("0.0.0.0/0", "22", "22"), state);
            assertThat(draft).isPresent();
            assertThat(draft.get().severity()).isEqualTo(Severity.HIGH);
            assertThat(draft.get().title()).contains("port 22");
        }

        @Test
        @DisplayName("every port open to the world is worse than one")
        void allPortsIsCritical() {
            Optional<AlertDraft> draft = rule.evaluate(ingress("0.0.0.0/0", "0", "65535"), state);
            assertThat(draft).isPresent();
            assertThat(draft.get().severity()).isEqualTo(Severity.CRITICAL);
            assertThat(draft.get().evidence()).containsEntry("allPortsExposed", true);
        }

        @Test
        @DisplayName("a wide-open port nobody attacks is not worth waking anyone for")
        void ignoresNonSensitivePort() {
            assertThat(rule.evaluate(ingress("0.0.0.0/0", "8080", "8080"), state)).isEmpty();
        }

        @Test
        @DisplayName("SSH restricted to the corporate range is fine")
        void ignoresNarrowCidr() {
            assertThat(rule.evaluate(ingress("10.0.0.0/8", "22", "22"), state)).isEmpty();
        }

        private CloudAuditEvent ingress(String cidr, String from, String to) {
            return CloudAuditEvent.builder()
                    .eventName("AuthorizeSecurityGroupIngress")
                    .eventSource("ec2.amazonaws.com")
                    .accountId("123456789012")
                    .userName("terraform-ci")
                    .resource("sg-0a1b2c3d")
                    .param("cidrIp", cidr)
                    .param("fromPort", from)
                    .param("toPort", to)
                    .param("ipProtocol", "tcp")
                    .build();
        }
    }

    @Nested
    class PrivilegeEscalation {

        private final PrivilegeEscalationRule rule = new PrivilegeEscalationRule();

        @Test
        @DisplayName("attaching AdministratorAccess to another user fires")
        void firesOnAdminPolicy() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("AttachUserPolicy")
                    .eventSource("iam.amazonaws.com")
                    .accountId("123456789012")
                    .userName("bob.martins")
                    .param("targetPrincipal", "svc-backdoor")
                    .param("policyArn", "arn:aws:iam::aws:policy/AdministratorAccess")
                    .build();

            Optional<AlertDraft> draft = rule.evaluate(event, state);
            assertThat(draft).isPresent();
            assertThat(draft.get().severity()).isEqualTo(Severity.CRITICAL);
            assertThat(draft.get().title()).contains("bob.martins").contains("svc-backdoor");
        }

        @Test
        @DisplayName("an inline policy with Action:* is escalation even without a managed policy")
        void firesOnWildcardInlinePolicy() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("PutUserPolicy")
                    .userName("bob.martins")
                    .param("targetPrincipal", "svc-backdoor")
                    .param("policyDocument", "{\"Effect\":\"Allow\",\"Action\": \"*\",\"Resource\":\"*\"}")
                    .build();
            assertThat(rule.evaluate(event, state)).isPresent();
        }

        @Test
        @DisplayName("a narrowly scoped read-only policy is not escalation")
        void ignoresScopedPolicy() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("AttachUserPolicy")
                    .userName("bob.martins")
                    .param("targetPrincipal", "svc-reporting")
                    .param("policyArn", "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess")
                    .build();
            assertThat(rule.evaluate(event, state)).isEmpty();
        }
    }

    @Nested
    class LogTampering {

        private final AuditLogTamperingRule rule = new AuditLogTamperingRule();

        @Test
        @DisplayName("stopping CloudTrail blinds the analyzer and is always critical")
        void firesOnStopLogging() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("StopLogging")
                    .eventSource("cloudtrail.amazonaws.com")
                    .accountId("123456789012")
                    .userName("root")
                    .principalType("Root")
                    .resource("trail/org-audit-trail")
                    .build();

            Optional<AlertDraft> draft = rule.evaluate(event, state);
            assertThat(draft).isPresent();
            assertThat(draft.get().severity()).isEqualTo(Severity.CRITICAL);
            assertThat(draft.get().evidence()).containsEntry("eventName", "StopLogging");
        }

        @Test
        @DisplayName("an UpdateTrail that does not narrow coverage is routine")
        void ignoresHarmlessTrailUpdate() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("UpdateTrail")
                    .resource("trail/org-audit-trail")
                    .param("isMultiRegionTrail", "true")
                    .param("includeGlobalServiceEvents", "true")
                    .build();
            assertThat(rule.evaluate(event, state)).isEmpty();
        }

        @Test
        @DisplayName("an UpdateTrail that drops multi-region coverage fires")
        void firesWhenTrailCoverageShrinks() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("UpdateTrail")
                    .resource("trail/org-audit-trail")
                    .param("isMultiRegionTrail", "false")
                    .param("includeGlobalServiceEvents", "true")
                    .build();
            assertThat(rule.evaluate(event, state)).isPresent();
        }
    }

    @Nested
    class RootActivity {

        private final RootAccountActivityRule rule = new RootAccountActivityRule();

        @Test
        @DisplayName("root without MFA is critical even for a harmless call")
        void rootWithoutMfaIsCritical() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("DescribeInstances")
                    .principalType("Root")
                    .userName("root")
                    .accountId("123456789012")
                    .mfaUsed(false)
                    .build();
            assertThat(rule.evaluate(event, state)).get()
                    .extracting(AlertDraft::severity).isEqualTo(Severity.CRITICAL);
        }

        @Test
        @DisplayName("root with MFA on a read call is still worth a high alert")
        void rootWithMfaIsHigh() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("DescribeInstances")
                    .principalType("Root")
                    .userName("root")
                    .mfaUsed(true)
                    .build();
            assertThat(rule.evaluate(event, state)).get()
                    .extracting(AlertDraft::severity).isEqualTo(Severity.HIGH);
        }

        @Test
        void ordinaryUsersAreNotRoot() {
            CloudAuditEvent event = CloudAuditEvent.builder()
                    .eventName("DescribeInstances").principalType("IAMUser").build();
            assertThat(rule.supports(event)).isFalse();
        }
    }
}
