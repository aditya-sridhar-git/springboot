package com.cloudsec.simulator;

import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Outcome;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Scripted attack sequences.
 *
 * <p>Each scenario returns the exact events an attacker would leave behind, with timestamps spread
 * across the past few minutes so the windowed rules see a realistic arrival pattern.
 */
@Component
public class ScenarioLibrary {

    private static final String ATTACKER_AGENT = "python-requests/2.31.0";

    private final CloudEventFactory factory;

    public ScenarioLibrary(CloudEventFactory factory) {
        this.factory = factory;
    }

    public List<CloudAuditEvent> generate(AttackScenario scenario) {
        Instant now = Instant.now();
        String account = factory.pick(factory.properties().accountIds());
        return switch (scenario) {
            case BRUTE_FORCE -> bruteForce(now, account);
            case IMPOSSIBLE_TRAVEL -> impossibleTravel(now, account);
            case PUBLIC_BUCKET -> publicBucket(now, account);
            case OPEN_SECURITY_GROUP -> openSecurityGroup(now, account);
            case PRIVILEGE_ESCALATION -> privilegeEscalation(now, account);
            case LOG_TAMPERING -> logTampering(now, account);
            case DATA_EXFILTRATION -> dataExfiltration(now, account);
            case CRYPTO_MINING -> cryptoMining(now, account);
            case CREDENTIAL_ENUMERATION -> credentialEnumeration(now, account);
        };
    }

    private List<CloudAuditEvent> bruteForce(Instant now, String account) {
        String attackerIp = factory.hostileIp();
        String victim = factory.pick(factory.properties().principals());
        List<CloudAuditEvent> events = new ArrayList<>();
        int attempts = 8 + factory.nextInt(5);
        for (int i = 0; i < attempts; i++) {
            events.add(CloudAuditEvent.builder()
                    .eventTime(now.minusSeconds((long) (attempts - i) * 6))
                    .eventSource("signin.amazonaws.com")
                    .eventName("ConsoleLogin")
                    .region("us-east-1")
                    .accountId(account)
                    .principalId(factory.principalIdFor(victim))
                    .principalType("IAMUser")
                    .userName(victim)
                    .sourceIp(attackerIp)
                    .userAgent(ATTACKER_AGENT)
                    .outcome(Outcome.FAILURE)
                    .errorCode("Failed authentication")
                    .mfaUsed(false)
                    .build());
        }
        return events;
    }

    private List<CloudAuditEvent> impossibleTravel(Instant now, String account) {
        String victim = factory.pick(factory.properties().principals().subList(0, 4));
        String principalId = factory.principalIdFor(victim);
        CloudAuditEvent first = CloudAuditEvent.builder()
                .eventTime(now.minusSeconds(480))
                .eventSource("signin.amazonaws.com")
                .eventName("ConsoleLogin")
                .region("us-east-1")
                .accountId(account)
                .principalId(principalId)
                .principalType("IAMUser")
                .userName(victim)
                .sourceIp(factory.corporateIp())
                .userAgent("console.amazonaws.com")
                .outcome(Outcome.SUCCESS)
                .mfaUsed(true)
                .build();
        CloudAuditEvent second = CloudAuditEvent.builder()
                .eventTime(now)
                .eventSource("signin.amazonaws.com")
                .eventName("ConsoleLogin")
                .region("ap-southeast-1")
                .accountId(account)
                .principalId(principalId)
                .principalType("IAMUser")
                .userName(victim)
                .sourceIp(factory.hostileIp())
                .userAgent("Mozilla/5.0 (X11; Linux x86_64)")
                .outcome(Outcome.SUCCESS)
                .mfaUsed(false)
                .build();
        return List.of(first, second);
    }

    private List<CloudAuditEvent> publicBucket(Instant now, String account) {
        String actor = factory.pick(factory.properties().principals());
        String bucket = "arn:aws:s3:::customer-exports-" + factory.shortId();
        return List.of(
                CloudAuditEvent.builder()
                        .eventTime(now.minusSeconds(20))
                        .eventSource("s3.amazonaws.com")
                        .eventName("DeletePublicAccessBlock")
                        .region("us-east-1")
                        .accountId(account)
                        .principalId(factory.principalIdFor(actor))
                        .principalType("IAMUser")
                        .userName(actor)
                        .sourceIp(factory.hostileIp())
                        .userAgent(ATTACKER_AGENT)
                        .resource(bucket)
                        .param("blockPublicAcls", "false")
                        .build(),
                CloudAuditEvent.builder()
                        .eventTime(now)
                        .eventSource("s3.amazonaws.com")
                        .eventName("PutBucketAcl")
                        .region("us-east-1")
                        .accountId(account)
                        .principalId(factory.principalIdFor(actor))
                        .principalType("IAMUser")
                        .userName(actor)
                        .sourceIp(factory.hostileIp())
                        .userAgent(ATTACKER_AGENT)
                        .resource(bucket)
                        .param("grantee", "http://acs.amazonaws.com/groups/global/AllUsers")
                        .param("acl", "public-read")
                        .build());
    }

    private List<CloudAuditEvent> openSecurityGroup(Instant now, String account) {
        String actor = factory.pick(factory.properties().principals());
        String group = "sg-" + factory.shortId();
        int port = factory.pick(List.of(22, 3389, 5432, 6379));
        return List.of(CloudAuditEvent.builder()
                .eventTime(now)
                .eventSource("ec2.amazonaws.com")
                .eventName("AuthorizeSecurityGroupIngress")
                .region(factory.pick(factory.properties().homeRegions()))
                .accountId(account)
                .principalId(factory.principalIdFor(actor))
                .principalType("AssumedRole")
                .userName(actor)
                .sourceIp(factory.hostileIp())
                .userAgent(ATTACKER_AGENT)
                .resource(group)
                .param("cidrIp", "0.0.0.0/0")
                .param("fromPort", String.valueOf(port))
                .param("toPort", String.valueOf(port))
                .param("ipProtocol", "tcp")
                .build());
    }

    private List<CloudAuditEvent> privilegeEscalation(Instant now, String account) {
        String actor = factory.pick(factory.properties().principals());
        String target = "svc-" + factory.shortId();
        return List.of(
                CloudAuditEvent.builder()
                        .eventTime(now.minusSeconds(30))
                        .eventSource("iam.amazonaws.com")
                        .eventName("AttachUserPolicy")
                        .region("us-east-1")
                        .accountId(account)
                        .principalId(factory.principalIdFor(actor))
                        .principalType("IAMUser")
                        .userName(actor)
                        .sourceIp(factory.hostileIp())
                        .userAgent(ATTACKER_AGENT)
                        .resource("user/" + target)
                        .param("targetPrincipal", target)
                        .param("policyArn", "arn:aws:iam::aws:policy/AdministratorAccess")
                        .build(),
                CloudAuditEvent.builder()
                        .eventTime(now)
                        .eventSource("iam.amazonaws.com")
                        .eventName("CreateAccessKey")
                        .region("us-east-1")
                        .accountId(account)
                        .principalId(factory.principalIdFor(actor))
                        .principalType("IAMUser")
                        .userName(actor)
                        .sourceIp(factory.hostileIp())
                        .userAgent(ATTACKER_AGENT)
                        .resource("user/" + target)
                        .param("targetPrincipal", target)
                        .build());
    }

    private List<CloudAuditEvent> logTampering(Instant now, String account) {
        return List.of(CloudAuditEvent.builder()
                .eventTime(now)
                .eventSource("cloudtrail.amazonaws.com")
                .eventName(factory.pick(List.of("StopLogging", "DeleteTrail", "DeleteFlowLogs")))
                .region("us-east-1")
                .accountId(account)
                .principalId("root")
                .principalType("Root")
                .userName("root")
                .sourceIp(factory.hostileIp())
                .userAgent(ATTACKER_AGENT)
                .resource("trail/org-audit-trail")
                .mfaUsed(false)
                .build());
    }

    private List<CloudAuditEvent> dataExfiltration(Instant now, String account) {
        String actor = factory.pick(factory.properties().principals());
        String principalId = factory.principalIdFor(actor);
        List<CloudAuditEvent> events = new ArrayList<>();
        int objects = 12 + factory.nextInt(6);
        for (int i = 0; i < objects; i++) {
            events.add(CloudAuditEvent.builder()
                    .eventTime(now.minusSeconds((long) (objects - i) * 8))
                    .eventSource("s3.amazonaws.com")
                    .eventName("GetObject")
                    .region("us-east-1")
                    .accountId(account)
                    .principalId(principalId)
                    .principalType("AssumedRole")
                    .userName(actor)
                    .sourceIp(factory.hostileIp())
                    .userAgent(ATTACKER_AGENT)
                    .resource("arn:aws:s3:::data-lake/exports/part-%04d.parquet".formatted(i))
                    // ~250 MiB per object, so the batch clears the 2 GiB window threshold.
                    .bytesTransferred(250L * 1024 * 1024 + factory.nextInt(50_000_000))
                    .build());
        }
        return events;
    }

    private List<CloudAuditEvent> cryptoMining(Instant now, String account) {
        String actor = factory.pick(factory.properties().principals());
        String region = factory.pick(List.of("ap-northeast-2", "sa-east-1", "af-south-1", "me-south-1", "cn-north-1"));
        return List.of(CloudAuditEvent.builder()
                .eventTime(now)
                .eventSource("ec2.amazonaws.com")
                .eventName("RunInstances")
                .region(region)
                .accountId(account)
                .principalId(factory.principalIdFor(actor))
                .principalType("AssumedRole")
                .userName(actor)
                .sourceIp(factory.hostileIp())
                .userAgent(ATTACKER_AGENT)
                .resource("i-" + factory.shortId())
                .param("instanceType", factory.pick(List.of("p4d.24xlarge", "g5.48xlarge", "p3.16xlarge")))
                .param("instanceCount", String.valueOf(4 + factory.nextInt(12)))
                .build());
    }

    private List<CloudAuditEvent> credentialEnumeration(Instant now, String account) {
        String actor = "svc-" + factory.shortId();
        String principalId = factory.principalIdFor(actor);
        String attackerIp = factory.hostileIp();
        List<String> probes = List.of("ListUsers", "ListRoles", "GetAccountAuthorizationDetails",
                "ListAttachedUserPolicies", "DescribeInstances", "ListBuckets", "GetCallerIdentity",
                "ListSecrets", "DescribeDBInstances", "ListFunctions", "ListKeys", "DescribeSnapshots",
                "ListAccessKeys", "GetBucketPolicy", "DescribeSecurityGroups");
        List<CloudAuditEvent> events = new ArrayList<>();
        for (int i = 0; i < probes.size(); i++) {
            events.add(CloudAuditEvent.builder()
                    .eventTime(now.minusSeconds((long) (probes.size() - i) * 4))
                    .eventSource("iam.amazonaws.com")
                    .eventName(probes.get(i))
                    .region("us-east-1")
                    .accountId(account)
                    .principalId(principalId)
                    .principalType("AssumedRole")
                    .userName(actor)
                    .sourceIp(attackerIp)
                    .userAgent(ATTACKER_AGENT)
                    .outcome(Outcome.FAILURE)
                    .errorCode("AccessDenied")
                    .build());
        }
        return events;
    }
}
