package com.cloudsec.simulator;

import com.cloudsec.config.SimulatorProperties;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Outcome;
import java.time.Instant;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import org.springframework.stereotype.Component;

/**
 * Builds the synthetic audit stream: a plausible background of day to day cloud activity, plus the
 * scripted attack sequences that the detection rules are meant to catch.
 */
@Component
public class CloudEventFactory {

    private record ApiCall(String source, String name, String resourcePrefix, boolean transfersData) {
    }

    /** Ordinary activity an idle-ish account produces all day. */
    private static final List<ApiCall> BENIGN_CALLS = List.of(
            new ApiCall("ec2.amazonaws.com", "DescribeInstances", "i-", false),
            new ApiCall("ec2.amazonaws.com", "DescribeVolumes", "vol-", false),
            new ApiCall("ec2.amazonaws.com", "CreateTags", "i-", false),
            new ApiCall("s3.amazonaws.com", "ListBuckets", "arn:aws:s3:::", false),
            new ApiCall("s3.amazonaws.com", "GetObject", "arn:aws:s3:::app-assets/", true),
            new ApiCall("s3.amazonaws.com", "PutObject", "arn:aws:s3:::app-uploads/", true),
            new ApiCall("iam.amazonaws.com", "ListRoles", "role/", false),
            new ApiCall("iam.amazonaws.com", "GetRole", "role/", false),
            new ApiCall("lambda.amazonaws.com", "Invoke", "function:", false),
            new ApiCall("logs.amazonaws.com", "PutLogEvents", "log-group:", false),
            new ApiCall("sts.amazonaws.com", "AssumeRole", "role/", false),
            new ApiCall("rds.amazonaws.com", "DescribeDBInstances", "db:", false),
            new ApiCall("cloudformation.amazonaws.com", "DescribeStacks", "stack/", false),
            new ApiCall("ecs.amazonaws.com", "RunTask", "task/", false),
            new ApiCall("kms.amazonaws.com", "Decrypt", "key/", false));

    private static final List<String> BENIGN_AGENTS = List.of(
            "aws-cli/2.15.30 Python/3.11.8", "Boto3/1.34.51 Python/3.11.8",
            "console.amazonaws.com", "terraform/1.7.4", "aws-sdk-java/2.25.1");

    private static final List<String> BENIGN_ERRORS = List.of(
            "ThrottlingException", "ValidationError", "ResourceNotFoundException", "AccessDenied");

    private final SimulatorProperties properties;
    private final Random random;

    public CloudEventFactory(SimulatorProperties properties) {
        this.properties = properties;
        this.random = properties.randomSeed() == 0 ? new Random() : new Random(properties.randomSeed());
    }

    // ---------------------------------------------------------------- benign

    public CloudAuditEvent benignEvent() {
        ApiCall call = pick(BENIGN_CALLS);
        String account = pick(properties.accountIds());
        String principal = pick(properties.principals());
        boolean machine = principal.contains("-");
        // Session events are tied to where the identity actually is; everything else is a service
        // call that may legitimately land in any region the organisation operates in.
        boolean identityEvent = call.name().equals("AssumeRole");
        // 3% of ordinary calls fail, which is roughly what a healthy account looks like.
        boolean failure = nextDouble() < 0.03;

        CloudAuditEvent.Builder builder = CloudAuditEvent.builder()
                .eventTime(Instant.now())
                .provider("AWS")
                .eventSource(call.source())
                .eventName(call.name())
                .region(identityEvent ? homeRegionFor(principal) : pick(properties.homeRegions()))
                .accountId(account)
                .principalId("AIDA" + Math.abs(principal.hashCode()))
                .principalType(machine ? "AssumedRole" : "IAMUser")
                .userName(principal)
                .sourceIp(corporateIp())
                .userAgent(machine ? "aws-sdk-java/2.25.1" : pick(BENIGN_AGENTS))
                .outcome(failure ? Outcome.FAILURE : Outcome.SUCCESS)
                .mfaUsed(!machine)
                .resource(call.resourcePrefix() + shortId());

        if (failure) {
            builder.errorCode(pick(BENIGN_ERRORS));
        } else if (call.transfersData()) {
            // Everyday object access: kilobytes to a few megabytes, nowhere near the egress threshold.
            builder.bytesTransferred(64_000L + (long) (nextDouble() * 4_000_000L));
        }
        return builder.build();
    }

    /** A routine, successful console sign-in from the home region. */
    public CloudAuditEvent benignLogin() {
        String principal = pick(properties.principals().subList(0, 4));
        return CloudAuditEvent.builder()
                .eventTime(Instant.now())
                .eventSource("signin.amazonaws.com")
                .eventName("ConsoleLogin")
                .region(homeRegionFor(principal))
                .accountId(pick(properties.accountIds()))
                .principalId("AIDA" + Math.abs(principal.hashCode()))
                .principalType("IAMUser")
                .userName(principal)
                .sourceIp(corporateIp())
                .userAgent("console.amazonaws.com")
                .outcome(Outcome.SUCCESS)
                .mfaUsed(true)
                .build();
    }

    // -------------------------------------------------------------- helpers

    /**
     * The region an identity habitually works from. Stable per principal, because a person who
     * signs in from Mumbai on Monday does not sign in from Dublin ninety seconds later.
     */
    public String homeRegionFor(String principal) {
        List<String> regions = properties.homeRegions();
        return regions.get(Math.floorMod(principal.hashCode(), regions.size()));
    }

    public String hostileIp() {
        return "%d.%d.%d.%d".formatted(45 + random.nextInt(150), random.nextInt(256),
                random.nextInt(256), 1 + random.nextInt(254));
    }

    public String corporateIp() {
        return "10.%d.%d.%d".formatted(random.nextInt(8), random.nextInt(256), 1 + random.nextInt(254));
    }

    public <T> T pick(List<T> values) {
        return values.get(random.nextInt(values.size()));
    }

    public String shortId() {
        return Long.toHexString(Math.abs(random.nextLong())).substring(0, 8);
    }

    public double nextDouble() {
        return random.nextDouble();
    }

    public int nextInt(int bound) {
        return random.nextInt(bound);
    }

    public String principalIdFor(String userName) {
        return "AIDA" + Math.abs(userName.hashCode());
    }

    public SimulatorProperties properties() {
        return properties;
    }

    /** Jitters a timestamp a little so batches do not all share one instant. */
    public Instant jitter(Instant base, int maxMillis) {
        return base.plusMillis(ThreadLocalRandom.current().nextInt(maxMillis));
    }
}
