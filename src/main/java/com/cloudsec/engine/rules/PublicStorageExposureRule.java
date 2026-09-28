package com.cloudsec.engine.rules;

import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** Object storage being opened to the whole internet through an ACL or bucket policy change. */
@Component
public class PublicStorageExposureRule implements DetectionRule {

    private static final String ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers";

    @Override
    public String id() {
        return "public-storage-exposure";
    }

    @Override
    public String name() {
        return "Storage exposed publicly";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1580";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded() && event.eventNameIn(
                "PutBucketAcl", "PutBucketPolicy", "PutObjectAcl",
                "DeletePublicAccessBlock", "PutBucketPublicAccessBlock", "SetIamPolicy");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String grantee = event.param("grantee");
        String acl = event.param("acl");
        String policy = event.param("policy");
        boolean blockRemoved = "DeletePublicAccessBlock".equalsIgnoreCase(event.eventName())
                || "false".equalsIgnoreCase(event.param("blockPublicAcls"));

        boolean publicGrant = ALL_USERS.equals(grantee)
                || "allUsers".equalsIgnoreCase(grantee)
                || (acl != null && acl.toLowerCase(Locale.ROOT).contains("public-read"))
                || (policy != null && policy.replace(" ", "").contains("\"Principal\":\"*\""))
                || blockRemoved;

        if (!publicGrant) {
            return Optional.empty();
        }

        String bucket = event.resource() == null ? "unknown-bucket" : event.resource();
        return Optional.of(AlertDraft.builder(id() + ":" + bucket)
                .title("Bucket %s made publicly readable".formatted(bucket))
                .description(("%s called %s on %s, which grants access to anonymous callers on the public "
                        + "internet. Any object in that bucket should now be treated as disclosed.")
                        .formatted(event.actor(), event.eventName(), bucket))
                .evidence("bucket", bucket)
                .evidence("eventName", event.eventName())
                .evidence("grantee", ALL_USERS.equals(grantee) ? "AllUsers (anonymous)" : grantee)
                .evidence("acl", acl)
                .evidence("bucketPolicy", policy)
                .evidence("publicAccessBlockRemoved", blockRemoved)
                .evidence("actor", event.actor())
                .evidence("sourceIp", event.sourceIp())
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(30);
    }
}
