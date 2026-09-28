package com.cloudsec.engine.rules;

import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Locale;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/** Identity changes that hand an existing principal more power than it had. */
@Component
public class PrivilegeEscalationRule implements DetectionRule {

    private static final Set<String> ADMIN_POLICIES = Set.of(
            "arn:aws:iam::aws:policy/AdministratorAccess",
            "arn:aws:iam::aws:policy/IAMFullAccess",
            "arn:aws:iam::aws:policy/PowerUserAccess");

    @Override
    public String id() {
        return "privilege-escalation";
    }

    @Override
    public String name() {
        return "IAM privilege escalation";
    }

    @Override
    public Severity severity() {
        return Severity.CRITICAL;
    }

    @Override
    public String mitreTechnique() {
        return "T1098";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded() && event.eventNameIn(
                "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
                "CreateAccessKey", "AddUserToGroup", "CreateLoginProfile", "UpdateAssumeRolePolicy");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String policy = event.param("policyArn");
        String document = event.param("policyDocument");
        String target = event.param("targetPrincipal");

        boolean adminPolicy = policy != null && ADMIN_POLICIES.contains(policy);
        boolean wildcardDocument = document != null
                && document.replace(" ", "").toLowerCase(Locale.ROOT).contains("\"action\":\"*\"");
        boolean keyMinted = event.eventNameIn("CreateAccessKey", "CreateLoginProfile")
                && target != null && !target.equals(event.actor());

        if (!adminPolicy && !wildcardDocument && !keyMinted) {
            return Optional.empty();
        }

        String reason = adminPolicy ? "attached the managed policy " + policy
                : wildcardDocument ? "attached an inline policy granting Action:*"
                : "minted new credentials for another principal";

        return Optional.of(AlertDraft.builder(id() + ":" + event.accountId() + ":" + (target == null ? event.actor() : target))
                .title("Privilege escalation: %s -> %s".formatted(event.actor(), target == null ? event.actor() : target))
                .description(("%s called %s and %s. This grants %s administrative control of account %s.")
                        .formatted(event.actor(), event.eventName(), reason,
                                target == null ? event.actor() : target, event.accountId()))
                .evidence("actor", event.actor())
                .evidence("targetPrincipal", target)
                .evidence("eventName", event.eventName())
                .evidence("policyArn", policy)
                .evidence("policyDocument", document)
                .evidence("wildcardAction", wildcardDocument)
                .evidence("sourceIp", event.sourceIp())
                .build(severity()));
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(20);
    }
}
