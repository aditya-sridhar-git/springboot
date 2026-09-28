package com.cloudsec.engine.rules;

import com.cloudsec.config.DetectionProperties;
import com.cloudsec.engine.AlertDraft;
import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.CloudAuditEvent;
import com.cloudsec.model.Severity;
import com.cloudsec.state.AnalyzerStateStore;
import java.time.Duration;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** A firewall rule that opens a sensitive port to the entire internet. */
@Component
public class OpenSecurityGroupRule implements DetectionRule {

    private final DetectionProperties.OpenIngress config;

    public OpenSecurityGroupRule(DetectionProperties properties) {
        this.config = properties.openIngress();
    }

    @Override
    public String id() {
        return "open-security-group";
    }

    @Override
    public String name() {
        return "Sensitive port open to the internet";
    }

    @Override
    public Severity severity() {
        return Severity.HIGH;
    }

    @Override
    public String mitreTechnique() {
        return "T1562.007";
    }

    @Override
    public boolean supports(CloudAuditEvent event) {
        return event.succeeded() && event.eventNameIn(
                "AuthorizeSecurityGroupIngress", "ModifyNetworkAclEntry",
                "CreateSecurityGroupRule", "UpdateFirewallRule");
    }

    @Override
    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        String cidr = event.param("cidrIp");
        if (cidr == null || config.wildcardCidrs().stream().noneMatch(cidr::equals)) {
            return Optional.empty();
        }

        Integer fromPort = parsePort(event.param("fromPort"));
        Integer toPort = parsePort(event.param("toPort"));
        if (fromPort == null) {
            return Optional.empty();
        }
        int upper = toPort == null ? fromPort : toPort;

        Optional<Integer> exposed = config.sensitivePorts().stream()
                .filter(p -> p >= fromPort && p <= upper)
                .findFirst();
        boolean allPorts = fromPort == 0 && upper >= 65535;
        if (exposed.isEmpty() && !allPorts) {
            return Optional.empty();
        }

        String group = event.resource() == null ? "unknown-sg" : event.resource();
        String portLabel = allPorts ? "every port" : "port " + exposed.get();
        Severity effective = allPorts ? Severity.CRITICAL : Severity.HIGH;

        return Optional.of(AlertDraft.builder(id() + ":" + group + ":" + fromPort + "-" + upper)
                .title("%s opened to 0.0.0.0/0 on %s".formatted(group, portLabel))
                .description(("%s authorised inbound traffic from %s to %s on security group %s. "
                        + "Administrative and database ports reachable from the public internet are "
                        + "scanned within minutes.")
                        .formatted(event.actor(), cidr, portLabel, group))
                .severity(effective)
                .evidence("securityGroup", group)
                .evidence("cidr", cidr)
                .evidence("fromPort", fromPort)
                .evidence("toPort", upper)
                .evidence("protocol", event.param("ipProtocol"))
                .evidence("actor", event.actor())
                .evidence("allPortsExposed", allPorts)
                .build(effective));
    }

    private static Integer parsePort(String raw) {
        if (raw == null) {
            return null;
        }
        try {
            return Integer.valueOf(raw.trim());
        } catch (NumberFormatException ex) {
            return null;
        }
    }

    @Override
    public Duration suppressionWindow() {
        return Duration.ofMinutes(30);
    }
}
