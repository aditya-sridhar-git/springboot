package com.cloudsec.engine;

import com.cloudsec.model.Severity;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * What a rule returns when it fires. The engine turns this into a persisted
 * {@link com.cloudsec.model.SecurityAlert} after de-duplication.
 *
 * @param title       one line summary shown in the dashboard feed
 * @param description human readable explanation of why this fired
 * @param severity    severity for this specific firing, which may exceed the rule default
 * @param riskScore   0-100 confidence weighted impact score
 * @param dedupKey    identity of the detection, used to suppress repeats within a cool-off window
 * @param evidence    supporting facts rendered in the alert detail view
 */
public record AlertDraft(
        String title,
        String description,
        Severity severity,
        int riskScore,
        String dedupKey,
        Map<String, Object> evidence) {

    public AlertDraft {
        evidence = evidence == null ? Map.of() : Map.copyOf(evidence);
        riskScore = Math.clamp(riskScore, 0, 100);
    }

    public static Builder builder(String dedupKey) {
        return new Builder(dedupKey);
    }

    public static final class Builder {
        private final String dedupKey;
        private final Map<String, Object> evidence = new LinkedHashMap<>();
        private String title = "";
        private String description = "";
        private Severity severity;
        private int riskScore = -1;

        private Builder(String dedupKey) {
            this.dedupKey = dedupKey;
        }

        public Builder title(String v) { this.title = v; return this; }
        public Builder description(String v) { this.description = v; return this; }
        public Builder severity(Severity v) { this.severity = v; return this; }
        public Builder riskScore(int v) { this.riskScore = v; return this; }

        public Builder evidence(String key, Object value) {
            if (value != null) {
                this.evidence.put(key, value);
            }
            return this;
        }

        public AlertDraft build(Severity ruleDefault) {
            Severity effective = severity == null ? ruleDefault : severity;
            int score = riskScore >= 0 ? riskScore : effective.baseRiskScore();
            return new AlertDraft(title, description, effective, score, dedupKey, evidence);
        }
    }
}
