package com.cloudsec.model;

/** Alert severity, ordered from least to most urgent. */
public enum Severity {
    INFO(10),
    LOW(25),
    MEDIUM(50),
    HIGH(75),
    CRITICAL(95);

    private final int baseRiskScore;

    Severity(int baseRiskScore) {
        this.baseRiskScore = baseRiskScore;
    }

    public int baseRiskScore() {
        return baseRiskScore;
    }
}
