package com.cloudsec.simulator;

/** The attack patterns the simulated cloud environment can replay on demand. */
public enum AttackScenario {

    BRUTE_FORCE("Credential stuffing against the console sign-in endpoint"),
    IMPOSSIBLE_TRAVEL("One identity signing in from two continents minutes apart"),
    PUBLIC_BUCKET("Object storage opened to anonymous readers"),
    OPEN_SECURITY_GROUP("SSH and database ports exposed to 0.0.0.0/0"),
    PRIVILEGE_ESCALATION("A low privileged user granted AdministratorAccess"),
    LOG_TAMPERING("CloudTrail stopped and the trail deleted"),
    DATA_EXFILTRATION("Bulk download of an entire data lake prefix"),
    CRYPTO_MINING("GPU fleet launched in a region the account has never used"),
    CREDENTIAL_ENUMERATION("A stolen key probing the API for what it can reach");

    private final String description;

    AttackScenario(String description) {
        this.description = description;
    }

    public String description() {
        return description;
    }
}
