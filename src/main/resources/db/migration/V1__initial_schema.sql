-- Alerts raised by the detection engine.
CREATE TABLE security_alert (
    id                UUID          PRIMARY KEY,
    rule_id           VARCHAR(64)   NOT NULL,
    rule_name         VARCHAR(128)  NOT NULL,
    severity          VARCHAR(16)   NOT NULL,
    risk_score        INTEGER       NOT NULL,
    title             VARCHAR(256)  NOT NULL,
    description       VARCHAR(2048) NOT NULL,
    mitre_technique   VARCHAR(64),
    account_id        VARCHAR(64),
    principal_id      VARCHAR(128),
    user_name         VARCHAR(128),
    source_ip         VARCHAR(64),
    region            VARCHAR(32),
    event_name        VARCHAR(128),
    resource          VARCHAR(512),
    trigger_event_id  VARCHAR(64),
    event_time        TIMESTAMP WITH TIME ZONE,
    detected_at       TIMESTAMP WITH TIME ZONE NOT NULL,
    status            VARCHAR(20)   NOT NULL,
    evidence          TEXT
);

CREATE INDEX idx_alert_detected_at ON security_alert (detected_at DESC);
CREATE INDEX idx_alert_severity    ON security_alert (severity);
CREATE INDEX idx_alert_status      ON security_alert (status);
CREATE INDEX idx_alert_rule_id     ON security_alert (rule_id);

-- Archive of every ingested audit event, for investigation and rule back-testing.
CREATE TABLE audit_event (
    event_id           VARCHAR(64)  PRIMARY KEY,
    event_time         TIMESTAMP WITH TIME ZONE NOT NULL,
    ingested_at        TIMESTAMP WITH TIME ZONE NOT NULL,
    provider           VARCHAR(16),
    event_source       VARCHAR(128),
    event_name         VARCHAR(128),
    region             VARCHAR(32),
    account_id         VARCHAR(64),
    principal_id       VARCHAR(128),
    principal_type     VARCHAR(32),
    user_name          VARCHAR(128),
    source_ip          VARCHAR(64),
    outcome            VARCHAR(16),
    error_code         VARCHAR(64),
    resource           VARCHAR(512),
    bytes_transferred  BIGINT,
    mfa_used           BOOLEAN,
    request_parameters TEXT
);

CREATE INDEX idx_event_time      ON audit_event (event_time DESC);
CREATE INDEX idx_event_principal ON audit_event (principal_id);
CREATE INDEX idx_event_name      ON audit_event (event_name);
