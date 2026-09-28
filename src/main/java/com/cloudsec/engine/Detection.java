package com.cloudsec.engine;

import com.cloudsec.model.CloudAuditEvent;

/** A rule firing on a specific event, before de-duplication and persistence. */
public record Detection(DetectionRule rule, AlertDraft draft, CloudAuditEvent event) {
}
