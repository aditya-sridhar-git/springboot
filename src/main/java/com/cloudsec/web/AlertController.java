package com.cloudsec.web;

import com.cloudsec.engine.DetectionRule;
import com.cloudsec.model.AlertStatus;
import com.cloudsec.model.SecurityAlert;
import com.cloudsec.model.Severity;
import com.cloudsec.engine.DetectionEngine;
import com.cloudsec.repository.SecurityAlertRepository;
import com.cloudsec.service.AlertService;
import com.cloudsec.service.DashboardStatsService;
import com.cloudsec.service.EventIngestService;
import com.cloudsec.web.dto.AlertView;
import com.cloudsec.web.dto.EventView;
import com.cloudsec.web.dto.StatsSnapshot;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** Read and triage API behind the dashboard. */
@RestController
@RequestMapping("/api")
@Validated
public class AlertController {

    private final SecurityAlertRepository repository;
    private final AlertService alertService;
    private final EventIngestService ingestService;
    private final DashboardStatsService statsService;
    private final DetectionEngine engine;
    private final ObjectMapper objectMapper;

    public AlertController(SecurityAlertRepository repository,
                           AlertService alertService,
                           EventIngestService ingestService,
                           DashboardStatsService statsService,
                           DetectionEngine engine,
                           ObjectMapper objectMapper) {
        this.repository = repository;
        this.alertService = alertService;
        this.ingestService = ingestService;
        this.statsService = statsService;
        this.engine = engine;
        this.objectMapper = objectMapper;
    }

    @GetMapping("/alerts")
    public List<AlertView> alerts(@RequestParam(required = false) Severity severity,
                                  @RequestParam(required = false) AlertStatus status,
                                  @RequestParam(defaultValue = "50") @Min(1) @Max(500) int limit) {
        PageRequest page = PageRequest.of(0, limit);
        List<SecurityAlert> alerts;
        if (severity != null) {
            alerts = repository.findBySeverityOrderByDetectedAtDesc(severity, page);
        } else if (status != null) {
            alerts = repository.findByStatusOrderByDetectedAtDesc(status, page);
        } else {
            alerts = repository.findByOrderByDetectedAtDesc(page);
        }
        return alerts.stream().map(a -> AlertView.of(a, objectMapper)).toList();
    }

    /** Served straight from the Redis hot cache, so a fresh dashboard paints without touching SQL. */
    @GetMapping("/alerts/recent")
    public List<AlertView> recentAlerts(@RequestParam(defaultValue = "50") @Min(1) @Max(200) int limit) {
        return alertService.recentFromCache(limit);
    }

    @GetMapping("/alerts/{id}")
    public ResponseEntity<AlertView> alert(@PathVariable UUID id) {
        return repository.findById(id)
                .map(a -> ResponseEntity.ok(AlertView.of(a, objectMapper)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PostMapping("/alerts/{id}/status")
    public ResponseEntity<AlertView> updateStatus(@PathVariable UUID id, @RequestParam AlertStatus status) {
        return alertService.updateStatus(id, status)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/events/recent")
    public List<EventView> recentEvents(@RequestParam(defaultValue = "50") @Min(1) @Max(100) int limit) {
        return ingestService.recentEvents(limit);
    }

    @GetMapping("/stats")
    public StatsSnapshot stats() {
        return statsService.snapshot();
    }

    @GetMapping("/rules")
    public List<Map<String, Object>> rules() {
        return engine.activeRules().stream()
                .map(AlertController::describe)
                .toList();
    }

    private static Map<String, Object> describe(DetectionRule rule) {
        return Map.of(
                "id", rule.id(),
                "name", rule.name(),
                "severity", rule.severity(),
                "mitreTechnique", rule.mitreTechnique(),
                "suppressionWindowSeconds", rule.suppressionWindow().toSeconds());
    }
}
