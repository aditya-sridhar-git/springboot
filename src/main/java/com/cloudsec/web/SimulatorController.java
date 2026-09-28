package com.cloudsec.web;

import com.cloudsec.simulator.AttackScenario;
import com.cloudsec.simulator.CloudAuditLogSimulator;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Lets the dashboard replay a specific attack on demand instead of waiting for the random one. */
@RestController
@RequestMapping("/api/simulator")
public class SimulatorController {

    private final ObjectProvider<CloudAuditLogSimulator> simulator;

    public SimulatorController(ObjectProvider<CloudAuditLogSimulator> simulator) {
        this.simulator = simulator;
    }

    @GetMapping("/scenarios")
    public List<Map<String, Object>> scenarios() {
        return Arrays.stream(AttackScenario.values())
                .map(s -> Map.<String, Object>of(
                        "id", s.name(),
                        "label", label(s),
                        "description", s.description()))
                .toList();
    }

    @PostMapping("/scenarios/{scenario}")
    public ResponseEntity<Map<String, Object>> inject(@PathVariable AttackScenario scenario) {
        CloudAuditLogSimulator active = simulator.getIfAvailable();
        if (active == null) {
            return ResponseEntity.status(409).body(Map.of(
                    "error", "The simulator is disabled; this analyzer is reading a real audit feed."));
        }
        int published = active.inject(scenario);
        return ResponseEntity.accepted().body(Map.of(
                "scenario", scenario.name(),
                "eventsPublished", published,
                "description", scenario.description()));
    }

    private static String label(AttackScenario scenario) {
        String[] words = scenario.name().toLowerCase().split("_");
        StringBuilder sb = new StringBuilder();
        for (String word : words) {
            sb.append(Character.toUpperCase(word.charAt(0))).append(word.substring(1)).append(' ');
        }
        return sb.toString().trim();
    }
}
