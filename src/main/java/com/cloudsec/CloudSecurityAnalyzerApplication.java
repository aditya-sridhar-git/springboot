package com.cloudsec;

import com.cloudsec.config.AnalyzerProperties;
import com.cloudsec.config.DetectionProperties;
import com.cloudsec.config.SimulatorProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

/**
 * Real-time cloud security analyzer.
 *
 * <pre>
 *   cloud audit events -> Kafka -> detection rules -> Redis + PostgreSQL -> WebSocket dashboard
 * </pre>
 */
@SpringBootApplication
@EnableConfigurationProperties({AnalyzerProperties.class, DetectionProperties.class, SimulatorProperties.class})
public class CloudSecurityAnalyzerApplication {

    public static void main(String[] args) {
        SpringApplication.run(CloudSecurityAnalyzerApplication.class, args);
    }
}
