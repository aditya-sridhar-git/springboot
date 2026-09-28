package com.cloudsec.repository;

import com.cloudsec.model.AlertStatus;
import com.cloudsec.model.SecurityAlert;
import com.cloudsec.model.Severity;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface SecurityAlertRepository extends JpaRepository<SecurityAlert, UUID> {

    List<SecurityAlert> findByOrderByDetectedAtDesc(Pageable pageable);

    List<SecurityAlert> findBySeverityOrderByDetectedAtDesc(Severity severity, Pageable pageable);

    List<SecurityAlert> findByStatusOrderByDetectedAtDesc(AlertStatus status, Pageable pageable);

    long countByStatus(AlertStatus status);

    long countBySeverity(Severity severity);

    long countByDetectedAtAfter(Instant since);

    @Query("select a.severity as severity, count(a) as total from SecurityAlert a "
            + "where a.detectedAt > :since group by a.severity")
    List<SeverityCount> countBySeveritySince(@Param("since") Instant since);

    @Query("select a.ruleId as ruleId, a.ruleName as ruleName, count(a) as total from SecurityAlert a "
            + "where a.detectedAt > :since group by a.ruleId, a.ruleName order by count(a) desc")
    List<RuleCount> countByRuleSince(@Param("since") Instant since);

    @Query("select a.sourceIp as sourceIp, count(a) as total from SecurityAlert a "
            + "where a.detectedAt > :since and a.sourceIp is not null "
            + "group by a.sourceIp order by count(a) desc")
    List<SourceCount> topSourceIpsSince(@Param("since") Instant since, Pageable pageable);

    interface SeverityCount {
        Severity getSeverity();
        long getTotal();
    }

    interface RuleCount {
        String getRuleId();
        String getRuleName();
        long getTotal();
    }

    interface SourceCount {
        String getSourceIp();
        long getTotal();
    }
}
