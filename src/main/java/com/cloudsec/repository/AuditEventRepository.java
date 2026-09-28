package com.cloudsec.repository;

import com.cloudsec.model.AuditEventRecord;
import java.time.Instant;
import java.util.List;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface AuditEventRepository extends JpaRepository<AuditEventRecord, String> {

    List<AuditEventRecord> findByOrderByEventTimeDesc(Pageable pageable);

    List<AuditEventRecord> findByPrincipalIdOrderByEventTimeDesc(String principalId, Pageable pageable);

    long countByEventTimeAfter(Instant since);

    @Modifying
    @Query("delete from AuditEventRecord e where e.eventTime < :cutoff")
    int deleteOlderThan(@Param("cutoff") Instant cutoff);
}
