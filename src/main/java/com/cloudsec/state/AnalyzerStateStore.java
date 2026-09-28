package com.cloudsec.state;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Short-lived detection state shared by every analyzer instance.
 *
 * <p>Stateful rules (brute force, impossible travel, exfiltration volume) need to remember what they
 * saw a few minutes ago. Keeping that in Redis rather than on the heap means the analyzer stays
 * horizontally scalable and survives restarts without losing detection context.
 */
public interface AnalyzerStateStore {

    /**
     * Adds a member to a sliding time window and returns how many members remain inside it.
     * Expired members are trimmed as a side effect.
     */
    long recordAndCount(String bucket, String key, String member, Instant now, Duration window);

    /**
     * Adds a weighted member to a sliding time window and returns the sum of weights inside it.
     */
    long recordAndSum(String bucket, String key, String member, long weight, Instant now, Duration window);

    /**
     * Attempts to claim a de-duplication key. Returns {@code true} only for the first caller within
     * {@code ttl}, which is how repeated firings of the same detection are suppressed.
     */
    boolean claim(String dedupKey, Duration ttl);

    Optional<Sighting> lastSighting(String principalId);

    void recordSighting(String principalId, Sighting sighting, Duration ttl);

    /**
     * Adds a value to a long-lived set and returns {@code true} when the value had never been seen
     * before, which is how "first ever activity in region X" style baselines are built.
     */
    boolean isFirstTimeSeen(String setKey, String value);

    void incrementCounter(String counterKey, String field, long delta);

    Map<String, Long> counters(String counterKey);

    /** Pushes a JSON payload onto the head of a capped list. */
    void pushRecent(String listKey, String json, int cap);

    List<String> recent(String listKey, int limit);

    /**
     * Increments one bucket of a bounded time series. Buckets expire on their own, so the series
     * never needs pruning and stays correct across multiple analyzer replicas.
     */
    void incrementTimeSeries(String series, long bucket, long delta, Duration ttl);

    /** Reads the named buckets of a time series, returning 0 for buckets that never existed. */
    List<Long> readTimeSeries(String series, List<Long> buckets);

    /** Clears all analyzer state. Exposed for demos and tests, never called during normal operation. */
    void reset();
}
