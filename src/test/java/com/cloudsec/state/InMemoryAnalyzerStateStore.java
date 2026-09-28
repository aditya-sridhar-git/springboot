package com.cloudsec.state;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/** Heap-backed stand-in for Redis so rule tests run without infrastructure. */
public class InMemoryAnalyzerStateStore implements AnalyzerStateStore {

    private record Entry(String member, long weight, long atMillis) {
    }

    private final Map<String, List<Entry>> windows = new HashMap<>();
    private final Map<String, Instant> claims = new HashMap<>();
    private final Map<String, Sighting> sightings = new HashMap<>();
    private final Map<String, Set<String>> seen = new HashMap<>();
    private final Map<String, Map<String, Long>> counters = new HashMap<>();
    private final Map<String, Deque<String>> lists = new HashMap<>();
    private final Map<String, Map<Long, Long>> series = new HashMap<>();

    /** Overridable so a test can advance time without sleeping. */
    private Instant now = Instant.now();

    public void setNow(Instant now) {
        this.now = now;
    }

    @Override
    public long recordAndCount(String bucket, String key, String member, Instant at, Duration window) {
        return record(bucket, key, member, 1L, at, window).size();
    }

    @Override
    public long recordAndSum(String bucket, String key, String member, long weight, Instant at, Duration window) {
        return record(bucket, key, member, weight, at, window).stream().mapToLong(Entry::weight).sum();
    }

    private List<Entry> record(String bucket, String key, String member, long weight, Instant at, Duration window) {
        List<Entry> entries = windows.computeIfAbsent(bucket + ":" + key, k -> new ArrayList<>());
        long cutoff = at.minus(window).toEpochMilli();
        entries.removeIf(e -> e.atMillis() <= cutoff);
        entries.add(new Entry(member, weight, at.toEpochMilli()));
        return entries;
    }

    @Override
    public boolean claim(String dedupKey, Duration ttl) {
        Instant existing = claims.get(dedupKey);
        if (existing != null && existing.isAfter(now)) {
            return false;
        }
        claims.put(dedupKey, now.plus(ttl));
        return true;
    }

    @Override
    public Optional<Sighting> lastSighting(String principalId) {
        return Optional.ofNullable(sightings.get(principalId));
    }

    @Override
    public void recordSighting(String principalId, Sighting sighting, Duration ttl) {
        sightings.put(principalId, sighting);
    }

    @Override
    public boolean isFirstTimeSeen(String setKey, String value) {
        return seen.computeIfAbsent(setKey, k -> new HashSet<>()).add(value);
    }

    @Override
    public void incrementCounter(String counterKey, String field, long delta) {
        counters.computeIfAbsent(counterKey, k -> new LinkedHashMap<>()).merge(field, delta, Long::sum);
    }

    @Override
    public Map<String, Long> counters(String counterKey) {
        return Map.copyOf(counters.getOrDefault(counterKey, Map.of()));
    }

    @Override
    public void pushRecent(String listKey, String json, int cap) {
        Deque<String> list = lists.computeIfAbsent(listKey, k -> new ArrayDeque<>());
        list.addFirst(json);
        while (list.size() > cap) {
            list.removeLast();
        }
    }

    @Override
    public List<String> recent(String listKey, int limit) {
        return lists.getOrDefault(listKey, new ArrayDeque<>()).stream().limit(limit).toList();
    }

    @Override
    public void incrementTimeSeries(String name, long bucket, long delta, Duration ttl) {
        series.computeIfAbsent(name, k -> new LinkedHashMap<>()).merge(bucket, delta, Long::sum);
    }

    @Override
    public List<Long> readTimeSeries(String name, List<Long> buckets) {
        Map<Long, Long> values = series.getOrDefault(name, Map.of());
        return buckets.stream().map(b -> values.getOrDefault(b, 0L)).toList();
    }

    @Override
    public void reset() {
        windows.clear();
        claims.clear();
        sightings.clear();
        seen.clear();
        counters.clear();
        lists.clear();
        series.clear();
    }
}
