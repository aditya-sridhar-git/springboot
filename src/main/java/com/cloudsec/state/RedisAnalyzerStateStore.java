package com.cloudsec.state;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

/** Redis backed implementation of the analyzer working set. */
@Component
public class RedisAnalyzerStateStore implements AnalyzerStateStore {

    private static final Logger log = LoggerFactory.getLogger(RedisAnalyzerStateStore.class);

    /** Every key this class owns is prefixed so a shared Redis stays tidy and easy to flush. */
    private static final String NS = "cloudsec:";
    private static final String WINDOW = NS + "win:";
    private static final String CLAIM = NS + "claim:";
    private static final String SIGHTING = NS + "sighting:";
    private static final String SEEN = NS + "seen:";
    private static final String SERIES = NS + "ts:";

    private final StringRedisTemplate redis;

    public RedisAnalyzerStateStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public long recordAndCount(String bucket, String key, String member, Instant now, Duration window) {
        String redisKey = WINDOW + bucket + ":" + key;
        trim(redisKey, now, window);
        redis.opsForZSet().add(redisKey, member, now.toEpochMilli());
        redis.expire(redisKey, window.plusSeconds(60));
        Long count = redis.opsForZSet().zCard(redisKey);
        return count == null ? 0L : count;
    }

    @Override
    public long recordAndSum(String bucket, String key, String member, long weight, Instant now, Duration window) {
        String redisKey = WINDOW + bucket + ":" + key;
        trim(redisKey, now, window);
        // The weight travels with the member so the window can be summed without a second structure.
        redis.opsForZSet().add(redisKey, member + "|" + weight, now.toEpochMilli());
        redis.expire(redisKey, window.plusSeconds(60));
        Set<String> members = redis.opsForZSet().range(redisKey, 0, -1);
        if (members == null) {
            return 0L;
        }
        long sum = 0L;
        for (String m : members) {
            int sep = m.lastIndexOf('|');
            if (sep < 0) {
                continue;
            }
            try {
                sum += Long.parseLong(m.substring(sep + 1));
            } catch (NumberFormatException ex) {
                log.debug("Ignoring malformed window member {}", m);
            }
        }
        return sum;
    }

    private void trim(String redisKey, Instant now, Duration window) {
        long cutoff = now.minus(window).toEpochMilli();
        redis.opsForZSet().removeRangeByScore(redisKey, Double.NEGATIVE_INFINITY, cutoff);
    }

    @Override
    public boolean claim(String dedupKey, Duration ttl) {
        Boolean claimed = redis.opsForValue().setIfAbsent(CLAIM + dedupKey, "1", ttl);
        return Boolean.TRUE.equals(claimed);
    }

    @Override
    public Optional<Sighting> lastSighting(String principalId) {
        Map<Object, Object> hash = redis.opsForHash().entries(SIGHTING + principalId);
        if (hash == null || hash.isEmpty()) {
            return Optional.empty();
        }
        try {
            return Optional.of(new Sighting(
                    String.valueOf(hash.get("region")),
                    Double.parseDouble(String.valueOf(hash.get("lat"))),
                    Double.parseDouble(String.valueOf(hash.get("lon"))),
                    String.valueOf(hash.get("ip")),
                    Instant.ofEpochMilli(Long.parseLong(String.valueOf(hash.get("at"))))));
        } catch (RuntimeException ex) {
            log.warn("Discarding unreadable sighting for {}: {}", principalId, ex.toString());
            return Optional.empty();
        }
    }

    @Override
    public void recordSighting(String principalId, Sighting sighting, Duration ttl) {
        String key = SIGHTING + principalId;
        Map<String, String> hash = new LinkedHashMap<>();
        hash.put("region", sighting.region());
        hash.put("lat", Double.toString(sighting.latitude()));
        hash.put("lon", Double.toString(sighting.longitude()));
        hash.put("ip", sighting.sourceIp() == null ? "" : sighting.sourceIp());
        hash.put("at", Long.toString(sighting.at().toEpochMilli()));
        redis.opsForHash().putAll(key, hash);
        redis.expire(key, ttl);
    }

    @Override
    public boolean isFirstTimeSeen(String setKey, String value) {
        Long added = redis.opsForSet().add(SEEN + setKey, value);
        return added != null && added == 1L;
    }

    @Override
    public void incrementCounter(String counterKey, String field, long delta) {
        redis.opsForHash().increment(NS + counterKey, field, delta);
    }

    @Override
    public Map<String, Long> counters(String counterKey) {
        Map<Object, Object> raw = redis.opsForHash().entries(NS + counterKey);
        Map<String, Long> out = new LinkedHashMap<>();
        if (raw == null) {
            return out;
        }
        raw.forEach((k, v) -> {
            try {
                out.put(String.valueOf(k), Long.parseLong(String.valueOf(v)));
            } catch (NumberFormatException ignored) {
                // a non numeric counter value is not worth failing the dashboard over
            }
        });
        return out;
    }

    @Override
    public void pushRecent(String listKey, String json, int cap) {
        String key = NS + listKey;
        redis.opsForList().leftPush(key, json);
        redis.opsForList().trim(key, 0, cap - 1L);
    }

    @Override
    public List<String> recent(String listKey, int limit) {
        List<String> values = redis.opsForList().range(NS + listKey, 0, limit - 1L);
        return values == null ? List.of() : new ArrayList<>(values);
    }

    @Override
    public void incrementTimeSeries(String series, long bucket, long delta, Duration ttl) {
        String key = SERIES + series + ":" + bucket;
        Long value = redis.opsForValue().increment(key, delta);
        if (value != null && value == delta) {
            // Only the caller that created the bucket needs to arm its expiry.
            redis.expire(key, ttl);
        }
    }

    @Override
    public List<Long> readTimeSeries(String series, List<Long> buckets) {
        if (buckets.isEmpty()) {
            return List.of();
        }
        List<String> keys = buckets.stream().map(b -> SERIES + series + ":" + b).toList();
        List<String> values = redis.opsForValue().multiGet(keys);
        List<Long> out = new ArrayList<>(buckets.size());
        for (int i = 0; i < buckets.size(); i++) {
            String raw = values == null || i >= values.size() ? null : values.get(i);
            long parsed = 0L;
            if (raw != null) {
                try {
                    parsed = Long.parseLong(raw);
                } catch (NumberFormatException ignored) {
                    parsed = 0L;
                }
            }
            out.add(parsed);
        }
        return out;
    }

    @Override
    public void reset() {
        Set<String> keys = redis.keys(NS + "*");
        if (keys != null && !keys.isEmpty()) {
            redis.delete(keys);
        }
    }
}
