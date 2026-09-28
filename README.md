# Sentinel — real-time cloud security analyzer

A streaming detection pipeline for cloud control-plane audit logs. Events arrive on Kafka, a rules
engine scores them against Redis-backed state, findings land in PostgreSQL, and a dashboard receives
them over WebSocket the moment they are raised.

```
  Cloud environment (simulated CloudTrail-style audit events)
            │
            ▼
        Kafka  cloud.security.events
            │
            ▼
  ┌──────────────────────────────┐
  │  Spring Boot                 │      Redis        sliding windows, dedup claims,
  │  security analyzer           │ ◄──► (state)      identity sightings, hot caches
  │  10 detection rules          │
  └──────────────────────────────┘      PostgreSQL   alerts + audit archive (Flyway)
            │        │            ◄──►
            │        └──────────────► Kafka  cloud.security.alerts  (SOAR / SIEM)
            ▼
       WebSocket  /ws/dashboard
            │
            ▼
     Security dashboard  +  Datadog / Prometheus metrics
```

No AWS or Azure account is needed. A built-in simulator produces a realistic background of cloud
activity and injects scripted attacks into it, so the pipeline always has something real to detect.
Point Kafka at a genuine CloudTrail feed and turn the simulator off; nothing downstream changes.

## Run it

```bash
docker compose up -d kafka postgres redis
./mvnw package && java -jar target/cloud-security-analyzer-1.0.0.jar
```

Then open **http://localhost:8080**.

If a port is already taken on your machine, override it for the infrastructure and the app together:

```bash
REDIS_PORT=6380 docker compose up -d kafka postgres redis
REDIS_PORT=6380 java -jar target/cloud-security-analyzer-1.0.0.jar
```

The dashboard fills in within a couple of seconds. Press any button under **Run a drill** to replay a
specific attack immediately rather than waiting for the next random one.

## What it detects

| Rule | Fires on | Severity | ATT&CK |
| --- | --- | --- | --- |
| `brute-force-login` | 5+ failed sign-ins from one address in 5 minutes | HIGH | T1110 |
| `impossible-travel` | One identity in two places, faster than 900 km/h | CRITICAL | T1078 |
| `root-account-activity` | Any use of the account root credential | HIGH / CRITICAL | T1078.004 |
| `public-storage-exposure` | A bucket opened to anonymous readers | CRITICAL | T1580 |
| `open-security-group` | A sensitive port opened to `0.0.0.0/0` | HIGH / CRITICAL | T1562.007 |
| `privilege-escalation` | `AdministratorAccess`, `Action:*`, or keys minted for another principal | CRITICAL | T1098 |
| `audit-log-tampering` | CloudTrail stopped, trails or flow logs deleted | CRITICAL | T1562.008 |
| `data-exfiltration-volume` | More than 2 GiB pulled from storage in 10 minutes | HIGH / CRITICAL | T1530 |
| `unusual-region` | First resource ever created in a region | MEDIUM | T1078.004 |
| `access-denied-spike` | 12+ authorisation failures for one principal in 5 minutes | MEDIUM / HIGH | T1087 |

Severity is escalated per firing when the evidence warrants it: root without MFA is CRITICAL rather
than HIGH, every port open to the internet is worse than one, four times the egress threshold is
worse than clearing it.

## How the pieces earn their place

**Kafka** decouples the audit feed from detection. The consumer is a batch listener across six
partitions keyed by principal, so one identity always lands on one partition and the stateful rules
see its sign-ins in order. A malformed record becomes a null payload rather than a stuck partition.

**Redis** holds everything a rule needs to remember: sliding windows as sorted sets trimmed on write,
de-duplication claims as `SET NX` with a TTL, last-known location per identity, the set of regions an
account has ever used, dashboard counters, and a capped hot cache of recent alerts and events. Keeping
this out of the heap is what lets you run more than one analyzer instance — the claim is also what
stops two instances writing the same alert twice.

**PostgreSQL** is the durable record: every alert, plus an archive of every ingested event for
investigation and rule back-testing. Schema is managed by Flyway and validated by Hibernate at boot.

**WebSocket** carries three frame types (`alert`, `events`, `stats`) as plain JSON. No STOMP and no
client library, which is why the dashboard is three static files with no build step.

**Datadog** export is wired through Micrometer and off by default. Set `DATADOG_ENABLED=true` and
`DATADOG_API_KEY` to turn it on; Prometheus is always available at `/actuator/prometheus`. A Datadog
agent for the StatsD route is in the compose file behind `--profile datadog`.

## Adding a detection

Implement `DetectionRule` and annotate it `@Component`. The engine discovers it at startup, times it,
and isolates it — a rule that throws is logged and skipped rather than stalling the pipeline.

```java
@Component
public class MyRule implements DetectionRule {
    public String id() { return "my-rule"; }
    public String name() { return "Something suspicious"; }
    public Severity severity() { return Severity.HIGH; }
    public String mitreTechnique() { return "T1234"; }

    public boolean supports(CloudAuditEvent event) {
        return event.eventNameIn("SomeApiCall");
    }

    public Optional<AlertDraft> evaluate(CloudAuditEvent event, AnalyzerStateStore state) {
        long hits = state.recordAndCount(id(), event.actor(), event.eventId(),
                event.eventTime(), Duration.ofMinutes(5));
        if (hits < 3) {
            return Optional.empty();
        }
        return Optional.of(AlertDraft.builder(id() + ":" + event.actor())
                .title("...").description("...").evidence("hits", hits)
                .build(severity()));
    }
}
```

Disable a noisy rule without redeploying: `cloudsec.detection.disabled-rules: [my-rule]`.

## API

| Endpoint | Purpose |
| --- | --- |
| `GET /api/alerts?severity=&status=&limit=` | Alerts from PostgreSQL, newest first |
| `GET /api/alerts/recent?limit=` | Same list from the Redis hot cache, no SQL |
| `GET /api/alerts/{id}` | One alert with its evidence |
| `POST /api/alerts/{id}/status?status=ACKNOWLEDGED` | Triage; broadcasts the change to every dashboard |
| `GET /api/events/recent?limit=` | The most recent ingested audit events |
| `GET /api/stats` | The dashboard snapshot: counters, timeline, leaderboards |
| `GET /api/rules` | Active rules, their severities and suppression windows |
| `GET /api/simulator/scenarios` | The attack drills available |
| `POST /api/simulator/scenarios/{id}` | Replay one drill now |
| `GET /actuator/health`, `/actuator/prometheus` | Liveness, readiness, metrics |

## Configuration

Everything below is overridable through `application.yml` or the environment.

| Setting | Default | Notes |
| --- | --- | --- |
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | |
| `POSTGRES_URL` / `POSTGRES_USER` / `POSTGRES_PASSWORD` | `jdbc:postgresql://localhost:5432/cloudsec`, `cloudsec`, `cloudsec` | |
| `REDIS_HOST` / `REDIS_PORT` | `localhost` / `6379` | |
| `SIMULATOR_ENABLED` | `true` | Set `false` to read a real audit feed |
| `SIMULATOR_EPS` | `6` | Baseline events per second |
| `SIMULATOR_ATTACK_INTERVAL` | `45` | Seconds between random attack injections |
| `DATADOG_ENABLED` / `DATADOG_API_KEY` | `false` / empty | |
| `cloudsec.detection.*` | see `application.yml` | Every rule threshold and window |
| `cloudsec.detection.persist-events` | `true` | Turn off to skip the audit archive |
| `cloudsec.event-retention` | `7d` | Archived events older than this are pruned hourly |

## Metrics

| Metric | Type | Tags |
| --- | --- | --- |
| `cloudsec.events.ingested` | counter | |
| `cloudsec.alerts.raised` | counter | `rule`, `severity` |
| `cloudsec.alerts.suppressed` | counter | `rule` |
| `cloudsec.alerts.open` | gauge | |
| `cloudsec.rule.evaluation` | timer | `rule` |
| `cloudsec.rule.errors` | counter | `rule` |
| `cloudsec.pipeline.batch` | timer | |
| `cloudsec.dashboard.clients` | gauge | |
| `cloudsec.simulator.events.published` | counter | |

Every series carries `service` and `env` tags, and the `http.server.requests` URI tag is capped at 100
values so a scanner hitting random paths cannot inflate the custom-metric bill.

## Tests

```bash
./mvnw test
```

The suite runs without Kafka, Redis or PostgreSQL: rules are tested against an in-memory state store.
The two tests worth knowing about are in `ScenarioDetectionTest` — one asserts that every scripted
attack is caught by the rule it was written for, and the other pushes 3,000 events of ordinary traffic
through the engine and asserts that **nothing** fires. The second is the false-positive guard, and it
is the test that will fail first if a threshold drifts.

## Layout

```
src/main/java/com/cloudsec/
  config/       properties, Kafka, Redis, WebSocket, metrics, scheduling
  model/        CloudAuditEvent, SecurityAlert, AuditEventRecord
  ingest/       the Kafka batch listener
  engine/       DetectionEngine, DetectionRule, AlertDraft, geo maths
  engine/rules/ the ten detections
  state/        AnalyzerStateStore and its Redis implementation
  service/      ingest, alerting, archiving, dashboard statistics
  simulator/    the synthetic cloud environment and its attack scenarios
  web/          REST API, WebSocket handler, DTOs
src/main/resources/
  application.yml
  db/migration/ Flyway schema
  static/       the dashboard (index.html, styles.css, app.js)
```
