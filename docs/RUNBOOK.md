# honeymcp — Operations Runbook

This is the runbook the on-call SOC analyst reaches for when something
about a honeymcp deployment looks wrong. Every section is paired with a
direct command or query; nothing here requires reading source.

If your incident isn't covered, file an issue with the page section you
expected to find guidance under.

## Table of contents

1. [Service overview](#service-overview)
2. [Deploy](#deploy)
3. [Health checks](#health-checks)
4. [Common alerts and responses](#common-alerts-and-responses)
5. [Triage queries](#triage-queries)
6. [Backup and restore](#backup-and-restore)
7. [Scaling](#scaling)
8. [Decommission](#decommission)

## Service overview

`honeymcp` is a single Rust binary that pretends to be an MCP server,
records every request to SQLite (and optionally JSONL), runs seven
threat detectors against the params, and exposes a server-rendered
analyst dashboard at `/dashboard`.

The deployed surface is intentionally minimal:

| Path | Purpose |
| --- | --- |
| `GET /` | Operator banner — research-honeypot disclosure + GDPR contact |
| `GET /healthz` | Liveness + readiness probe |
| `GET /version` | Build provenance (crate version + git sha + build time) |
| `GET /stats` | JSON event counters; defaults to `is_operator=0` |
| `GET /dashboard` | Server-rendered Attack Story Timeline |
| `POST /mcp` | Streamable HTTP MCP transport (spec 2025-06-18) |
| `GET /mcp`, `DELETE /mcp` | SSE stream + session teardown |
| `POST /message`, `GET /sse` | Legacy HTTP+SSE transport |

Everything else is honeymcp-internal: the SQLite DB lives on disk, the
dashboard reads from it directly, no separate API gateway, no admin UI,
no write path exposed to the network.

## Deploy

### From the signed Docker image

```bash
docker pull ghcr.io/kosiorkosa47/honeymcp:latest
cosign verify ghcr.io/kosiorkosa47/honeymcp:latest \
    --certificate-identity-regexp '^https://github\.com/kosiorkosa47/honeymcp/' \
    --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

If `cosign verify` fails, **do not deploy** — the image is unsigned or
signed by an identity that doesn't match the repo. File an issue and
quarantine the pulled image.

```bash
docker run -d --name honeymcp \
    --restart unless-stopped \
    -p 8080:8080 \
    -v /var/lib/honeymcp:/var/lib/honeymcp \
    ghcr.io/kosiorkosa47/honeymcp:latest \
    --transport http \
    --persona /opt/honeymcp/personas/postgres-admin.yaml \
    --db /var/lib/honeymcp/hive.db \
    --jsonl /var/lib/honeymcp/hive.jsonl
```

### From source

```bash
cargo build --release --bin honeymcp
./target/release/honeymcp --transport http --persona personas/...
```

### Post-deploy smoke

```bash
# Liveness
curl -fsS http://localhost:8080/healthz

# Build provenance — confirm the deployed sha is what you expect
curl -s http://localhost:8080/version | jq

# MCP handshake — the persona must respond
curl -fsS -X POST http://localhost:8080/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json' \
  -d '{"jsonrpc":"2.0","method":"initialize","id":1,"params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
```

If any of those fail, see [Common alerts](#common-alerts-and-responses).

## Health checks

| Probe | Healthy | Unhealthy |
| --- | --- | --- |
| `GET /healthz` | `200 OK` body `ok` | Anything else |
| `GET /version` | JSON with non-`unknown` `git_sha` | `git_sha = "unknown"` means the build isn't traceable |
| `du -sh /var/lib/honeymcp/hive.db` | < 5 GB on a small VPS | Investigate trim path; the logger drops the oldest 10% at 1M events but a stuck trim is possible |
| `journalctl -u honeymcp` (or `docker logs`) | No `ERROR` lines for ~5 min | Persistent `ERROR` lines = read [Triage queries](#triage-queries) |

Set the container `HEALTHCHECK` to `curl -fsS http://127.0.0.1:8080/healthz`
(it's already wired in the `Dockerfile`).

## Common alerts and responses

### Alert: "honeymcp returns 503 / connection refused"

1. Check the process is up: `systemctl status honeymcp` or `docker ps | grep honeymcp`.
2. Check disk: `df -h /var/lib/honeymcp`. SQLite blocks all writes if the
   filesystem is full — `df` < 90% used is the line.
3. Check process logs for `ERROR` — most common is `database is locked`,
   which means a stale lock from an interrupted process. Stop the
   service, `rm /var/lib/honeymcp/hive.db-journal /var/lib/honeymcp/hive.db-wal`,
   restart.

### Alert: "events_total stopped increasing"

Either the honeypot stopped receiving traffic (firewall change, DNS
moved, cert expired) or it's accepting and silently dropping. Check:

```bash
# Are we receiving anything at all?
sudo tcpdump -i any port 8080 -c 5

# Is the dispatcher logging?
journalctl -u honeymcp --since '5 minutes ago' | grep handle_request
```

If `tcpdump` shows traffic but the dispatcher isn't logging, the most
likely cause is a transport-level rejection (TLS mismatch, rate limit
hit). Look for `tower_governor` or `tls` in the logs.

### Alert: "detection rate spiked 10x"

Probably a real attack. Pull the top three detectors in the last hour:

```sql
SELECT detector, COUNT(*) AS hits
FROM detections
WHERE timestamp_ms > (strftime('%s', 'now') - 3600) * 1000
GROUP BY detector
ORDER BY hits DESC;
```

Cross-reference attacker IPs:

```sql
SELECT e.remote_addr, COUNT(*) AS reqs
FROM events e
JOIN detections d ON d.event_id = e.id
WHERE d.timestamp_ms > (strftime('%s', 'now') - 3600) * 1000
GROUP BY e.remote_addr
ORDER BY reqs DESC
LIMIT 10;
```

### Alert: "dashboard returns 500"

Tail logs for the failing template; almost always one of:

- Bad UTF-8 in `params` (we now snap to char boundaries; if you see this on a build before MITRE-mapping PR, upgrade)
- Logger query timeout (DB is too large; see [Scaling](#scaling))

### Alert: "/version reports `git_sha = unknown`"

The deployed binary wasn't built with `HONEYMCP_GIT_SHA` set. This
means the image isn't traceable to a commit and is **not safe to
deploy** to a public IP. Rebuild from a tagged release.

## Triage queries

Common SQL the SOC reaches for. Run via:

```bash
sqlite3 /var/lib/honeymcp/hive.db "<query>"
```

```sql
-- Detections in the last 24h, by category, excluding operator traffic.
SELECT d.category, COUNT(*) AS hits
FROM detections d
JOIN events e ON e.id = d.event_id
WHERE d.timestamp_ms > (strftime('%s', 'now') - 86400) * 1000
  AND e.is_operator = 0
GROUP BY d.category
ORDER BY hits DESC;

-- Distinct MITRE technique IDs observed today (requires PR #51).
SELECT DISTINCT json_each.value AS technique
FROM detections, json_each(detections.mitre_techniques)
WHERE detections.timestamp_ms > (strftime('%s', 'now') - 86400) * 1000
ORDER BY technique;

-- Top 10 attacker IPs by detection volume.
SELECT e.remote_addr, COUNT(*) AS hits
FROM detections d
JOIN events e ON e.id = d.event_id
WHERE e.is_operator = 0
GROUP BY e.remote_addr
ORDER BY hits DESC
LIMIT 10;

-- Sessions with both prompt-injection AND tool-enumeration (the
-- classic "exfil chain via LLM context" pattern).
SELECT e.session_id, COUNT(*) AS detections
FROM detections d
JOIN events e ON e.id = d.event_id
WHERE d.category IN ('prompt_injection', 'recon')
  AND e.is_operator = 0
GROUP BY e.session_id
HAVING COUNT(DISTINCT d.category) = 2
ORDER BY detections DESC;
```

## Backup and restore

The DB is the corpus. Lose it and you lose the threat-intel value.

```bash
# Backup. SQLite VACUUM INTO is consistent and crash-safe.
sqlite3 /var/lib/honeymcp/hive.db "VACUUM INTO '/backup/hive-$(date +%Y%m%dT%H%M%S).db'"

# Restore.
systemctl stop honeymcp
cp /backup/hive-2026-05-05T103000.db /var/lib/honeymcp/hive.db
chown honeymcp:honeymcp /var/lib/honeymcp/hive.db
systemctl start honeymcp
```

For continuous backup, ship the JSONL mirror to S3 / B2 / GCS via
`logrotate` + `aws s3 cp`. The JSONL is append-only so incremental
upload is trivial.

## Scaling

honeymcp is designed for one-VPS deployments. The bottleneck order
under sustained load (M1 baseline numbers from `cargo bench`):

1. SQLite write throughput — ~8k inserts/s on a single SSD before
   `database is locked` errors start.
2. Detector pipeline — ~2 µs/event per detector × 7 detectors = ~14 µs
   per event. ~71k events/sec ceiling on one core.
3. Network throughput on a $5 VPS — usually the actual ceiling.

When you hit (1):

- Switch to Postgres backend: `cargo build --features postgres`, point
  `--db postgresql://...`. Migrations live in `migrations/*.sql`.
- Or shard by persona: run multiple containers, each with its own
  `--db`, behind nginx with `Host`-based routing.

When you hit (2): file a bug. We tested the pipeline cold-start to
2.1k events/s on 64 KB payloads; if you're slower, something is wrong.

## Decommission

```bash
# Final snapshot for the corpus archive.
sqlite3 /var/lib/honeymcp/hive.db "VACUUM INTO '/backup/hive-final.db'"

# Stop and remove.
systemctl stop honeymcp
systemctl disable honeymcp
rm /etc/systemd/system/honeymcp.service
docker rm -f honeymcp 2>/dev/null || true

# Either archive or zero the data dir per your retention policy.
shred -uvz /var/lib/honeymcp/hive.db /var/lib/honeymcp/hive.jsonl
rmdir /var/lib/honeymcp
```

GDPR contact: see `docs/legal/privacy-gdpr-lia.md`. If you ran the
honeypot on a public IP and need to comply with an erasure request,
the `params_hash` column is a SHA-256 — you can prove a record matched
without retaining the raw payload.
