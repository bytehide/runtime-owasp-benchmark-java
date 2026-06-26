# OWASP Benchmark × ByteHide Runtime

Dockerized OWASP Benchmark with **ByteHide Runtime** protecting it at runtime. The runtime
agent is attached to the JVM (`-javaagent`) **without modifying the application code**, runs
in **block** mode, and answers detected attacks with **HTTP 403 (RFC 7807)**.

Everything is self-contained in this folder: **`docker compose up` and it builds and runs.**

## What it protects

The OWASP Benchmark has 11 vulnerability categories. Six of them are request-borne attacks
that a runtime firewall can intercept; ByteHide Runtime covers all six:

| Category | Test cases | Real vulnerabilities | Protection |
|---|---:|---:|---|
| SQL injection | 504 | 272 | SQL Injection |
| Cross-site scripting | 455 | 246 | Cross-Site Scripting |
| Path traversal | 268 | 133 | Path Traversal |
| Command injection | 251 | 126 | Command Injection |
| LDAP injection | 59 | 27 | LDAP Injection |
| XPath injection | 35 | 15 | XPath Injection |

The remaining five categories (weak cryptography, insecure hashing, weak randomness, insecure
cookies and trust-boundary violations) are internal misuses of crypto/RNG/session APIs, not
injectable payloads, so they are out of scope for runtime request protection.

## Contents

Added to the Benchmark repository:

```
README.md                   # this guide (run the protected Benchmark + scorecard)
README.original.md          # the upstream OWASP Benchmark README
docker-compose.yml          # the protected Benchmark service (run from the repo root)
.env.example                # environment template (set your BYTEHIDE_MONITOR_TOKEN)
bytehide-runtime/
├─ Dockerfile               # builds the Benchmark and runs Tomcat with ByteHide Runtime attached
├─ packages/
│  ├─ monitor-java-agent-1.0.4.jar   # ByteHide Runtime agent
│  ├─ monitor-config.json            # ByteHide Runtime agent configuration
│  └─ servlet-api.jar                # used by the inbound request scan
└─ attack/
   └─ attack-scorecard.py            # measures recall (blocked attacks) and false positives
```

## Requirements

- Docker with Docker Compose.
- Give Docker enough memory (≈6 GB recommended; the Benchmark is large).
- Python 3 on the host to run the scorecard (standard library only, no packages to install).

## Step 1 — Bring it up

From the repository root, copy the env template and set your ByteHide Runtime token (required):

```bash
cp .env.example .env
# edit .env and set BYTEHIDE_MONITOR_TOKEN=bh_...   (required; compose will not start without it)
docker compose up -d --build
```

The first build compiles the Benchmark and may take several minutes. When it is ready the app
is available at:

- **https://localhost:9443/benchmark** (self-signed certificate)

Check that ByteHide Runtime started:

```bash
docker compose logs benchmark | grep -i bytehide
```

## Step 2 — See the protection in action

A real attack is blocked with 403; a benign request goes through:

```bash
# Attack -> 403 (blocked by ByteHide Runtime)
curl -k "https://localhost:9443/benchmark/sqli-00/BenchmarkTest00001" \
  -d "username=admin&password=' OR '1'='1' --"

# Benign -> normal response
curl -k "https://localhost:9443/benchmark/sqli-00/BenchmarkTest00001" \
  -d "username=admin&password=hunter2"
```

## Step 3 — Measure protection with the scorecard

```bash
BENCH_URL=https://localhost:9443/benchmark python3 bytehide-runtime/attack/attack-scorecard.py
```

For each test case of the six runtime-applicable categories the scorecard runs two passes:

1. **Attack** — sends a real exploit to each truly-vulnerable endpoint. A **403 means
   ByteHide Runtime blocked the attack** (recall / true-positive rate).
2. **Benign** — replays the Benchmark's own benign values to every endpoint. A 403 here would
   be a **false positive** (blocking legitimate traffic).

It prints recall and false positives per category and writes `scorecard.csv`.

## Important — token and block mode

ByteHide Runtime requires a **project token** (`BYTEHIDE_MONITOR_TOKEN` in `.env`); `docker compose`
will not start without it. The agent applies your ByteHide Runtime project's policy, so make sure
that project's protections are in **block** mode — in `log` mode attacks are detected but not
blocked, and the scorecard will report them as not blocked.

## Why the bundled scorecard (and not the Benchmark crawler)

The Benchmark's own crawler sends **benign** inputs, because it is designed to score static and
data-flow analysis tools. With benign traffic a runtime firewall correctly blocks nothing, so
the crawler cannot measure it. The scorecard instead drives real attack payloads against the
vulnerable endpoints and measures what gets blocked.

## Rebuild after a change

```bash
docker compose up -d --build --force-recreate
```

## Notes

- The HTTPS certificate is self-signed (use `-k` with curl / accept it in the browser).
- To use a different host port, set `BENCH_HOST_PORT` in `.env` (the port inside the container
  stays 9443).
- The protection set and actions are defined in `packages/monitor-config.json`.
