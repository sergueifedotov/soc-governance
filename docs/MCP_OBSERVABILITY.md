# MCP Agent Traffic Observability

This document describes the persistent monitoring stack for **every MCP
JSON-RPC call** flowing through the Wazuh MCP Server: who called which tool,
how long it took, whether it succeeded, and how to view the data in Grafana.

---

## 1. Why this exists

`wazuh-mcp-server` exposes a JSON-RPC `/mcp` endpoint that is consumed by
Claude, Open WebUI + Docker Model Runner, LangGraph agents, and CLI clients.
Operators need a per-call view (method, tool, params summary, status,
latency, client IP, auth subject, error message) **and** a long-term
aggregate view for capacity, error tracking, and SLOs.

The observability tooling provides both:

| Need | Mechanism |
|---|---|
| Per-call live feed (last N events) | In-memory ring buffer + SSE at `/observability/stream` |
| Filtered JSON queries from scripts/CI | `/observability/recent`, `/observability/stats` |
| Persistent time-series + dashboards | Prometheus scrape + Grafana dashboard |
| Alerting / SLOs | PromQL on the same metrics |

The in-memory buffer is **not** the system of record. Prometheus's TSDB is.
The buffer is reset on container restart; Prometheus retains 30 days / 5 GB.

---

## 2. Architecture

```
                Claude / Open WebUI / DMR / LangGraph / CLI
                                  │
                                  │  JSON-RPC over HTTP
                                  ▼
                        wazuh-mcp-server (:3000)
                        ├── /mcp           ← every call passes through
                        │   └─ record_mcp_call()
                        │       ├─► in-memory ring buffer (1000 events)
                        │       │       │
                        │       │       └─► /observability/stream (SSE)
                        │       │           /observability/recent (JSON)
                        │       │           /observability/stats   (JSON)
                        │       │           /observability/ui/legacy (HTML)
                        │       │
                        │       └─► Prometheus client metrics
                        │              wazuh_mcp_calls_total
                        │              wazuh_mcp_call_duration_seconds
                        │              wazuh_mcp_call_errors_total
                        │              (+ existing wazuh_mcp_* metrics)
                        │
                        └── /metrics      ← Prometheus exposition format
                                  ▲
                                  │ scrape every 15 s
                                  │
                        phase4-prometheus (:9091)
                          retention: 30 days / 5 GB
                                  ▲
                                  │ datasource (uid: prometheus-ds)
                                  │
                        phase4-grafana (:3002)
                          dashboard uid: mcp-agent-traffic
                          provisioned at startup from
                          config/phase4/grafana/dashboards/mcp-agent-traffic.json
```

**Key files**

| File | Purpose |
|---|---|
| [src/wazuh_mcp_server/mcp_traffic.py](../src/wazuh_mcp_server/mcp_traffic.py) | `MCPTrafficRecorder`, JSON-RPC event recorder, `/observability/*` router, Prometheus metric emission |
| [src/wazuh_mcp_server/monitoring.py](../src/wazuh_mcp_server/monitoring.py) | Shared `prometheus_client` `REGISTRY` for the `/metrics` endpoint |
| [config/phase4/prometheus.yml](../config/phase4/prometheus.yml) | Scrape job for `wazuh-mcp-server:3000` |
| [compose.phase4.yml](../compose.phase4.yml) | `phase4-prometheus` (retention) and `phase4-grafana` services |
| [config/phase4/grafana/provisioning/datasources/prometheus.yml](../config/phase4/grafana/provisioning/datasources/prometheus.yml) | Prometheus datasource |
| [config/phase4/grafana/dashboards/mcp-agent-traffic.json](../config/phase4/grafana/dashboards/mcp-agent-traffic.json) | The provisioned dashboard |

---

## 3. Endpoints

All `/observability/*` endpoints (except `/health`) require the same bearer
token used elsewhere by the MCP server.

| Endpoint | Method | Description |
|---|---|---|
| `/observability/ui` | GET | **302 redirect** to the Grafana dashboard |
| `/observability/ui/legacy` | GET | Self-contained in-page dashboard (fallback) |
| `/observability/stats` | GET | Aggregate JSON: KPIs, by-tool table, timeline, top clients, recent errors |
| `/observability/recent` | GET | Recent events list. Query params: `limit`, `tool`, `method`, `status` |
| `/observability/stream` | GET | Server-Sent Events live feed (one event per call) |
| `/observability/health` | GET | Liveness probe — buffer size and capacity |
| `/metrics` | GET | Prometheus exposition for **all** server metrics including the new MCP traffic ones |

**Auth precedence:**

1. `Authorization: Bearer <token>` header
2. `?token=<token>` query string
3. `X-Observability-Token: <token>` header

The expected token is `MCP_OBSERVABILITY_TOKEN`, falling back to `MCP_API_KEY`.
Set `MCP_OBSERVABILITY_OPEN=1` to disable auth (dev only). If neither
variable is set, the routes are open by default.

### 3.1 Programmatic access

Resolve the bearer token (checks `$MCP_API_KEY`, `.env`, then the running
container in that order) and call the JSON / SSE endpoints from a script
or terminal:

```bash
# Export MCP_API_KEY into the current shell
source tools/mcp_api_key.sh --quiet

# Aggregate JSON (KPIs, by-tool table, recent errors, top clients)
curl -H "Authorization: Bearer $MCP_API_KEY" \
     http://localhost:3000/observability/stats

# Last 20 error events
curl -H "Authorization: Bearer $MCP_API_KEY" \
     "http://localhost:3000/observability/recent?status=error&limit=20"

# Live SSE feed (one event per JSON-RPC call) - press Ctrl-C to stop
curl -N -H "Authorization: Bearer $MCP_API_KEY" \
     http://localhost:3000/observability/stream
```

The helper [tools/mcp_api_key.sh](../tools/mcp_api_key.sh) can also be run
directly to print the key (e.g., `MCP_API_KEY=$(tools/mcp_api_key.sh)`).
It works under both bash and zsh, sourced or executed.

---

## 4. Configuration

| Env var | Default | Purpose |
|---|---|---|
| `MCP_API_KEY` | `wazuh_local_demo_change_me` | Server auth + observability fallback |
| `MCP_OBSERVABILITY_TOKEN` | unset | Override auth token for `/observability/*` |
| `MCP_OBSERVABILITY_CAPACITY` | `1000` | Ring buffer size (events) |
| `MCP_OBSERVABILITY_OPEN` | unset | `1`/`true` disables auth (dev) |
| `MCP_OBSERVABILITY_GRAFANA_URL` | `http://localhost:3002/d/mcp-agent-traffic/mcp-agent-traffic` | Override the redirect target of `/observability/ui` |

---

## 5. Prometheus metrics emitted

All metrics share the labels below for cross-correlation. `tool` is `-` for
non-`tools/call` methods (e.g. `tools/list`, `initialize`).

| Metric | Type | Labels | Description |
|---|---|---|---|
| `wazuh_mcp_calls_total` | counter | `method`, `tool`, `status` | One increment per JSON-RPC call. `status` is `success` or `error`. |
| `wazuh_mcp_call_duration_seconds` | histogram | `method`, `tool` | Per-call latency. Buckets: 5 ms → 30 s. |
| `wazuh_mcp_call_errors_total` | counter | `method`, `tool`, `error_code` | Errors with the JSON-RPC `error.code`. |

These complement the existing server metrics (`wazuh_mcp_requests_total`,
`wazuh_mcp_tool_executions_total`, `wazuh_mcp_tool_duration_seconds`, etc.)
without duplicating them — the new metrics are scoped to the MCP JSON-RPC
layer specifically.

### Useful PromQL

```promql
# Calls per second by tool (last 1 m)
sum by (tool) (rate(wazuh_mcp_calls_total[1m]))

# Error percentage (last 5 m)
100 * sum(rate(wazuh_mcp_calls_total{status="error"}[5m]))
    / clamp_min(sum(rate(wazuh_mcp_calls_total[5m])), 1e-9)

# p95 latency overall
histogram_quantile(
  0.95,
  sum by (le) (rate(wazuh_mcp_call_duration_seconds_bucket[5m]))
)

# Top 10 tools by total calls in the last hour
topk(10, sum by (tool) (increase(wazuh_mcp_calls_total[1h])))

# Errors by JSON-RPC code
sum by (error_code) (increase(wazuh_mcp_call_errors_total[1h]))
```

---

## 6. Grafana dashboard

There are two provisioned dashboards in the `Wazuh` folder:

| Dashboard | UID / URL | What it shows | Source |
|---|---|---|---|
| **MCP Agent Traffic** | `mcp-agent-traffic` <br> `http://localhost:3002/d/mcp-agent-traffic/mcp-agent-traffic` | Aggregate / historical: calls/sec, error rate %, p50/p95/p99 latency, top tools, errors by code. 30-day retention. | Prometheus (`/metrics` scrape) |
| **MCP Agent Traffic - Live** | `mcp-agent-traffic-live` <br> `http://localhost:3002/d/mcp-agent-traffic-live/mcp-agent-traffic-live` | Per-call human-readable feed: time, method, tool, status (color-coded), latency gauge, auth subject, client IP, error message, args. Auto-refresh every 5 s. | `/observability/recent` (ring buffer) via the Infinity datasource |

**Login:** `admin / ${GRAFANA_PASSWORD:-admin}`. Provisioned automatically — no manual import required.

### 6.1 Live dashboard wiring

The Live dashboard polls `GET /observability/recent?limit=200` every 5 s
through the Grafana **Infinity** plugin (auto-installed via
`GF_INSTALL_PLUGINS` in [compose.phase4.yml](../compose.phase4.yml)). The
datasource is provisioned at
[config/phase4/grafana/provisioning/datasources/mcp-traffic-json.yml](../config/phase4/grafana/provisioning/datasources/mcp-traffic-json.yml)
and uses bearer auth: the value of `MCP_API_KEY` is forwarded from the
host into the Grafana container as a secret token, so the dashboard works
without any per-user login or token paste.

Advantages over the raw SSE stream at `/observability/stream`:
- color-coded status, gauge-rendered latency, clickable column filters;
- one URL anyone with Grafana access can open;
- shares the same auth/RBAC story as the rest of the SOC stack.

The SSE stream is still available for terminals and bots — see
[§3.1 Programmatic access](#31-programmatic-access).

### 6.2 Aggregate dashboard variables and panels

Folder `Wazuh`. Variables `tool` and `method` populate from Prometheus
label values.

### Panels

| Panel | Source query (simplified) |
|---|---|
| Calls / sec (1 m) | `sum(rate(wazuh_mcp_calls_total[1m]))` |
| Error rate % (5 m) | `100 * sum(rate(...status="error"))` / total |
| p95 latency (5 m) | `histogram_quantile(0.95, ...)` |
| Total calls (range) | `sum(increase(wazuh_mcp_calls_total[$__range]))` |
| Calls / sec by tool (1 m) | `sum by (tool) (rate(...))` |
| Errors / sec by tool (1 m) | `sum by (tool) (rate(...status="error"))` |
| Latency p50 / p95 / p99 (5 m) | `histogram_quantile(0.50/0.95/0.99, ...)` |
| Avg latency by tool (5 m) | `rate(..._sum) / rate(..._count)` per tool |
| Top tools by total calls (range) | `topk(20, sum by (tool, method) (increase(...)))` |
| Errors by tool / code (range) | `topk(20, sum by (tool, error_code) (...))` |

### Customising the dashboard

1. Edit the JSON in
   [config/phase4/grafana/dashboards/mcp-agent-traffic.json](../config/phase4/grafana/dashboards/mcp-agent-traffic.json).
2. Bump `"version"` (Grafana ignores stale provisioned dashboards on hot reload).
3. `docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml up -d --force-recreate phase4-grafana`.

To save edits made in the Grafana UI back to the file, export the JSON
from **Dashboard settings → JSON Model**, replace the file, then recreate
the container as above.

---

## 7. Operations

### 7.1 Start the stack

The MCP traffic metrics are emitted by `wazuh-mcp-server` regardless of
which overlay is active, but Prometheus + Grafana require the Phase 4
overlay:

```bash
docker compose \
  -f compose.full.yml \
  -f compose.phase3.langgraph.yml \
  -f compose.phase4.yml \
  up -d
```

### 7.2 Verify everything is wired up

```bash
source .env

# 1. MCP exposes the new metrics
curl -s http://localhost:3000/metrics \
  | grep -E '^wazuh_mcp_calls_total|^wazuh_mcp_call_duration_seconds_count'

# 2. Generate some traffic so Prometheus has data to scrape
for i in {1..5}; do
  curl -s -X POST http://localhost:3000/mcp \
    -H "Authorization: Bearer $MCP_API_KEY" \
    -H "Content-Type: application/json" \
    -d "{\"jsonrpc\":\"2.0\",\"id\":$i,\"method\":\"tools/list\"}" \
    -o /dev/null
done

# 3. Prometheus is scraping wazuh-mcp-server (target should be UP)
curl -s 'http://localhost:9091/api/v1/targets' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); \
    [print(t['labels'].get('job'), t['health']) \
     for t in d['data']['activeTargets']]"

# 4. Prometheus query returns the data
curl -s 'http://localhost:9091/api/v1/query?query=sum(wazuh_mcp_calls_total)' \
  | python3 -m json.tool

# 5. Grafana dashboard provisioned
curl -s -u admin:${GRAFANA_PASSWORD:-admin} \
  'http://localhost:3002/api/search?query=mcp' | python3 -m json.tool

# 6. /observability/ui redirects to Grafana
curl -s -o /dev/null -w "HTTP %{http_code} -> %{redirect_url}\n" \
  http://localhost:3000/observability/ui
```

### 7.3 Apply code changes

`wazuh-mcp-server` runs from the prebuilt image `wazuh-mcp-server:4.2.1`
with **no source bind mount**, so plain `docker compose restart` will
**not** pick up changes in `mcp_traffic.py`. Always rebuild:

```bash
docker compose \
  -f compose.full.yml \
  -f compose.phase3.langgraph.yml \
  -f compose.phase4.yml \
  up -d --build wazuh-mcp-server
```

For Prometheus / Grafana provisioning changes, recreate the containers:

```bash
docker compose \
  -f compose.full.yml \
  -f compose.phase3.langgraph.yml \
  -f compose.phase4.yml \
  up -d --force-recreate phase4-prometheus phase4-grafana
```

### 7.4 Retention

Prometheus is started with:

```yaml
- "--storage.tsdb.retention.time=30d"
- "--storage.tsdb.retention.size=5GB"
- "--web.enable-lifecycle"
```

Tune these in [compose.phase4.yml](../compose.phase4.yml) under
`phase4-prometheus.command` if you need longer retention.

---

## 8. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `/observability/ui` returns blank page | Empty token in `?token=` parameter on the legacy page | The new redirect to Grafana avoids this. If you really need the legacy UI, paste the token into the input field and press Enter, or use `/observability/ui/legacy?token=$MCP_API_KEY`. |
| `wazuh_mcp_calls_total` is missing from `/metrics` | Old image without the new code | Rebuild: `docker compose ... up -d --build wazuh-mcp-server`. |
| Grafana dashboard panels show "No data" | Prometheus has not yet scraped, or no MCP traffic | Wait one scrape interval (15 s) and generate traffic with the curl loop in §7.2. |
| Prometheus target `wazuh-mcp-server` is `DOWN` | Networking — `phase4-prometheus` cannot reach `wazuh-mcp-server:3000` | Ensure both services share the `phase4` network (already declared in [compose.phase4.yml](../compose.phase4.yml)). |
| Buffer count drops to 0 after restart | Ring buffer is in-memory; resets on container restart | Expected. Persistent history lives in Prometheus. |
| Many `tool="-"` rows in the dashboard | Non-`tools/call` JSON-RPC methods (e.g., `tools/list`) | Expected — `tool` is only set for `tools/call`. |
| `/metrics` flood with high cardinality | Custom tools with unbounded names | Tool names are truncated to 80 chars in [mcp_traffic.py](../src/wazuh_mcp_server/mcp_traffic.py); add an allowlist if needed. |

---

## 9. History and design notes

### 9.1 First implementation (in-page HTML dashboard)

The first iteration of this feature shipped a self-contained HTML dashboard
served by `/observability/ui`. It read directly from the in-memory ring
buffer via `/observability/stats`, `/observability/recent`, and the SSE
stream. Strengths: zero external dependencies. Weaknesses:

- No persistence across container restarts (the buffer was the only store).
- Required pasting a bearer token into a JS-only page.
- Silent failures when the token was empty (`?token=` with no value).
- Difficult to set alerts or correlate with other Wazuh signals.

### 9.2 Why we switched to Prometheus + Grafana

The Phase 4 stack already runs Prometheus and Grafana for SLA / analytics
dashboards. Reusing them gave us:

- **Persistence:** 30-day / 5-GB rolling TSDB without writing a new store.
- **Alerting hook:** PromQL is the standard alerting language already used
  elsewhere in the stack.
- **Correlation:** the same Grafana instance can put MCP call rates next
  to Wazuh alert rates, ML drift, and Phase 4 incident metrics.
- **Operator familiarity:** Grafana auth, RBAC, and screenshot/export
  workflows are already in place.

The legacy HTML dashboard is preserved at `/observability/ui/legacy` for
local debugging when Grafana is not running.

### 9.3 Why metrics live alongside the ring buffer

Both stores are written from the same `record_mcp_call()` call site so
they cannot diverge. The Prometheus emission is wrapped in `try/except`
so a metric error can never break request handling — observability must
not become a source of incidents.

### 9.4 Lessons learned

- **`docker compose restart` does not rebuild images.** When iterating on
  `mcp_traffic.py`, always `up -d --build wazuh-mcp-server`.
- **Browsers cache the HTML dashboard aggressively.** Hard-reload (⌘ + Shift + R)
  or open a fresh URL with `?token=$MCP_API_KEY` baked in.
- **`tool` cardinality matters.** We label-truncate tool names and never
  put `client_ip` or `auth_subject` into Prometheus labels — those are
  per-event details exposed only via the JSON endpoints.

---

## 10. See also

- [docs/OPERATIONS.md](OPERATIONS.md) — health endpoints, log management, port map.
- [docs/PHASE4_IMPLEMENTATION.md](PHASE4_IMPLEMENTATION.md) — the broader
  Prometheus + Grafana setup for Phase 4.
- [docs/TROUBLESHOOTING.md](TROUBLESHOOTING.md) — generic MCP server
  troubleshooting (auth, networking, container health).
