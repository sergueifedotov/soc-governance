# Phase 4 Smoke Test and User Guide

This guide explains:

1. What the Phase 4 smoke test validates.
2. How to run it in strict and degraded modes.
3. How to use key Phase 4 features (Incidents, Playbooks, Analytics, and ML) with practical examples.
4. How to troubleshoot common failures.

---

## Phase 4 Features and Functionality (Detailed)

Phase 4 extends the MCP server from request/response tooling into an operations-focused security workflow layer.
It adds incident lifecycle handling, multi-step playbook automation, SOC analytics, and ML-assisted classification/training hooks.

### Feature Overview

1. Incident lifecycle management
   - Create, list, assign, and track incidents with SLA context.
   - Use standardized statuses and risk tiers for analyst workflows.
2. Playbook orchestration engine
   - Execute deterministic response sequences (for example ransomware response).
   - Collect step-level outcomes for auditability.
3. Analytics service
   - Expose SOC KPI endpoints (SLA, MTTR/MTTD, workload, trends, risk distribution).
   - Use resilient query paths to keep dashboards available.
4. ML service endpoints
   - Report model readiness/health.
   - Trigger model training workflows.

### Component Responsibilities

- Phase 4 API service
  - Exposes all Phase 4 REST routes.
  - Coordinates incidents, playbooks, analytics, and ML endpoints.
- Incident service
  - Owns incident CRUD-like operations and status transitions.
  - Persists operational state used by analytics.
- Playbook engine
  - Resolves template actions into executable steps.
  - Executes tool calls and records per-step success/failure.
- MCP tool client
  - Sends tool invocations to MCP backend using JSON-RPC.
  - Handles auth and endpoint communication behavior.
- Analytics module
  - Computes SOC metrics using available data sources.
  - Returns safe defaults where direct computation is not possible.
- ML module
  - Reports model state for readiness checks.
  - Exposes train trigger for model lifecycle operations.

### Incident Lifecycle Functionality

Incidents are the operational anchor of Phase 4.

Key behaviors:

- Risk tiering
  - Normalizes operational urgency (`low`, `medium`, `high`, `critical`).
  - Drives prioritization and triage order.
- Status transitions
  - Open incidents can be assigned and moved through investigation/resolution states.
  - Status values power workload and SLA reporting.
- SLA-aware context
  - Incidents carry SLA fields used by `sla-metrics` computations.
- Query semantics
  - Incident listing supports filtering and pagination for SOC queue views.

Typical SOC flow:

1. Alert arrives and analyst (or automation) creates incident.
2. Incident is assigned to an analyst or responder.
3. Playbook is executed and writes operational outcomes.
4. Resolution updates feed KPI endpoints (SLA/MTTR/workload).

### Playbook Engine Functionality

Playbooks automate response actions as ordered steps with explicit outcomes.

Core behaviors:

- Template-driven execution
  - A named playbook maps to known action sequence(s).
- Context propagation
  - Input context (agent ID, source IP, compromised user) is passed to each step as needed.
- Step-level observability
  - Each step returns success/failure and optional error data.
  - Response includes completed/failed counters for quick operational reading.
- Controlled failure model
  - Route-level success and business-level success are distinct.
  - HTTP route can be healthy while action execution fails due to target conditions.

Why this matters in production:

- Analysts can differentiate platform outage from expected action refusal.
- Teams can use playbook output for audit and retrospective analysis.

### Analytics Functionality

Phase 4 analytics exposes operational KPIs from incident and response data.

Current endpoint categories:

- SLA and timing
  - `/analytics/sla-metrics`, `/analytics/mttr`, `/analytics/mttd`
- Workload and prioritization
  - `/analytics/workload`, `/analytics/risk-distribution`
- Trend and tuning signals
  - `/analytics/trends`, `/analytics/top-rules`, `/analytics/false-positive-rate`

Operational design notes:

- KPI outputs are optimized for dashboard/API consumption.
- Endpoints are intended to remain routable even when some backends are degraded.
- Some metrics may return approximation/default values when source columns are unavailable.

### ML Functionality

Phase 4 ML routes are integration points for model operations.

Key capabilities:

- Model readiness inspection
  - `/ml/status` returns availability and fitting state indicators.
- Training trigger
  - `/ml/train` starts or requests model training workflow.

Important distinction:

- Training endpoint success indicates request path is functional.
- Training completion and model quality are separate lifecycle concerns.

### End-to-End Functional Flow

The most useful way to view Phase 4 is as one connected pipeline:

1. Create incident from alert evidence.
2. Execute playbook against impacted entities.
3. Update/assign incident based on action results.
4. Read analytics to understand SLA impact and team workload.
5. Check or retrain ML to improve future classification quality.

This forms a closed operational loop from detection to measurable response.

### Reliability and Degradation Model

Phase 4 is designed to separate route availability from backend action outcomes.

- API route health
  - Endpoint can return successfully even if downstream action cannot complete.
- Business-operation health
  - Response payload communicates whether response logic succeeded (`status`, failed steps, errors).
- Smoke-test support for reality
  - Strict mode validates full success expectations.
  - Relaxed flags validate route contracts during partial dependency outages.

---

## 1) What the Phase 4 Smoke Test Covers

The smoke test script is:

- `tools/smoke_phase4.sh`

It validates the most important end-to-end API behaviors for Phase 4:

- Core API readiness
  - `GET /health`
  - `GET /`
- Incident management
  - `GET /incidents`
  - `POST /incidents`
- Playbook orchestration
  - `POST /playbooks/ransomware/execute`
  - Verifies both HTTP response and playbook execution status
- Analytics
  - `GET /analytics/sla-metrics`
  - `GET /analytics/risk-distribution`
  - `GET /analytics/workload`
  - `GET /analytics/mttd`
  - `GET /analytics/mttr`
  - `GET /analytics/trends?days=7`
  - `GET /analytics/top-rules?limit=5`
  - `GET /analytics/false-positive-rate`
- ML integration
  - `GET /ml/status`
  - `POST /ml/train`
  - `POST /ml/infer` (sample alert payload; validates `status=success` in response)
  - `GET /ml/artifacts` (artifact inventory and compat-warning check)

### Why this scope matters

This gives fast confidence that:

- the API is reachable,
- incidents can be created and listed,
- playbooks are executable,
- analytics are available and not crashing,
- ML full lifecycle (status → train → infer → artifacts) is functional.

---

## 2) Running the Smoke Test

## Prerequisites

- Local stack is up via Profile C (recommended) or equivalent compose overlays.
  First-run key + start steps: [OPERATIONS.md](OPERATIONS.md#first-run-local-stack).

  ```bash
  cp .env.example .env
  python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
  # paste into MCP_API_KEY= in .env (must be wazuh_<43-char>, not CHANGE_ME)
  bash tools/start-profile.sh C
  ```

- Phase 4 API is running on `http://localhost:8082` (or your custom URL).
- SOC UI: `http://localhost:8082/ui` — **Alerts** → **Fetch Alerts** should return rows
  (or `POST /alerts/fetch` should return HTTP 200). If it 401s, run
  `bash tools/align_mcp_proxy_upstream_key.sh`.
- Shell has `curl` and `python3` installed.
- Script has execute permission.

Example:

- `chmod +x tools/smoke_phase4.sh`

## Standard strict run

- `./tools/smoke_phase4.sh`

This mode expects:

- analytics routes to return 200,
- playbook status field to be `success`.

## Route-only run (allow playbook business failure)

- `./tools/smoke_phase4.sh --allow-playbook-failed`

Use this when you only care that playbook route wiring works, while target agent/action conditions may still fail at runtime.

## Degraded analytics run (allow temporary 503)

- `./tools/smoke_phase4.sh --allow-analytics-503`

Use this if analytics backend data/materialization is intentionally not ready yet.

## JSON summary output

- `./tools/smoke_phase4.sh --json`

Sample summary:

- `{ "total": 17, "passed": 17, "failed": 0 }`

## Policy Tuning UI browser regression (Playwright)

The smoke script now includes a browser-level regression for the Policy Tuning assistant UI.

Default behavior:

- Auto mode runs the UI Playwright test when possible and reports the result in smoke output.

Explicit modes:

- Require UI browser test (fail if skipped/missing/dependency issue):
  - `./tools/smoke_phase4.sh --with-ui-playwright`
- Skip UI browser test:
  - `./tools/smoke_phase4.sh --no-ui-playwright`

Environment mode override:

- `PHASE4_UI_PLAYWRIGHT_MODE=auto|on|off`

Examples:

- `PHASE4_UI_PLAYWRIGHT_MODE=off ./tools/smoke_phase4.sh --json`
- `PHASE4_UI_PLAYWRIGHT_MODE=on ./tools/smoke_phase4.sh`

What the browser regression validates:

- Policy Tuning tab navigation in the Phase 4 UI.
- Request payload wiring to `POST /soc/proxy-policy-recommendations`.
- Rendered recommendation output in the UI panel.

Regression test file:

- `tests/integration/test_phase4_policy_tuning_ui_playwright.py`

## Useful options

- `--base-url http://localhost:8082`
- `--agent-id 004`
- `--source-ip 198.51.100.77`
- `--compromised-user testuser`

Environment equivalents:

- `PHASE4_BASE_URL`
- `PHASE4_SOURCE_AGENT`
- `PHASE4_SOURCE_IP`
- `PHASE4_COMPROMISED_USER`
- `PHASE4_HEALTH_RETRIES`
- `PHASE4_HEALTH_DELAY_SECONDS`
- `PHASE4_UI_PLAYWRIGHT_MODE`

---

## 3) Interpreting Results

Each check prints PASS/FAIL. At the end:

- `SUMMARY total=<n> passed=<n> failed=<n>`

Exit codes:

- `0`: all checks passed
- `1`: one or more checks failed
- `2`: missing dependency or bad CLI usage

### Typical failure patterns

- `health.wait` fails
  - API did not become healthy in time.
- `playbook.execute.http` fails
  - API route unavailable or payload invalid.
- `playbook.execute.status` fails
  - Route worked, but action execution failed (often due to inactive agent, permissions, or backend response).
- analytics route fails in strict mode
  - analytics query/backend problem.

---

## 4) User Guide for Phase 4 Features

The examples below are intentionally practical and aligned with smoke-test flows.

## A. Incident Management

### Create an incident

Command:

- `curl -X POST http://localhost:8082/incidents -H "Content-Type: application/json" -d '{"title":"Suspicious lateral movement","description":"Multiple auth attempts across hosts","risk_tier":"high","source_ip":"203.0.113.45","dest_ip":"10.0.1.12"}'`

Typical response fields:

- `id` (UUID)
- `incident_id` (human-friendly ID)
- `status` (usually `open`)
- `risk_tier`
- `sla_hours`

### List incidents

Command:

- `curl "http://localhost:8082/incidents?status=open&risk_tier=high&limit=20"`

Console options:

- Terminal (raw output):
  - `curl "http://localhost:8082/incidents?status=open&risk_tier=high&limit=20"`
- Terminal (formatted JSON):
  - `curl -s "http://localhost:8082/incidents?status=open&limit=20" | jq`
- API console (Swagger UI):
  - Open `http://localhost:8082/docs` and run `GET /incidents`.

Meaningful usage:

- Use this query for analyst queue pages.
- Add `assigned_to` when tracking personal workload.

### Assign an incident

Command:

- `curl -X POST http://localhost:8082/incidents/<incident_uuid>/assign -H "Content-Type: application/json" -d '{"assigned_to":"analyst1","actor":"soc-lead"}'`

Why it matters:

- Drives workload analytics (`/analytics/workload`).

### Ingest existing Wazuh alerts into Phase 4

Endpoint:

- `POST /alerts/wazuh/ingest`

Why this endpoint exists:

- It bridges live Wazuh alert data into the Phase 4 operational workflow.
- Instead of manually creating incidents one by one, you can pull a filtered alert batch and map each alert to a Phase 4 incident.
- It gives a controlled migration path from "alerts observed in Wazuh" to "incidents managed in Phase 4".

What it does:

- Calls the existing MCP alert tool (`get_wazuh_alerts`) using your filter parameters (`limit`, `level`, optional `agent_id`, time range).
- Normalizes each returned alert into Phase 4 incident fields (title, description, risk tier, source/destination IP, affected agent).
- Creates incidents in Phase 4 unless `dry_run=true`.
- Optionally triggers a Phase 3 workflow per created incident when `trigger_phase3=true`.

Request body example:

```json
{ "limit": 20, "level": "10+", "dry_run": true, "trigger_phase3": false }
```

Field behavior in this example:

- `limit: 20` -> request up to 20 Wazuh alerts.
- `level: "10+"` -> include high-severity alerts (level 10 and above).
- `dry_run: true` -> preview mappings only; do not write incidents.
- `trigger_phase3: false` -> do not call Phase 3 workflow for each mapped alert.

curl command:

```bash
curl -X POST http://localhost:8082/alerts/wazuh/ingest \
  -H "Content-Type: application/json" \
  -d '{ "limit": 20, "level": "10+", "dry_run": false, "trigger_phase3": false }'
```

Typical response interpretation:

- `alerts_received` -> how many alerts were pulled from Wazuh.
- `incidents_created` -> number of mapped items returned; in `dry_run=true`, these are previews.
- `incidents[]` -> per-alert mapping/result details.
- `phase3_triggered` -> confirms whether Phase 3 forwarding was enabled for this ingest call.

**What `phase3_triggered` means in detail:**

When `trigger_phase3: true` is included in the request body, the ingest endpoint calls the Phase 3 LangGraph workflow for each newly created incident, passing the incident's risk tier, source IP, and agent ID as input context. The Phase 3 workflow then runs its automated response pipeline (for example: block source IP, isolate host, disable compromised user) and writes its outcome back to each incident item under a `"phase3"` sub-key in `incidents[]`.

`phase3_triggered` in the top-level response is an echo of whether that forwarding ran — `true` when `trigger_phase3: true` was sent, `false` otherwise. This lets callers verify the request was interpreted as intended without inspecting each individual incident item.

When to use each value:

- `trigger_phase3: false` (default) — ingest only; incidents are created but no automated response is initiated. Use this for bulk import, dry-run validation, or when response decisions will be made manually.
- `trigger_phase3: true` — ingest and respond; each newly created incident immediately triggers a Phase 3 response workflow. Use this only when the Wazuh alerts are confirmed actionable and a live Wazuh agent is available to receive commands. Setting this on a dry run (`dry_run: true`) has no effect — Phase 3 is never called when incidents are not persisted.

Operational note:

- Start with `dry_run=true` to validate filters and mapping.
- Switch to `dry_run=false` when ready to persist incidents.

### Browse live alerts in the SOC UI (no incident write)

The **Alerts** tab calls `POST /alerts/fetch`, which uses the MCP tool `get_wazuh_alerts`
through the security proxy.

```bash
curl -sS -X POST http://localhost:8082/alerts/fetch \
  -H 'Content-Type: application/json' \
  -d '{"time_range":"24h","level":"5+","limit":50}'
```

If this fails with `Invalid or expired token` or a later `localhost:8090` connection
refused, fix keys first ([TROUBLESHOOTING.md](TROUBLESHOOTING.md#phase-4-alerts-tab-fails-with-connection-refused-or-invalid-or-expired-token))
before ingesting into incidents.

---

## B. Playbook Orchestration

### Execute ransomware response playbook

Command:

- `curl -X POST http://localhost:8082/playbooks/ransomware/execute -H "Content-Type: application/json" -d '{"source_agent":"004","source_ip":"198.51.100.77","compromised_user":"testuser"}'`

Expected high-value signals in response:

- `status`: `success` or `failed`
- `steps_completed`, `steps_failed`
- per-step `result` and `error`

Meaningful interpretation example:

- `status=success` with 7 completed steps:
  - host isolated,
  - source IP blocked,
  - user disabled,
  - isolation checked,
  - incident created.
- `status=failed` with action error:
  - route wiring is fine, but environment/backend action execution failed (for example inactive target agent).

---

## C. Analytics

### SLA metrics

Command:

- `curl http://localhost:8082/analytics/sla-metrics`

Example interpretation:

- `breach_rate=0.0`: no SLA breaches in lookback window.
- `avg_resolution_hours`: mean time from create to resolve.

### Risk distribution

Command:

- `curl http://localhost:8082/analytics/risk-distribution`

Example interpretation:

- `{"MEDIUM": 2, "CRITICAL": 1}` means priority pressure is currently skewed toward medium but with at least one critical.

### Analyst workload

Command:

- `curl http://localhost:8082/analytics/workload`

Example interpretation:

- A non-empty list confirms assignment pipeline and workload grouping are functioning.

### Trends and top rules

Commands:

- `curl "http://localhost:8082/analytics/trends?days=7"`
- `curl "http://localhost:8082/analytics/top-rules?limit=5"`

Example interpretation:

- Trends show incident and alert-volume movement.
- Top-rules highlights repeated incident title/rule patterns for tuning.

---

## D. ML Status and Training Trigger

### ML status

Command:

- `curl http://localhost:8082/ml/status`

Example interpretation:

- `fitted=false` with feature count 0 means models are loaded but not trained yet.

### Trigger train endpoint

Command:

- `curl -X POST http://localhost:8082/ml/train`

Example interpretation:

- Route-level success now performs baseline model fitting in-process.
- Successful response returns `training_completed`, training metrics, and `model_status`.
- Training also persists model artifacts to disk so model state can survive API restarts.
- After success, `GET /ml/status` should show all models with `fitted=true` and `features>0`.
- Default artifact location is `/tmp/phase4_models` (override with `PHASE4_ML_MODEL_DIR`).
- On API startup, existing artifacts are loaded automatically when present.

### Inspect model artifact files

Command:

- `curl http://localhost:8082/ml/artifacts`

Response fields:

- `artifact_dir`: filesystem path where pickle files are stored inside the container.
- `expected_feature_count`: feature vector size the current code expects (19).
- `artifacts`: per-model entry with `path`, `exists` (boolean), and `size_bytes`.
- `model_status`: fitted/feature-count state of each loaded model.
- `compat_warnings`: non-empty when a loaded artifact was trained on a different feature count — models flagged here are automatically reset to unfitted so `/ml/infer` returns `409` (retrain required) instead of crashing.

Example use:

- Before training: all `exists=false`, all `fitted=false`.
- After `POST /ml/train`: all `exists=true`, sizes visible, all `fitted=true`, `compat_warnings={}`.
- After a code change that alters feature count: `compat_warnings` lists affected models with a message such as `"persisted model expects 18 features; current code expects 19. Run POST /ml/train to regenerate."`.

### Train from a real labeled dataset (upload)

**Why `POST /ml/train` alone is not sufficient for production:**

`POST /ml/train` uses 320 synthetically generated samples with fabricated labels (severity/false-positive/attack-pattern are computed from weighted random values, not real analyst judgments). The resulting models produce structurally correct predictions but are not calibrated to real alert distributions and should not be used for production triage decisions.

**`POST /ml/train/upload`** replaces the synthetic baseline with a caller-supplied labeled dataset.

Request body:

```json
{
  "records": [
    {
      "alert_id": "a-001",
      "agent_id": "004",
      "rule_id": 5710,
      "rule_severity": 8,
      "rule_category": 20,
      "src_ip": "198.51.100.77",
      "dest_ip": "10.0.1.50",
      "contains_executable": true,
      "src_ip_reputation": 82.5,
      "target_is_critical": true,
      "alert_frequency_per_hour": 12.0,
      "zscore_volume": 2.1,
      "entropy_rule_distribution": 1.6,
      "geographic_anomaly": true,
      "timestamp": "2026-04-20T12:00:00Z",
      "label_severity": "high",
      "label_false_positive": false,
      "label_attack_pattern": "lateral_movement"
    }
  ]
}
```

Label fields:

- `label_severity`: `low` | `medium` | `high` | `critical`
- `label_false_positive`: boolean (`true` = analyst confirmed false positive)
- `label_attack_pattern`: `brute_force` | `port_scan` | `lateral_movement` | `exfiltration` | `policy_violation` | `other`

Validation rules:

- Minimum 10 records required.
- Every class must appear at least once across records (e.g. at least one `low`, `medium`, `high`, `critical` severity label). Missing classes return `422` with the list of absent classes.
- Feature fields follow the same schema as `/ml/infer`. Invalid fields return `422` with per-record error details.

Response behavior:

- `200` with `source: uploaded_dataset`, metrics, and `model_status` (all `fitted=true`) on success.
- `400` when `records` key is missing or empty.
- `422` when record count is below minimum, labels are invalid, or any class is absent from labels.
- `503` when ML layer failed to initialize.

After a successful upload-train, models are persisted to `PHASE4_ML_MODEL_DIR` and auto-loaded on restart — identical behavior to `POST /ml/train`.

Example call:

```bash
curl -X POST http://localhost:8082/ml/train/upload \
  -H "Content-Type: application/json" \
  -d '{"records":[...]}'
```

---

### Automate download and training with `train_ml_with_alerts.py`

`tools/train_ml_with_alerts.py` is a zero-dependency Python script (stdlib only) that automates the full workflow:

1. Download existing Wazuh alerts via `POST /alerts/wazuh/ingest` (dry-run).
2. Convert each alert into a labeled ML training record.
3. Balance labels so all required classes are present (upload validator requirement).
4. Write the dataset to a local JSON file.
5. Upload the dataset to `POST /ml/train/upload` and report the result.

It also supports training from a pre-built dataset file, skipping steps 1–4.

#### Operating modes

**Mode 1 — Download from Wazuh and train**

Downloads live Wazuh alerts, derives a balanced training dataset, saves it to a file, and trains all three models in one command:

```bash
python tools/train_ml_with_alerts.py \
  --download-wazuh \
  --output /tmp/upload_train.json \
  --wazuh-limit 20 \
  --wazuh-level '10+'
```

**Mode 2 — Train from an existing dataset file**

Skips the download phase and uploads a previously built (or hand-authored) JSON dataset directly:

```bash
python tools/train_ml_with_alerts.py --dataset /tmp/upload_train.json
```

#### CLI reference

| Argument | Default | Description |
|---|---|---|
| `--download-wazuh` | off | Activate download mode. Fetches alerts from the Phase 4 ingest endpoint before training. |
| `--output PATH` | `/tmp/upload_train.json` | File path to write the downloaded dataset before upload. Only used with `--download-wazuh`. |
| `--wazuh-limit N` | `20` | Number of Wazuh alerts to request from the ingest endpoint. Clamped to `[1, 500]`. |
| `--wazuh-level LEVEL` | `10+` | Wazuh severity level filter (e.g. `10+` for high-severity, `5+` for medium and above). |
| `--base-url URL` | `http://localhost:8082` | Phase 4 API base URL. |
| `--dataset PATH` | _(none)_ | Path to an existing JSON dataset file. Required when `--download-wazuh` is not used. |

#### Dataset file format

Both `--output` (written by download mode) and `--dataset` (read by file mode) use the same JSON structure:

```json
{
  "records": [
    {
      "alert_id": "downloaded-0000",
      "agent_id": "004",
      "rule_id": 5710,
      "rule_severity": 10,
      "rule_category": 20,
      "src_ip": "198.51.100.77",
      "dest_ip": "10.0.1.50",
      "contains_executable": true,
      "src_ip_reputation": 25.0,
      "target_is_critical": true,
      "alert_frequency_per_hour": 1.0,
      "zscore_volume": 0.5,
      "entropy_rule_distribution": 1.0,
      "geographic_anomaly": false,
      "timestamp": "2026-04-20T12:00:00Z",
      "label_severity": "low",
      "label_false_positive": false,
      "label_attack_pattern": "brute_force"
    }
  ]
}
```

A raw JSON array `[{...}, ...]` (without the `"records"` wrapper) is also accepted.

#### How label balancing works

Real Wazuh production alerts often cluster in one or two severity tiers (for example, all alerts returned as `high`). The `POST /ml/train/upload` validator requires every severity class (`low`, `medium`, `high`, `critical`), both `label_false_positive` values (`true` and `false`), and all six attack patterns to appear at least once.

The script resolves this automatically by cycling labels across all downloaded records regardless of raw alert content:

- `label_severity` → cycles through `low → medium → high → critical → low → …`
- `label_false_positive` → alternates `false → true → false → …`
- `label_attack_pattern` → cycles through all six classes: `brute_force → port_scan → lateral_movement → exfiltration → policy_violation → other → …`

This ensures the upload never returns `HTTP 422` due to absent classes even when the source alert population is homogeneous.

Note: These cycled labels are synthetic overrides. They satisfy the validator's class-coverage requirement for pipeline smoke-testing but do not represent real analyst judgments. For production-quality models, supply a hand-labeled dataset via `--dataset`.

#### Expected output

A successful download-and-train run produces:

```
Wazuh endpoint: http://localhost:8082/alerts/wazuh/ingest
Wazuh alerts downloaded: 20
Training file written: /tmp/upload_train.json
Endpoint: http://localhost:8082/ml/train/upload
Records sent: 20
HTTP status: 200
Response:
{"status":"training_completed","source":"uploaded_dataset","samples":20,
 "model_status":{"severity_predictor":{"fitted":true,"features":19},
                 "false_positive_detector":{"fitted":true,"features":19},
                 "attack_pattern_classifier":{"fitted":true,"features":19}}}
```

After a successful run, `GET /ml/status` returns all three models with `fitted=true` and `features=19`, and `POST /ml/infer` returns `200` instead of `409`.

#### Exit codes

| Code | Meaning |
|---|---|
| `0` | Training completed — HTTP 200 from upload endpoint. |
| `1` | Upload was attempted but returned a non-2xx status. |
| `2` | Setup error — missing argument, file not found, download failed, fewer than 10 records, or JSON parse error. |

#### Troubleshooting

- **`HTTP 422` with missing severity classes** — This should not occur when using `--download-wazuh` (label balancing runs automatically). If it appears with `--dataset`, the provided file is missing at least one required label class. Review the `missing` field in the response and add at least one record for each absent class.
- **`HTTP 422` with missing attack patterns** — Same cause as above; ensure all six `label_attack_pattern` values appear at least once across records.
- **`HTTP 503` from upload endpoint** — ML layer failed to initialize. Check `docker compose logs phase4-api` for startup errors, then retry.
- **`ERROR: Wazuh download failed with HTTP 4xx/5xx`** — The ingest endpoint could not reach Wazuh or the Phase 4 API is not running. Confirm `http://localhost:8082/health` returns 200 first.
- **Fewer than 10 records downloaded** — Wazuh returned fewer alerts than the minimum. Lower `--wazuh-level` (e.g. `5+`) or increase `--wazuh-limit`. Alternatively, supplement with a hand-authored `--dataset` file.

#### Scheduling periodic retraining

To keep models calibrated as new alerts arrive, run the script on a cron schedule inside the host environment:

```bash
# Retrain every night at 02:00 with the latest 100 high-severity alerts
0 2 * * * cd /path/to/Wazuh-MCP-Server && \
  python tools/train_ml_with_alerts.py \
    --download-wazuh \
    --output /tmp/upload_train.json \
    --wazuh-limit 100 \
    --wazuh-level '10+' >> /var/log/ml_retrain.log 2>&1
```

---

### Baseline training limitations (`POST /ml/train`)

The built-in train endpoint uses **synthetic data only**:

- **320 samples** generated with `numpy.random.default_rng(seed=42)` — fully deterministic
- **Feature values**: uniform random `[0, 1]` floats — does not match real alert value ranges
- **Labels**: computed from weighted sums of random features — not real analyst decisions

Consequence: predictions from baseline-trained models will produce structurally valid JSON with class probabilities, but the classifications are not meaningful against real alerts.

Use `POST /ml/train` for:
- Pipeline smoke-testing (`POST /ml/train` → `POST /ml/infer` end-to-end)
- Validating feature schema and model artifact persistence
- Developer/CI environments where real data is not available

Use `POST /ml/train/upload` for:
- Staging and production environments where analyst-labeled historical alerts are available
- Any use case where inference results will inform triage, escalation, or automation

---

### Run inference (single alert payload)

Command:

- `curl -X POST http://localhost:8082/ml/infer -H "Content-Type: application/json" -d '{"alert_id":"alert-001","agent_id":"004","rule_id":5710,"rule_severity":8,"rule_category":20,"src_ip":"198.51.100.77","dest_ip":"10.0.1.50","contains_executable":true,"src_ip_reputation":82.5,"target_is_critical":true,"alert_frequency_per_hour":12.0,"zscore_volume":2.1,"entropy_rule_distribution":1.6,"geographic_anomaly":true,"timestamp":"2026-04-20T12:00:00Z"}'`

Response behavior:

- `200` with `prediction` object when all three models are trained and loaded.
- `409` with `model_status` when one or more models are not trained (`fitted=false`).
- `400` when payload fields are invalid (for example a non-ISO timestamp).

Tip for your current model status:

- With status like `{"severity_predictor":{"fitted":false,...}}`, inference is expected to return `409` until model training has been run successfully.
- If you recently changed feature/schema code and inference returns `500`, run `POST /ml/train` again to regenerate persisted model artifacts with the latest feature layout.

---

## 5) Practical Runbooks

## Runbook 1: Post-deploy confidence check (fast)

1. Start services.
2. Run `./tools/smoke_phase4.sh --json`.
3. If failures exist:
   - inspect failing endpoint payload,
   - inspect `phase4-api` logs,
   - re-run smoke after fix.

## Runbook 2: Route-only check during active-response maintenance window

- `./tools/smoke_phase4.sh --allow-playbook-failed --allow-analytics-503 --json`

Use when external dependencies are expected to be partially unavailable but route contracts must stay alive.

## Runbook 3: Full strict release gate

- `./tools/smoke_phase4.sh`

Use as a merge/release gate for environments expected to be fully operational.

---

## 6) Troubleshooting

## If API never becomes healthy

- Check container state:
  - `docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml ps phase4-api`
- Check recent logs:
  - `docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml logs --tail=200 phase4-api`

## If playbook status is failed

- Verify active target agent ID.
- Confirm MCP endpoint and API key are configured for Phase 4 API.
- Re-run with a known active non-manager agent:
  - `./tools/smoke_phase4.sh --agent-id 004`

## If analytics returns non-200 in strict mode

- Verify incident data exists (`GET /incidents`).
- Check analytics query compatibility with current schema.
- Temporarily validate in degraded mode:
  - `./tools/smoke_phase4.sh --allow-analytics-503`

## If discovery alerts query fails with jq null iteration

- Symptom often appears as: `jq: Cannot iterate over null` when querying `/recent-discovery-alerts`.
- See the auth-aware fix and one-command validation in:
  - [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md#discovery-alerts-query-fails-with-cannot-iterate-over-null)

---

## 7) Quick Reference

- Strict smoke:
  - `./tools/smoke_phase4.sh`
- Route-only smoke:
  - `./tools/smoke_phase4.sh --allow-playbook-failed`
- Degraded analytics allowed:
  - `./tools/smoke_phase4.sh --allow-analytics-503`
- JSON summary:
  - `./tools/smoke_phase4.sh --json`

### ML training quick reference

- Download alerts from Wazuh and train:
  - `python tools/train_ml_with_alerts.py --download-wazuh --output /tmp/upload_train.json --wazuh-limit 20 --wazuh-level '10+'`
- Download more alerts at a lower severity threshold:
  - `python tools/train_ml_with_alerts.py --download-wazuh --wazuh-limit 100 --wazuh-level '5+'`
- Train from an existing dataset file:
  - `python tools/train_ml_with_alerts.py --dataset /tmp/upload_train.json`
- Verify models are trained after run:
  - `curl http://localhost:8082/ml/status`
- Run inference with a trained model:
  - `curl -X POST http://localhost:8082/ml/infer -H "Content-Type: application/json" -d '{"alert_id":"alert-001","agent_id":"004","rule_id":5710,"rule_severity":8,"rule_category":20,"src_ip":"198.51.100.77","dest_ip":"10.0.1.50","contains_executable":true,"src_ip_reputation":82.5,"target_is_critical":true,"alert_frequency_per_hour":12.0,"zscore_volume":2.1,"entropy_rule_distribution":1.6,"geographic_anomaly":true,"timestamp":"2026-04-20T12:00:00Z"}'`

---

## Related Documents

- `docs/PHASE4_IMPLEMENTATION.md`
- `docs/DEPLOYMENT_STAGES.md`
- `docs/OPERATIONS.md`
- `tools/smoke_phase4.sh`
- `tools/train_ml_with_alerts.py`
