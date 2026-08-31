# Phase 3 & Phase 4 Architecture Decisions & Proposals

**Date:** April 18, 2026  
**Status:** Active discussion  
**Last Updated:** 2026-04-18 (ML + Phase 3 correlation checklist)

---

## Table of Contents

1. [Node Proposal Action Analysis](#node-proposal-action-analysis)
2. [Framework Integration Discussion](#framework-integration-discussion)
3. [Phase 3 Enhancement Proposals](#phase-3-enhancement-proposals)
4. [Phase 4 Advanced SOC Architecture](#phase-4-advanced-soc-architecture)
   - [Layer 7: ML & Anomaly Detection](#layer-7-ml--anomaly-detection-scikit-learn--xgboost--mlflow)
     - [7.1 Problem Statement](#71-problem-statement)
     - [7.2 Use Cases & Business Impact](#72-use-cases--business-impact)
     - [7.3 Data Pipeline & Feature Engineering](#73-data-pipeline--feature-engineering)
     - [7.4 Model Architecture](#74-model-architecture)
     - [7.5 Training & Validation Pipeline](#75-training--validation-pipeline)
     - [7.6 Integration with Phase 3 Workflow](#76-integration-with-phase-3-workflow)
     - [7.7 Deployment & Monitoring Strategy](#77-deployment--monitoring-strategy)
     - [7.8 Expected Business Impact](#78-expected-business-impact)
     - [7.9 Challenges & Mitigation](#79-challenges--mitigation)
     - [7.10 Roadmap: Q4 2026 → Q1 2027](#710-roadmap-q4-2026--q1-2027)
     - [7.11 Alternative Approaches](#711-alternative-approaches-not-recommended)
     - [7.12 Phase 3 Mapping: Graph Correlation + LlamaIndex](#712-phase-3-mapping-graph-correlation--llamaindex)
     - [7.13 Implementation Checklist (Phase 3)](#713-implementation-checklist-phase-3)
    - [7.14 Engineering Task Map (Files and Functions)](#714-engineering-task-map-files-and-functions)
5. [Recommended Implementation Roadmap](#recommended-implementation-roadmap)

---

## Node Proposal Action Analysis

### Finding
The `node_propose_action` in Phase 3 LangGraph is **request-driven**, not **triage/enrichment-driven**.

### Current Implementation
**File:** [`services/phase3_langgraph/app/main.py#L180`](../services/phase3_langgraph/app/main.py#L180)

```python
async def node_propose_action(state: Phase3State) -> Phase3State:
    req = state["request"]
    
    # Action comes from request.use_case → hardcoded mapping
    plan = _build_action_plan(req["use_case"])
    
    # Args come from request.action_args or defaults
    action_args = req["action_args"] or _default_action_args(req["use_case"])
    
    # Risk tier sets approval thresholds
    approval_required = req["risk_tier"] in {"medium", "high", "critical"}
    approvals_needed = 2 if req["risk_tier"] in {"high", "critical"} else 1
```

### What is NOT Used

| State Key | What it Holds | Usage |
|---|---|---|
| `state["triage"]` | Alert summary, severity breakdown, top rules | **Not read** in node_propose_action |
| `state["enrichment"]` | Top threats, threat patterns, context | **Not read** in node_propose_action |

These nodes run and populate state, but `node_propose_action` ignores their output.

### Decision Matrix

| Decision | Current | Dynamic (Proposed) |
|---|---|---|
| Action tool selection | Hardcoded by `use_case` | Selected by LLM + triage context |
| Action arguments | From request or defaults | Extracted from enrichment (e.g., src_ip from top threat) |
| Approval strictness | Hardcoded by `risk_tier` | Computed from triage severity scores |
| Verification method | Hardcoded per tool | Could be dynamically selected |

### Trade-offs

| Approach | Pros | Cons |
|---|---|---|
| **Current (Request-driven)** | Auditable, simple, fast, deterministic | Limited by request params; can't auto-correct bad choices |
| **Triage-driven** | Uses context intelligently; could recommend action if user doesn't specify | Opaque; LLM hallucinations possible; slower |
| **Hybrid** | Request-driven by default; override if triage suggests better action | Adds complexity; need ranking algorithm |

### Recommendation

**Keep request-driven for Phase 3.** The workflow is auditable and predictable.

**Implement Hybrid in Phase 4** when playbooks can override:
```yaml
playbook:
  - if: triage.severity > 8 and enrichment.brute_force_count > 20
    then: use_case: block_ip  # override default
    else: use_case: $(request.use_case)
```

---

## Framework Integration Discussion

### Question: Should We Add LlamaIndex?

**LlamaIndex:** Data framework for building LLM applications with retrieval-augmented generation (RAG).

#### Use Cases for Wazuh
1. Semantic alert search ("find incidents similar to this detection")
2. Dynamic action selection from historical runbooks
3. Threat intelligence semantic search

#### Decision: **Not Yet**

**Reasoning:**
- Phase 3 is still in active development
- Hardcoded mappings already work
- No large historical incident archive to index yet
- Adds dependency overhead (embedding API calls, vector DB)

**When to revisit:** 6–12 months post-Phase 3 production launch, if analysts request "smarter" recommendations.

**Alternative (lighter):** Add simple vector similarity (scikit-learn cosine) to enrich_wazuh_context for similar-alert retrieval without full LlamaIndex.

---

## Phase 3 Enhancement Proposals

### Implementation Status (April 2026)

| Enhancement | Current Status | Validation Path |
|---|---|---|
| Tenacity retries | ✅ Implemented in `_mcp_call` retry decorator | `POST /phase3/run` execution path |
| Structlog audit logging | ✅ Implemented for approval, pending/resumed, execute, verify, rollback | `services/phase3_langgraph/app/audit_logging.py` |
| Parallel execution | ✅ Implemented via `proposed_actions` + `asyncio.gather` | `critical-parallel` scenario |
| Langfuse OSS tracing | ✅ Implemented on `run_phase3` endpoint (client trace lifecycle) | `POST /phase3/run` entrypoint |
| Human-in-the-loop pause/resume | ✅ Implemented with pending store and resume API | `/phase3/approvals/{incident_id}`, `/phase3/approvals/{incident_id}/resume` |

Enhancement smoke test command:

```bash
bash tools/smoke_phase3_enhancements.sh
```

Enhancement regression tests:

```bash
python -m pytest tests/integration/test_phase3_human_approval.py -q
```

---

### 1. ✅ **Tenacity** — Smart Retries (HIGH PRIORITY)

**Problem:** AR commands can fail transiently; `verify` steps return false negatives due to indexing lag.

**Solution:** Retry with exponential backoff before rolling back.

```python
from tenacity import retry, wait_exponential, stop_after_attempt

@retry(
    wait=wait_exponential(multiplier=1, min=2, max=10),
    stop=stop_after_attempt(3)
)
async def execute_with_retry(self, tool, args):
    response = await _mcp_call(tool, args)
    if response.get("error"):
        raise RuntimeError("Tool failed, will retry")
    return response
```

**Status:** Implemented

---

### 2. ✅ **Structlog** — Audit Logging (HIGH PRIORITY)

**Problem:** Approval decisions, AR commands, verification steps are not persistently logged.

**Solution:** Structured JSON logs for compliance + incident investigation.

```python
import structlog

structlog.get_logger().info(
    "approval_gate",
    decision="approved",
    actor="auto-approval",
    risk_tier="critical",
    incident_id="INC-crit-004",
    approvals_needed=2,
    timestamp=datetime.now().isoformat()
)
```

**Output:** Queryable audit trail for "Who approved what and when?"

**Status:** Implemented

---

### 3. **Parallel Execution** — Multi-Action Workflows (MEDIUM PRIORITY)

**Problem:** Ransom response often needs: isolate host + block IP + disable user *simultaneously*.

**Current:** Sequential (medium-block → high-isolate → can't do both)

**Solution:** Support multiple actions in parallel.

```python
# critical-parallel scenario
proposed_actions = [
    {"tool": "wazuh_isolate_host", "args": {...}},
    {"tool": "wazuh_firewall_drop", "args": {...}},
    {"tool": "wazuh_disable_user", "args": {...}},
]

results = await asyncio.gather(*[
    _mcp_call(action["tool"], action["args"])
    for action in proposed_actions
])
```

**Status:** Implemented

---

### 4. **Langfuse OSS Integration** — Observability (MEDIUM PRIORITY)

**Problem:** No visibility into per-node performance or failure patterns.

**Solution:** Trace all workflow execution with OSS Langfuse.

```python
trace = langfuse_client.trace(name="phase3_workflow", input=request.model_dump())
async def run_phase3(request):
    result = await workflow.ainvoke(initial_state)
    trace.update(output={"workflow_status": result.get("workflow_status")})
    return result
```

**Benefit:** Self-hosted, open-source observability without vendor lock-in.

**Status:** Implemented

---

### 5. **Human-in-the-Loop** — Interactive Approvals (LOWER PRIORITY)

**Problem:** Auto-approval is only for demos; real SOC needs analyst interaction.

**Solution:** Pause workflow, send to Slack/PagerDuty, resume on approval.

```python
if not state["request"]["auto_approve"]:
    state["pending_approval"] = True
    # Webhook listener waits for analyst response
    await analyst_approval_webhook.wait()
```

**Status:** Implemented

---

## Phase 4 Advanced SOC Architecture

### Layers & Frameworks

#### Layer 1: Incident Management (SQLAlchemy + PostgreSQL)

**Purpose:** The central ticketing and tracking system for the SOC — the persistent state store that every other layer reads from and writes back to. Without Layer 1 there is no record of what happened, who acted, or whether SLAs were honoured.

**What it does:**

- **Creates and tracks incidents** — every Wazuh alert that crosses a severity threshold becomes an `IncidentTicket` with a human-readable ID (`INC-2026-00001`), status, priority, and timestamps
- **Enforces SLA policies** — each risk tier has a resolution deadline (critical=1h, high=4h, medium=8h, low=24h); tickets are marked `sla_breach=True` automatically when the deadline passes
- **Manages the incident lifecycle** — `open → assigned → investigating → escalated → resolved → closed → archived`, with every transition logged
- **Stores forensic context** — source IP, dest IP, affected agents, alert count, ML predictions (severity, false-positive probability, attack pattern)
- **Links evidence** — attach log excerpts, file hashes, network captures with storage paths and SHA256 integrity hashes
- **Provides a full audit trail** — every status change, assignment, comment, and action is written to `incident_activities` with actor + timestamp
- **Exposes aggregate statistics** — counts by status/risk tier, SLA breach rate, unassigned count, open critical incidents

**Why it matters for the rest of the stack:**

| Layer | Dependency on Layer 1 |
|---|---|
| Layer 3 (Playbooks) | Reads incident risk tier to select playbook; writes status updates back |
| Layer 4 (Celery) | Queues tasks keyed by incident ID; writes execution results back |
| Layer 5 (Analytics) | DuckDB queries the `incidents` table for SLA, MTTR, and trend KPIs |
| Layer 7 (ML) | Stores `ml_predicted_severity`, `ml_false_positive_prob`, `ml_attack_pattern` on the incident row |

**API surface (implemented):**

| Endpoint | Purpose |
|---|---|
| `POST /incidents` | Create incident from alert |
| `GET /incidents` | List with status/risk-tier/assignee filters |
| `GET /incidents/stats` | Aggregate counts, SLA breach rate |
| `GET /incidents/{id}` | Fetch single incident |
| `PUT /incidents/{id}` | Field-level update |
| `POST /incidents/{id}/assign` | Assign to analyst |
| `POST /incidents/{id}/escalate` | Raise priority, set escalated status |
| `POST /incidents/{id}/resolve` | Mark resolved, compute SLA breach |
| `POST /incidents/{id}/close` | Final close after resolution |
| `POST /incidents/{id}/archive` | Long-term retention |
| `POST /incidents/{id}/activities` | Append audit log entry |
| `GET /incidents/{id}/activities` | Full activity timeline (newest first) |
| `POST /incidents/{id}/evidence` | Attach artifact (log/file/network) |
| `GET /incidents/{id}/evidence` | List evidence for incident |
| `GET /sla-policies` | List SLA policies by risk tier |
| `POST /sla-policies/seed` | Upsert default SLA policies (idempotent) |

**curl examples (base URL: `http://localhost:8082`):**

```bash
# Seed default SLA policies (run once on startup)
curl -s -X POST http://localhost:8082/sla-policies/seed | jq .

# List SLA policies
curl -s http://localhost:8082/sla-policies | jq .

# Create an incident
curl -s -X POST http://localhost:8082/incidents \
  -H 'Content-Type: application/json' \
  -d '{
    "title": "Brute-force attack on web server",
    "description": "Multiple failed SSH logins from 198.51.100.77",
    "risk_tier": "high",
    "source_ip": "198.51.100.77",
    "dest_ip": "10.0.1.50",
    "alert_count": 42
  }' | jq .

# List incidents (with optional filters)
curl -s "http://localhost:8082/incidents?status=open&risk_tier=high" | jq .

# Aggregate stats
curl -s http://localhost:8082/incidents/stats | jq .

# Fetch a single incident  (replace INC-2026-00001 with real ID)
curl -s http://localhost:8082/incidents/INC-2026-00001 | jq .

# Assign to analyst
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/assign \
  -H 'Content-Type: application/json' \
  -d '{"assigned_to": "analyst@soc.local", "actor": "analyst@soc.local"}' | jq .

# Escalate
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/escalate \
  -H 'Content-Type: application/json' \
  -d '{"escalated_by": "analyst@soc.local", "reason": "Second failed login burst detected"}' | jq .

# Add an activity note
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/activities \
  -H 'Content-Type: application/json' \
  -d '{
    "activity_type": "comment",
    "actor": "analyst@soc.local",
    "title": "Confirmed source IP is in GreyNoise malicious list"
  }' | jq .

# List activity timeline
curl -s http://localhost:8082/incidents/INC-2026-00001/activities | jq .

# Attach evidence
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/evidence \
  -H 'Content-Type: application/json' \
  -d '{
    "evidence_type": "log_excerpt",
    "title": "auth.log lines 1240-1280",
    "storage_path": "s3://soc-evidence/INC-2026-00001/auth.log",
    "storage_hash": "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "collected_at": "2026-04-20T12:00:00Z",
    "relevance_score": 92,
    "is_primary": true
  }' | jq .

# List evidence
curl -s http://localhost:8082/incidents/INC-2026-00001/evidence | jq .

# Resolve
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/resolve \
  -H 'Content-Type: application/json' \
  -d '{"resolved_by": "analyst@soc.local", "notes": "IP blocked at firewall. No further activity observed."}' | jq .

# Close
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/close \
  -H 'Content-Type: application/json' \
  -d '{"closed_by": "analyst@soc.local", "notes": "Verified resolved. Firewall rule in place."}' | jq .

# Archive
curl -s -X POST http://localhost:8082/incidents/INC-2026-00001/archive \
  -H 'Content-Type: application/json' \
  -d '{"archived_by": "analyst@soc.local", "reason": "30-day retention policy"}' | jq .
```

```python
class IncidentTicket(Base):
    __tablename__ = "incidents"
    
    id: int
    incident_id: str  # INC-2026-001
    status: str  # open, assigned, investigating, escalated, resolved, closed, archived
    priority: int  # 1-5, 1 = highest
    risk_tier: str  # low, medium, high, critical
    assigned_to: Optional[str]
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    sla_hours: int
    sla_breach: bool
    external_ticket_id: Optional[str]  # Jira issue key
    ml_predicted_severity: Optional[str]
    ml_false_positive_prob: Optional[int]  # 0-100
    ml_attack_pattern: Optional[str]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    affected_agent_ids: Optional[str]
```

**Frameworks:** SQLAlchemy ORM + PostgreSQL

**Status:** ✅ Implemented (April 2026)

**Timeline:** Q2 2026 (month 1–2)

---

#### Layer 1 Web UI: Incident Management CRUD Interface

**URL:** `http://localhost:8082/ui`

**Purpose:** A self-contained browser-based interface for SOC analysts to perform all incident lifecycle operations without requiring curl or direct API access. Served directly from the `phase4-api` FastAPI container — no additional service or container is needed.

**How it is served:**

The route `GET /ui` is registered in `src/wazuh_mcp_server/phase4/server.py`. It reads `src/wazuh_mcp_server/phase4/static/index.html` from disk (cached in memory after first load) and returns it as an `HTMLResponse`. Because the HTML page makes API calls to relative paths (e.g. `/incidents`, `/incidents/stats`), it works from any host/port the container is bound to with no CORS configuration required.

```python
@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
async def incident_ui():
    ui_path = Path(__file__).parent / "static" / "index.html"
    return HTMLResponse(content=ui_path.read_text(encoding="utf-8"))
```

**Implementation:** Single-file vanilla HTML + CSS + JavaScript (`static/index.html`, ~650 lines). No build step, no npm, no framework dependencies — the container image does not need to change when the UI is updated.

**UI Structure:**

| Area | Description |
|---|---|
| **Header** | Brand + Actor field (username pre-filled into all action modals) + Refresh + API Docs link |
| **Stats bar** | Live counts: Total / Open / SLA Breach / Critical / Unassigned (from `GET /incidents/stats`) |
| **Sidebar** | Incident list with status + risk-tier filters; relative timestamps; SLA breach dot indicator |
| **Detail panel** | Three tabs: Overview, Activities, Evidence |

**Detail Panel Tabs:**

| Tab | Content |
|---|---|
| **Overview** | All incident fields in a two-column grid: status, risk tier, priority, SLA status, assigned to, IPs, agent IDs, ML predictions, all timestamps, description |
| **Activities** | Chronological audit trail (newest first) with type, actor, title, description, and before/after values. Add Note button opens modal |
| **Evidence** | All attached artifacts with type, title, storage path, SHA-256 hash, relevance score, primary flag. Attach button opens modal |

**Action Buttons (context-aware by status):**

| Status | Available Actions |
|---|---|
| `open` | Assign, Escalate |
| `assigned` | Assign, Escalate, Resolve |
| `investigating` | Assign, Escalate, Resolve |
| `escalated` | Resolve |
| `resolved` | Close |
| `closed` | Archive |
| All except `archived` | + Note (add activity) |
| All | + Evidence (attach artifact) |

**Modals (all pre-fill the Actor field from the header):**

| Modal | Fields |
|---|---|
| Create Incident | Title\*, Risk Tier\*, Description, Source IP, Dest IP, Affected Agent IDs, Alert Count |
| Assign | Assign To\*, Actor\* |
| Escalate | Escalated By\*, Reason\* |
| Resolve | Resolved By\*, Resolution Notes |
| Close | Closed By\*, Closing Notes |
| Archive | Archived By\*, Reason |
| Add Activity | Type (comment/action/note/…)\*, Actor\*, Title\*, Description |
| Attach Evidence | Type\*, Collected At\*, Title\*, Description, Storage Path, SHA-256 Hash, Relevance Score, Primary flag |

**Build & deploy procedure:**

The UI is part of the `phase4-api` service. The `static/` directory is mounted into the container via the existing volume bind:

```yaml
volumes:
  - ./src/wazuh_mcp_server:/app  # includes phase4/static/index.html
```

No separate build step or container rebuild is required when only `index.html` is edited — changes take effect on the next browser request (the file is read from disk on first hit, then cached in the process). To force a reload after editing the HTML:

```bash
# Restart only the API container (fast — deps already installed)
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml \
  restart phase4-api

# Or do a full rebuild (required if server.py or other Python files changed)
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml \
  up -d --build phase4-api
```

After startup, verify the UI is reachable:

```bash
curl -s -o /dev/null -w '%{http_code}' http://localhost:8082/ui
# Expected: 200
```

Then open **http://localhost:8082/ui** in any browser.

**Files changed:**

| File | Change |
|---|---|
| `src/wazuh_mcp_server/phase4/static/index.html` | New file — self-contained HTML/CSS/JS UI |
| `src/wazuh_mcp_server/phase4/server.py` | Added `HTMLResponse` import; added `GET /ui` route; updated root `/` response to include `"ui": "/ui"` |

---

#### Layer 2: Case Management & Evidence (Neo4j + MinIO)

Build forensic timelines by linking:
- Alerts → files → processes → network connections → domains

```python
# Graph structure
ALERT --detected--> FILE --modified-by--> PROCESS --connects-to--> IP
     --contains--> USER --logon-from--> WORKSTATION
```

Use **Neo4j Cypher** to query: "Show all incidents involving this C2 domain"

**Frameworks:** Neo4j Community (graph) + MinIO (artifact storage)

**Status:** ✅ Implemented (April 2026)

**Timeline:** Q3 2026 (month 4–5)

---

##### Layer 2 Implementation Details

**Files:**

| File | Purpose |
|---|---|
| `src/wazuh_mcp_server/phase4/forensics/__init__.py` | `ForensicGraph` class — all Neo4j Cypher queries, node/relationship helpers, schema bootstrap |
| `src/wazuh_mcp_server/phase4/forensics/minio_client.py` | `ArtifactStore` class — MinIO upload/download/list/delete/presigned-URL |
| `src/wazuh_mcp_server/phase4/forensics/api.py` | FastAPI router factory `create_forensics_router(graph, store)` — all 14 HTTP endpoints |

**Graph schema (node labels and relationship types):**

```
NodeType:  ALERT | FILE | PROCESS | IP_ADDRESS | USER | WORKSTATION | DOMAIN
RelType:   DETECTED | MODIFIED_BY | SPAWNED_BY | CONNECTS_TO | LOGGED_IN_TO | RESOLVES_TO | INVOLVES
```

**API surface (`/cases/…`):**

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/cases/alerts` | Ingest alert node; auto-link src_ip / dest_ip / username |
| `POST` | `/cases/entities` | Merge entity node (IP, DOMAIN, USER, WORKSTATION, PROCESS, FILE) |
| `POST` | `/cases/relationships` | Create free-form relationship between two existing nodes |
| `GET`  | `/cases/{id}/timeline` | Chronological alert list + direct links for an incident |
| `GET`  | `/cases/{id}/graph` | Full subgraph (nodes + edges, up to 4 hops) for visualisation |
| `GET`  | `/cases/query/by-ip/{ip}` | "Which incidents touched this IP?" |
| `GET`  | `/cases/query/by-domain/{domain}` | "Show all incidents involving this C2 domain" |
| `GET`  | `/cases/query/by-user/{username}` | "Which incidents involve this user account?" |
| `GET`  | `/cases/query/lateral-movement` | Users logged into ≥ N distinct workstations |
| `GET`  | `/cases/query/attack-chain/{ip}` | Kill-chain path from a source IP (configurable hops) |
| `POST` | `/cases/{id}/artifacts` | Upload evidence file to MinIO (`multipart/form-data`) |
| `GET`  | `/cases/{id}/artifacts` | List all artifacts for an incident |
| `GET`  | `/cases/{id}/artifacts/{aid}/download-url` | Presigned download URL (configurable expiry) |
| `DELETE` | `/cases/{id}/artifacts/{aid}` | Delete artifact by MinIO object path |
| `GET`  | `/cases/health` | Neo4j + MinIO liveness check |

**Graceful degradation:** Every graph endpoint returns `HTTP 503` when Neo4j is unavailable; every artifact endpoint returns `HTTP 503` when MinIO is unavailable. The health endpoint always returns `HTTP 200` with per-service availability flags so monitoring works even during a database outage.

**MinIO object layout:** `{incident_id}/{artifact_id}/{filename}` — enables `list_objects(prefix="{incident_id}/")` per-incident scoping without a separate index.

---

##### Layer 2 Web UI: Forensic Case Investigation Interface

**URL:** `http://localhost:8082/cases/ui`

**Purpose:** A self-contained browser-based interface for SOC analysts to investigate forensic cases — query the Neo4j graph, visualise incident subgraphs as interactive D3 force-directed diagrams, walk event timelines, and browse all incidents from PostgreSQL. No build step or npm required; served directly from the `phase4-api` FastAPI container alongside the Layer 1 `/ui`.

**How it is served:**

The route `GET /cases/ui` is registered in `src/wazuh_mcp_server/phase4/server.py`. D3.js v7.8.5 is downloaded locally and served at `/static/d3.min.js` to avoid CDN SRI hash failures.

```python
@app.get("/cases/ui", response_class=HTMLResponse, include_in_schema=False)
async def forensics_ui():
    ui_path = Path(__file__).parent / "static" / "forensics.html"
    return HTMLResponse(content=ui_path.read_text(encoding="utf-8"))

@app.get("/static/d3.min.js", include_in_schema=False)
async def serve_d3():
    from fastapi.responses import FileResponse
    d3_path = Path(__file__).parent / "static" / "d3.min.js"
    return FileResponse(str(d3_path), media_type="application/javascript")
```

**Implementation:** Single-file vanilla HTML + CSS + JavaScript (`static/forensics.html`). All API calls use relative paths so the page works from any host/port.

**UI Structure:**

| Area | Description |
|---|---|
| **Header** | Brand + Neo4j health dot + MinIO health dot + API Docs link + Incident CRUD link |
| **Health dots** | Live liveness indicators polling `GET /cases/health` every 30 s |
| **Tab bar** | Four tabs: 🔎 Investigator Queries, 📅 Incident Timeline, 🕸️ Graph View, 📋 All Cases |

**Tab: 🔎 Investigator Queries**

Six query cards, each with an input and a Run button. Results render as enriched incident cards (fetched in parallel from `GET /incidents/{id}`) with risk tier badge, status badge, SLA breach tag, source IP, Timeline button, and **Open Manager →** link to `/ui?incident=ID`.

| Query Card | API Call | Result |
|---|---|---|
| C2 Domain Lookup | `GET /cases/query/by-domain/{domain}` | All incidents whose graph touches that domain |
| IP Pivot | `GET /cases/query/by-ip/{ip}` | All incidents linked to a source or dest IP |
| User Account | `GET /cases/query/by-user/{username}` | All incidents involving that user node |
| Lateral Movement | `GET /cases/query/lateral-movement?min_workstations=N` | Users logged into ≥ N distinct workstations |
| Attack Chain | `GET /cases/query/attack-chain/{ip}?max_hops=N` | Kill-chain path from a source IP |
| Quick Graph | — | Pre-fills Graph View tab and opens it |

**Tab: 📅 Incident Timeline**

Loads `GET /cases/{id}/timeline`. Renders a vertical timeline of alert events, each with a severity-coloured dot, timestamp, rule name, log excerpt, and node-type chips (ALERT, IP_ADDRESS, DOMAIN, …). Quick-pick suggestion chips appear below the input.

**Tab: 🕸️ Graph View**

Loads `GET /cases/{id}/graph`. Renders an interactive D3 v7 force-directed graph:

- **Nodes** coloured by type (ALERT=red, IP_ADDRESS=blue, DOMAIN=orange, USER=green, WORKSTATION=purple, PROCESS=yellow, FILE=grey)
- **Edges** labelled with relationship type (INVOLVES, CONNECTS_TO, RESOLVES_TO, …)
- **Interactions:** drag nodes, scroll to zoom, hover for tooltip showing all node properties
- **Click dark area** or click the empty-state overlay to trigger Visualize using the current input value
- Errors surface visibly in the overlay (no silent failures)

| Control | Behaviour |
|---|---|
| Input field | Pre-filled with `INC-FORENSIC-001`; Enter key triggers Visualize |
| Visualize button | Fetches graph data, renders D3 simulation |
| Reset Zoom | Restores `translate(0,0) scale(1)` via `d3.zoom` |
| Legend | Node-type colour reference |

**Tab: 📋 All Cases**

Loads `GET /incidents?limit=200` (PostgreSQL, not Neo4j). Renders a responsive card grid. Each card shows:

- Incident ID (monospace, clickable) + risk tier badge + status badge + SLA breach tag
- Title (truncated with hover tooltip)
- Source IP / Dest IP + creation timestamp
- Three action buttons: **📅 Timeline** (jumps to Timeline tab pre-filled + loads), **🕸️ Graph** (jumps to Graph tab pre-filled + loads), **Open Manager →** (`/ui?incident=ID` in new tab)

Toolbar has Status and Risk Tier dropdowns — changing either auto-reloads the grid.

**Files:**

| File | Purpose |
|---|---|
| `src/wazuh_mcp_server/phase4/static/forensics.html` | Self-contained HTML/CSS/JS forensics UI |
| `src/wazuh_mcp_server/phase4/static/d3.min.js` | Local copy of D3.js v7.8.5 (279,633 bytes) |
| `src/wazuh_mcp_server/phase4/server.py` | `GET /cases/ui` + `GET /static/d3.min.js` routes |

**Build & deploy:**

The `static/` directory is bind-mounted into the container (`./src/wazuh_mcp_server → /app`), so HTML edits are live immediately on the next browser request. Only `server.py` changes require a container restart.

```bash
# Restart only API (fast — deps already installed)
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml -f compose.phase4.yml \
  restart phase4-api

# Verify
curl -s -o /dev/null -w '%{http_code}' http://localhost:8082/cases/ui  # 200
curl -s -o /dev/null -w '%{http_code}' http://localhost:8082/static/d3.min.js  # 200
```

---

##### Layer 2 Test Suite

Regression tests run with:

```bash
python -m pytest tests/integration/test_layer2_forensics_api.py tests/integration/test_layer2_unit.py -v
# 78 passed in ~1.1 s (no Neo4j or MinIO required)
```

**Test architecture:**

- All Neo4j and MinIO calls are replaced with `unittest.mock.MagicMock` — tests run entirely in-process.
- HTTP tests build a throwaway `FastAPI()` app around `create_forensics_router(graph, store)` and exercise it via `fastapi.testclient.TestClient` — identical to the Phase 3 test pattern.
- Three fixture variants cover the full availability matrix: `client_with_backends` (both live), `client_no_backends` (both `None`), `client_graph_only` (store=`None` only).

---

###### File 1: `tests/integration/test_layer2_forensics_api.py` — HTTP-level (51 tests)

| Test class | Test name | What it asserts |
|---|---|---|
| `TestHealth` | `test_health_both_available` | Both backends mock `ping()=True` → `available=true, connected=true` for both services |
| | `test_health_both_unavailable` | `graph=None, store=None` → `available=false, connected=false` for both |
| | `test_health_graph_only` | `store=None` → neo4j available, minio not |
| `TestIngestAlert` | `test_missing_alert_id_returns_422` | Body without `alert_id` → 422 |
| | `test_missing_incident_id_returns_422` | Body without `incident_id` → 422 |
| | `test_ingest_minimal_success` | Only required fields → 201, `links_created=[]` |
| | `test_ingest_with_src_ip_creates_ip_link` | `src_ip` present → `merge_ip` + `link_alert_ip(role="src")` called, link in response |
| | `test_ingest_with_dest_ip_creates_dst_link` | `dest_ip` present → `link_alert_ip(role="dst")` called |
| | `test_ingest_with_username_creates_user_link` | `username` present → `merge_user` + `link_alert_user` called |
| | `test_ingest_all_optional_fields` | All optional fields sent → `links_created` has 3 entries (src, dst, user) |
| | `test_graph_unavailable_returns_503` | `graph=None` → 503 |
| `TestCreateEntity` | `test_unknown_node_type_returns_422` | `node_type="UNICORN"` → 422 |
| | `test_ip_address_entity` | `IP_ADDRESS` with `ip` field → 201, `node_type` in response |
| | `test_domain_entity` | `DOMAIN` with `name` field → 201 |
| | `test_user_entity` | `USER` with `username` field → 201 |
| | `test_workstation_entity` | `WORKSTATION` with `hostname` field → 201 |
| | `test_process_entity` | `PROCESS` with `pid_host`, `name`, `cmdline` → 201 |
| | `test_file_entity` | `FILE` with `path` field → 201 |
| | `test_ip_missing_required_key_returns_422` | `IP_ADDRESS` body missing `ip` key → 422 |
| | `test_graph_unavailable_returns_503` | `graph=None` → 503 |
| `TestCreateRelationship` | `test_success` | Valid body, `create_relationship` returns `True` → 201 |
| | `test_missing_rel_type_returns_422` | Body missing `rel_type` → 422 |
| | `test_missing_from_label_returns_422` | Body missing `from_label` → 422 |
| | `test_nodes_not_found_returns_404` | `create_relationship` returns `False` → 404 |
| | `test_graph_unavailable_returns_503` | `graph=None` → 503 |
| `TestTimeline` | `test_returns_events` | Returns `incident_id`, `count=1`, one-element `events` list |
| | `test_graph_unavailable_returns_503` | `graph=None` → 503 |
| | `test_graph_error_returns_500` | `get_incident_timeline` raises `RuntimeError` → 500 |
| `TestIncidentGraph` | `test_returns_nodes_and_edges` | Returns `node_count=1`, `edge_count=0` |
| | `test_graph_unavailable_returns_503` | `graph=None` → 503 |
| `TestQueryEndpoints` | `test_by_ip` | `find_incidents_by_ip` called, response has `ip`, `count`, `incident_ids` |
| | `test_by_domain` | `find_incidents_by_domain` called, `domain` and `count` in response |
| | `test_by_user` | `find_incidents_by_user` called, `username` and `count` in response |
| | `test_lateral_movement_default` | `detect_lateral_movement(2)` called, `count=1`, candidates list returned |
| | `test_lateral_movement_min_workstations_param_forwarded` | `?min_workstations=3` → `detect_lateral_movement(3)` called |
| | `test_attack_chain` | `get_attack_chain` called, `source_ip` and `path_count` in response |
| | `test_attack_chain_max_hops_param_forwarded` | `?max_hops=7` → `get_attack_chain("1.2.3.4", 7)` called |
| | `test_all_query_endpoints_return_503_when_no_graph` | All 5 query paths return 503 when `graph=None` |
| `TestArtifactUpload` | `test_upload_success` | Multipart POST → 201, `artifact_id` and `filename` in body |
| | `test_upload_empty_file_returns_422` | Zero-byte file → 422 |
| | `test_upload_with_description` | `description` form field → metadata passed to `store.upload` as `x-description` |
| | `test_store_unavailable_returns_503` | `store=None` → 503 |
| | `test_store_error_returns_500` | `store.upload` raises → 500 |
| `TestArtifactList` | `test_list_returns_artifacts` | Returns `incident_id`, `count=1`, artifacts list with `filename` |
| | `test_store_unavailable_returns_503` | `store=None` → 503 |
| `TestArtifactDownloadUrl` | `test_download_url_returned` | Returns `url`, `artifact_id`, `expires_in=3600` |
| | `test_custom_expires_forwarded` | `?expires=7200` → `get_download_url(..., expires_seconds=7200)` called |
| | `test_store_unavailable_returns_503` | `store=None` → 503 |
| `TestArtifactDelete` | `test_delete_success` | Returns `status="deleted"`, `artifact_id` in body |
| | `test_missing_object_name_returns_422` | No `?object_name` query param → 422 |
| | `test_store_error_returns_500` | `store.delete` raises → 500 |
| | `test_store_unavailable_returns_503` | `store=None` → 503 |

---

###### File 2: `tests/integration/test_layer2_unit.py` — Unit-level (27 tests)

| Test class | Test name | What it asserts |
|---|---|---|
| `TestForensicGraphImportGuard` | `test_raises_when_neo4j_unavailable` | `_NEO4J_AVAILABLE=False` → `RuntimeError("neo4j driver is not installed")` on construction |
| `TestForensicGraphPing` | `test_ping_returns_true_when_session_runs` | Driver session succeeds → `ping()` returns `True` |
| | `test_ping_returns_false_on_exception` | `driver.session()` raises → `ping()` returns `False` (no exception propagation) |
| `TestForensicGraphMergeAlert` | `test_merge_alert_returns_node_dict` | Mocked session returns record → `merge_alert()` returns a `dict` and calls `session.run` |
| `TestForensicGraphNodeTypesAndRelTypes` | `test_node_type_constants` | All seven `NodeType.*` constants have correct string values |
| | `test_rel_type_constants` | All seven `RelType.*` constants have correct string values |
| `TestForensicCaseManagerAlias` | `test_alias_exists` | `ForensicCaseManagerAlias is ForensicGraph` (backwards-compat alias intact) |
| `TestArtifactStoreImportGuard` | `test_raises_when_minio_unavailable` | `_MINIO_AVAILABLE=False` → `RuntimeError("minio package is not installed")` on construction |
| `TestArtifactStoreObjectName` | `test_object_name_format` | `_object_name("INC-001", "art-123", "auth.log")` == `"INC-001/art-123/auth.log"` |
| | `test_object_name_preserves_subpath_in_filename` | Filename with subdirectory retains full path after the artifact-ID segment |
| `TestArtifactStorePing` | `test_ping_returns_true_when_bucket_exists` | `bucket_exists()` succeeds → `ping()` returns `True` |
| | `test_ping_returns_false_on_connection_error` | `bucket_exists()` raises → `ping()` returns `False` |
| `TestArtifactStoreUpload` | `test_upload_returns_required_keys` | Return dict contains all seven expected keys: `artifact_id`, `object_name`, `filename`, `size_bytes`, `content_type`, `incident_id`, `bucket` |
| | `test_upload_size_bytes_matches_data` | 1024-byte payload → `size_bytes == 1024` |
| | `test_upload_object_name_contains_incident_id` | Object name starts with `{incident_id}/` |
| | `test_upload_object_name_ends_with_filename` | Object name ends with `/{filename}` |
| | `test_upload_generates_unique_artifact_ids` | Two uploads of same file → different `artifact_id` values (UUID-based) |
| | `test_upload_passes_metadata_to_put_object` | `metadata={"x-description":…}` forwarded to `Minio.put_object(metadata=…)` |
| | `test_upload_calls_put_object_with_bytesio` | Data argument to `put_object` is a file-like object (has `.read` method) |
| `TestArtifactStoreListArtifacts` | `test_list_parses_object_names_correctly` | Object name `INC-001/art-uuid-001/auth.log` → `artifact_id="art-uuid-001"`, `filename="auth.log"`, `size_bytes=512` |
| | `test_list_passes_correct_prefix` | `list_artifacts("INC-007")` → `list_objects(prefix="INC-007/", recursive=True)` |
| `TestArtifactStoreDelete` | `test_delete_calls_remove_object` | `delete(object_name)` → `Minio.remove_object(FORENSIC_BUCKET, object_name)` called exactly once |
| `TestArtifactStoreGetDownloadUrl` | `test_presigned_url_calls_minio` | `get_download_url(name, expires_seconds=7200)` → `presigned_get_object(bucket, name, expires=timedelta(seconds=7200))` |
| `TestExtrasHelper` | `test_strips_node_type_and_excludes` | `_extras(body, exclude=("ip",))` removes `node_type` and `ip`, keeps other keys |
| | `test_empty_body_returns_empty` | Empty dict in → empty dict out |
| | `test_none_values_excluded` | Keys with `None` values are stripped from the extras dict |

---

#### Layer 3: Workflow Orchestration (Prefect → Airflow)

Move from hardcoded Phase 3 actions to **playbooks** defined in YAML.

```yaml
playbook: ransomware_response
triggers:
  - severity >= 8
    AND (rule_id in [ransomware_rules])
steps:
  - parallel:
    - isolate_host: { agent_id: $source_agent }
    - block_ip: { src_ip: $source_ip }
  - wait: 60
  - verify_all
  - notify_soc
  - create_ticket
```

**Frameworks:** 
- **Prefect** (lightweight, fast iteration) → Phase 4 Q3
- **Apache Airflow** (enterprise, if volume > 20 playbooks) → Phase 4 Q4 upgrade

**Timeline:** Q3 2026 (month 5–6)

---

#### Layer 4: Event Queue (Celery + RabbitMQ)

Scale incident responses without overload.

```python
from celery import Celery

app = Celery('phase3', broker='amqp://guest:guest@rabbitmq:5672//')

@app.task(bind=True, retry_limit=3)
def execute_phase3_workflow(self, incident_id, request_json):
    # Retry on failure, exponential backoff
    try:
        return run_phase3(incident_id, request_json)
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
```

**Frameworks:** Celery + RabbitMQ

**Timeline:** Q3 2026 (month 4–5)

---

#### Layer 5: Analytics & BI (DuckDB + Plotly Dash + Grafana)

Three separate needs:

| Need | Framework | Query Type |
|---|---|---|
| **Real-time SLA metrics** | Prometheus + Grafana | Time-series, alerts |
| **Incident dashboards** | Plotly Dash | Ad-hoc, interactive |
| **Executive reports** | DuckDB + Jinja2 | Batch queries |

```python
# Incident dashboard (Plotly Dash)
fig = dcc.Graph(
    figure=px.bar(
        incident_df.groupby('status').size(),
        title="Incidents by Status"
    )
)

# SLA metrics (Prometheus)
sla_breach_rate = Counter('incident_sla_breaches', 'Count of SLA breaches')
mttd = Histogram('mean_time_to_detect_seconds', 'MTTD in seconds')
```

**Frameworks:** DuckDB (analytics DB) + Plotly Dash (UI) + Grafana (metrics)

**Timeline:** Q4 2026 (month 7–9)

---

#### Layer 6: Threat Intelligence (APScheduler + requests)

Periodic sync from public feeds.

```python
from apscheduler.schedulers.background import BackgroundScheduler

scheduler = BackgroundScheduler()

@scheduler.scheduled_job('interval', hours=4)
def sync_threat_intel():
    """Fetch GreyNoise IPs, abuse.ch hashes, MISP events"""
    greynoise_ips = fetch_greynoise()
    abuse_ch_hashes = fetch_abuse_ch()
    misp_events = fetch_misp()
    
    insert_into_db(greynoise_ips, abuse_ch_hashes, misp_events)

scheduler.start()
```

**Frameworks:** APScheduler (Phase 4 start) → Airflow TI DAGs (if 5+ sources)

**Timeline:** Q4 2026 (month 7–8)

---

#### Layer 7: ML & Anomaly Detection (Scikit-learn + XGBoost + MLflow)

##### 7.1 Problem Statement

**Current limitations:**
- Phase 3 uses hardcoded risk_tier (low/medium/high/critical) without data-driven validation
- No way to detect if an alert is a false positive before executing AR actions
- Analyst workload grows linearly with alert volume; no prioritization
- No detection of unusual patterns (e.g., 1000 failed SSH logins in 5 minutes = brute force, not anomaly)

**ML Objectives:**
1. **Severity Prediction:** Predict true incident severity from alert features → tune approval gates
2. **False-Positive Filtering:** Detect likely noise before incident creation
3. **Attack Pattern Detection:** Recognize coordinated campaigns vs. isolated noise
4. **Analyst Workload Optimization:** Rank incidents by action-worthiness

---

##### 7.2 Use Cases & Business Impact

| Use Case | Input | Output | Business Impact |
|---|---|---|---|
| **Severity Ranking** | alert_level, rule_id, source_ip_reputation, target_user_privileges | predicted_severity (0.0–1.0) | Prioritize critical alerts; reduce alert fatigue |
| **False-Positive Filter** | alert_text, source_ip_geolocation, user_role, historical_frequency | is_likely_fp (True/False, prob 0.0–1.0) | 30–50% reduction in low-value incident tickets |
| **Attack Pattern Recognition** | alert_cluster (10 related alerts), time_window (30 min), src_ip_uniqueness | attack_type ("brute_force", "port_scan", "lateral_movement", "exfiltration") | Auto-apply targeted response playbooks |
| **Anomaly Detection (SIEM Activity)** | hourly_alert_count, daily_unique_src_ips, variance in rule distribution | anomaly_score (0.0–1.0), baseline_alert_count | Detect SOC attacks or insider threats targeting Wazuh itself |

---

##### 7.3 Data Pipeline & Feature Engineering

**Data Sources:**
```
Wazuh Indexer (Elasticsearch)
    ↓
Extract 60-day rolling window of:
  - Alert details: rule_id, severity, agent_id, src_ip, dest_ip, user_id, process_id
  - Rule metadata: rule_category, rule_group, rule_description
  - Post-incident analyst labeling: false_positive_label, actual_severity, action_taken
    ↓
Feature Engineering (Pandas + Numpy)
    ↓
Feature Store (DuckDB)
    ↓
Train/Validation Split (80/10/10)
    ↓
Model Training (Scikit-learn + XGBoost)
```

**Feature Set (45 features total):**

| Category | Features | Example |
|---|---|---|
| **Alert Properties** | rule_severity, rule_category, alert_text_length, contains_executable | severity=5, category="malware", keywords_matched=3 |
| **Context Enrichment** | source_ip_reputation (GreyNoise), dest_user_privilege_level, target_is_critical_asset | src_ip_score=85, user_role="admin", critical_server=True |
| **Temporal** | hour_of_day_utc, day_of_week, alert_frequency_per_hour (source_ip), time_since_last_alert (agent) | hour=23, freq=2_alerts_per_min, last_alert=5min_ago |
| **Historical** | source_ip_incident_history, agent_alert_count_7day, rule_false_positive_rate | ip_history=5_past_incidents, agent_volume=200_alerts, fp_rate=0.15 |
| **Statistical** | z_score_of_volume (vs. baseline), entropy_of_rule_id_distribution, geographic_anomaly | zscore=3.2, entropy=4.5, geo_anomaly=True |

**Feature Engineering Pseudocode:**

```python
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from datetime import datetime, timedelta

def engineer_features(alert_row, historical_db, reputation_api):
    """Build feature vector from single alert + context"""
    
    features = {}
    
    # Alert properties
    features['rule_severity'] = alert_row['severity']
    features['rule_category'] = encode_category(alert_row['rule_id'])
    features['alert_text_tokens'] = len(alert_row['full_log'].split())
    
    # Context enrichment
    src_ip = alert_row['src_ip']
    features['src_ip_reputation'] = reputation_api.query(src_ip).score  # GreyNoise
    features['dest_user_privilege'] = historical_db.get_user_privilege(alert_row['user'])
    features['target_is_critical'] = is_critical_asset(alert_row['dest_ip'])
    
    # Temporal
    now = datetime.now()
    features['hour_of_day_utc'] = now.hour
    features['day_of_week'] = now.weekday()
    
    # Historical
    features['src_ip_incident_count_30d'] = historical_db.count_incidents(src_ip, days=30)
    features['agent_alert_count_7d'] = historical_db.count_alerts(
        agent_id=alert_row['agent_id'], days=7
    )
    features['rule_fp_rate'] = historical_db.get_fp_rate(alert_row['rule_id'])
    
    # Statistical
    hourly_baseline = historical_db.get_hourly_baseline(
        alert_row['rule_id'], 
        hour=now.hour
    )
    current_rate = historical_db.count_alerts_this_hour(alert_row['rule_id'])
    features['zscore_volume'] = (current_rate - hourly_baseline.mean) / (hourly_baseline.std + 1e-5)
    
    return features
```

---

##### 7.4 Model Architecture

**Three complementary models:**

**Model A: Severity Predictor (XGBoost Classification)**
- **Input:** 45 features (see table above)
- **Output:** Multi-class probability (low, medium, high, critical)
- **Algorithm:** XGBClassifier with 5-fold cross-validation
- **Config:**
  ```python
  XGBClassifier(
      n_estimators=100,
      max_depth=6,
      learning_rate=0.1,
      subsample=0.8,
      colsample_bytree=0.8,
      random_state=42,
      scale_pos_weight=2,  # weight critical/high more
      class_weight='balanced'
  )
  ```
- **Training:** 60 days of historical alerts + analyst labels
- **Performance Target:** 82% F1-score on validation set (macro-average)

**Model B: False-Positive Detector (Random Forest Classifier)**
- **Input:** 35 features (subset of A, focused on alert characteristics)
- **Output:** Binary (is_false_positive: True/False)
- **Algorithm:** RandomForestClassifier (interpretable, fast inference)
- **Config:**
  ```python
  RandomForestClassifier(
      n_estimators=50,
      max_depth=8,
      min_samples_split=10,
      min_samples_leaf=5,
      random_state=42
  )
  ```
- **Training:** Alerts labeled by analysts as "false positive" vs. "true positive"
- **Performance Target:** 75% precision on validation (minimize false positives from classifier)
- **Use:** Pre-filter alerts before incident creation

**Model C: Attack Pattern Classifier (XGBoost Multi-class)**
- **Input:** Aggregated alert cluster (10–50 related alerts), temporal window
- **Output:** Attack type (brute_force, port_scan, lateral_movement, exfiltration, policy_violation, other)
- **Algorithm:** XGBClassifier trained on MITRE ATT&CK mapped rules
- **Training:** 30-day rolling window of alert clusters
- **Performance Target:** 80% accuracy
- **Use:** Auto-select response playbook

---

##### 7.5 Training & Validation Pipeline

**Data Preparation (Weekly, automated via Airflow DAG):**

```python
# Weekly retraining pipeline
import mlflow
from sklearn.model_selection import train_test_split, cross_val_score
from xgboost import XGBClassifier
import pickle

@scheduler.scheduled_job('cron', day_of_week='sun', hour=2)
def weekly_retrain_models():
    """Sunday 02:00 UTC: Pull fresh data, retrain models, promote to production if better"""
    
    # 1. Extract last 60 days of alerts + analyst labels
    raw_data = query_wazuh_indexer(
        start_time=datetime.now() - timedelta(days=60),
        end_time=datetime.now(),
        filter="analyst_label IS NOT NULL"
    )
    
    # 2. Engineer features for each alert
    features_df = parallel_engineer_features(raw_data, n_workers=8)
    
    # 3. Split data (80/10/10 train/val/test)
    X_train, X_temp, y_train, y_temp = train_test_split(
        features_df.drop('label', axis=1),
        features_df['label'],
        test_size=0.2,
        stratify=features_df['label']
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.5, stratify=y_temp
    )
    
    # 4. Train models with MLflow tracking
    with mlflow.start_run(run_name=f"severity_model_week_{week_number}"):
        model = XGBClassifier(n_estimators=100, max_depth=6)
        model.fit(X_train, y_train)
        
        # Cross-validation on train
        cv_scores = cross_val_score(model, X_train, y_train, cv=5)
        
        # Validation metrics
        val_score = model.score(X_val, y_val)
        test_score = model.score(X_test, y_test)
        
        # Log metrics
        mlflow.log_metric("cv_mean_f1", cv_scores.mean())
        mlflow.log_metric("validation_f1", val_score)
        mlflow.log_metric("test_f1", test_score)
        mlflow.sklearn.log_model(model, "model")
        
        # Promote to production if better than current
        current_prod_f1 = get_current_prod_metric("validation_f1")
        if val_score > current_prod_f1 * 1.02:  # 2% improvement threshold
            mlflow.register_model(
                model_uri=f"runs:/{mlflow.active_run().info.run_id}/model",
                name="severity_predictor"
            )
            promote_to_production("severity_predictor")
            notify_team(f"New model promoted. F1: {val_score:.3f} (+{(val_score - current_prod_f1)*100:.1f}%)")
        
    return metrics
```

---

##### 7.6 Integration with Phase 3 Workflow

**Modified node proposal logic:**

```python
async def node_propose_action_v2(state: Phase3State) -> Phase3State:
    """
    Enhanced proposal: use ML to confirm/override risk_tier
    """
    req = state["request"]
    enrichment = state["enrichment"]  # Now consumed!
    
    # 1. Get hardcoded action plan (fallback)
    plan = _build_action_plan(req["use_case"])
    
    # 2. Check if alert looks like false positive
    fp_probability = ml_severity_model.predict_proba(
        engineer_alert_features(enrichment)
    )[1]  # Class 1 = false positive
    
    if fp_probability > 0.80:
        state["proposed_action"] = {
            "tool": "analyst_review_required",
            "reason": f"ML detected likely false positive ({fp_probability:.0%} confidence)",
            "recommended_action": plan["tool"],
            "ml_confidence": fp_probability
        }
        return state
    
    # 3. Predict true severity (may override user's risk_tier)
    predicted_severity_probs = ml_severity_model.predict_proba(
        engineer_alert_features(enrichment)
    )
    predicted_risk_tier = ["low", "medium", "high", "critical"][
        np.argmax(predicted_severity_probs)
    ]
    
    # 4. If ML predicts higher severity, tighten approvals
    original_risk = req["risk_tier"]
    severity_escalation_factor = SEVERITY_RANK.get(predicted_risk_tier, 0) / SEVERITY_RANK.get(original_risk, 1)
    
    if severity_escalation_factor > 1.2:
        state["approvals_needed"] *= 2
        state["approval_reason"] = f"ML predicts {predicted_risk_tier} (user said {original_risk})"
    
    # 5. Use pattern detector to suggest playbook
    attack_pattern = ml_pattern_detector.predict([
        enrichment["cluster_of_10_related_alerts"]
    ])[0]
    
    # 6. Proposed action with ML confidence
    state["proposed_action"] = {
        **plan,
        "ml_predicted_severity": predicted_risk_tier,
        "ml_attack_pattern": attack_pattern,
        "ml_false_positive_prob": fp_probability,
        "approvals_needed": state["approvals_needed"]
    }
    
    return state
```

**Phase 3 response with ML context:**

```json
{
  "stage": "proposal",
  "proposed_action": "isolate_host",
  "risk_tier": "critical",
  "approvals_needed": 2,
  "ml_context": {
    "predicted_severity": "critical",
    "severity_confidence": 0.91,
    "false_positive_probability": 0.04,
    "attack_pattern": "lateral_movement",
    "feature_importance": {
      "source_ip_reputation": 0.34,
      "rule_category": 0.18,
      "user_privilege_level": 0.15,
      "historical_incidents": 0.12,
      "geolocation_anomaly": 0.11
    }
  }
}
```

---

##### 7.7 Deployment & Monitoring Strategy

**Canary Deployment (First 4 weeks Q4 2026):**

```
Production Traffic  → 90% current (hardcoded) + 10% ML (shadow mode)
                    → Collect predictions, compare to outcomes
                    → Week 1–2: 90/10
                    → Week 3: 80/20
                    → Week 4: 50/50, prepare rollback if < 95% agreement
```

**Shadow Mode Metrics:**

```python
# Compare ML prediction vs. analyst ground truth (after incident closed)

def evaluate_shadow_predictions():
    shadow_preds = query_ml_predictions_from_shadow_mode(last_week=True)
    analyst_labels = query_incident_analyst_labels(last_week=True)
    
    metrics = {
        "accuracy": accuracy_score(analyst_labels, shadow_preds),
        "precision": precision_score(analyst_labels, shadow_preds),
        "recall": recall_score(analyst_labels, shadow_preds),
        "f1": f1_score(analyst_labels, shadow_preds),
        "auc_roc": roc_auc_score(analyst_labels, shadow_pred_proba),
    }
    
    # Alert if metrics drop below thresholds
    if metrics["f1"] < 0.80:
        alert_team("ML F1 dropped below 80%", metrics)
        trigger_model_investigation()
```

**Production Monitoring (Post-promotion):**

```python
@scheduler.scheduled_job('interval', hours=6)
def monitor_ml_performance():
    """Monitor model drift and data quality"""
    
    # 1. Feature drift detection
    current_feature_stats = compute_stats()
    baseline_feature_stats = load_baseline_from_training()
    
    feature_drift = detect_drift(current_feature_stats, baseline_feature_stats)
    if feature_drift.detected:
        alert_team(f"Feature drift detected: {feature_drift.features}")
    
    # 2. Prediction drift (are model outputs changing?)
    current_pred_dist = query_predictions_last_24h().distribution()
    baseline_pred_dist = query_predictions_baseline_month().distribution()
    
    kl_divergence = scipy.stats.entropy(current_pred_dist, baseline_pred_dist)
    if kl_divergence > 0.5:
        alert_team(f"High prediction drift (KL={kl_divergence:.2f})")
    
    # 3. Analyst override rate (are analysts rejecting model decisions?)
    override_rate = query_analyst_overrides_last_24h().count() / query_total_incidents().count()
    if override_rate > 0.15:
        alert_team(f"Override rate high ({override_rate:.0%}), model may be degraded")
    
    # 4. Actionable incident rate (are we proposing the right actions?)
    actionable_rate = query_incidents_with_actions_taken_last_24h().count() / query_total_incidents().count()
    
    log_metrics({
        "feature_drift_score": max(feature_drift.scores.values()),
        "prediction_kl_divergence": kl_divergence,
        "analyst_override_rate": override_rate,
        "actionable_incident_rate": actionable_rate
    })
```

---

##### 7.8 Expected Business Impact

| Metric | Current | With ML (6 months in) | Improvement |
|---|---|---|---|
| **Alert Fatigue** | 2000 alerts/day → 200 incidents | 2000 alerts/day → 100 incidents | 50% reduction |
| **MTTD (Mean Time to Detect)** | 15 min (analyst resume) | 3 min (auto-flagged by severity model) | 80% faster |
| **False-Positive Noise** | 20% of tickets | 5% of tickets | 75% cleaner |
| **Unauthorized AR Success** | N/A (hardcoded only) | 94% (ML confidence: planned action == best action) | — |
| **SLA Compliance** | 60% P1 < 1hr | 88% P1 < 1hr | 47% more compliant |
| **Analyst Productivity** | 40 tickets/analyst/day | 65 tickets/analyst/day | 62.5% increase |

---

##### 7.9 Challenges & Mitigation

| Challenge | Impact | Mitigation |
|---|---|---|
| **Label scarcity** | Need analyst labels for training; cold start problem | Start with rule-based heuristics + weak supervision; collect labels incrementally |
| **Model drift** | New attack types not in training set; models degrade over time | Weekly retraining pipeline; drift detection alerts; human-in-loop review |
| **Class imbalance** | "Critical" incidents rare vs. "low"; model biased toward majority | Weighted loss functions; SMOTE oversampling; stratified train/val splits |
| **Latency** | Feature engineering takes time; must complete before decision | Pre-compute features async; use cached reputation scores; fallback to defaults if slow |
| **Explainability** | Analysts don't trust or understand model decisions | SHAP values + feature importance; audit logs showing top contributing features |
| **Data quality** | Missing values, duplicates, inconsistent enrichment | Validation layer on ingestion; alert on anomalies; versioned dataset snapshots |
| **Integration complexity** | Phase 3 workflow changes need careful testing | Gradual canary rollout; shadow mode for 4 weeks; rollback automation |

---

##### 7.10 Roadmap: Q4 2026 → Q1 2027

| Phase | Timeline | Deliverable | Effort |
|---|---|---|---|
| **POC** | Weeks 1–2 (Q4) | Train Severity Model on synthetic data; validate F1 ≥ 75% | 1 week |
| **Pilot (Shadow)** | Weeks 3–6 (Q4) | Deploy to production in shadow mode; collect 4 weeks of comparison data | 1.5 weeks |
| **Production (Canary)** | Weeks 7–10 (Q4) | 10% → 50% traffic; promote if metrics stable | 1 week |
| **Full Rollout** | Weeks 11–13 (Q4) | 100% traffic; retrain with new labels weekly | 0.5 week |
| **Extensions** | Q1 2027 | Add False-Positive Detector + Pattern recognition; MLflow versioning | 3 weeks |

**Total Phase 4 ML Effort:** 7 weeks (1.5 months)

---

##### 7.11 Alternative Approaches (Not Recommended)

| Alternative | Pros | Cons | Decision |
|---|---|---|---|
| **Zero ML** | Simple, no model maintenance | Miss 50% false positives; poor severity ranking | ❌ |
| **LlamaIndex + GPT-4** | State-of-the-art; semantic understanding | $$ API costs (5¢ per alert × 2000/day = $3k/month); latency; hallucinations | ❌ |
| **AutoML (H2O, AutoGluon)** | Hands-off training; best model selection | Overkill for this problem; hard to debug | ❌ |
| **Scikit-learn + XGBoost** ✅ | Lightweight; mature; explainable; low cost | No deep learning; manual feature engineering | ✅ RECOMMENDED |
| **PyTorch + LSTM** | State-of-the-art; temporal awareness | Requires GPU; hard to interpret; overkill | ❌ |

**Frameworks:** Scikit-learn + XGBoost (models) + MLflow (experiment tracking) + DuckDB (feature store)

**Timeline:** Q4 2026 (month 8–9); full integration Q1 2027

---

##### 7.12 Phase 3 Mapping: Graph Correlation + LlamaIndex

This pattern keeps detection and action selection deterministic while using LlamaIndex only for contextual enrichment.

**Node-by-node implementation (existing Phase 3 flow):**

1. `node_triage`
- Build a correlation bundle from Wazuh events in the selected time window.
- Compute deterministic correlation score from host spread, privileged activity, and event density.

```python
triage = {
        "event_clusters": [
                {
                        "src_ip": "185.10.10.9",
                        "host_count": 3,
                        "failed_auth_count": 27,
                        "privileged_activity": True,
                }
        ],
        "correlation_score": 87,
        "top_rules": ["5710", "5763"],
}
```

2. `node_enrichment`
- Enrich with external reputation and historical incidents.
- Query LlamaIndex for similar incidents and runbook snippets.

```python
enrichment = {
        "source_ip_reputation": 92,
        "asset_criticality": "domain_controller",
        "llamaindex_context": {
                "similar_incidents": ["INC-7312", "INC-7198"],
                "related_runbooks": ["RB-22 Credential Abuse"],
                "confidence": 0.81,
        },
}
```

3. `node_propose_action`
- Keep current action map as baseline (`use_case` -> tool/verify/rollback).
- Use deterministic score to tighten approvals.
- Use LlamaIndex context as advisory text, not as action authority.

```python
def decide_approvals(risk_tier: str, correlation_score: int, llm_confidence: float) -> int:
        approvals = 2 if risk_tier in {"high", "critical"} else 1
        if correlation_score >= 80:
                approvals = max(approvals, 2)
        if llm_confidence < 0.60:
                approvals = max(approvals, 2)
        return approvals
```

4. `node_approval_gate`
- Require dual approval for critical incidents or high correlation score.
- Persist both evidence tracks:
    - deterministic evidence: score + matched conditions
    - semantic evidence: similar incidents + runbook hints

5. `node_execute_action` -> `node_verify_action` -> `node_rollback_action`
- Execute only approved deterministic tool plan.
- Verify outcome from Wazuh evidence (not LlamaIndex).
- Roll back on failed verification.

**Example Phase 3 state contract:**

```json
{
    "request": {
        "incident_id": "INC-2026-0418-01",
        "use_case": "isolate_host",
        "risk_tier": "high",
        "time_range": "15m",
        "query": "failed logins + admin privilege changes",
        "action_args": {"agent_id": "003"}
    },
    "triage": {
        "correlation_score": 87,
        "event_clusters": [
            {"src_ip": "185.10.10.9", "host_count": 3, "privileged_activity": true}
        ]
    },
    "enrichment": {
        "source_ip_reputation": 92,
        "llamaindex_context": {
            "similar_incidents": ["INC-7312"],
            "related_runbooks": ["RB-22 Credential Abuse"],
            "confidence": 0.81
        }
    },
    "proposed_action": {
        "tool": "wazuh_isolate_host",
        "verify_tool": "wazuh_check_agent_isolation",
        "rollback_tool": "wazuh_unisolate_host",
        "approvals_needed": 2,
        "decision_basis": {
            "deterministic": "high correlation score + privileged activity",
            "semantic_enrichment": "similar incidents recommend immediate containment"
        }
    }
}
```

**Decision policy recommendation:**
- Deterministic correlation decides whether response is allowed.
- LlamaIndex improves analyst context and speed.
- Verification and rollback remain deterministic and auditable.

---

##### 7.13 Implementation Checklist (Phase 3)

Use this checklist to implement Section 7.12 with minimal risk and clear acceptance criteria.

**A) Schema and state updates**
- Add to `triage` state:
    - `event_clusters`
    - `correlation_score`
    - `correlation_reasons`
- Add to `enrichment` state:
    - `source_ip_reputation`
    - `asset_criticality`
    - `llamaindex_context` with `similar_incidents`, `related_runbooks`, `confidence`
- Add to `proposed_action` state:
    - `decision_basis.deterministic`
    - `decision_basis.semantic_enrichment`
    - `approvals_needed`

**B) Node-level implementation tasks**
- `node_triage`:
    - build deterministic cluster summary from Wazuh query results
    - compute `correlation_score` (0-100)
    - persist why score was assigned (`correlation_reasons`)
- `node_enrichment`:
    - call reputation and asset metadata helpers
    - call LlamaIndex retrieval for similar incidents/runbooks
    - fail open: if LlamaIndex is unavailable, continue with deterministic path
- `node_propose_action`:
    - keep current `use_case` mapping as baseline
    - apply approval rule using `risk_tier`, `correlation_score`, `llamaindex_context.confidence`
    - include explicit explanation in `decision_basis`
- `node_approval_gate`:
    - enforce dual approval for `correlation_score >= 80`
    - log deterministic and semantic evidence separately
- `node_verify_action`/`node_rollback_action`:
    - unchanged authority model (Wazuh evidence decides pass/fail)

**C) Logging and audit fields (required)**
- `incident_id`
- `use_case`
- `correlation_score`
- `approvals_needed`
- `llamaindex_confidence`
- `decision_basis.deterministic`
- `decision_basis.semantic_enrichment`
- `approved_by` (or `auto_approved`)
- `verify_status` and `rollback_status`

**D) Safety guardrails**
- Never allow LlamaIndex output to directly select a tool without deterministic rule support.
- If `llamaindex_context.confidence < 0.60`, require analyst approval.
- If enrichment lookup exceeds timeout (for example 2s), continue with deterministic-only mode.
- Keep rollback plan deterministic and pre-declared per `use_case`.

**E) Testing checklist**
- Unit tests:
    - score calculation edge cases (0, threshold 80, 100)
    - approval rule behavior for low/high/critical
    - LlamaIndex unavailable timeout path
- Integration tests:
    - full run with deterministic-only mode
    - full run with deterministic + LlamaIndex enrichment
    - verify/rollback behavior unchanged
- Regression tests:
    - existing `medium-block`, `high-isolate`, `critical-rollback` scenarios still pass

**F) Acceptance criteria**
- `node_propose_action` still produces valid plan when LlamaIndex is down.
- High correlation incidents (`score >= 80`) always require dual approval.
- Audit logs include both deterministic and semantic evidence fields.
- Existing Phase 3 scenarios remain behaviorally compatible.
- P95 latency increase from enrichment is <= 15% vs baseline.

---

##### 7.14 Engineering Task Map (Files and Functions)

This converts Section 7.13 into concrete implementation tasks mapped to current repository files.

| Task ID | Task | Primary File | Function(s) | Expected Output |
|---|---|---|---|---|
| P3-01 | Extend Phase 3 state schema for correlation and retrieval context | `services/phase3_langgraph/app/main.py` | `Phase3State`, `RunPhase3Response` | `triage.correlation_score`, `triage.correlation_reasons`, `enrichment.llamaindex_context`, `proposed_action.decision_basis` included in response |
| P3-02 | Add deterministic correlation computation in triage stage | `services/phase3_langgraph/app/main.py` | `node_triage` | Node computes and stores score/reasons from cluster indicators |
| P3-03 | Add optional semantic enrichment retrieval step | `services/phase3_langgraph/app/main.py` | `node_enrichment` | `llamaindex_context` populated on success; deterministic fallback on timeout/error |
| P3-04 | Hybrid approval logic using risk + correlation + retrieval confidence | `services/phase3_langgraph/app/main.py` | `node_propose_action`, `node_approval_gate` | `approvals_needed` elevated when `correlation_score >= 80` or low retrieval confidence |
| P3-05 | Preserve deterministic execution/verify/rollback authority | `services/phase3_langgraph/app/main.py` | `node_execute_action`, `node_verify_action`, `node_rollback_action` | No behavior regression in write-path safety |
| P3-06 | Add structured audit events for decision basis | `services/phase3_langgraph/app/main.py` | `_append_step` call sites in approval/execute/verify | Step trail includes deterministic vs semantic decision markers |
| P3-07 | Extend demo scenarios with enriched output visibility | `tools/demo_phase3_langgraph.sh` | scenario payloads and printed headers | Optional scenario demonstrates correlation/retrieval metadata |
| P3-08 | Extend CLI formatter for new fields | `tools/format_phase3_output.py` | output formatter functions | Displays `correlation_score`, `approvals_needed`, `decision_basis` and retrieval confidence |
| P3-09 | Update user-facing Phase 3 documentation | `docs/LANGGRAPH_PHASE3_GUIDE.md` | Scenario + payload examples | Guide documents deterministic-first policy and fallback behavior |

**Suggested implementation order (low-risk):**
1. P3-01 -> P3-02 -> P3-04 (core policy)
2. P3-03 (optional enrichment with timeout/fallback)
3. P3-05 (safety path verification)
4. P3-06 -> P3-08 -> P3-07 (observability/demo)
5. P3-09 (documentation finalization)

**Definition of done by task group:**
- **Core policy (P3-01/02/04):** `run_phase3` response contains correlation and approval rationale for medium/high/critical flows.
- **Resilience (P3-03/05):** workflow succeeds in deterministic-only mode when enrichment is unavailable.
- **Visibility (P3-06/07/08):** demo output surfaces correlation and decision basis without breaking existing scenarios.
- **Docs (P3-09):** phase guide includes one deterministic-only and one enriched payload example.

---

### Implementation Roadmap: Phase 4 (12–18 months)

#### Q2 2026: Foundation (2–3 months)
- ✅ Structlog audit logging (Phase 3)
- ✅ Tenacity retry logic (Phase 3)
- ⚠️ APScheduler for SLA tracking
- **Add:** PostgreSQL incident table + SQLAlchemy ORM

**Deliverable:** Incidents tracked, audit trail logged, SLAs monitored

---

#### Q3 2026: Scale & Correlation (2–3 months)
- **Add:** Celery + RabbitMQ (event queue)
- **Add:** Neo4j (evidence linking)
- **Add:** Plotly Dash (incident dashboard)
- **Add:** Prefect (workflow orchestration)

**Deliverable:** Multi-step playbooks, forensic timelines, analyst dashboard

---

#### Q4 2026: Intelligence & Metrics (2–3 months)
- **Add:** DuckDB (analytics DB)
- **Add:** Scikit-learn + XGBoost + MLflow (severity prediction, false-positive detection, attack pattern recognition)
  - Week 1–2: Data engineering + POC
  - Week 3–4: Build three models (severity, FP detector, pattern classifier)
  - Week 5–6: Shadow mode canary deployment (90/10 → 50/50 traffic split)
  - Week 7–8: Full rollout + weekly retraining pipeline
  - Week 1–2 Q1: MLflow model versioning + extended monitoring
- **Add:** Grafana (KPI dashboards)
- **Add:** APScheduler TI sync (GreyNoise, abuse.ch, MISP)

**Deliverable:** ML-assisted triage with 50% false-positive reduction, real-time KPIs, threat intel enrichment

---

#### Q1 2027: Graduation & Hardening (Optional)
- **Upgrade:** Prefect →  Airflow (if playbooks > 20)
- **Add:** MLflow model registry + A/B testing framework for new model versions
- **Add:** Elastic Stack or Loki (log aggregation)
- **Add:** Advanced ML extensions:
  - User behavior analytics (UBA) for insider threat detection
  - Time-series forecasting for capacity planning (alert volume prediction)
  - Clustering analysis for grouping similar incidents
- **Document:** SOC Standard Operating Procedures + ML model runbooks

**Deliverable:** Enterprise-ready platform with production ML ops

---

## Recommended Implementation Roadmap

### Why This Order?

| Decision | Rationale |
|---|---|
| SQLAlchemy first | Without incident tracking, Phase 4 is invisible |
| Celery + RabbitMQ early | Prevents alert storms from overwhelming the system |
| Neo4j before analytics | Forensics are more valuable than dashboards |
| ML after 3 months of data | Need baseline to train on |
| Airflow upgrade late | Prefect is sufficient until playbook complexity grows |

### Effort Estimates

| Component | Effort | ROI |
|---|---|---|
| SQLAlchemy incident table | Low (1 week) | High |
| Celery + RabbitMQ | Medium (2 weeks) | High |
| Neo4j basic linking | Medium (3 weeks) | High |
| Plotly Dash analyst dashboard | Medium (2 weeks) | Medium |
| Prefect playbook engine | High (4 weeks) | Very High |
| **ML End-to-End** | **High (7 weeks)** | **Very High** |
| — POC & data engineering | 1 week | — |
| — Severity predictor model | 1.5 weeks | — |
| — False-positive detector + pattern classifier | 2 weeks | — |
| — MLflow integration + canary deployment | 1.5 weeks | — |
| — Monitoring + retraining pipeline | 1 week | — |
| Grafana SLA dashboards | Low (1 week) | Medium |
| Threat intel sync | Low (1 week) | Low–Medium |

**Total Phase 4 Effort:** ~23–25 weeks (5.5–6 months of full-time work)

**Note:** ML was 3 weeks; expanded to 7 weeks with comprehensive feature engineering, multi-model approach, and production canary strategy.

---

## Decision Log

| Date | Decision | Status |
|---|---|---|
| 2026-04-18 | Skip LlamaIndex for now; revisit in 6 months | ✅ Decided |
| 2026-04-18 | Implement Tenacity + Structlog in Phase 3 MVP | ✅ Approved |
| 2026-04-18 | Plan Prefect (not Airflow) for Phase 4 | ✅ Approved |
| 2026-04-18 | Document this decision framework for future reference | ✅ Done |
| 2026-04-18 | Use Scikit-learn + XGBoost (not LLM-based ML) for Phase 4 | ✅ Approved |
| 2026-04-18 | Implement three-model approach (severity, FP detector, pattern classifier) | ✅ Approved |
| 2026-04-18 | Deploy ML via 4-week canary strategy (shadow → 10% → 50% → 100%) | ✅ Approved |
| 2026-04-20 | Implement DB-backed HITL approvals in Phase 4 (PostgreSQL + web UI) | ✅ Implemented |

---

## Phase 4 HITL Approval Implementation

**Status:** ✅ Implemented  
**Date:** 2026-04-20

### Overview

When a Phase 3 LangGraph workflow reaches an approval gate for a `medium`, `high`, or `critical` risk action, it now:

1. Stores the pending state in the Phase 3 in-memory dict (existing behaviour — preserved for direct API resumption).
2. **NEW** — POSTs an approval record to `POST http://phase4-api:8082/approvals`, persisting it to PostgreSQL.
3. Returns `{"workflow_status": "pending_approval"}` to the caller.

SOC analysts then use the **Phase 4 web UI** at `http://localhost:8082/ui` → **🔐 Approvals** tab to review context, approve, or reject.  
Phase 4 calls `POST /phase3/approvals/{incident_id}/resume` to resume the Phase 3 workflow.

### Key Design Decisions

| Decision | Rationale |
|---|---|
| Keep Phase 3 in-memory dict | Direct API resumption (`POST /phase3/approvals/{id}/resume`) still works without Phase 4 |
| Phase 4 is the approval UI — Phase 3 is the executor | Separation of concerns: Phase 4 owns the human interface; Phase 3 owns execution |
| Phase 4 constructs the Phase 3 resume URL | Phase 3 doesn't need to know its own external URL; Phase 4 derives it from `PHASE3_BASE_URLS` |
| `PHASE4_API_URL` is optional in Phase 3 | If Phase 4 is not running, Phase 3 simply skips the persistence step silently |
| `asyncio` background task for expiry (not APScheduler) | Avoids adding an extra dependency; runs inside existing FastAPI event loop |

### New DB Models (`incident_management/__init__.py`)

**`ApprovalRequest`** (`approval_requests` table)
- `approval_id` — `APR-YYYY-NNNNN` generated serial
- `phase3_incident_id` — links back to the Phase 3 workflow incident
- `incident_id` — optional link to a Phase 4 `INC-YYYY-NNNNN` ticket
- `risk_tier`, `approvals_needed`, `approvals_received` — approval logic
- `status` — `pending` / `approved` / `rejected` / `expired` / `cancelled`
- `proposed_action` (JSON) — full tool plan snapshot
- `workflow_summary` (Text) — human-readable triage context for the analyst
- `phase3_resume_url` — URL Phase 4 calls when decision is final
- `expires_at` — auto-expired by background task if no decision within 30 minutes

**`ApprovalDecision`** (`approval_decisions` table)
- `actor`, `decision`, `comment`, `decided_at`
- Many-to-one relationship to `ApprovalRequest`

### New API Endpoints (`server.py`)

| Method | Path | Description |
|---|---|---|
| `POST` | `/approvals` | Phase 3 creates approval on workflow pause |
| `GET` | `/approvals` | List with `?status=pending&risk_tier=high` filters |
| `GET` | `/approvals/stats` | Count by status (for dashboard badge) |
| `GET` | `/approvals/{id}` | Detail + all decisions |
| `POST` | `/approvals/{id}/decide` | `{"decision":"approved","actor":"...","comment":"..."}` |
| `POST` | `/approvals/{id}/cancel` | Cancel a pending approval |

### Phase 3 Integration Points

**`services/phase3_langgraph/app/main.py`** — `node_pending_approval()`:
- Reads `PHASE4_API_URL` env var (default: `""` — disabled)
- If set, sends `httpx.AsyncClient.post(PHASE4_API_URL + "/approvals", json=payload)`
- Fire-and-forget — exceptions are silently suppressed to never block the Phase 3 workflow

**`compose.phase3.langgraph.yml`**:
- Added `PHASE4_API_URL: ${PHASE4_API_URL:-http://phase4-api:8082}` to Phase 3 service environment

### Web UI Changes (`static/index.html`)

- **View switcher** added below stats bar: `📋 Incidents` | `🔐 Approvals`
- **Stats bar** extended with `⏳ Pending Approvals` count
- **Approvals view** — two-panel layout matching Incidents:
  - Left: filterable queue list with risk-tier badge and expiry countdown
  - Right: detail panel showing proposed action (JSON), triage summary, decisions so far
  - Inline decision form with `Approve`/`Reject` buttons and comment field
  - Reject requires a non-empty comment
  - 15-second auto-poll when Approvals tab is active
- **Badge** on the Approvals tab button shows pending count

---

## Open Questions

1. **Auto-versioning of playbooks:** Should playbooks be Git-tracked or in Neo4j?
2. **Multi-tenant SOC:** How to isolate incidents/cases per customer/org?
3. **Compliance reporting:** Which SOC2/HIPAA/PCI-DSS controls map to which components?
4. **Analyst permissions:** RBAC model for playbook creation, approval override, evidence access?
5. **Integration priority:** Which external tools first? (Jira, Splunk, ServiceNow, Slack?)
6. **ML feature store infrastructure:** Should we use Tecton, Feast, or simple DuckDB for production?
7. **Retraining trigger strategy:** Time-based (weekly) vs. drift-based (triggered by monitoring alerts)?
8. **Model explainability:** How to present SHAP/feature importance to non-ML analysts in Phase 3 UI?
9. **Feedback loop:** How to systematically collect analyst corrective feedback to improve models?
10. **Cost optimization:** Should ML inference be cached/batched vs. real-time per-alert?

---

## References

- Phase 3 LangGraph: [`services/phase3_langgraph/app/main.py`](../services/phase3_langgraph/app/main.py)
- Phase 3 Guide: [`docs/LANGGRAPH_PHASE3_GUIDE.md`](../docs/LANGGRAPH_PHASE3_GUIDE.md)
- MCP Server: [`src/wazuh_mcp_server/api/wazuh_client.py`](../src/wazuh_mcp_server/api/wazuh_client.py)

---

## Change History

| Date | Author | Change |
|---|---|---|
| 2026-04-18 | -- | Initial document created from discussion |
| 2026-04-18 | -- | Expanded ML section (Layer 7) with 11 subsections: problem statement, use cases, feature engineering pipeline, three-model architecture, training/validation, Phase 3 integration, canary deployment, business impact, challenges/mitigations, team roadmap, alternative approaches |
| 2026-04-18 | -- | Added Section 7.12 with a concrete Phase 3 node mapping for deterministic graph correlation + LlamaIndex enrichment, including approval rule and state contract JSON |
| 2026-04-18 | -- | Added Section 7.13 implementation checklist with schema/state changes, node tasks, audit fields, safety guardrails, tests, and acceptance criteria |
| 2026-04-18 | -- | Added Section 7.14 engineering task map with file/function-level implementation plan for `main.py`, demo tooling, and Phase 3 guide updates |

