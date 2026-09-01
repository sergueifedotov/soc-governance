# Docker Compose Deployment Stages

Complete guide to deploying Wazuh MCP Server with different composition stages.

## Deployment Stages Overview

The Wazuh MCP Server project uses a modular Docker Compose strategy with multiple overlay-able compose files:

MCP proxy feature status and packaging references:

- `mcp-security-proxy/README.md` (Implementation Status Snapshot)
- `docs/MCP_PROXY_COMMERCIAL_PACKAGING.md` (commercial packaging and feature boundaries)

| Stage | File | Services | Purpose | Use Case |
|-------|------|----------|---------|----------|
| **1. MCP Server Only** | `compose.yml` | 1 (wazuh-mcp-server) | Remote MCP server | Production remote server, integrate with existing SIEM |
| **2. Full Stack** | `compose.full.yml` | 10 (Wazuh SIEM + MCP + LLM + UI) | Complete demo environment | Local development, demos, air-gapped deployments |
| **3. Phase 3 Workflow** | `+compose.phase3.langgraph.yml` | +1 (phase3-langgraph) | LangGraph incident workflow | Add intelligent incident response automation |
| **4. Observability** | `+compose.langfuse.oss.yml` | +3 (langfuse-web, db, worker) | LLM tracing & observability | Monitor workflow decisions, debug automation |
| **5. Phase 4 Advanced SOC** | `+compose.phase4.yml` | +11 (incident mgmt, ML, orchestration) | Enterprise SOC automation | Scale incident response with ML and playbooks |

## Quick Reference: Common Deployments

**Recommended laptop bring-up** (Wazuh + MCP proxy + Phase 3/4 + OpenCTI): generate a
valid `wazuh_` `MCP_API_KEY` in `.env`, then `bash tools/start-profile.sh C`. See
[OPERATIONS.md](OPERATIONS.md#first-run-local-stack) and the [README](../README.md#quick-start-local-soc-stack).

### Stage 1: Remote MCP Server (Production)
```bash
# Minimal deployment - just the MCP server standalone
docker compose up -d

# Access the API
curl http://localhost:3000/health
```

**Use when:** Connecting to an existing Wazuh installation, self-hosted SIEM, or cloud security tools.

---

### Stage 2: Full Stack (Development & Demos)
```bash
# Complete Wazuh + MCP + LLM + Chat UI
docker compose -f compose.full.yml up -d

# Watch services start
docker compose -f compose.full.yml ps

# Access services
# - Open WebUI:         http://localhost:3100
# - Wazuh Dashboard:    https://localhost:8443 (admin / SecretPassword)
# - Wazuh MCP API:      http://localhost:3000/mcp
# - Health:             http://localhost:3000/health
```

**Use when:** Developing locally, running demos, or fully air-gapped environments.

**Duration:** ~2 minutes to full startup (Wazuh Indexer initialization takes time on first run).

---

### Stage 3: Full Stack + Phase 3 LangGraph
```bash
# Start base stack
docker compose -f compose.full.yml up -d

# Add Phase 3 workflow automation
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml up -d --build phase3-langgraph

# Verify services
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml ps
```

**What Phase 3 adds:**
- Incident workflow orchestration (LangGraph)
- Multi-step reasoning about security events
- API calls back to Wazuh for active response
- Decision logging

**Access Phase 3:** Health check at `http://localhost:3000/health` (integrated with MCP server).

---

### Stage 4: Full Stack + Phase 3 + Langfuse Observability
```bash
# Start base stack
docker compose -f compose.full.yml up -d

# Add Phase 3
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml up -d --build phase3-langgraph

# Add observability (traces all LLM calls & decisions)
export LANGFUSE_ENABLED=true \
       LANGFUSE_PUBLIC_KEY=pk-local-smoke \
       LANGFUSE_SECRET_KEY=sk-local-smoke

docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.langfuse.oss.yml \
               up -d --build langfuse-web langfuse-worker

# Verify all stacks
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.langfuse.oss.yml \
               ps
```

**What Langfuse adds:**
- Full trace of LLM API calls (prompts, completions)
- Latency metrics per LLM call
- Token usage tracking
- Decision tree visualization
- Integration with LangGraph workflow

**Access Langfuse:** `http://localhost:3001` (after login at `/auth/sign-in`)

---

### Stage 5: Full Stack + Phase 3 + Phase 4 Advanced SOC
```bash
# Start base stack
docker compose -f compose.full.yml up -d

# Add Phase 3 workflow
docker compose -f compose.full.yml -f compose.phase3.langgraph.yml up -d --build phase3-langgraph

# Add Phase 4 Advanced SOC (incident management, ML, playbooks, orchestration)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d --build

# Watch all services initialize
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               ps

# View logs from Phase 4 API
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs -f phase4-api
```

**What Phase 4 adds:**
- PostgreSQL incident database
- Neo4j forensic graph
- ML models (severity, false-positive detection, attack pattern)
- Playbook orchestration (Prefect)
- Celery async task queue (RabbitMQ)
- Analytics dashboard (Grafana)
- Threat intelligence synchronization (APScheduler)
- MLflow model tracking

**Access Phase 4 services:**
- Phase 4 API:      `http://localhost:8082/docs` (interactive API docs)
- Grafana:          `http://localhost:3002` (analytics dashboards)
- Neo4j Browser:    `http://localhost:7474` (forensic graph explorer — login: `neo4j` / `phase4_admin`)
- MLflow:           `http://localhost:5001` (model registry)
- PostgreSQL:       `localhost:5433` (incident database)

---

## Port Usage Reference

| Service | Port | URL | Notes |
|---------|------|-----|-------|
| **Open WebUI** | 3100 | http://localhost:3100 | Chat UI (Stage 2+) |
| **Wazuh MCP API** | 3000 | http://localhost:3000/mcp | MCP protocol (all stages) |
| **Wazuh Dashboard** | 8443 | https://localhost:8443 | Wazuh SIEM UI (Stage 2+) |
| **Wazuh Indexer** | 9200 | (internal) | OpenSearch (Stage 2+) |
| **Phase 4 API** | 8082 | http://localhost:8082/docs | FastAPI (Stage 5) |
| **Phase 4 PostgreSQL** | 5433 | localhost:5433 | Incident database (Stage 5) |
| **Phase 4 Neo4j** | 7474/7687 | http://localhost:7474 | Forensics graph — `neo4j` / `phase4_admin` (Stage 5) |
| **Phase 4 Grafana** | 3002 | http://localhost:3002 | Analytics dashboards (Stage 5) |
| **Phase 4 MLflow** | 5001 | http://localhost:5001 | ML experiment tracking (Stage 5) |
| **Phase 4 RabbitMQ** | 5673/15673 | http://localhost:15673 | Message broker (Stage 5) |
| **Phase 4 Redis** | 6380 | localhost:6380 | Task result backend (Stage 5) |
| **Langfuse Web** | 3001 | http://localhost:3001 | Observability UI (Stage 4) |

---

## Phase 4 Stack Operations

### Full Stage 5 Deployment (Complete)
```bash
# Start all services (takes 2-3 min for all to be healthy)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d

# Wait for services to become healthy
sleep 10x
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               ps

# View initialization logs
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs --tail=50
```

### Initialize Phase 4 Databases
```bash
# PostgreSQL incident database is auto-initialized via SQLAlchemy
# Check initialization:
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               exec phase4-postgres psql -U phase4_admin -d phase4_incidents -c "SELECT count(*) FROM incidents;"

# Neo4j graph database is auto-initialized
# Check Neo4j (credentials: neo4j / phase4_admin):
curl -u neo4j:phase4_admin http://localhost:7474/browser/
```

### Scale Phase 4 Workers
```bash
# Scale Celery workers for higher throughput (default: 1)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d --scale phase4-celery-worker=3

# Verify scaled workers
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               ps | grep celery
```

### Monitor Phase 4 Training Job
```bash
# Watch ML model retraining (runs weekly on Sunday 02:00 UTC)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs -f phase4-ml-trainer

# Check MLflow for model runs
# Open: http://localhost:5001
```

### Query Phase 4 Incident Database
```bash
# Connect to PostgreSQL
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               exec phase4-postgres psql \
                 -U phase4_admin \
                 -d phase4_incidents

# Example queries:
# SELECT * FROM incidents ORDER BY created_at DESC LIMIT 5;
# SELECT risk_tier, COUNT(*) FROM incidents GROUP BY risk_tier;
# SELECT * FROM incident_activities WHERE incident_id = 'INC-2026-00001';
```

### Stop Phase 4 (Without Removing Data)
```bash
# Stop all services (volumes persist)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               down

# Restart later (data is preserved)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d
```

### Full Cleanup (Remove All Data)
```bash
# Stop and delete volumes (⚠️ destructive)
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               down --volumes --remove-orphans

# Clean up system
docker system prune -f
```

---

## Phase 4 + Phase 3 Integration

### How They Work Together

```
Wazuh Alert (compose.full.yml)
    ↓
Phase 3 LangGraph Workflow (compose.phase3.langgraph.yml)
    • Analyze alert context
    • Call Wazuh API for enrichment
    • Generate proposal for action
    ↓
Phase 4 ML Enhancement (compose.phase4.yml)
    • Filter false positives (ML detector)
    • Predict severity (ML classifier)
    • Recommend attack pattern (ML model)
    ↓
Phase 4 Incident Creation
    • Create incident ticket (PostgreSQL)
    • Link to forensic timeline (Neo4j)
    • Queue playbook execution (Celery)
    ↓
Phase 4 Playbook Orchestration (Prefect)
    • Execute multi-step response
    • Block attacker IP
    • Disable compromised user
    • Notify security team
    ↓
Phase 4 Analytics (Grafana)
    • Track SLA compliance
    • MTTD/MTTR metrics
    • Alert trends
```

### Workflow Configuration

In Phase 3 workflow, enable ML enhancement:

```python
# Phase 3 (services/phase3_langgraph/workflow.py)
from wazuh_mcp_server.phase4.ml import Phase3MLIntegration

ml_integration = Phase3MLIntegration(
    severity_predictor=load_model('severity'),
    fp_detector=load_model('false_positive'),
    attack_classifier=load_model('attack_pattern'),
)

# In node_propose_action:
proposal = await ml_integration.enhance_propose_action(
    base_proposal,
    alert_data,
)

# proposal now includes:
# - ml_context.predicted_severity
# - ml_context.false_positive_probability
# - ml_context.attack_pattern_recommendation
# - ml_context.feature_importance
```

---

## Environment Configuration

### Phase 4 Environment Variables

Create `.env` with Phase 4 settings:

```bash
# Database Configuration
DATABASE_URL=postgresql://phase4_admin:password@phase4-postgres:5432/phase4_incidents
NEO4J_URI=bolt://phase4-neo4j:7687
NEO4J_USER=neo4j
NEO4J_PASSWORD=neo4j_password

# Message Queue
CELERY_BROKER_URL=amqp://phase4_user:password@phase4-rabbitmq:5672/phase4
CELERY_RESULT_BACKEND=redis://phase4-redis:6379/0

# ML Configuration
MLFLOW_TRACKING_URI=http://phase4-mlflow:5000
ML_MODEL_PATH=/models
TRAINING_ENABLED=true

# Threat Intelligence
GREYNOISE_API_KEY=your-greynoise-key
MISP_URL=https://misp.example.com
MISP_AUTH_KEY=your-misp-key

# Analytics
PROMETHEUS_URL=http://phase4-prometheus:9090

# Logging
LOG_LEVEL=INFO
```

### Load Environment

```bash
# Use .env file
export $(cat .env | xargs)

# Or pass to docker compose
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d --env-file .env
```

---

## Troubleshooting

### Phase 4 PostgreSQL Won't Connect
```bash
# Check if PostgreSQL is healthy
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs phase4-postgres

# Verify with manual connect
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               exec phase4-postgres psql -U phase4_admin -d phase4_incidents -c "SELECT 1;"
```

### Neo4j Browser Not Accessible
```bash
# Check Neo4j health
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs phase4-neo4j

# Wait for startup (~30 sec on first run)
# Then visit: http://localhost:7474 (login: neo4j / phase4_admin)
```

### Query Alerts in Neo4j Browser

Open http://localhost:7474, connect with `neo4j` / `phase4_admin`, then run these Cypher queries:

```cypher
// Count all alerts
MATCH (a:ALERT) RETURN count(a) AS total
```

```cypher
// Latest 10 alerts
MATCH (a:ALERT)
RETURN a.alert_id, a.rule_name, a.severity, a.timestamp
ORDER BY a.timestamp DESC
LIMIT 10
```

```cypher
// Alerts grouped by severity
MATCH (a:ALERT)
RETURN a.severity, count(a) AS total
ORDER BY total DESC
```

```cypher
// All node types and counts
MATCH (n)
RETURN labels(n)[0] AS label, count(n) AS total
ORDER BY total DESC
```

```cypher
// Alerts linked to IP addresses (visual graph)
MATCH (a:ALERT)-[r]->(ip:IP_ADDRESS)
RETURN a, r, ip
LIMIT 25
```

```cypher
// Full graph of all relationships
MATCH (n)-[r]->(m)
RETURN n, r, m
LIMIT 50
```

```cypher
// Search alerts by rule name keyword
MATCH (a:ALERT)
WHERE a.rule_name CONTAINS 'ssh'
RETURN a.alert_id, a.rule_name, a.severity, a.timestamp
ORDER BY a.timestamp DESC
```

> **Tip:** Queries returning `n, r, m` render as interactive visual graphs in the browser — click nodes to expand relationships.

### Query Forensic Cases in Neo4j Browser

> **Note:** Neo4j stores the forensic graph — `ALERT` nodes tagged with `incident_id` (the Wazuh agent name), linked to `IP_ADDRESS`, `USER`, `FILE`, `PROCESS`, `WORKSTATION`, and `DOMAIN` nodes. PostgreSQL holds the incident tickets (INC-xxxx). Use `GET /incidents` at http://localhost:8082/docs to see those.

**Graph schema relationships:**
```
(ALERT)-[:INVOLVES]->(IP_ADDRESS | USER)
(ALERT)-[:DETECTED]->(FILE)
(FILE)-[:MODIFIED_BY]->(PROCESS)
(PROCESS)-[:SPAWNED_BY]->(PROCESS)
(PROCESS)-[:CONNECTS_TO]->(IP_ADDRESS)
(USER)-[:LOGGED_IN_TO]->(WORKSTATION)
(IP_ADDRESS)-[:RESOLVES_TO]->(DOMAIN)
```

```cypher
// Step 1: Discover what agent groups exist (run this first)
MATCH (a:ALERT)
RETURN a.incident_id AS agent_group, count(a) AS alerts
ORDER BY alerts DESC
```

```cypher
// All nodes connected to a specific agent group (visual graph)
// Replace 'wazuh-manager' with a value from the query above
MATCH (a:ALERT {incident_id: 'wazuh-manager'})-[r]->(entity)
RETURN a, r, entity
LIMIT 50
```

```cypher
// Alerts → IPs (INVOLVES)
MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS)
RETURN a.rule_name, a.severity, ip.ip, a.timestamp
ORDER BY a.timestamp DESC
LIMIT 20
```

```cypher
// Alerts → Users (INVOLVES)
MATCH (a:ALERT)-[:INVOLVES]->(u:USER)
RETURN a.rule_name, a.severity, u.username, a.timestamp
ORDER BY a.timestamp DESC
```

```cypher
// Alerts → Files (DETECTED)
MATCH (a:ALERT)-[:DETECTED]->(f:FILE)
RETURN a.rule_name, f.path, a.timestamp
ORDER BY a.timestamp DESC
```

```cypher
// File → Process chain (MODIFIED_BY)
MATCH (f:FILE)-[:MODIFIED_BY]->(p:PROCESS)
RETURN f.path, p.name, p.pid_host
```

```cypher
// Process → IP connections (CONNECTS_TO)
MATCH (p:PROCESS)-[:CONNECTS_TO]->(ip:IP_ADDRESS)
RETURN p.name, p.pid_host, ip.ip
```

```cypher
// Lateral movement — users on multiple workstations
MATCH (u:USER)-[:LOGGED_IN_TO]->(ws:WORKSTATION)
WITH u, collect(DISTINCT ws.hostname) AS workstations, count(DISTINCT ws) AS cnt
WHERE cnt >= 2
RETURN u.username, workstations, cnt
ORDER BY cnt DESC
```

```cypher
// IP → Domain resolution (RESOLVES_TO)
MATCH (ip:IP_ADDRESS)-[:RESOLVES_TO]->(d:DOMAIN)
RETURN ip.ip, d.name
```

```cypher
// Full attack chain from a suspicious IP (up to 4 hops)
MATCH path = (ip:IP_ADDRESS {ip: '203.0.113.45'})-[*1..4]->(entity)
RETURN [n IN nodes(path) | labels(n)] AS node_types,
       [r IN relationships(path) | type(r)] AS rel_chain,
       length(path) AS depth
ORDER BY depth
```

```cypher
// C2 domain lookup — which agent groups touched a domain
MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS)-[:RESOLVES_TO]->(d:DOMAIN)
WHERE d.name CONTAINS 'evil'
RETURN DISTINCT a.incident_id AS agent_group, ip.ip, d.name
```

```cypher
// Most targeted IPs across all alerts
MATCH (a:ALERT)-[:INVOLVES]->(ip:IP_ADDRESS)
RETURN ip.ip, count(a) AS hit_count
ORDER BY hit_count DESC
LIMIT 10
```

### ML Models Not Loading
```bash
# Check MLflow service
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs phase4-mlflow

# Check model persistence volume
docker volume ls | grep ml_models

# Verify models exist
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               exec phase4-ml-trainer ls -la /models/
```

### Celery Tasks Not Processing
```bash
# Check RabbitMQ broker
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs phase4-rabbitmq

# Check Celery worker
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               logs phase4-celery-worker

# Monitor task queue
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               exec phase4-celery-worker celery -A events inspect active
```

---

## Performance Tuning

### Adjust ML Training Frequency
Edit `compose.phase4.yml` `phase4-ml-trainer` command:

```yaml
phase4-ml-trainer:
  # Default: Weekly (Sunday 02:00 UTC)
  # Options: daily, weekly, monthly
  environment:
    TRAINING_SCHEDULE: weekly  # Change to daily for more frequent retraining
```

### Scale Incident Processing
```bash
# Increase Celery workers for higher throughput
docker compose -f compose.full.yml \
               -f compose.phase3.langgraph.yml \
               -f compose.phase4.yml \
               up -d --scale phase4-celery-worker=5
```

### Increase Redis Cache Size
Edit `compose.phase4.yml`:

```yaml
phase4-redis:
  command: redis-server --maxmemory 1gb --maxmemory-policy allkeys-lru
```

---

## What's Next?

1. **Deploy Phase 4:** Start with `docker compose -f compose.full.yml -f compose.phase4.yml up -d`
2. **Create Sample Incidents:** Use Phase 4 API at `http://localhost:8082/docs` to create test incidents
3. **Train ML Models:** Submit alerts and trigger retraining at `http://localhost:5001` (MLflow)
4. **Create Custom Playbooks:** Define response playbooks in Phase 4 database
5. **Monitor Analytics:** View dashboards at `http://localhost:3002` (Grafana)
6. **Integrate Phase 3:** Link Phase 3 workflows to Phase 4 incident creation

See [PHASE4_IMPLEMENTATION.md](PHASE4_IMPLEMENTATION.md) for detailed architecture and API reference.
