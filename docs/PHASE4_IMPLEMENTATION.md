# Phase 4 Advanced SOC Architecture - Implementation Guide

**Status:** Complete (Full Stack Implemented)  
**Date:** April 20, 2026  
**Last Updated:** 2026-04-20  

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Layer-by-Layer Implementation](#layer-by-layer-implementation)
3. [Quick Start](#quick-start)
4. [Configuration](#configuration)
5. [Integration with Phase 3](#integration-with-phase3)
6. [API Reference](#api-reference)
7. [Monitoring & Operations](#monitoring--operations)
8. [Troubleshooting](#troubleshooting)

---

## Architecture Overview

Phase 4 builds on Phase 3 (LangGraph workflow) with enterprise-grade incident management and ML-driven automation.

### Component Stack

```
┌──────────────────────────────────────────────────────────┐
│ Phase 3 LangGraph + ML-Enhanced Decision Making           │
└────────────────────┬─────────────────────────────────────┘
                     │
     ┌───────────────┴────────────────┬──────────────────┐
     ▼                                ▼                  ▼
┌─────────────────┐    ┌──────────────────────┐  ┌─────────────┐
│  Orchestration  │    │  Incident Management │  │ Playbook    │
│  (Prefect)      │    │  (PostgreSQL + API)  │  │ Execution   │
└─────────────────┘    └──────────────────────┘  └─────────────┘
     │                           │
     ▼                           ▼
┌─────────────────┐    ┌──────────────────────┐
│  Event Queue    │    │ Case Management      │
│  (Celery +      │    │ (Neo4j Forensics)    │
│   RabbitMQ)     │    └──────────────────────┘
└─────────────────┘
     │
     ▼
┌─────────────────────────────────────────────────────────┐
│  Analytics & BI (Grafana + Prometheus + DuckDB)         │
│  Threat Intel (APScheduler + feeds)                     │
│  ML/Anomaly Detection (XGBoost + MLflow)                │
└─────────────────────────────────────────────────────────┘
```

---

## Layer-by-Layer Implementation

### Layer 1: Incident Management (PostgreSQL)

**Purpose:** Central incident ticketing and SLA tracking

**Files:**
- `src/wazuh_mcp_server/phase4/incident_management/__init__.py` - ORM models
  - `IncidentTicket` - Main incident record
  - `IncidentActivity` - Activity audit trail
  - `IncidentEvidence` - Linked evidence/artifacts
  - `SLAPolicy` - SLA definitions by risk tier
  
- `src/wazuh_mcp_server/phase4/incident_management/api.py` - REST endpoints
  - `POST /incidents` - Create incident
  - `GET /incidents` - List with filtering
  - `PUT /incidents/{id}` - Update
  - `POST /incidents/{id}/assign` - Assign to analyst
  - `POST /incidents/{id}/resolve` - Resolve with SLA tracking
  - `POST /incidents/{id}/escalate` - Escalate
  - `POST /incidents/{id}/activities` - Add activity

**Database Schema:**

```
incidents (core table)
├── id (UUID, PK)
├── incident_id (INC-2026-00001, unique)
├── status (open, assigned, investigating, escalated, resolved, closed)
├── risk_tier (low, medium, high, critical)
├── priority (1-5)
├── assigned_to (analyst username)
├── created_at, updated_at, resolved_at
├── sla_hours, sla_breach
├── external_ticket_id (Jira, etc.)
├── ml_predicted_severity, ml_false_positive_prob, ml_attack_pattern
├── alert_count, source_ip, dest_ip
├── title, description

incident_activities (audit trail)
├── id (UUID, PK)
├── incident_id (FK)
├── activity_type (approval, action, status_change, comment)
├── actor, title, description
├── previous_value, new_value

incident_evidences (linked artifacts)
├── id (UUID, PK)
├── incident_id (FK)
├── evidence_type (alert, log, file, network)
├── storage_path, storage_hash
├── collected_at, relevance_score
```

**Example Usage:**

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from phase4.incident_management import IncidentCreate, RiskTier, IncidentService

engine = create_engine("postgresql://user:pass@localhost/phase4_incidents")
db = Session(engine)
service = IncidentService(db)

# Create incident from alert
incident = service.create_incident(IncidentCreate(
    title="SSH brute force from 203.0.113.45",
    description="High-volume auth failures",
    risk_tier=RiskTier.HIGH,
    source_ip="203.0.113.45",
    dest_ip="10.0.1.50"
))
print(incident.incident_id)  # INC-2026-00001
```

---

### Layer 2: Case Management & Forensics (Neo4j)

**Purpose:** Link alerts, files, processes, users, and IPs in forensic timelines

**Graph Model:**

```
ALERT --detected--> FILE --modified-by--> PROCESS --connects-to--> IP_ADDRESS
    --involves--> USER --logon-from--> WORKSTATION
    --triggered-by--> RULE --in-group--> RULE_GROUP
```

**Example Queries:**

```cypher
// Find all incidents involving a C2 domain
MATCH (alert:ALERT)-->(threat:THREAT_INTEL {domain: "c2.evil.com"})
RETURN alert.id, alert.severity, alert.timestamp

// Impossible travel detection
MATCH (user:USER)-[login1:LOGGED_IN]->(ws1:WORKSTATION),
      (user)-[login2:LOGGED_IN]->(ws2:WORKSTATION)
WHERE login1.timestamp < login2.timestamp 
  AND distance(ws1.geolocation, ws2.geolocation) > 500
  AND login2.timestamp - login1.timestamp < 3600
RETURN user, ws1, ws2, distance, time_delta
```

**Implementation:** (Files in `src/wazuh_mcp_server/phase4/forensics/`)
- Neo4j driver initialization
- Graph schema setup
- Query builders for common patterns
- Evidence correlation

---

### Layer 3: Playbook Orchestration (Prefect)

**Purpose:** Define and execute multi-step response playbooks

**Files:**
- `src/wazuh_mcp_server/phase4/orchestration/playbooks.py`
  - `PlaybookDefinition` - YAML/dict definition
  - `PlaybookEngine` - Execution engine
  - Example playbooks: Ransomware, Brute Force, Lateral Movement

**Example Playbook (YAML):**

```yaml
name: ransomware_response
description: Rapid response to ransomware
triggers:
  - severity >= 8 AND rule_id in [ransomware_rules]

steps:
  - name: isolate_host
    action: wazuh_isolate_host
    arguments: { agent_id: $source_agent }
    on_failure: abort

  - name: block_source_ip
    action: wazuh_firewall_drop
    arguments: { src_ip: $source_ip }
    on_failure: continue

  - name: wait
    action: wait
    arguments: { seconds: 60 }

  - name: verify_isolation
    action: wazuh_check_agent_status
    arguments: { agent_id: $source_agent, expected: disconnected }
    retry_count: 3

  - name: create_incident
    action: create_incident
    arguments: { 
      title: "Ransomware: $source_agent",
      risk_tier: critical 
    }

  - name: notify_soc
    action: notify
    arguments: { channel: soc-alerts }
```

**Execution:**

```python
from phase4.orchestration.playbooks import PlaybookEngine, RANSOMWARE_RESPONSE_PLAYBOOK

engine = PlaybookEngine(mcp_client, incident_service, audit_logger)

result = await engine.execute_playbook(
    RANSOMWARE_RESPONSE_PLAYBOOK,
    context={
        "source_agent": "wazuh-agent-001",
        "source_ip": "203.0.113.45",
        "compromised_user": "jdoe",
    }
)

print(f"Playbook {result['status']}: {result['steps_completed']} completed")
```

---

### Layer 4: Event Queue (Celery + RabbitMQ)

**Purpose:** Scale incident response with async task queuing

**Workers:**
- Incident creation
- Alert aggregation
- Phase 3 workflow triggering
- Evidence collection
- Analyst notifications

**Example Task:**

```python
from celery import Celery

app = Celery('phase4', broker='amqp://guest:guest@rabbitmq:5672//')

@app.task(bind=True, retry_limit=3)
def cascade_phase3_workflow(self, incident_id, alert_data):
    """Trigger Phase 3 workflow for incident"""
    try:
        # Make MCP call to Phase 3
        result = trigger_phase3_workflow(alert_data)
        return result
    except Exception as exc:
        # Retry with exponential backoff
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
```

---

### Layer 5: Analytics & BI (Grafana + Prometheus)

**Purpose:** Real-time SOC metrics and incident dashboards

**Dashboards:**
- SLA compliance (% incidents resolved within SLA)
- Mean Time To Detect (MTTD)
- Mean Time To Response (MTTR)
- Alert volume trends
- Risk tier distribution
- Analyst workload

**Prometheus Metrics:**
```
phase4_incidents_created{risk_tier="critical"} 5
phase4_incidents_resolved{sla_breach="true"} 12
phase4_sla_breach_rate 0.18
phase4_mean_time_to_resolution_hours 4.2
phase4_alert_false_positive_rate 0.22
```

---

### Layer 6: Threat Intelligence (APScheduler)

**Purpose:** Periodically sync threat feeds

**Files:**
- `src/wazuh_mcp_server/phase4/threat_intel/feed_sync.py`

**Supported Sources:**
- GreyNoise (IP reputation)
- abuse.ch (malware hashes)
- MISP (threat intelligence)
- Custom feeds (STIX/TAXII)

**Schedule:**

```python
@scheduler.scheduled_job('interval', hours=4)
def sync_threat_intel():
    """Every 4 hours: fetch and store threat intelligence"""
    greynoise_ips = fetch_greynoise()
    abuse_ch_hashes = fetch_abuse_ch()
    misp_events = fetch_misp()
    
    insert_into_threat_intel_db(greynoise_ips, abuse_ch_hashes, misp_events)
```

---

### Layer 7: ML & Anomaly Detection (XGBoost + MLflow)

**Purpose:** Intelligent severity prediction and false-positive filtering

**Files:**
- `src/wazuh_mcp_server/phase4/ml/feature_engineering.py` - Feature extraction
- `src/wazuh_mcp_server/phase4/ml/models.py` - Severity, FP, Attack Pattern classifiers
- `src/wazuh_mcp_server/phase4/ml/training.py` - Training pipeline with MLflow
- `src/wazuh_mcp_server/phase4/ml/monitoring.py` - Drift detection
- `src/wazuh_mcp_server/phase4/ml/phase3_integration.py` - Phase 3 integration

**Three Models:**

1. **Severity Predictor** (XGBoost, multi-class: low/medium/high/critical)
   - Input: 19 alert features
   - Output: Predicted severity + confidence
   - Used to override user risk tier if ML is more confident

2. **False-Positive Detector** (Random Forest, binary: TP/FP)
   - Input: 10 most predictive features
   - Output: is_false_positive probability
   - Filters noise before incident creation

3. **Attack Pattern Classifier** (XGBoost, 6 classes)
   - Input: 19 alert features + alert cluster context
   - Output: Attack type (brute_force, port_scan, lateral_movement, exfiltration, policy_violation)
   - Used to auto-select playbook

**Feature Engineering (19 Features):**

| Category | Features | Count |
|----------|----------|-------|
| Alert Properties | rule_severity, rule_category, alert_text_tokens, contains_executable | 4 |
| Context Enrichment | src_ip_reputation, dest_user_privilege, target_is_critical, src_ip_in_whitelist | 4 |
| Temporal | hour_of_day_utc, day_of_week, alert_frequency_per_hour | 3 |
| Historical | src_ip_incident_count_30d, agent_alert_count_7d, rule_false_positive_rate, time_since_last_alert | 4 |
| Statistical | zscore_volume, entropy_rule_distribution, geographic_anomaly | 3 |

**Weekly Training:**

```python
@scheduler.scheduled_job('cron', day_of_week='sun', hour=2)
def weekly_retrain_models():
    # 1. Extract 60 days of alerts with analyst labels
    raw_data = query_wazuh_indexer(start_time=now - timedelta(days=60))
    
    # 2. Engineer features for each alert
    features_df = parallel_engineer_features(raw_data, n_workers=8)
    
    # 3. Train models with MLflow tracking
    with mlflow.start_run(run_name=f"severity_model_week_{week_number}"):
        model = train_severity_predictor(features_df)
        
        # Evaluate
        val_f1 = evaluate(model, X_val, y_val)
        
        # Promote if better than current production model
        if val_f1 > current_prod_f1 * 1.02:  # 2% improvement threshold
            mlflow.register_model(...)
            promote_to_production(model)
```

**Canary Deployment (4 weeks):**

```
Week 1-2: 90% hardcoded / 10% ML (shadow mode)
Week 3:   80% hardcoded / 20% ML
Week 4:   50% hardcoded / 50% ML (rollback ready)

At each step: Compare ML predictions vs analyst labels (ground truth)
            If agreement < 95%, pause and investigate
```

**Production Monitoring:**

```python
@scheduler.scheduled_job('interval', hours=6)
def monitor_ml_performance():
    # Feature drift detection (KS test)
    feature_drift = detect_drift(current_X, baseline_X)
    
    # Prediction drift (KL divergence)
    if kl_divergence > 0.5:
        alert_team("High prediction drift")
    
    # Analyst override rate
    override_rate = query_overrides_last_24h() / query_total_incidents()
    if override_rate > 0.15:
        alert_team("Analysts overriding predictions >15%")
```

---

## Quick Start

### 1. Start Phase 4 Stack

```bash
# Set environment variables
export POSTGRES_PASSWORD="your-secure-password"
export RABBITMQ_PASSWORD="your-secure-password"
export GRAFANA_PASSWORD="admin"

# Launch all services
docker compose -f compose.phase4.yml up -d

# Verify services
docker compose -f compose.phase4.yml ps
```

### 2. Initialize Databases

```bash
# PostgreSQL: Create incident schema
docker exec phase4-postgres psql -U phase4_admin -d phase4_incidents \
  -f /app/schema/init_phase4.sql

# Neo4j: Create graph indexes
docker exec phase4-neo4j cypher-shell -u neo4j -p phase4_admin \
  < /app/schema/init_neo4j.cypher
```

### 3. Access Dashboards

- **Incident Management API:** http://localhost:8082/docs
- **Grafana:** http://localhost:3002 (admin/admin)
- **Neo4j Browser:** http://localhost:7474 (neo4j/phase4_admin)
- **Prefect UI:** http://localhost:4200
- **MLflow Tracking:** http://localhost:5001

---

## Configuration

### PostgreSQL Connection

```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

DATABASE_URL = "postgresql://phase4_admin:password@phase4-postgres:5432/phase4_incidents"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
```

### ML Model Configuration

```python
from phase4.ml import ModelTrainer, TrainingConfig

config = TrainingConfig(
    window_days=60,
    min_samples_per_class=50,
    cv_folds=5,
    severity_f1_threshold=0.80,
    fp_precision_threshold=0.75,
    attack_accuracy_threshold=0.80,
    improvement_threshold=1.02,
    model_dir=Path("/models"),
    mlflow_uri="http://phase4-mlflow:5000",
)

trainer = ModelTrainer(config, feature_engineer)
```

### Playbook Configuration

```python
# Load playbooks from YAML
from phase4.orchestration.playbooks import PlaybookDefinition
import yaml

with open("playbooks/ransomware_response.yml") as f:
    playbook_dict = yaml.safe_load(f)

playbook = PlaybookDefinition(**playbook_dict)
result = await engine.execute_playbook(playbook, context)
```

---

## Integration with Phase 3

### Enhanced Proposal Node

The ML module enhances Phase 3's `node_propose_action` with:

```python
from phase4.ml import Phase3MLIntegration, SeverityPredictor, FalsePositiveDetector, AttackPatternClassifier

# In Phase 3 workflow initialization
ml_integration = Phase3MLIntegration(
    severity_predictor=SeverityPredictor(),
    fp_detector=FalsePositiveDetector(),
    attack_classifier=AttackPatternClassifier(),
)

# In node_propose_action
proposal = await ml_integration.enhance_propose_action(
    request=state["request"],
    enrichment=state["enrichment"],
    alert_features=state["alert_features"],
    build_action_plan=_build_action_plan,
)

# Proposal now includes ML context:
{
    "proposed_action": "isolate_host",
    "ml_context": {
        "predicted_severity": "critical",
        "severity_confidence": 0.91,
        "false_positive_probability": 0.04,
        "attack_pattern": "lateral_movement",
        "approval_escalation": {
            "escalated": True,
            "reason": "ML predicts critical (user said high)",
            "escalation_factor": 1.5
        }
    }
}
```

### Playbook Triggering from Phase 3

After Phase 3 resolves an action, trigger playbooks for follow-up:

```python
# After action execution in Phase 3
if state["workflow_status"] == "completed":
    # Create incident
    incident = incident_service.create_incident(...)
    
    # Trigger playbook based on attack pattern
    if ml_context["attack_pattern"] == "ransomware":
        playbook_result = await playbook_engine.execute_playbook(
            RANSOMWARE_RESPONSE_PLAYBOOK,
            context={
                "source_agent": alert.agent_id,
                "source_ip": threat.src_ip,
            }
        )
```

---

## API Reference

### Create Incident

```bash
curl -X POST http://localhost:8082/incidents \
  -H "Content-Type: application/json" \
  -d '{
    "title": "SSH brute force",
    "description": "High-volume auth failures from 203.0.113.45",
    "risk_tier": "high",
    "source_ip": "203.0.113.45",
    "dest_ip": "10.0.1.50"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "incident_id": "INC-2026-00001",
  "status": "open",
  "risk_tier": "high",
  "created_at": "2026-04-20T14:30:00Z",
  "sla_hours": 4
}
```

### List Incidents

```bash
curl "http://localhost:8082/incidents?status=open&risk_tier=critical&limit=50"
```

### Assign Incident

```bash
curl -X POST http://localhost:8082/incidents/{id}/assign \
  -H "Content-Type: application/json" \
  -d '{
    "assigned_to": "john.smith",
    "actor": "system"
  }'
```

---

## Monitoring & Operations

### Health Checks

```bash
# Check all services
docker compose -f compose.phase4.yml ps

# View logs
docker compose -f compose.phase4.yml logs -f phase4-api
docker compose -f compose.phase4.yml logs -f phase4-mlflow
```

### Backups

```bash
# PostgreSQL backup
docker exec phase4-postgres pg_dump \
  -U phase4_admin phase4_incidents \
  > incidents_backup_$(date +%Y%m%d).sql

# Neo4j backup
docker exec phase4-neo4j neo4j-admin database dump neo4j \
  --to-path=/backups
```

---

## Troubleshooting

### PostgreSQL Connection Error

```bash
# Check PostgreSQL logs
docker compose -f compose.phase4.yml logs phase4-postgres

# Verify connectivity
docker exec phase4-api psql -h phase4-postgres -U phase4_admin \
  -d phase4_incidents -c "SELECT * FROM incidents LIMIT 1;"
```

### ML Model Not Loading

```bash
# Check MLflow server
curl http://localhost:5001/api/2.0/mlflow/version

# List models in MLflow
curl http://localhost:5001/api/2.0/mlflow/registered-models/list
```

### RabbitMQ/Celery Issues

```bash
# Check RabbitMQ status
docker exec phase4-rabbitmq rabbitmq-diagnostics ping

# View Celery workers
docker exec phase4-celery-worker celery -A phase4.events.tasks inspect active

# Purge failed tasks
docker exec phase4-celery-worker celery -A phase4.events.tasks purge
```

---

## Next Steps

1. **Deploy to Production:**
   - Use PaaS (EKS, GKE, AKS) for scaling
   - Set up DB replicas
   - Configure SSL/TLS
   - Implement rate limiting

2. **Extend ML Models:**
   - Add custom features for your environment
   - Train attack pattern classifier on your data
   - Implement canary deployment

3. **Integrate Additional Feeds:**
   - Connect MISP instance
   - Add custom threat feeds
   - Implement STIX/TAXII consumer

4. **Develop Custom Playbooks:**
   - Map your IR processes to playbooks
   - Add approval workflows
   - Integrate with Slack/Teams/Jira

---

**Questions? See [TROUBLESHOOTING.md](../TROUBLESHOOTING.md) or [OPERATIONS.md](../OPERATIONS.md)**
