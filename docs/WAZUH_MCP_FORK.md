# Forked MCP SIEM README (upstream Wazuh MCP Server v4.2.1)

> This file is the inherited product README from
> [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) v4.2.1, kept as
> operational documentation for the SIEM tool surface. The Marifort front door is
> [README.md](../README.md). Licence: MIT, dual copyright — see [LICENSE](../LICENSE) and
> [NOTICE](../NOTICE).

# Wazuh MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![MCP 2025-11-25](https://img.shields.io/badge/MCP-2025--11--25-green.svg)](https://modelcontextprotocol.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://github.com/gensecaihq/Wazuh-MCP-Server)

**Talk to your SIEM.** Query alerts, hunt threats, check vulnerabilities, and trigger active responses across your entire Wazuh deployment — through natural conversation with any AI assistant.

> **v4.2.1** | 51 security tools | Wazuh 4.8.0–4.14.4 | [Changelog](CHANGELOG.md)

---

## What This Does

Your Wazuh SIEM generates thousands of alerts, vulnerability findings, and agent events daily. Investigating them means juggling dashboards, writing API queries, and manually correlating data across tools.

This MCP server turns that workflow into a conversation:

```
You:    "Show me critical alerts from the last hour"
AI:     [calls get_wazuh_alerts] Found 3 critical alerts:
        1. SSH brute force from 10.0.1.45 → agent-003 (Rule 5712, Level 10)
        2. Rootkit detection on agent-007 (Rule 510, Level 12)
        3. FIM change /etc/shadow on agent-001 (Rule 550, Level 10)

You:    "Block that source IP on agent-003"
AI:     [calls wazuh_block_ip] Blocked 10.0.1.45 via firewall-drop on agent-003.

You:    "Which agents have unpatched critical CVEs?"
AI:     [calls get_critical_vulnerabilities] 3 agents with critical vulnerabilities...
```

It works with **Claude Desktop**, **Open WebUI + Docker Model Runner** (fully local, air-gapped), or any MCP-compliant client.

## MCP Security Proxy Status

For current standalone MCP proxy feature status (implemented now vs planned), see:

- `mcp-security-proxy/README.md` (Implementation Status Snapshot)
- `docs/MCP_PROXY_COMMERCIAL_PACKAGING.md` (commercial packaging and feature boundaries)

---

## Works With Cloud AND Local LLMs

This is a standard MCP tool server. It doesn't care what LLM you use — it just executes tools and returns results.

| Mode | LLM | Client | Data leaves your network? |
|------|-----|--------|--------------------------|
| **Cloud** | Claude, GPT, etc. | Claude Desktop, any MCP client | Yes (to LLM provider) |
| **Local** | Llama, Qwen, Mistral via Docker Model Runner | Open WebUI, IBM/mcp-cli | **No. Fully air-gappable.** |

**For security teams that can't send SIEM data to cloud APIs** (compliance, air-gapped networks, data sovereignty), the local mode with Docker Model Runner keeps everything on-premises. Both modes coexist — same server, same tools, same API.

### Quick Start: Full Stack with Docker Model Runner

Everything — Wazuh 4.8, MCP server, local LLM, and chat UI — in a single command. Uses [Docker Model Runner](https://docs.docker.com/ai/model-runner/) (built into Docker Desktop 4.40+) for fully local, air-gapped LLM inference with no extra installs.

Migrating this repo to your own private GitHub project? See [GitHub Repository Migration Checklist](#github-repository-migration-checklist).

**Prerequisites:** Docker Desktop 4.40+ with Model Runner enabled (`Settings -> AI -> Enable Docker Model Runner`) and Docker Compose v2.38+.

On Linux hosts, set the OpenSearch kernel limit first:

```bash
sudo sysctl -w vm.max_map_count=262144
```

```bash
# 1. Create the env file used by the MCP server and Open WebUI
cp .env.example .env

# Optional but recommended: set a stable MCP API key so Open WebUI can be
# preconfigured automatically instead of relying on the demo fallback value.
# MCP_API_KEY=wazuh_your-generated-key-here

# Optional: override the default low-memory Docker Model Runner profile.
# MODEL_RUNNER_MODEL=ai/gemma3-qat

# 2. Start the full stack
#    - Wazuh cert generator
#    - Wazuh indexer
#    - Wazuh manager
#    - Wazuh dashboard
#    - Wazuh MCP server
#    - Open WebUI
docker compose -f compose.full.yml up -d --build

# 3. Watch services until the dashboard and MCP server are up
docker compose -f compose.full.yml ps
```

The full stack includes an `apache-log-generator` service that continuously writes synthetic Apache access logs into Wazuh for testing and demos.

First startup takes a few minutes because the stack generates TLS certificates, initializes Wazuh Indexer, and starts the embedded Wazuh services in dependency order.

After startup:

- Open WebUI: `http://localhost:3100`
- Wazuh Dashboard: `https://localhost:8443`
- Wazuh MCP API: `http://localhost:3000/mcp`
- MCP health check: `http://localhost:3000/health`

The Wazuh Dashboard uses a self-signed certificate in this demo stack, so your browser will show a certificate warning on first visit. Continue past the warning and sign in with:

- Username: `admin`
- Password: `SecretPassword`

Open **http://localhost:3100**, create your Open WebUI admin account, then connect the MCP server once:

The full stack now pre-registers the Wazuh MCP server automatically. On a fresh stack, by the time Open WebUI is up, the MCP connection is already present.

Step by step in Open WebUI:

1. Open `http://localhost:3100` in your browser.
2. On first launch, create the initial Open WebUI admin account.
3. Sign in and open the admin area.
4. Go to **Admin Panel** -> **Settings** -> **Integrations** -> **Manage Tool Servers**.
5. Confirm that **Wazuh MCP Server** is already listed.
6. Start a new chat and ask a simple Wazuh question such as `Show me Wazuh cluster health` to verify the tool connection.

If you want a custom bearer token instead of the demo fallback, set `MCP_API_KEY` in `.env` before `docker compose up`. The same value is injected into both the MCP server and Open WebUI's preloaded tool-server config.

Why this URL works: Open WebUI and the MCP server run on the same Docker Compose network, so `wazuh-mcp-server` resolves as the internal container hostname.

Docker Model Runner uses `ai/gemma3-qat` by default and injects the OpenAI-compatible endpoint directly into Open WebUI via Compose model bindings — no manual URL configuration needed. This default is intentionally lighter on memory than larger Qwen variants.

> Override the model anytime from `.env` with `MODEL_RUNNER_MODEL`. Any compatible model from [Docker Hub `ai/` namespace](https://hub.docker.com/u/ai) works.

Low-memory model examples:

- `MODEL_RUNNER_MODEL=ai/gemma3-qat`
- `MODEL_RUNNER_MODEL=ai/qwen3`
- `MODEL_RUNNER_MODEL=docker.io/ai/qwen3:14B-Q6_K` if you explicitly want the larger Qwen model

The default context size remains `4096` to keep memory use lower.

Suggested presets:

- Ultra-low-RAM: `MODEL_RUNNER_MODEL=ai/gemma3-qat`
- Balanced Qwen: `MODEL_RUNNER_MODEL=ai/qwen3`
- Larger Qwen: `MODEL_RUNNER_MODEL=docker.io/ai/qwen3:14B-Q6_K`

After changing the model in `.env`, apply it with:

```bash
docker compose -f compose.full.yml up -d open-webui
```

Verification commands:

```bash
# 1) Confirm stack services are running
docker compose -f compose.full.yml ps

# 1b) Confirm synthetic Apache log generator is running
docker compose -f compose.full.yml logs --tail=20 apache-log-generator

# 2) Confirm MCP server health + auth mode
curl -sf http://localhost:3000/health

# 3) Confirm Open WebUI saved MCP server URL + key settings
docker exec open-webui sh -lc "python - <<'PY'
import sqlite3, json
conn = sqlite3.connect('/app/backend/data/webui.db')
cur = conn.cursor()
cur.execute('SELECT data FROM config ORDER BY id DESC LIMIT 1')
row = cur.fetchone()
cfg = json.loads(row[0]) if row else {}
print(json.dumps(cfg.get('tool_server', {}), indent=2))
PY"
```

Expected values:
- `url`: `http://wazuh-mcp-server:3000/mcp`
- `auth_type`: `bearer`
- `config.enable`: `true`
- `key`: your `MCP_API_KEY` value from `.env`

Test AI queries against generated logs and alerts:

1. Wait 1-2 minutes after startup so Wazuh indexes generated events.
2. In Open WebUI, ask prompts such as:
    - `Show me the latest Wazuh alerts related to Apache or web attacks.`
    - `Search security events for sqlmap SQL injection attempts in the last hour.`
    - `Find all nikto vulnerability scanner activity in the web logs.`
    - `Analyze WordPress login attacks and brute-force attempts from the last 2 hours.`
    - `What are the top attack sources hitting our web servers?`
3. If you need faster/slower event generation, set `APACHE_LOG_GENERATOR_INTERVAL_SECONDS` in `.env` (default: `3`) and restart only the generator:

```bash
docker compose -f compose.full.yml up -d apache-log-generator
```

Apache log generator details:

- Service name: `apache-log-generator`
- Log file target: `/var/ossec/logs/apache_access.log` (shared `wazuh_logs` Docker volume)
- Wazuh ingestion path: manager `localfile` with `log_format` set to `apache`
- Default cadence: every `3` seconds (`APACHE_LOG_GENERATOR_INTERVAL_SECONDS`, configurable in `.env`)
- Build behavior: no custom image build required for the generator (`alpine:3.21` image). Running full-stack `--build` rebuilds local project images (such as `wazuh-mcp-server`) and keeps the generator pulled from registry.

**Attack Patterns Generated:**

The generator creates realistic web attack traffic for testing, training, and Phase 2 analysis workflows. Four attack streams run concurrently, each from a distinct source IP:

| Attack Type | Source IP | Pattern Examples | User Agents |
|-------------|-----------|------------------|------------|
| **SQL Injection** | `198.51.100.27` | UNION-based payloads, login bypasses, database enumeration | `sqlmap/1.8.20201219.2` |
| **Web Scanners** | `198.51.100.28` | Route enumeration, admin path discovery, fingerprinting | `nikto/2.5.0` |
| **WordPress Attacks** | `192.0.2.99` | Login brute-force, password reset abuse, REST API enumeration | `curl/8.7.1`, custom user agents |
| **Legitimate Traffic** | `203.0.113.44` | Normal web requests, CSS/JS resources | `Mozilla/5.0` |

**SQL Injection Attempts** (4 patterns, `198.51.100.27`):
```
GET /index.php?id=1' UNION SELECT NULL,NULL,NULL--
GET /search.php?q=admin' OR '1'='1
POST /api/login (with sqlmap payloads)
GET /product.php?id=-1 UNION ALL SELECT database(),version(),user()--
```

**Web Scanner Activity** (6 patterns, `198.51.100.28`):
```
GET /            (root enumeration)
GET /admin/      (admin panel discovery)
GET /administrator/
GET /phpmyadmin/ (database interface probe)
HEAD /server-status
OPTIONS /        (method enumeration)
```

**WordPress Login Attacks** (5 patterns, `192.0.2.99`):
```
POST /wp-login.php        (brute-force attempts)
GET /wp-login.php?action=lostpassword
GET /wp-admin/admin-ajax.php?action=heartbeat
GET /wp-json/wp/v2/users  (REST API user enum)
```

**Customizing Log Generation:**

Adjust the attack frequency and log output interval in `.env`:

```bash
# Logs generated every 3 seconds (default)
APACHE_LOG_GENERATOR_INTERVAL_SECONDS=3

# For faster attack simulation (1 second)
APACHE_LOG_GENERATOR_INTERVAL_SECONDS=1

# For slower, sparser logs (10 seconds)
APACHE_LOG_GENERATOR_INTERVAL_SECONDS=10
```

Restart the generator to apply:

```bash
docker compose -f compose.full.yml up -d apache-log-generator
```

**Using with Phase 2 Analysis:**

Query the generated attack patterns through Phase 2 workflows:

```bash
# Run enrichment targeting SQL injection attempts
PHASE2_DEMO_ENRICH_QUERY='sqlmap' ./tools/demo_phase2_orchestration.sh

# Analyze WordPress login attacks
PHASE2_DEMO_ENRICH_QUERY='wp-login.php' ./tools/demo_phase2_orchestration.sh

# Comprehensive web attack analysis
PHASE2_DEMO_ENRICH_QUERY='sqlmap OR nikto OR wp-login.php' ./tools/demo_phase2_orchestration.sh
```

**Expected Phase 2 Demo Output:**

The Phase 2 orchestration demo runs four sequential steps. Console output shows summary stats with preview text truncated for readability:

```
[1/4] Phase 2 triage
triage_engine=langchain
triage_status=LangChain synthesis enabled
triage_model=ai/gemma3-qat:latest
triage_total_alerts=5
triage_top_rules=2

[2/4] Phase 2 enrichment
enrich_engine=langchain
enrich_status=LangChain synthesis enabled (compact payload retry)
enrich_match_count=10
enrich_filters={'time_range': '24h', 'query': 'sqlmap OR nikto OR wp-login.php', ...}
enrich_analysis_preview=Here's a summary of the Wazuh facts provided, designed for operational use...
[Analysis truncated for display; full output available via MCP tool call]

[3/4] Phase 2 SOC handoff report
report_engine=langchain
report_status=LangChain synthesis enabled (ultra-compact payload retry)
report_type=shift
report_sections=7
report_analysis_preview=Here's a concise SOC handoff report summary based on the provided Wazuh facts...
[Analysis truncated for display; full output available via MCP tool call]

[4/4] Phase 2 orchestration demo completed
```

To view the **complete untruncated analysis**, call the Phase 2 tools directly via Open WebUI or the MCP API:

```bash
# Retrieve token from .env
MCP_API_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)

# Get full triage analysis via MCP API
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"1h"}}}' | python3 tools/format_phase2_output.py

# Or in Open WebUI: ask "Analyze critical alerts and provide a detailed triage summary"
```

**Querying Attack Patterns via MCP API:**

Target specific attack patterns generated by the apache-log-generator:

```bash
# Retrieve token from .env
MCP_API_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)

# Query SQL Injection attempts (sqlmap)
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"search_security_events",
      "arguments":{
        "query":"sqlmap",
        "time_range":"24h",
        "limit":10
      }
    }
  }' | python3 tools/format_phase2_output.py

# Query Web Scanner activity (nikto)
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"search_security_events",
      "arguments":{
        "query":"nikto",
        "time_range":"24h",
        "limit":10
      }
    }
  }' | python3 tools/format_phase2_output.py

# Query WordPress login attacks
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"search_security_events",
      "arguments":{
        "query":"wp-login.php",
        "time_range":"24h",
        "limit":10
      }
    }
  }' | python3 tools/format_phase2_output.py

# Query all web attacks (combined)
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"search_security_events",
      "arguments":{
        "query":"sqlmap OR nikto OR wp-login.php",
        "time_range":"24h",
        "limit":20
      }
    }
  }' | python3 tools/format_phase2_output.py

# Enrich context with full Phase 2 analysis (compact retry handling)
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"enrich_wazuh_context",
      "arguments":{
        "time_range":"24h",
        "query":"sqlmap OR nikto OR wp-login.php",
        "limit":10
      }
    }
  }' | python3 tools/format_phase2_output.py

# Generate SOC handoff report for web attacks
curl -s http://localhost:3000/mcp \
  -H "Authorization: Bearer $MCP_API_KEY" \
  -d '{
    "jsonrpc":"2.0",
    "id":1,
    "method":"tools/call",
    "params":{
      "name":"generate_soc_handoff_report",
      "arguments":{
        "time_range":"24h",
        "query":"sqlmap OR nikto OR wp-login.php",
        "report_type":"shift"
      }
    }
  }' | python3 tools/format_phase2_output.py
```

The generator ensures that Phase 2 triage, enrichment, and report tools always have realistic data to analyze with full, untruncated AI-generated summaries.

Generator validation commands:

```bash
# 1) Confirm generator container is up
docker compose -f compose.full.yml ps apache-log-generator

# 2) Confirm generator startup and loop logs
docker compose -f compose.full.yml logs --tail=30 apache-log-generator

# 3) Confirm Apache lines are being written in Wazuh manager
docker exec wazuh-soc-wazuh.manager-1 sh -lc "tail -n 10 /var/ossec/logs/apache_access.log"

# 4) Confirm Wazuh is watching the file
docker exec wazuh-soc-wazuh.manager-1 sh -lc "grep -E 'apache_access.log|wazuh-logcollector' /var/ossec/logs/ossec.log | tail -n 20"

# 5) Confirm alerts are generated from the synthetic traffic
docker exec wazuh-soc-wazuh.manager-1 sh -lc "grep -E 'apache_access.log|wp-login|phpmyadmin|sqlmap|nikto' /var/ossec/logs/alerts/alerts.json | tail -n 20"
```

Expected alert patterns from generated traffic:

- Rule `31101`: `Web server 400 error code` (for `401/403/404` requests)
- Rule `31508`: `Blacklisted user agent (known malicious user agent)` (for `nikto` user-agent)
- Rule `31103` / `31104`: HTTP method-specific rules (OPTIONS, HEAD)
- `location` field should be `/var/ossec/logs/apache_access.log`

Alert sample matching `sqlmap OR nikto OR wp-login.php`:

```json
{
  "timestamp": "2026-04-15T10:15:32.000Z",
  "rule": { "id": 31508, "level": 5, "description": "Blacklisted user agent (sqlmap)" },
  "data": { "srcip": "198.51.100.27", "http_user_agent": "sqlmap/1.8.20201219.2" },
  "location": "/var/ossec/logs/apache_access.log"
}
```

If you changed `config/wazuh_cluster/wazuh_manager.conf`, restart Wazuh manager to reload localfile inputs:

```bash
docker compose -f compose.full.yml restart wazuh.manager
```

Next steps:

1. Replace demo defaults in `.env` before exposing this stack beyond local testing:
    - Set `MCP_API_KEY` to a strong random value.
    - Set `AUTH_SECRET_KEY` to a strong random value.
    - Set `WEBUI_SECRET_KEY` to a strong random value.
    - Rotate default Wazuh credentials (`admin`, `wazuh-wui`, `kibanaserver`).
2. Re-apply the relevant services after updating secrets:

```bash
docker compose -f compose.full.yml up -d --build wazuh-mcp-server open-webui open-webui-config-init
```

3. Run a functional smoke test in Open WebUI by asking:
    - `Show me Wazuh cluster health`
    - Confirm the assistant executes the MCP tool call successfully.
4. For team rollout, keep `.env` out of version control and document the verification commands in your internal runbook.

Useful commands:

```bash
# Follow startup logs
docker compose -f compose.full.yml logs -f

# Restart the full stack
docker compose -f compose.full.yml restart

# Stop everything but keep data
docker compose -f compose.full.yml down

# Remove all containers and persistent volumes
docker compose -f compose.full.yml down -v
```

If you want to run the MCP server against an existing external Wazuh deployment instead of the embedded stack, use `compose.yml` and the standard `.env` variables below.

### Multi-User SOC with Open WebUI

Open WebUI v0.6.31+ connects to the `/mcp` endpoint natively. The `compose.full.yml` above includes Open WebUI pre-wired to Docker Model Runner, giving your entire team AI-powered SIEM analysis with conversation history, RBAC, and a web UI — all on-premises.

---

## 51 Security Tools

Every tool is validated, rate-limited, scope-checked, and audit-logged.

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Alerts** (4) | `get_wazuh_alerts` `get_wazuh_alert_summary` `analyze_alert_patterns` `search_security_events` | Query, filter, search, and analyze alert data via Elasticsearch |
| **Agents** (6) | `get_wazuh_agents` `get_wazuh_running_agents` `check_agent_health` `get_agent_processes` `get_agent_ports` `get_agent_configuration` | Monitor agent status, running processes, open ports, and configs |
| **Vulnerabilities** (3) | `get_wazuh_vulnerabilities` `get_critical_vulnerabilities` `vulnerability_summary` | Query CVEs by severity, agent, and package |
| **Security Analysis** (6) | `analyze_security_threat` `check_ioc_reputation` `perform_risk_assessment` `get_top_security_threats` `generate_security_report` `run_compliance_check` | Threat analysis, IOC lookup, risk scoring, compliance checks |
| **System** (10) | `get_wazuh_statistics` `get_wazuh_cluster_health` `get_wazuh_rules_summary` `search_wazuh_manager_logs` ... | Cluster health, rules, manager logs, stats |
| **SOC Orchestration** (3) | `triage_wazuh_alerts` `enrich_wazuh_context` `generate_soc_handoff_report` | Read-only analyst workflows for triage, enrichment, and handoff reporting |
| **Active Response** (9) | `wazuh_block_ip` `wazuh_isolate_host` `wazuh_kill_process` `wazuh_disable_user` `wazuh_quarantine_file` ... | Block IPs, isolate hosts, kill processes, quarantine files |
| **Verification** (5) | `wazuh_check_blocked_ip` `wazuh_check_agent_isolation` `wazuh_check_process` `wazuh_check_user_status` ... | Verify active response actions took effect |
| **Rollback** (5) | `wazuh_unisolate_host` `wazuh_enable_user` `wazuh_restore_file` `wazuh_firewall_allow` `wazuh_host_allow` | Undo active response actions |

---

## Quick Start

### Prerequisites

- Docker 20.10+ with Compose v2
- Wazuh 4.8.0–4.14.4 with API access enabled

### Deploy

```bash
git clone https://github.com/gensecaihq/Wazuh-MCP-Server.git
cd Wazuh-MCP-Server
cp .env.example .env
```

Edit `.env`:
```env
WAZUH_HOST=your-wazuh-server
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
```

```bash
docker compose up -d
curl http://localhost:3000/health
```

### Connect Claude Desktop

1. **Settings** → **Connectors** → **Add custom connector**
2. URL: `https://your-server/mcp`
3. Add Bearer token in Advanced settings

> Detailed setup: [Claude Integration Guide](docs/CLAUDE_INTEGRATION.md)

---

## Security

This server sits between an LLM and your SIEM. Security is not optional.

| Layer | What It Does |
|-------|-------------|
| **RBAC** | Per-tool scope enforcement. 14 active response tools require `wazuh:write`. Read-only tokens can query but never trigger actions. Authless mode is read-only by default. |
| **Audit Logging** | Every destructive tool call (block IP, isolate host, kill process) is logged with client ID, session, timestamp, and full arguments. |
| **Output Sanitization** | Credentials, tokens, and API keys in alert `full_log` fields are redacted before reaching the LLM. Prevents credential leakage through AI responses. |
| **Input Validation** | Every parameter validated: regex agent IDs, `ipaddress` module for IPs, shell metacharacter blocking for active response, Elasticsearch Query DSL (no string interpolation). |
| **Rate Limiting** | Per-client sliding window with escalating block duration (10s → 5min). |
| **Circuit Breakers** | Wazuh API failures trigger fail-fast for 60s, auto-recover. Single trial in HALF_OPEN state. |
| **Log Sanitization** | Global filter redacts passwords, tokens, secrets from all server logs. |
| **Container Hardening** | Non-root user, read-only filesystem, `CAP_DROP ALL`, `no-new-privileges`. |

```bash
# Generate a secure API key
python -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
```

---

## Configuration

### Required

| Variable | Description |
|----------|-------------|
| `WAZUH_HOST` | Wazuh Manager hostname or IP |
| `WAZUH_USER` | API username |
| `WAZUH_PASS` | API password |

### Optional

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_PORT` | `55000` | Manager API port |
| `MCP_HOST` | `0.0.0.0` | Server bind address |
| `MCP_PORT` | `3000` | Server port |
| `AUTH_MODE` | `bearer` | `oauth`, `bearer`, or `none` |
| `AUTH_SECRET_KEY` | auto-generated | JWT signing key |
| `AUTHLESS_ALLOW_WRITE` | `false` | Allow active response in authless mode |
| `ALLOWED_ORIGINS` | `https://claude.ai` | CORS origins (comma-separated) |
| `REDIS_URL` | — | Redis URL for multi-instance session storage |

### Optional Phase 2 LangChain Settings

The SOC orchestration tools can use LangChain to turn structured Wazuh data into analyst-facing summaries while keeping the workflow read-only.

| Variable | Default | Description |
|----------|---------|-------------|
| `PHASE2_LLM_ENABLED` | `false` | Enable LangChain synthesis for Phase 2 tools |
| `PHASE2_LLM_MODEL` | empty | Model name exposed by your OpenAI-compatible local endpoint |
| `PHASE2_LLM_BASE_URL` | empty | Base URL for a local OpenAI-compatible API, such as Docker Model Runner, Open WebUI, Ollama proxy, or vLLM |
| `PHASE2_LLM_API_KEY` | empty | Optional API key for the endpoint; a local placeholder is used if omitted |
| `PHASE2_LLM_TIMEOUT_SECONDS` | `30` | Timeout for Phase 2 LLM synthesis requests |

Example:

```env
PHASE2_LLM_ENABLED=true
PHASE2_LLM_MODEL=ai/qwen3
PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
PHASE2_LLM_API_KEY=not-needed
PHASE2_LLM_TIMEOUT_SECONDS=45
```

If these settings are not configured, the Phase 2 tools still work using deterministic summaries and recommendations.

Quick verification:

```bash
./tools/verify_phase2_langchain.sh
```

What it validates:

- MCP health endpoint is reachable and reports `healthy`
- Phase 2 tool call (`triage_wazuh_alerts`) succeeds
- `data.analysis` exists and is non-empty
- `data.orchestration.engine=langchain`

Useful options:

```bash
# Allow setup-time fallback as success
./tools/verify_phase2_langchain.sh --allow-deterministic

# Target a non-default MCP endpoint
./tools/verify_phase2_langchain.sh --base-url http://localhost:3000
```

Environment overrides supported by the script:

- `MCP_API_KEY` (falls back to `.env` if unset)
- `MCP_BASE_URL` (default `http://localhost:3000`)
- `PHASE2_TEST_TIME_RANGE` (default `24h`)
- `PHASE2_TEST_MIN_LEVEL` (default `10`)
- `PHASE2_TEST_LIMIT` (default `20`)
- `PHASE2_TEST_INCLUDE_AGENT_HEALTH` (default `true`)

For complete troubleshooting guidance and expected output examples, see [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md).

### GitHub Repository Migration Checklist

If you are moving this project to a new private GitHub repository, use this quick checklist:

1. Create a private repository on GitHub under your account (do not initialize with README, license, or gitignore).
2. Ensure local remote points to the expected repository URL:

```bash
git remote set-url origin https://github.com/<owner>/<repo>.git
git branch -M main
```

3. Push with interactive credentials if terminal appears stuck:

```bash
GIT_TERMINAL_PROMPT=1 GIT_ASKPASS= SSH_ASKPASS= DISPLAY= \
git -c core.askPass= -c credential.helper= push -u origin main -v
```

4. Authenticate with username + GitHub PAT (not account password).
5. If workflow files are present in `.github/workflows/*`, ensure PAT includes workflow permissions.
6. Optional: switch remote to SSH to avoid PAT prompts on future pushes.

See [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md#git-push-hangs-or-fails-during-github-migration) for full troubleshooting and the optional `~/.ssh/config` block.

### Wazuh Indexer (for alert search + vulnerabilities)

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_INDEXER_HOST` | — | Indexer hostname |
| `WAZUH_INDEXER_PORT` | `9200` | Indexer port |
| `WAZUH_INDEXER_USER` | — | Indexer username |
| `WAZUH_INDEXER_PASS` | — | Indexer password |

> Full reference: [Configuration Guide](docs/configuration.md)

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/mcp` | POST/GET/DELETE | MCP Streamable HTTP (recommended) |
| `/sse` | GET | Legacy Server-Sent Events |
| `/health` | GET | Health check (no auth required) |
| `/metrics` | GET | Prometheus metrics |
| `/auth/token` | POST | Exchange API key for JWT |
| `/docs` | GET | OpenAPI documentation |

---

## Architecture

```
src/wazuh_mcp_server/
├── server.py           # MCP protocol + 48 tool handlers
├── config.py           # Environment-based configuration
├── auth.py             # JWT + API key authentication
├── oauth.py            # OAuth 2.0 with Dynamic Client Registration
├── security.py         # Rate limiting, CORS, input validation
├── monitoring.py       # Prometheus metrics, structured logging
├── resilience.py       # Circuit breakers, retries, graceful shutdown
├── session_store.py    # Pluggable sessions (in-memory + Redis)
└── api/
    ├── wazuh_client.py    # Wazuh Manager REST API client
    └── wazuh_indexer.py   # Wazuh Indexer (Elasticsearch) client
```

---

## Take It Further: Autonomous Agentic SOC

Combine this MCP server with [**Wazuh OpenClaw Autopilot**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot) to build a fully autonomous Security Operations Center.

While this server gives you conversational access to Wazuh, OpenClaw deploys AI agents that **work around the clock** — triaging alerts, correlating incidents, and recommending responses without human intervention.

```
Manual SOC:    Alert → Analyst reviews → Hours → Response
Agentic SOC:   Alert → AI triages → Seconds → Response ready for approval
```

[**Explore OpenClaw Autopilot**](https://github.com/gensecaihq/Wazuh-Openclaw-Autopilot)

---

## Documentation

| Guide | Description |
|-------|-------------|
| [Claude Integration](docs/CLAUDE_INTEGRATION.md) | Claude Desktop setup and authentication |
| [Configuration](docs/configuration.md) | Full configuration reference |
| [Advanced Features](docs/ADVANCED_FEATURES.md) | HA, serverless, compact mode |
| [API Documentation](docs/api/) | Per-tool documentation |
| [LangChain Phase 2 Guide](docs/LANGCHAIN_PHASE2_GUIDE.md) | Complete LangChain conversation outcomes, config, and verification flow |
| [LangGraph Phase 3 Guide](docs/LANGGRAPH_PHASE3_GUIDE.md) | Guarded write-action workflow, Langfuse architecture, build guide, hooks, smoke tests, and UI verification |
| [Phase 4 Smoke Test and User Guide](docs/PHASE4_SMOKE_TEST_AND_USER_GUIDE.md) | Route-level smoke testing plus practical Incident, Playbook, Analytics, and ML usage examples |
| [OpenCTI Integration](docs/OPENCTI_INTEGRATION.md) | Threat-intel overlay: architecture, worker role, push flow, native arm64 build, and operations |
| [MCP Observability](docs/MCP_OBSERVABILITY.md) | Per-call MCP traffic monitoring with Prometheus + Grafana (persistent), live SSE feed, JSON APIs |
| [Autonomous Threat Hunting + MCP Proxy Policy](docs/AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md) | Autonomous hunting flow, MCP security proxy deny rules, denied-call dashboards, and LLM analysis of proxy denials |
| [AgentGuard Local LLM Demo](docs/AGENTGUARD_LOCAL_LLM_DEMO.md) | Copy-paste demo runbook for AgentGuard in front of Docker Model Runner local LLM |
| [Local Optimization and Runtime Profiles](docs/LOCAL_OPTIMIZATION_AND_PROFILES.md) | Single-workstation tuning, profile A-D startup and shutdown, and local service optimization guidance |
| [Security](docs/security/) | Security hardening guide |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [Operations](docs/OPERATIONS.md) | Deployment, monitoring, maintenance, and Git label check-in/publish plus checkout workflow |

---

## Contributing

We welcome contributions. See [Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues) for bugs and feature requests, [Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions) for questions.

---

## License

[MIT](LICENSE)

---

## Acknowledgments

- [Wazuh](https://wazuh.com/) — Open source security platform
- [Model Context Protocol](https://modelcontextprotocol.io/) — AI tool integration standard
- [Docker Model Runner](https://docs.docker.com/ai/model-runner/) — Built-in local LLM inference for Docker Desktop
- [Open WebUI](https://github.com/open-webui/open-webui) — Self-hosted AI chat interface

---

<details>
<summary><strong>Contributors</strong></summary>

<!-- CONTRIBUTORS-START -->
### Contributors

| Avatar | Username | Contributions |
|--------|----------|---------------|


**Legend:** 💻 Code · 🐛 Issues · 🔀 Pull Requests · 💬 Discussions
<!-- CONTRIBUTORS-END -->

> Auto-updated by [GitHub Actions](.github/workflows/update-contributors.yml)

</details>
