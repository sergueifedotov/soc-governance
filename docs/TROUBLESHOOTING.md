## LangChain Synthesis Fails with Context Size Error

**Symptom:**

When running `tools/verify_phase2_langchain.sh` or calling `triage_wazuh_alerts`, you see an error like:

```
LangChain synthesis failed: Error code: 400 - {'error': {'code': 400, 'message': 'request (2269 tokens) exceeds the available context size (2048 tokens)', ...}}
```

**Cause:**

The triage request is sending too many alerts or too much data for the model's context window. The LLM call is rejected, and the system falls back to deterministic mode (`engine=deterministic`).

**How to Fix:**

1. **Reduce the alert count or time window** for the triage tool so the payload fits the model's context size.
   - Example (run with smaller window and limit):
     ```bash
     PHASE2_TEST_LIMIT=5 PHASE2_TEST_TIME_RANGE=1h PHASE2_LLM_MODEL=ai/qwen3:latest bash tools/verify_phase2_langchain.sh
     PHASE2_TEST_LIMIT=5 PHASE2_TEST_TIME_RANGE=1h PHASE2_TEST_MIN_LEVEL=3 PHASE2_LLM_MODEL=ai/qwen3:14B-Q6_KV:latest bash tools/verify_phase2_langchain.sh
     PHASE2_TEST_LIMIT=5 PHASE2_TEST_TIME_RANGE=1h PHASE2_TEST_MIN_LEVEL=3 bash tools/verify_phase2_langchain.sh
     PHASE2_TEST_LIMIT=5 PHASE2_TEST_TIME_RANGE=1h PHASE2_TEST_MIN_LEVEL=5 bash tools/verify_phase2_langchain.sh     
    ```
   - Or, set these variables in your `.env` before running the verifier.
2. **(Optional)** If you control the model runner, increase the `context_size` in your model serving config (if supported by your model).

**Summary:**
- This is not a bug in your integration—LangChain is working, but the payload is too large for the model’s context window.
- Reducing the number of alerts or the time range will allow the LLM path to succeed and pass the verifier (`engine=langchain`).

**See also:** [OPERATIONS.md](OPERATIONS.md#cicd-verification-phase-2-langchain)

### Interpreting Phase 2 Compact-Retry Status Messages

After recent hardening, Phase 2 may report one of these statuses while still using LangChain successfully:

- `LangChain synthesis enabled`
- `LangChain synthesis enabled (compact payload retry)`
- `LangChain synthesis enabled (ultra-compact payload retry)`

Meaning:

- These are healthy outcomes where the first prompt exceeded context and the server retried with a reduced payload.
- If `engine=langchain`, synthesis succeeded and deterministic fallback was not used.

When to treat as an issue:

- `engine=deterministic` with `LangChain synthesis failed: ...` indicates retries also exceeded context or another model/runtime error occurred.
- In that case, reduce `time_range` or limits further, or increase model context size if available.

## Phase 2 Verifier Fails with `Tool execution failed: list index out of range`

**Symptom:**

When running `tools/verify_phase2_langchain.sh`, step 3 fails with:

```text
Tool call returned error: Tool execution failed: list index out of range
```

**Cause:**

This usually happens when the requested triage window returns no usable alert aggregations for the chosen filters. A narrow window such as `1h` combined with a high `min_level` can produce an empty result set. Older builds also had a bug in the deterministic fallback summary that indexed into empty `top_rules` or `top_agents` lists.

**How to Fix:**

1. Retry with a broader window or lower severity threshold so the triage tool has real alerts to summarize.

  ```bash
  PHASE2_TEST_TIME_RANGE=24h PHASE2_TEST_MIN_LEVEL=3 PHASE2_TEST_LIMIT=5 bash tools/verify_phase2_langchain.sh
  ```

2. If you want real-environment validation only, confirm fresh Wazuh alerts exist before re-running the verifier.

  ```bash
  MCP_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)
  curl -sS http://localhost:3000/ \
    -H "Authorization: Bearer $MCP_KEY" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":"diag-phase2","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"limit":5}}}' \
    | python3 -m json.tool
  ```

3. Rebuild and restart the MCP service if you were running a version affected by the empty-list fallback bug.

  ```bash
  docker compose -f compose.full.yml up -d --build wazuh-mcp-server
  ```

**What changed:**

- The fallback triage summary now handles empty `top_rules` and `top_agents` safely.
- If the verifier still fails after rebuilding, the problem is likely that the selected time window has too few alerts rather than a formatter crash.

## Smoke Test Shows No Alerts but Wazuh UI Shows Alerts

**Symptom:**

`tools/verify_phase2_langchain.sh` passes, but `analysis` says no alerts for `1h` while Wazuh Dashboard appears to show recent alerts.

**Why this happens:**

1. The verifier uses strict backend filters (`time_range`, `min_level`, `limit`) from `triage_wazuh_alerts`.
2. Dashboard views can still show older data depending on UI time picker and aggregation panels.
3. Frontend and backend timezone differences can make "last 1h" appear inconsistent.

**Quick checks:**

```bash
# Backend clock (UTC)
date -u '+backend_utc_now=%Y-%m-%dT%H:%M:%SZ'

# Latest alert timestamp visible to MCP backend
MCP_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"diag-latest","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"limit":1}}}' \
  | python3 -c 'import json,sys,re; o=json.load(sys.stdin); t=(o.get("result",{}).get("content") or [{}])[0].get("text",""); m=re.search(r"\{[\s\S]*\}\s*$",t); p=json.loads(m.group(0)) if m else {}; i=p.get("data",{}).get("affected_items",[]); print(i[0].get("timestamp") if i else "no_alerts")'
```

If the latest alert is older than one hour, `PHASE2_TEST_TIME_RANGE=1h` will correctly return zero alerts.

**Fix for mismatched frontend/backend time interpretation:**

1. Set a single timezone for all containers in `.env`:

```env
TZ=UTC
```

2. Recreate services so timezone env is applied:

```bash
docker compose -f compose.full.yml up -d --build wazuh-mcp-server wazuh.manager wazuh.indexer wazuh.dashboard open-webui apache-log-generator
```

3. Use the same time range in both places:
- Wazuh Dashboard time picker: set `Last 24 hours` (or the same range as verifier).
- Verifier: set `PHASE2_TEST_TIME_RANGE` to the same value.

**Known behavior reminder:**

- `PHASE2_LLM_MODEL=...` on the verifier command line does **not** override the running container model by itself.
- To change backend synthesis model, update `.env` and rebuild `wazuh-mcp-server`.

# Troubleshooting Guide

Common issues and their solutions.

## Smoke Test Fails with `playbook.execute.status=failed`

**Symptom:**

`tools/smoke_phase4.sh` reports a single failure like:

- `PASS playbook.execute.http`
- `FAIL playbook.execute.status: status_field=failed`

**Cause:**

The playbook route is reachable, but one or more active-response actions are being denied by MCP proxy policy (`tool_denied` / HTTP 403).

**Quick fix (policy-enforced environments):**

```bash
bash tools/smoke_phase4.sh --allow-playbook-failed
```

**Optional (pin a known active agent):**

```bash
bash tools/smoke_phase4.sh --agent-id 004 --allow-playbook-failed
```

**Notes:**

- Correct flag name is `--agent-id`.
- `BUILD_DATE` compose warning is non-blocking.
- If strict playbook success is required, relax MCP proxy policy for the required active-response tools and rerun without `--allow-playbook-failed`.

**Detailed runbook:**

See [Policy Tuning Recommendation Assistant API troubleshooting](autonomous-threat-hunting/13-policy-tuning-recommendations-api.md#troubleshooting-toolssmoke_phase4sh-playbook-status-failed).

## Discovery Alerts Query Fails with `Cannot iterate over null`

**Symptom:**

Running:

```bash
curl -sS http://localhost:8090/recent-discovery-alerts | jq '.alerts[]'
```

returns:

- `jq: error ... Cannot iterate over null`

**Cause:**

`/recent-discovery-alerts` is protected by MCP proxy auth. Without bearer token, proxy returns:

```json
{"detail":"Unauthorized"}
```

so `.alerts` does not exist.

**Quick fix:**

```bash
curl -sS "http://localhost:8090/recent-discovery-alerts?limit=50" \
  -H "Authorization: Bearer ${MCP_PROXY_API_KEY:-mcp_proxy_local_demo_change_me}" \
  | jq '.alerts[]?'
```

**Validate `write_tool_abuse` end-to-end:**

```bash
bash tools/test_discovery_write_tool_abuse.sh
```

This script triggers denied write-tool activity and verifies `write_tool_abuse` alerting under active-window deduplication.

## Git Push Hangs or Fails During GitHub Migration

**Symptoms:**

- `git push -u origin main` appears stuck for minutes after `Pushing to https://github.com/...`
- `remote: Invalid username or token. Password authentication is not supported for Git operations.`
- `remote rejected ... refusing to allow a Personal Access Token to create or update workflow ... without workflow scope`
- `remote: Repository not found.`

**Root causes:**

- Git is waiting for hidden credential input.
- GitHub account password was used instead of a PAT.
- PAT is missing required scopes (`repo`, and `workflow` when pushing `.github/workflows/*`).
- Repository URL is wrong or repository does not exist yet.

**Reliable interactive push command (forces terminal prompts):**

```bash
GIT_TERMINAL_PROMPT=1 GIT_ASKPASS= SSH_ASKPASS= DISPLAY= \
git -c core.askPass= -c credential.helper= push -u origin main -v
```

Use:

- Username: your GitHub username
- Password: a GitHub Personal Access Token (PAT), not your GitHub account password

**Clear wrong cached credential (macOS keychain):**

```bash
printf "protocol=https\nhost=github.com\nusername=<your-username>\n" | git credential-osxkeychain erase
```

**Fix PAT scope errors for workflow files:**

- Classic PAT: include `repo` and `workflow`.
- Fine-grained PAT: grant repo access with write permission to code contents and workflow/actions updates.

**Repository not found checks:**

```bash
git remote -v
git remote set-url origin https://github.com/<owner>/<repo>.git
```

Confirm the repository exists under the expected owner and name on GitHub.

### Optional: Switch to SSH (no PAT prompts)

```bash
ssh-keygen -t ed25519 -C "<your-email>"
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_ed25519
pbcopy < ~/.ssh/id_ed25519.pub
```

Add the copied public key in GitHub: `Settings -> SSH and GPG keys -> New SSH key`.

Test and switch remote:

```bash
ssh -T git@github.com
git remote set-url origin git@github.com:<owner>/<repo>.git
git push -u origin main
```

**Optional `~/.ssh/config` block:**

```sshconfig
Host github.com
  HostName github.com
  User git
  IdentityFile ~/.ssh/id_ed25519
  IdentitiesOnly yes
  AddKeysToAgent yes
  UseKeychain yes
```

## MCP Endpoint Issues

### Testing SSE Endpoint

```bash
# Test SSE endpoint authentication
curl -I http://localhost:3000/sse
# Expected: 401 Unauthorized (good - auth required)

# Test with valid token
curl -H "Authorization: Bearer your-jwt-token" \
     -H "Origin: http://localhost" \
     -H "Accept: text/event-stream" \
     http://localhost:3000/sse
# Expected: 200 OK with SSE stream

# Get new authentication token
curl -X POST http://localhost:3000/auth/token \
     -H "Content-Type: application/json" \
     -d '{"api_key": "your-api-key"}'
```

---

## Claude Desktop Connection Issues

```bash
# Verify Claude Desktop can reach the server
curl http://localhost:3000/health
# Expected: {"status": "healthy"}

# Check CORS configuration
grep ALLOWED_ORIGINS .env
# Should include: https://claude.ai,https://*.anthropic.com
```

**Common Causes:**
- Server not running or not accessible via HTTPS
- CORS not configured for Claude domains
- Using JSON config instead of Connectors UI (see [Claude Integration Guide](CLAUDE_INTEGRATION.md))

---

## Connection Refused

```bash
# Check service status
docker compose ps
docker compose logs wazuh-mcp-remote-server

# Verify port availability
netstat -ln | grep 3000

# Check if container is healthy
docker inspect wazuh-mcp-remote-server --format='{{.State.Health.Status}}'
```

**Common Causes:**
- Container not running
- Port 3000 already in use
- Docker network issues

---

## Authentication Errors

### Wazuh API Authentication

```bash
# Verify Wazuh credentials
curl -u "$WAZUH_USER:$WAZUH_PASS" "$WAZUH_HOST:$WAZUH_PORT/"

# Check environment variables
grep -E "WAZUH_USER|WAZUH_HOST" .env
```

### MCP API Key Issues

```bash
# Check API key in server logs
docker compose logs wazuh-mcp-remote-server | grep "API key"

# Exchange API key for token
curl -X POST http://localhost:3000/auth/token \
  -H "Content-Type: application/json" \
  -d '{"api_key": "wazuh_your-generated-api-key"}'
```

---

## SSL/TLS Issues

```bash
# Disable SSL verification for testing
echo "WAZUH_VERIFY_SSL=false" >> .env
docker compose up -d

# Check Wazuh SSL certificate
openssl s_client -connect your-wazuh-server:55000 </dev/null 2>/dev/null | openssl x509 -noout -dates
```

---

## Wazuh Connectivity Issues

### Wazuh Manager API

```bash
# Test direct API access
curl -k -u admin:password https://wazuh-server:55000/

# Check server logs for connection errors
docker compose logs wazuh-mcp-remote-server | grep -i "wazuh"
```

### Wazuh Indexer (Vulnerabilities)

For Wazuh 4.8.0+, vulnerability data requires the Indexer:

```bash
# Test Indexer connectivity
curl -k -u admin:password https://wazuh-indexer:9200/

# Verify Indexer configuration
grep -E "WAZUH_INDEXER" .env
```

**Required for vulnerability tools:**
```env
WAZUH_INDEXER_HOST=your-indexer-host
WAZUH_INDEXER_PORT=9200
WAZUH_INDEXER_USER=admin
WAZUH_INDEXER_PASS=your-password
```

---

## Performance Issues

### High Memory Usage

```bash
# Check container resource usage
docker stats wazuh-mcp-remote-server --no-stream

# View configured limits
grep -E "memory|cpus" compose.yml
```

### Slow Response Times

```bash
# Check Wazuh API latency
time curl -k -u admin:password https://wazuh-server:55000/agents

# Check server metrics
curl http://localhost:3000/metrics | grep request_duration
```

### Docker Model Runner Is Slow and Mac Fan Is Loud

If chat responses are slow and your laptop fan is roaring, the bottleneck is usually model inference load (Docker Model Runner) plus background event generation.

Use this proven low-noise preset.

#### 1) Set low-noise values

In `.env`:

```env
MODEL_RUNNER_MODEL=ai/gemma3-qat
APACHE_LOG_GENERATOR_INTERVAL_SECONDS=30
```

In `compose.full.yml` under `models.llm`:

```yaml
models:
  llm:
    model: ${MODEL_RUNNER_MODEL:-ai/gemma3-qat}
    context_size: 2048
```

Why this helps:
- Smaller model and smaller context window reduce CPU/GPU compute per token.
- Slower synthetic Apache event generation reduces background Wazuh processing load.

#### 2) Apply changes (only affected services)

```bash
docker compose -f compose.full.yml up -d open-webui apache-log-generator
```

#### 3) Verify settings are active

```bash
grep -E '^(MODEL_RUNNER_MODEL|APACHE_LOG_GENERATOR_INTERVAL_SECONDS)=' .env

awk 'BEGIN{p=0} /^models:/{p=1} p==1{print} /^services:/{exit}' compose.full.yml
```

Expected values:
- `MODEL_RUNNER_MODEL=ai/gemma3-qat`
- `APACHE_LOG_GENERATOR_INTERVAL_SECONDS=30`
- `context_size: 2048`

#### 4) Verify runtime load dropped

```bash
docker stats --no-stream --format 'table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.PIDs}}'
```

Notes:
- Docker Model Runner itself is managed by Docker Desktop and does not always appear as a normal container.
- You should still see lower CPU usage in `open-webui`, `wazuh.manager`, and `apache-log-generator` after tuning.

#### 5) Optional extra cooling (when not needed for demos)

```bash
# Stop dashboard if you are not actively using it
docker compose -f compose.full.yml stop wazuh.dashboard

# Stop synthetic attack traffic if you do not need fresh demo alerts
docker compose -f compose.full.yml stop apache-log-generator
```

#### 6) Roll back for higher quality answers

If you want better model quality and can tolerate more load:

```env
MODEL_RUNNER_MODEL=ai/qwen3
```

And in `compose.full.yml`:

```yaml
context_size: 4096
```

Then apply:

```bash
docker compose -f compose.full.yml up -d open-webui apache-log-generator
```

#### 7) If still slow after tuning

1. Disable voice transcription usage in Open WebUI while testing (audio transcription can spike CPU).
2. Close idle chat tabs/sessions and rerun `docker stats`.
3. In Docker Desktop, reduce contention by setting practical limits (for example 4 to 6 CPUs, 8 to 12 GB RAM).
4. Keep `APACHE_LOG_GENERATOR_INTERVAL_SECONDS` at 20 to 30 for quieter operation.

---

## Log Analysis

```bash
# Follow live logs
docker compose logs -f --timestamps wazuh-mcp-remote-server

# Search for errors
docker compose logs wazuh-mcp-remote-server | grep -i error

# Export logs for analysis
docker compose logs --since=24h wazuh-mcp-remote-server > server.log
```

---

## Apache Log Generator Issues (Full Stack)

## Open WebUI Shows Sample-Like Output Instead of Real Wazuh Data

If Open WebUI responses look like generic or demo examples, there are two common causes:

1. The model answered without executing MCP tools.
2. MCP tools ran successfully, but data came from the synthetic `apache-log-generator` service.

### How to verify MCP tool execution happened

```bash
docker compose -f compose.full.yml logs --tail=200 open-webui | grep -E "POST http://wazuh-mcp-server:3000/mcp|/api/chat/completions"
docker compose -f compose.full.yml logs --tail=200 wazuh-mcp-server | grep -E "POST /mcp|wazuh-alerts\*/_search|/agents\?"
```

If you do not see MCP traffic, Open WebUI did not use the tool path for that response.

### How to force tool-backed responses in Open WebUI

1. In Open WebUI, ensure the MCP server is enabled in Admin Settings -> Tools.
2. Start a fresh chat after enabling the tool server.
3. Use an explicit prompt that requires a tool call and metadata:

```text
You must call MCP tool triage_wazuh_alerts with time_range=1h, min_level=5, limit=20, include_agent_health=true.
Return only:
1) tool name called,
2) raw orchestration metadata,
3) triage findings from tool output.
If tool call fails, reply exactly TOOL_CALL_FAILED.
```

### Why results can still look like sample data

The full stack intentionally includes synthetic traffic via `apache-log-generator`. That creates realistic demo alerts with test IP ranges such as `198.51.100.x` and `192.0.2.x`.

Stop synthetic generation when validating real environment signals:

```bash
docker compose -f compose.full.yml stop apache-log-generator
```

Then run triage for a recent window (for example `15m`) after real events are ingested.

### How to get truly real Wazuh-backed output

1. Keep `wazuh.manager` and `wazuh.indexer` running.
2. Ingest real events (agent enrollment or real log forwarding).
3. Stop `apache-log-generator` during validation.
4. Use short time windows to avoid old synthetic alerts.

### Generator Not Running

```bash
# Check service status
docker compose -f compose.full.yml ps apache-log-generator

# Start generator
docker compose -f compose.full.yml up -d apache-log-generator

# Inspect recent startup logs
docker compose -f compose.full.yml logs --tail=50 apache-log-generator
```

Common causes:
- Wazuh manager is not healthy yet.
- Full stack was started with `compose.yml` instead of `compose.full.yml`.

### Logs Generated but No Wazuh Alerts

```bash
# Confirm Apache log file has fresh lines
docker exec wazuh-soc-wazuh.manager-1 sh -lc "tail -n 10 /var/ossec/logs/apache_access.log"

# Confirm logcollector is watching the file
docker exec wazuh-soc-wazuh.manager-1 sh -lc "grep -E 'apache_access.log|wazuh-logcollector' /var/ossec/logs/ossec.log | tail -n 20"

# Check alert output for expected web rules
docker exec wazuh-soc-wazuh.manager-1 sh -lc "grep -E 'apache_access.log|31101|31508|wp-login|phpmyadmin|nikto' /var/ossec/logs/alerts/alerts.json | tail -n 20"
```

If Wazuh does not show `Analyzing file: '/var/ossec/logs/apache_access.log'`, restart manager:

```bash
docker compose -f compose.full.yml restart wazuh.manager
```

### Event Rate Too High or Too Low

```bash
# Set generator rate in .env (seconds between batches)
echo "APACHE_LOG_GENERATOR_INTERVAL_SECONDS=10" >> .env

# Recreate only the generator service
docker compose -f compose.full.yml up -d apache-log-generator
```

Lower values increase event volume. Higher values reduce noise for demos.

---

## Health Check

```bash
# Full health status
curl -s http://localhost:3000/health | jq .

# Prometheus metrics
curl -s http://localhost:3000/metrics | head -50

# Container health
docker inspect wazuh-mcp-remote-server --format='{{json .State.Health}}' | jq .
```

For end-to-end MCP traffic monitoring (per-call latency, error rates, and
Grafana dashboards), see [MCP_OBSERVABILITY.md](MCP_OBSERVABILITY.md).

---

## Reset and Clean Start

```bash
# Stop and remove containers
docker compose down

# Remove volumes (WARNING: deletes data)
docker compose down --volumes

# Clean rebuild
docker compose build --no-cache
docker compose up -d
```

---

## Open WebUI Returns Generic Answers Instead of Real Alerts

**Symptom:** You ask a security question in Open WebUI and the model gives a general explanation instead of calling a Wazuh tool and returning live data.

This is almost always caused by one of three things, diagnosed in order below.

---

### Step 1 — Confirm the MCP server is reachable from Open WebUI

```bash
# Verify the MCP server container is healthy
docker compose -f compose.full.yml ps wazuh-mcp-server

# Hit the health endpoint directly
curl -s http://localhost:3000/health | python3 -m json.tool
# Expected: "status": "healthy", "services": { "wazuh_manager": "healthy", "wazuh_indexer": "healthy" }
```

If health is not healthy, check Wazuh manager and indexer first:

```bash
docker compose -f compose.full.yml ps wazuh.manager wazuh.indexer
docker compose -f compose.full.yml logs --tail=40 wazuh-mcp-server
```

---

### Step 2 — Confirm Open WebUI has the MCP server preloaded

```bash
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

Expected output:
```json
{
  "connections": [
    {
      "type": "mcp",
      "url": "http://wazuh-mcp-server:3000/mcp",
      "auth_type": "bearer",
      "key": "<your MCP_API_KEY>",
      "config": { "enable": true }
    }
  ]
}
```

If empty or wrong, re-run the bootstrap and restart Open WebUI:

```bash
docker compose -f compose.full.yml up -d open-webui-config-init
docker compose -f compose.full.yml restart open-webui
```

Also confirm the UI setting manually: **Admin Panel → Settings → Integrations → Manage Tool Servers** — the Wazuh MCP Server entry must be listed with a green status indicator.

---

### Step 3 — Verify a direct tool call returns live data

This bypasses Open WebUI entirely and confirms the MCP server itself works:

```bash
# Replace the key with your actual MCP_API_KEY value from .env
MCP_KEY=$(grep MCP_API_KEY .env | cut -d= -f2)

curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"get_wazuh_alerts","arguments":{"limit":3}}}' \
  | python3 -m json.tool
```

A healthy response contains `"isError": false` and a `data.affected_items` array with real alert objects. If this fails, the issue is on the MCP/Wazuh side (fix those first). If it succeeds but Open WebUI still answers generically, continue to Step 4.

---

### Step 4 — Check Open WebUI logs for MCP protocol errors

```bash
docker logs --tail=200 open-webui | grep -iE 'tool|mcp|error|model|validation'
```

**If you see lines like:**

```
Failed to validate notification: 20 validation errors for ServerNotification
  Input should be 'notifications/cancelled' ... input_value='notifications/session'
  Input should be 'notifications/cancelled' ... input_value='notifications/ping'
```

This means the MCP server was sending nonstandard SSE JSON-RPC notifications (`notifications/session`, `notifications/capabilities`, `notifications/ping`) that Open WebUI's MCP client rejects. The server-side fix is in `src/wazuh_mcp_server/server.py` — replace nonstandard notifications with comment-only keepalives in `generate_sse_events()`. Rebuild after fixing:

```bash
docker compose -f compose.full.yml up -d --build wazuh-mcp-server
```

---

### Step 5 — Check whether the model supports tool calling

Open WebUI passes the 48 Wazuh tools to the model as OpenAI-style function definitions. Small quantised models (e.g. `ai/gemma3-qat` at the default 4096 context window) may not reliably choose to call a tool for every prompt.

**Switch to a tool-calling-capable model:**

```bash
# Edit .env — recommended presets:
MODEL_RUNNER_MODEL=ai/qwen3              # balanced, good tool-calling
MODEL_RUNNER_MODEL=ai/gemma3-qat         # lower RAM, less reliable for tools

# Apply without rebuilding Wazuh services:
docker compose -f compose.full.yml up -d open-webui
```

**Use explicit, actionable prompts.** Vague questions ("tell me about alerts") are more likely to get a generic answer than direct commands:

| Generic (may hallucinate) | Explicit (triggers tool call) |
|---------------------------|-------------------------------|
| Tell me about security alerts | Show me the last 10 Wazuh alerts |
| Are there any threats? | Get Wazuh alerts with severity level 10 or higher from the last hour |
| What does Wazuh see? | Search security events for wp-login.php in the last 15 minutes |
| Check for vulnerabilities | Get critical vulnerabilities from Wazuh |
| Is the cluster healthy? | Show Wazuh cluster health |

---

### Sample queries that reliably trigger tool calls

Paste these into a new Open WebUI chat exactly as written:

```
Show me the latest Wazuh alerts related to Apache or web attacks.
```
→ calls `get_wazuh_alerts` or `search_security_events`

```
Search security events for wp-login.php, phpmyadmin, or sqlmap in the last 15 minutes.
```
→ calls `search_security_events` with a Lucene query

```
Summarise the top source IPs triggering web login alerts in the last hour.
```
→ calls `analyze_alert_patterns` or `get_wazuh_alert_summary`

```
Get me all Wazuh alerts at rule level 10 or above from the last 6 hours.
```
→ calls `get_wazuh_alerts` with `level=10` and `time_range=6h`

```
Show me Wazuh cluster health and list active agents.
```
→ calls `get_wazuh_cluster_health` then `get_wazuh_running_agents`

```
Check for critical vulnerabilities across all agents.
```
→ calls `get_wazuh_critical_vulnerabilities`

```
Analyze alert patterns from the last 24 hours and identify the top threats.
```
→ calls `analyze_alert_patterns` then `get_top_security_threats`

```
Search for any events related to nikto or sqlmap in the last 30 minutes.
```
→ calls `search_security_events` with `query="nikto OR sqlmap"`

```
Run a PCI-DSS compliance check across the environment.
```
→ calls `run_compliance_check` with `framework=PCI-DSS`

```
Validate the Wazuh connection and show server version details.
```
→ calls `validate_wazuh_connection`

---

### Quick end-to-end verification checklist

```bash
# 1. MCP server healthy
curl -s http://localhost:3000/health | python3 -c "import sys,json; d=json.load(sys.stdin); print('OK' if d['status']=='healthy' else 'FAIL')"

# 2. Live alerts retrievable
MCP_KEY=$(grep MCP_API_KEY .env | cut -d= -f2)
curl -s http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{"name":"validate_wazuh_connection","arguments":{}}}' \
  | python3 -c "import sys,json; r=json.load(sys.stdin); print('OK' if not r['result']['isError'] else 'FAIL')"

# 3. Open WebUI config present
docker exec open-webui sh -lc "python - <<'PY'
import sqlite3,json,sys
cur=sqlite3.connect('/app/backend/data/webui.db').cursor()
cur.execute('SELECT data FROM config ORDER BY id DESC LIMIT 1')
row=cur.fetchone()
cfg=json.loads(row[0]) if row else {}
conns=cfg.get('tool_server',{}).get('connections',[])
print('OK' if conns else 'MISSING')
PY"

# 4. No SSE notification errors in last 100 Open WebUI log lines
docker logs --tail=100 open-webui 2>&1 | grep -c 'notifications/session\|notifications/capabilities\|notifications/ping' || true
# Expected: 0  (non-zero means the protocol mismatch bug is present; rebuild wazuh-mcp-server)
```

---

## Step-by-step Test Flow (Build, Run, Phase 2)

Use this flow when validating a fresh local deployment end to end.

### 1) Prepare environment

```bash
cp .env.example .env
```

Set at least these values in `.env`:

```env
WAZUH_HOST=your-wazuh-server
WAZUH_USER=your-api-user
WAZUH_PASS=your-api-password
MCP_API_KEY=your-mcp-api-key

PHASE2_LLM_ENABLED=true
PHASE2_LLM_MODEL=ai/gemma3-qat:latest
PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
PHASE2_LLM_API_KEY=not-needed
PHASE2_LLM_TIMEOUT_SECONDS=45
```

### 2) Build and run services

```bash
docker compose -f compose.full.yml up -d --build
```

### 3) Verify service health

```bash
docker compose -f compose.full.yml ps
curl -sS http://localhost:3000/health | python3 -m json.tool
```

### 4) Run automatic Phase 2 verification

```bash
chmod +x ./tools/verify_phase2_langchain.sh
./tools/verify_phase2_langchain.sh
```

Expected output includes:

- `engine=langchain`
- `status=LangChain synthesis enabled`
- `Phase 2 verifier passed`

If you need setup-tolerant checks while model wiring is in progress:

```bash
./tools/verify_phase2_langchain.sh --allow-deterministic
```

### 5) Run manual Phase 2 calls

```bash
MCP_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)

# Optional: make the formatter executable once
chmod +x tools/format_phase2_output.py

# triage_wazuh_alerts
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-triage","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"24h","min_level":10,"limit":20,"include_agent_health":true}}}' \
  | python3 tools/format_phase2_output.py

# enrich_wazuh_context
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-enrich","method":"tools/call","params":{"name":"enrich_wazuh_context","arguments":{"time_range":"24h","limit":10,"query":"sqlmap OR nikto"}}}' \
  | python3 tools/format_phase2_output.py

# generate_soc_handoff_report
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-report","method":"tools/call","params":{"name":"generate_soc_handoff_report","arguments":{"report_type":"shift","time_range":"12h","include_recommendations":true}}}' \
  | python3 tools/format_phase2_output.py
```

The formatter prints:

- `result.content[0].text` with real line breaks
- the embedded JSON body as pretty JSON
- `data.analysis` as a separate `Analysis:` block when present
- `data.orchestration.summary` as a separate `Summary:` block when present

If you prefer the executable form after running `chmod +x tools/format_phase2_output.py`, use:

```bash
curl ... | ./tools/format_phase2_output.py
```

Examples:

```bash
# Triage output
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-triage","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"24h","min_level":10,"limit":20,"include_agent_health":true}}}' \
  | python3 tools/format_phase2_output.py

# Enrichment output
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-enrich","method":"tools/call","params":{"name":"enrich_wazuh_context","arguments":{"time_range":"24h","limit":10,"query":"sqlmap OR nikto"}}}' \
  | python3 tools/format_phase2_output.py

# SOC handoff report output
curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2-report","method":"tools/call","params":{"name":"generate_soc_handoff_report","arguments":{"report_type":"shift","time_range":"12h","include_recommendations":true}}}' \
  | python3 tools/format_phase2_output.py
```

For each response, verify:

- `data.analysis` is present
- `data.orchestration.engine` is `langchain` (or `deterministic` in fallback mode)
- `data.orchestration.status` is informative

Sample successful LangChain payload (trimmed):

```json
{
  "jsonrpc": "2.0",
  "id": "phase2-triage",
  "result": {
    "content": [
      {
        "type": "text",
        "text": "Phase 2 Alert Triage:\n{\n  \"data\": {\n    \"workflow\": \"phase2_alert_triage\",\n    \"analysis\": \"Here is an analyst summary...\",\n    \"orchestration\": {\n      \"engine\": \"langchain\",\n      \"status\": \"LangChain synthesis enabled\",\n      \"model\": \"ai/gemma3-qat:latest\"\n    }\n  }\n}"
      }
    ],
    "isError": false
  }
}
```

The important indicators are:

- `isError: false`
- `analysis` contains model-generated text
- `orchestration.engine: "langchain"`
- `orchestration.status: "LangChain synthesis enabled"`

### 6) Inspect logs if validation fails

```bash
docker logs --tail=200 wazuh-mcp-server
docker compose -f compose.full.yml logs --tail=200 wazuh.manager wazuh.indexer
```

### 7) Stop stack after testing (optional)

```bash
docker compose -f compose.full.yml down
```

---

## Test Phase 2 LangChain with Local Model Runner

Use this when you want `triage_wazuh_alerts`, `enrich_wazuh_context`, and `generate_soc_handoff_report` to return live model-written `analysis` text instead of deterministic fallback summaries.

### 1) Configure `.env` for Docker Model Runner

```env
PHASE2_LLM_ENABLED=true
PHASE2_LLM_MODEL=ai/gemma3-qat:latest
PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
PHASE2_LLM_API_KEY=not-needed
PHASE2_LLM_TIMEOUT_SECONDS=45
```

### 2) Restart only the MCP service

```bash
docker compose -f compose.full.yml up -d --build wazuh-mcp-server
```

### 3) Run the one-command verifier script

```bash
./tools/verify_phase2_langchain.sh
```

Expected success output includes:

- `engine=langchain`
- `status=LangChain synthesis enabled`
- `Phase 2 verifier passed`

What the script checks:

1. MCP health endpoint returns `healthy`
2. `triage_wazuh_alerts` returns a successful MCP response
3. Returned Phase 2 payload contains `analysis` and `orchestration`
4. Orchestration engine matches expected mode (`langchain` by default)

If you intentionally want to accept fallback mode during setup checks:

```bash
./tools/verify_phase2_langchain.sh --allow-deterministic
```

Additional verifier options:

```bash
# Show usage
./tools/verify_phase2_langchain.sh --help

# Override MCP endpoint
./tools/verify_phase2_langchain.sh --base-url http://localhost:3000
```

Environment overrides:

- `MCP_API_KEY` - Bearer key (falls back to `.env`)
- `MCP_BASE_URL` - Base URL if not using localhost
- `PHASE2_TEST_TIME_RANGE` - Time range for the triage test call
- `PHASE2_TEST_MIN_LEVEL` - Minimum rule level for triage
- `PHASE2_TEST_LIMIT` - Alert limit for triage
- `PHASE2_TEST_INCLUDE_AGENT_HEALTH` - Include agent health in test call

Verifier exit codes:

- `0` success
- `2` missing dependency/config
- `3` request or tool-call failure
- `4` malformed/unexpected response payload
- `5` orchestration engine mismatch

### 4) Manual fallback: run a direct MCP call to Phase 2 triage

```bash
MCP_KEY=$(grep '^MCP_API_KEY=' .env | cut -d= -f2-)

curl -sS http://localhost:3000/ \
  -H "Authorization: Bearer $MCP_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"phase2","method":"tools/call","params":{"name":"triage_wazuh_alerts","arguments":{"time_range":"24h","min_level":10,"limit":20,"include_agent_health":true}}}' \
  | python3 -m json.tool
```

### 5) Validate that LangChain is active

In the response payload, inspect:

- `result.content[0].text` JSON block
- `data.orchestration.engine`
- `data.orchestration.status`
- `data.analysis`

Expected when Local Model Runner synthesis is active:

- `data.orchestration.engine = "langchain"`
- `data.analysis` contains model-generated SOC summary text

Example successful orchestration block:

```json
{
  "analysis": "Here is an analyst summary of the top Wazuh findings...",
  "orchestration": {
    "engine": "langchain",
    "status": "LangChain synthesis enabled",
    "model": "ai/gemma3-qat:latest",
    "base_url": "http://model-runner.docker.internal/engines/v1"
  }
}
```

If you see fallback mode:

- `data.orchestration.engine = "deterministic"`

Example fallback orchestration block:

```json
{
  "engine": "deterministic",
  "status": "PHASE2_LLM_ENABLED is false"
}
```

Then check:

```bash
docker logs --tail=200 wazuh-mcp-server | grep -iE 'langchain|phase2|import|error|model-runner'
```

### 6) Optional quick sanity call

```bash
curl -sS http://localhost:3000/health | python3 -m json.tool
```

`services.mcp` and `services.wazuh_manager` should be healthy before relying on Phase 2 results.

---

## Support Resources

- **Documentation**: [MCP Specification](https://modelcontextprotocol.io/)
- **Framework Guidance**: [AI Frameworks FAQ](FRAMEWORKS_FAQ.md)
- **Issues**: [GitHub Issues](https://github.com/gensecaihq/Wazuh-MCP-Server/issues)
- **Discussions**: [GitHub Discussions](https://github.com/gensecaihq/Wazuh-MCP-Server/discussions)

---

[← Back to README](../README.md)
