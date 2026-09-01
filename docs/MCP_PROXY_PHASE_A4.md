# Phase A4 — Keys and deployment hygiene (runbook)

Operator runbook for **roadmap Phase A4**: keep **Wazuh MCP**, **MCP proxy upstream**, and **client bearer** tokens aligned, and verify the proxy can reach upstream discovery (`tools/list`).

Builds on [Phase A1](MCP_PROXY_PHASE_A1_DEPLOY.md)–[A3](MCP_PROXY_PHASE_A3.md).

Related:

- [MCP_PROXY_NEXT_STEPS.md](MCP_PROXY_NEXT_STEPS.md) — Phase A5 regression
- [tools/mcp_api_key.sh](../tools/mcp_api_key.sh) — resolve bearer token for curl/UI

---

## What was implemented

| Component | Location | Purpose |
|-----------|----------|---------|
| Align script (enhanced) | `tools/align_mcp_proxy_upstream_key.sh` | Sets `MCP_PROXY_UPSTREAM_API_KEY` from wazuh; **keeps** existing `MCP_PROXY_API_KEY` |
| Apply script | `tools/apply_mcp_proxy_phase_a4.sh` | Align + verify hygiene |
| Test script | `tools/test_mcp_proxy_phase_a4.sh` | Key report, health, ping, `tools/list` |
| Key report helper | `tools/mcp_proxy_test_common.sh` → `mcp_test_print_key_report` | JSON summary of key sources |

---

## Key model (Profile C)

| Variable | Container | Role |
|----------|-----------|------|
| `MCP_API_KEY` | `wazuh-mcp-server` | Upstream MCP authentication |
| `MCP_PROXY_UPSTREAM_API_KEY` | `mcp-security-proxy` | Bearer sent **to** Wazuh when proxy forwards |
| `MCP_PROXY_API_KEY` | `mcp-security-proxy` | Bearer **clients** use for `/mcp` and `/admin/*` |

**A4 goal:** `MCP_PROXY_UPSTREAM_API_KEY` equals `wazuh-mcp-server` `MCP_API_KEY` after
start or align. `MCP_PROXY_API_KEY` is the client bearer (Phase 4 default
`mcp_proxy_local_demo_change_me`); align no longer overwrites it.

First-run: generate a valid `wazuh_` `MCP_API_KEY` in `.env`, then
`bash tools/start-profile.sh C`. See [OPERATIONS.md](OPERATIONS.md#first-run-local-stack).

Compose wiring (`mcp-security-proxy/docker-compose.yml`):

- `MCP_PROXY_UPSTREAM_API_KEY: ${MCP_API_KEY}`
- `MCP_PROXY_API_KEY: ${MCP_PROXY_API_KEY}`

Set both in the environment (or `.env`) **before** `docker compose up` / Profile C start.

---

## Prerequisites

1. Profile **C** running: `mcp-security-proxy`, `wazuh-mcp-server`.
2. `bash`, `curl`, `jq`, `docker`.

---

## Quick start

```bash
bash tools/apply_mcp_proxy_phase_a4.sh
```

Expected trailer: `Phase A4 complete.` and `PHASE A4 KEYS AND HYGIENE TEST PASSED`.

Verify only (no recreate):

```bash
bash tools/test_mcp_proxy_phase_a4.sh
```

After proxy code changes:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh --rebuild-proxy
```

---

## Before first Profile C start (greenfield)

1. Copy `.env.example` → `.env` (if needed).
2. Set a valid Wazuh MCP key (`wazuh_` + 43 URL-safe chars — not `CHANGE_ME`):

```bash
python3 -c "import secrets; print('wazuh_' + secrets.token_urlsafe(32))"
# In repo .env (do not commit real secrets to git):
# MCP_API_KEY=<printed value>
```

Leave `MCP_PROXY_API_KEY` unset unless you also recreate `phase4-api` with the same
value. The Phase 4 default client bearer is `mcp_proxy_local_demo_change_me`.

3. Start Profile C:

```bash
bash tools/start-profile.sh C
```

4. Run A4 to confirm:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh
```

---

## After key drift (common fix)

Symptoms:

- `Invalid or expired token` on `tools/list` through proxy
- `FAIL: proxy upstream API key does not match`

Fix:

```bash
bash tools/align_mcp_proxy_upstream_key.sh
bash tools/test_mcp_proxy_phase_a4.sh
```

Or the combined apply script:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh
```

---

## Manual checks

```bash
# Key report (JSON)
source tools/mcp_proxy_test_common.sh
mcp_test_print_key_report | jq .

# Compare containers
docker exec wazuh-mcp-server printenv MCP_API_KEY
docker exec mcp-security-proxy printenv MCP_PROXY_UPSTREAM_API_KEY
docker exec mcp-security-proxy printenv MCP_PROXY_API_KEY

# Health
curl -s http://localhost:8090/health | jq .

# tools/list (use proxy bearer)
curl -sS -H "Authorization: Bearer $(bash tools/mcp_api_key.sh --proxy)" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}' \
  http://localhost:8090/mcp | jq '.result.tools | length'
```

---

## Rebuild proxy after code changes

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
cd ..
bash tools/align_mcp_proxy_upstream_key.sh
```

Or:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh --rebuild-proxy
```

---

## Completion criteria

Phase A4 is **complete** when:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh
```

exits 0 with:

- `PASS: proxy upstream API key matches wazuh-mcp-server MCP_API_KEY`
- `PASS: MCP_PROXY_API_KEY (client bearer) matches wazuh MCP_API_KEY` (after align)
- `PASS: tools/list returned N tool(s)` (unless `--skip-tools-list`)

---

## Troubleshooting

### Upstream matches but client bearer differs

Older align runs only set `MCP_API_KEY` for upstream. Re-run:

```bash
bash tools/align_mcp_proxy_upstream_key.sh
```

(Now exports `MCP_PROXY_API_KEY` as well.)

### `wazuh-mcp-server` not running

```bash
bash tools/start-profile.sh C
```

### Admin UI 401

Set the UI admin token to `MCP_PROXY_API_KEY` from `bash tools/mcp_api_key.sh --proxy`.

### `.env` out of sync with running containers

Print sync hint without writing files:

```bash
bash tools/apply_mcp_proxy_phase_a4.sh --print-env-sync --no-align
```

Update `.env` manually, then recreate stacks on the **next** planned restart.

---

## After Phase A4

**Phase A5** — [MCP_PROXY_PHASE_A5.md](MCP_PROXY_PHASE_A5.md):

```bash
bash tools/apply_mcp_proxy_phase_a5.sh
```

---

## Files reference

| Path | Description |
|------|-------------|
| `tools/apply_mcp_proxy_phase_a4.sh` | A4 apply + verify |
| `tools/test_mcp_proxy_phase_a4.sh` | A4 verification |
| `tools/align_mcp_proxy_upstream_key.sh` | Force-recreate proxy with aligned keys |
| `tools/mcp_api_key.sh` | Resolve bearer for scripts/UI |
| `.env.example` | Template for `MCP_API_KEY` |
