# MCP Security Proxy — Containment and Fail-Safe (Sprint 2)

This document describes Sprint 2 controls added to `mcp-security-proxy`.

Sprint 2 objective:

- enforce containment for execution-like tools
- fail closed when required enforcing dependencies are unavailable
- prevent silent bypass of required security layers

## 1. Sandbox attestation gate

The proxy can now require sandbox attestation evidence for selected tools (by
name-pattern) before allowing `tools/call`.

### Policy

```json
{
  "sandbox_attestation_profile": {
    "enabled": true,
    "action": "deny",
    "require_for_tools": ["shell", "exec", "python_repl"],
    "trusted_issuers": ["trusted-attestor"],
    "allowed_modes": ["isolated", "sandboxed"],
    "max_age_seconds": 900,
    "allow_missing_expiry": false,
    "require_pass": true
  }
}
```

### Behavior

- Missing evidence: `sandbox_attestation_missing` (or `sandbox_attestation_challenge` when action=`challenge`).
- Invalid evidence: `sandbox_attestation_invalid` (or challenge equivalent).
- Monitor mode: emits decision event `sandbox_attestation_monitor`.

Supported evidence sources in request payload:

- `params.metadata.sandbox_attestation`
- `params.arguments.sandbox_attestation`

## 2. Required dependency fail-safe checks

When enforcing controls are enabled (for example `llm_risk.enforce=true`), the
proxy now performs required dependency checks and can block if dependencies are
not healthy.

### Policy

```json
{
  "dependency_fail_safe_profile": {
    "enabled": true,
    "action": "deny",
    "required_controls": ["llm_risk", "tool_intent"],
    "require_network_reachability": true,
    "health_cache_ttl_seconds": 15,
    "prevent_silent_bypass": true
  }
}
```

### Behavior

- Dependency failure in deny mode: `dependency_health_failed`
- Dependency failure in challenge mode: `dependency_health_challenge`
- Monitor mode: decision event `dependency_health_monitor`

## 3. Silent-bypass prevention

In enforce mode, if a required security layer cannot produce a real decision
and falls back to an unavailable/no-engine path, the request is blocked.

### Behavior

- Deny reason: `security_layer_bypass_prevented`
- Error payload includes `required_layer` (for example `llm_risk` or
  `tool_intent`)

This prevents allow decisions caused by unavailable scoring dependencies.

## New discovery signals (Sprint 2)

- `sandbox_attestation_failures`
- `dependency_health_failures`
- `security_layer_bypass_attempts`

Default threshold for each: `1 event in 1 hour (default)`.

## Unit tests

Source: `mcp-security-proxy/tests/test_app.py`

Sprint 2 unit test cases:

- `test_sandbox_attestation_missing_denies_execution_tool`
  - setup: enable `sandbox_attestation_profile` with `action=deny`
  - action: call `tools/call` on `shell_exec` without attestation
  - expected deny reason: `sandbox_attestation_missing`
  - expected discovery signal: `sandbox_attestation_failures`
- `test_dependency_fail_safe_blocks_when_enforcing_dependency_unreachable`
  - setup: enforce `llm_risk`, enable `dependency_fail_safe_profile`, monkeypatch dependency probe unreachable
  - action: call `tools/call`
  - expected deny reason: `dependency_health_failed`
  - expected discovery signal: `dependency_health_failures`
- `test_prevent_silent_bypass_denies_when_required_llm_layer_unavailable`
  - setup: enforce `llm_risk`, `prevent_silent_bypass=true`, monkeypatch `llm_risk` result unavailable
  - action: call `tools/call`
  - expected deny reason: `security_layer_bypass_prevented`
  - expected error field: `required_layer=llm_risk`

Run:

```bash
.venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
```

## End-to-end scripts

See [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) for prerequisites
(upstream key alignment, policy samples) and the full Sprint 2 scenario table.

**Recommended:**

```bash
bash tools/switch_mcp_policy_sample.sh sprint-2
bash tools/test_sprint2_no_restart.sh
```

- `tools/test_sandbox_attestation.sh`
- `tools/test_dependency_fail_safe.sh`
- `tools/test_sprint2_no_restart.sh`

Detailed E2E test cases:

- `tools/test_sandbox_attestation.sh`
  - preflight: checks running Docker container `mcp-security-proxy` includes Sprint 2 symbol `_sandbox_attestation_check`; exits early with rebuild hint if missing
  - policy patch for test: enables `sandbox_attestation_profile` in `deny` mode; disables `tool_intent` enforcement and **`execution_tool_profile`** so Sprint 1 does not deny `shell_exec` before attestation runs
  - request under test: `tools/call` for `shell_exec` without attestation
  - expected result: JSON-RPC error `-32003` with `error.data.reason=sandbox_attestation_missing`
  - telemetry assertions:
    - `/recent-denied` contains a `sandbox_attestation*` reason
    - `/recent-discovery-alerts` contains `sandbox_attestation_failures`
- `tools/test_dependency_fail_safe.sh`
  - preflight: checks running Docker container `mcp-security-proxy` includes Sprint 2 symbol `_dependency_fail_safe_check`; exits early with rebuild hint if missing
  - policy patch for test: sets `llm_risk.enforce=true`, points `llm_risk.base_url` to unreachable endpoint, enables `dependency_fail_safe_profile` in `deny` mode
  - request under test: `tools/call` for a non-execution tool (`wazuh_lookup_alert`)
  - expected result: JSON-RPC error `-32003` with `error.data.reason=dependency_health_failed`
  - telemetry assertions:
    - `/recent-denied` contains a `dependency_health*` reason
    - `/recent-discovery-alerts` contains `dependency_health_failures`
- `tools/test_sprint2_no_restart.sh`
  - orchestration flow:
    - health preflight (`/health`)
    - sandbox attestation script
    - dependency fail-safe script
    - optional pytest run
    - telemetry summary from denied reasons and discovery signals
  - expected terminal trailer: `SPRINT 2 VERIFICATION PASSED`

Run all (without restarting profile):

```bash
bash tools/test_sprint2_no_restart.sh
```

Troubleshooting:

- symptom: expected Sprint 2 deny reason is replaced by unrelated reasons (for example `llm_intent_challenge`) or upstream transport errors
  - likely cause: stale runtime image/container not running current Sprint 2 code
  - fix:

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
```

## UI / observability expectations

During Sprint 2 tests, check `/ui` -> `Tuning Studio` -> `Evidence and Decisions`:

- `Recent Denied Calls` contains Sprint 2 reasons above.
- `Recent Decision Events` contains `sandbox_attestation` and
  `dependency_health` stage evidence.
- Discovery alerts contain Sprint 2 signals.

### Evidence and Decisions time scale semantics

The two Evidence and Decisions tables are based on rolling recent-event buffers,
not on the Live dashboard time-window selector.

- `Recent Denied Calls` data source:
  - endpoint: `GET /recent-denied`
  - UI call: no explicit `limit`, so backend default applies (`limit=200`)
  - backend in-memory cap: `MCP_PROXY_RECENT_DENIED_LIMIT` (default `200`)
  - effective max visible rows: up to `200` newest denied events
- `Recent Decision Events` data source:
  - endpoint: `GET /recent-decisions`
  - UI call: `limit=10000`
  - backend in-memory cap: `MCP_PROXY_RECENT_DECISION_LIMIT` (default `5000`)
  - effective max visible rows: up to `5000` newest decision events (unless env cap is raised)
- Ordering and timestamp basis:
  - events are written with UTC ISO timestamps (`YYYY-MM-DDTHH:MM:SSZ`)
  - new events are prepended to the rolling deque
  - table default sort is `timestamp` descending (newest first)
- Refresh cadence:
  - with UI Auto Refresh enabled, tables update every 5 seconds
- Important distinction:
  - the `liveTimeScale` selector (5m/15m/30m/...) filters Live dashboard and
    Live RPC views only
  - it does not currently filter `Recent Denied Calls` and `Recent Decision Events`
