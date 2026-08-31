# MCP Security Proxy — Trust Hardening (Sprint 1)

This document describes the trust-hardening controls added to
`mcp-security-proxy`. They close the most dangerous trust gaps in an MCP
deployment by validating the upstream server itself, detecting silent tool
descriptor changes, and applying strict defaults to execution-like tools.

All controls are policy-driven, default to safe/back-compatible behavior, and
emit observable deny reasons + discovery signals that flow into the existing
`/recent-denied` and `/recent-discovery-alerts` panels.

---

## Why Sprint 1 is required

Sprint 1 addresses three high-impact trust gaps that are common in MCP
deployments.

1. Upstream trust gap (server identity)
   - Risk: the proxy may forward traffic to an unexpected upstream endpoint
     (misconfiguration, DNS drift, environment mix-up, or hostile redirection).
   - Impact: even safe policy at the proxy can be bypassed if the upstream is
     not the intended system.
   - Sprint 1 control: `trusted_servers` + `untrusted_server_action`.

2. Capability drift gap (tool contract integrity)
   - Risk: a tool can keep the same name while changing behavior via
     `description`, schemas, or annotations.
   - Impact: operators believe a tool is known/safe, while runtime behavior has
     silently changed.
   - Sprint 1 control: `tool_descriptor_hashes` + `descriptor_drift_action`.

3. Execution-surface gap (default blast radius)
   - Risk: generic execution-like tools (shell/eval/subprocess/REPL) are
     reachable by default in high-risk contexts.
   - Impact: greatly increased chance of abuse, lateral movement, or policy
     bypass through broad execution interfaces.
   - Sprint 1 control: `execution_tool_profile` with strict defaults.

Why now:

- These controls reduce systemic trust risk before adding more advanced
  autonomy features.
- They are low-cost to operate because they reuse existing deny/discovery/UI
  telemetry surfaces.
- They support staged rollout (`monitor` -> `challenge` -> `deny`) to minimize
  operational disruption.

---

## 1. Trusted upstream MCP servers

Enforces that the proxy will only forward requests to upstream MCP servers on
an allow-list. The configured `MCP_PROXY_UPSTREAM_URL` is checked against
`trusted_servers` before each forward.

### Policy

```json
{
  "trusted_servers": [
    "https://wazuh-mcp-server.example.com/mcp",
    "wazuh-mcp-server.internal:3000"
  ],
  "untrusted_server_action": "deny"
}
```

- `trusted_servers`: list of any of:
  - full URL (`https://host:port/path`)
  - origin (`scheme://host:port`)
  - host or host:port
- `untrusted_server_action`: `deny` (default), `challenge`, or `monitor`.

Empty list disables the check (back-compat).

### Behavior

- `deny` / `challenge`: request is rejected with HTTP 403 and JSON-RPC error
  `{"reason": "untrusted_server"}` or `"untrusted_server_challenge"`.
- `monitor`: request is forwarded but a `decision_event` with reason
  `untrusted_server_monitor` is recorded.

### Discovery signal

`untrusted_server_calls` — fires on any `untrusted_server*` reason.

### How to implement in an environment

1. Determine the exact upstream identifiers you want to trust:
   - canonical full URL
   - origin (`scheme://host:port`)
   - host[:port] aliases if needed for container/internal DNS forms
2. Add all valid identifiers to `trusted_servers`.
3. Start with `untrusted_server_action: monitor` in staging.
4. Observe `untrusted_server_calls` for unexpected matches.
5. Move to `challenge`, then `deny` after false positives are resolved.

### Primary testing scenarios

- Positive path: upstream matches allow-list, request forwards normally.
- Negative path: upstream not in allow-list, request denied/challenged.
- Telemetry path: denied event reason is `untrusted_server*` and discovery
  signal `untrusted_server_calls` appears.
- Rollback safety: clearing `trusted_servers` returns to back-compat behavior.

---

## 2. Tool descriptor drift detection

Pins the canonical sha256 hash of each tool descriptor (the
`name`, `description`, `inputSchema`, `outputSchema`, `annotations` subset
returned by the upstream). On every `tools/list` response, the proxy
recomputes the hash and compares it.

### Policy

```json
{
  "tool_descriptor_hashes": {
    "wazuh_lookup_alert": "8e2c…<sha256-hex>…",
    "wazuh_search":        "1ab0…<sha256-hex>…"
  },
  "descriptor_drift_action": "deny"
}
```

- `descriptor_drift_action`: `deny` (default), `challenge`, or `monitor`.

### Behavior on a drifted descriptor

- `deny`: tool is removed from the `tools/list` response and a
  `_descriptor_drift` array is appended to the `result` object listing
  `{tool, expected, actual}` for every drift detected. A denied-event with
  reason `descriptor_drift` is recorded.
- `challenge`: same filtering but findings are placed under
  `_descriptor_drift_challenge`; reason `descriptor_drift_challenge`.
- `monitor`: tool is kept but each descriptor is annotated with
  `_descriptor_drift = {expected, actual}`; reason `descriptor_drift_monitor`.

### Producing the expected hash

Use the helper exposed by the module:

```bash
python - <<'PY'
import json
from mcp_security_proxy.app import _compute_tool_descriptor_hash
descriptor = {
  "name": "wazuh_lookup_alert",
  "description": "Look up a Wazuh alert by id",
  "inputSchema": {"type": "object", "properties": {"alert_id": {"type": "string"}}},
}
print(_compute_tool_descriptor_hash(descriptor))
PY
```

Or capture the live descriptor from a trusted environment:

```bash
curl -sS -H "Authorization: Bearer $MCP_PROXY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":"1","method":"tools/list"}' \
  http://localhost:8090/mcp \
| jq -r '.result.tools[] | "\(.name) \(@base64)"'
```

…then sha256 the canonical JSON
(`{name, description, inputSchema, outputSchema, annotations}` sorted keys,
compact separators, ASCII).

### Discovery signal

`descriptor_drift_events` — fires on any `descriptor_drift*` reason.

### How to implement in an environment

1. Build a trusted baseline descriptor snapshot in a known-good environment.
2. Compute and store hashes in `tool_descriptor_hashes`.
3. Start with `descriptor_drift_action: monitor` to detect natural drift.
4. Investigate any drift events:
   - legitimate upstream version/update
   - policy mismatch
   - possible tampering
5. Move to `challenge` or `deny` once baseline stability is verified.
6. Update pinned hashes through change control whenever an approved tool
   contract change is released.

### Primary testing scenarios

- Positive path: descriptor hash matches pin; tool remains in `tools/list`.
- Negative path (deny/challenge): descriptor mismatch; tool filtered out and
  finding emitted in `_descriptor_drift` or `_descriptor_drift_challenge`.
- Monitor path: descriptor mismatch retained in tool list with drift annotation.
- Telemetry path: denied reason is `descriptor_drift*` and discovery signal
  `descriptor_drift_events` appears.

---

## 3. Execution-tool strict profile

Most production MCP servers should not expose generic execution surfaces
(shell, eval, subprocess, REPL). This profile denies or challenges any
`tools/call` whose tool name contains a known execution token.

### Policy

```json
{
  "execution_tool_profile": {
    "enabled": true,
    "action": "deny",
    "patterns": ["exec", "shell", "run_command", "eval", "subprocess",
                 "python_repl", "bash", "powershell", "ssh"]
  }
}
```

Default `patterns` (used if `patterns` is empty/missing):
`exec`, `shell`, `run_command`, `run_script`, `command`, `cmd`, `eval`,
`subprocess`, `system`, `powershell`, `bash`, `ssh`, `python_repl`,
`interpreter`, `sandbox_run`.

### Behavior

- `deny` (default): request denied with reason `execution_tool_blocked`.
- `challenge`: request denied with reason `execution_tool_challenge`.

Match is a case-insensitive substring on the tool name (`shell_exec`,
`run_command_v2`, `python_repl_run` all match). To narrow the profile,
provide an explicit `patterns` list.

### Discovery signal

`execution_tool_attempts` — fires on any `execution_tool_*` reason.

### How to implement in an environment

1. Enable `execution_tool_profile.enabled: true` in staging.
2. Keep default `patterns` initially unless you have strict naming governance.
3. Start with `action: challenge` to observe impact on existing workflows.
4. Review denied/challenged events for legitimate use-cases.
5. Narrow patterns where needed, then move to `action: deny` for production.

### Primary testing scenarios

- Positive path: non-execution tools are unaffected.
- Negative path: execution-like tool names are denied/challenged.
- Pattern coverage path: verify expected naming variants match (`shell_exec`,
  `python_repl_run`, etc.).
- Telemetry path: denied reason is `execution_tool_*` and discovery signal
  `execution_tool_attempts` appears.

---

## Deny-reason quick reference (new in Sprint 1)

| Reason | Source | Trigger |
|---|---|---|
| `untrusted_server` | trust gate | Upstream URL absent from `trusted_servers` (action=`deny`). |
| `untrusted_server_challenge` | trust gate | Same, action=`challenge`. |
| `untrusted_server_monitor` | decision event (not a deny) | Same, action=`monitor`. |
| `descriptor_drift` | `tools/list` post-filter | Tool descriptor hash mismatch (action=`deny`). |
| `descriptor_drift_challenge` | `tools/list` post-filter | Same, action=`challenge`. |
| `descriptor_drift_monitor` | `tools/list` post-filter | Same, action=`monitor`. |
| `execution_tool_blocked` | `_policy_decision` | Tool matches `execution_tool_profile.patterns` (action=`deny`). |
| `execution_tool_challenge` | `_policy_decision` | Same, action=`challenge`. |

All reasons appear in:

- `GET /recent-denied`
- `GET /recent-discovery-alerts` (via the corresponding discovery signals)
- Prometheus metric `mcp_security_proxy_denied_total{reason=...}`
- Existing UI panels at `/ui` (Discovery Alerts + MCP Proxy Denied Calls).

No UI changes are required: the new reasons and signals flow through the
existing dashboards and the live `/ui` panels.

---

## End-to-end implementation checklist

Use this as an operator implementation sequence for Sprint 1.

1. Baseline and backups
  - Export current policy and confirm backup path/write permissions.
2. Configure trusted upstream control
  - Set `trusted_servers` and `untrusted_server_action`.
3. Configure descriptor pinning
  - Add `tool_descriptor_hashes`; set `descriptor_drift_action`.
4. Configure execution strict profile
  - Set `execution_tool_profile.enabled/action/patterns`.
5. Configure discovery rules
  - Add/verify signals: `untrusted_server_calls`,
    `descriptor_drift_events`, `execution_tool_attempts`.
6. Runtime apply and validation
  - Apply policy through admin API.
  - Execute Sprint 1 e2e tests.
  - Verify `/recent-denied` and `/recent-discovery-alerts`.
7. Promotion strategy
  - Stage in `monitor`/`challenge` where needed.
  - Promote to `deny` after tuning.

---

## Testing scenario matrix

The table below summarizes what to test and what "pass" looks like.

| Feature | Scenario | Expected result | Evidence |
|---|---|---|---|
| Trusted servers | Upstream on allow-list | Request forwarded | Normal MCP response, no `untrusted_server*` deny |
| Trusted servers | Upstream not on allow-list (`deny`) | Request blocked | JSON-RPC error reason `untrusted_server`; alert `untrusted_server_calls` |
| Descriptor drift | Descriptor matches pin | Tool remains available | Tool present in `tools/list` |
| Descriptor drift | Descriptor mismatch (`deny`) | Tool filtered | `_descriptor_drift` finding; deny reason `descriptor_drift` |
| Descriptor drift | Descriptor mismatch (`monitor`) | Tool retained + annotated | Tool present + `_descriptor_drift` annotation |
| Execution profile | Non-execution tool | Allowed by this gate | No `execution_tool_*` deny reason |
| Execution profile | Execution-like tool (`deny`) | Blocked | deny reason `execution_tool_blocked`; alert `execution_tool_attempts` |

Recommended evidence capture per run:

- Script output
- `/recent-denied?limit=...` snapshot
- `/recent-discovery-alerts?limit=...` snapshot
- Optional screenshot of `/ui` denied/discovery panels

---

## Reloading policy at runtime

Add the new fields to the active policy file
(`mcp-security-proxy/config/policy.json` or
`config/phase4/mcp_proxy/policy.json`) and either restart, or apply at
runtime via:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $MCP_PROXY_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --slurpfile p policy.json '{raw_policy: $p[0]}')" \
  http://localhost:8090/admin/policy-config | jq .summary
```

A timestamped backup of the previous policy is written next to the active
file on every update.

---

## End-to-end test scripts

Sprint 1 verification is documented in depth in
[MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) (prerequisites, policy
samples, troubleshooting, and scenario tables).

### All-in-one (recommended)

```bash
bash tools/align_mcp_proxy_upstream_key.sh   # when proxy upstream key ≠ wazuh MCP_API_KEY
bash tools/test_sprint1_no_restart.sh
```

The wrapper:

1. Applies `policy.sample.sprint-1-trust-hardening.json` via `/admin/policy-config`
2. Verifies `MCP_PROXY_UPSTREAM_API_KEY` matches `wazuh-mcp-server` `MCP_API_KEY`
3. Preflights upstream MCP (`ping` via proxy; detects upstream auth failures)
4. Runs the three gate scripts below
5. Runs unit tests (optional `--skip-unit-tests`)
6. Prints telemetry summary (`reasons` + `signals`)

Policy sample shortcut: `bash tools/switch_mcp_policy_sample.sh sprint-1`

### Per-control scripts

Scripts use [tools/mcp_proxy_test_common.sh](../tools/mcp_proxy_test_common.sh) for
proxy auth (`tools/mcp_api_key.sh --proxy`), upstream preflight, and error hints.

| Script | Scenario | Expected |
|--------|----------|----------|
| [tools/test_trusted_servers.sh](../tools/test_trusted_servers.sh) | Bogus `trusted_servers` | `untrusted_server` + `untrusted_server_calls` |
| [tools/test_descriptor_drift.sh](../tools/test_descriptor_drift.sh) | Wrong pin in `tool_descriptor_hashes` | Filtered tool, `_descriptor_drift[]`, `descriptor_drift_events` |
| [tools/test_execution_tool_profile.sh](../tools/test_execution_tool_profile.sh) | `execution_tool_profile` deny | `execution_tool_blocked` + `execution_tool_attempts` |

Each script snapshots policy, applies a test patch, asserts `/recent-denied` and
`/recent-discovery-alerts`, and restores on exit (even on failure).

Environment: `DRIFT_TARGET_TOOL` (optional) for descriptor drift when auto-discovery
from `tools/list` is not desired.

---

## Unit-test coverage

See `mcp-security-proxy/tests/test_app.py`:

- `test_execution_tool_profile_denies_strict_default`
- `test_untrusted_upstream_blocks_request`
- `test_descriptor_drift_denies_and_filters_tools_list`
- `test_descriptor_drift_monitor_keeps_tool`
- `test_execution_tool_discovery_signal_triggers_alert`

Run:

```bash
.venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
```

---

## UI observations during Sprint 1 tests

When running Sprint 1 scripts, expected UI behavior at `/ui` is:

1. Recent Denied Calls increments with reasons:
  - `untrusted_server`
  - `descriptor_drift`
  - `execution_tool_blocked`
2. Discovery Alerts shows triggered signals:
  - `untrusted_server_calls`
  - `descriptor_drift_events`
  - `execution_tool_attempts`
3. Live security/deny trend lines show short spikes near test execution time.

Note: discovery alerts may dedupe within cooldown windows, so immediate reruns
can produce fewer new alert rows than expected.
