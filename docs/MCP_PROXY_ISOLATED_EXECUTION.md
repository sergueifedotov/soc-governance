# MCP Security Proxy — Isolated Execution and Upstream Provenance (Sprint 3)

This document describes Sprint 3 controls added to `mcp-security-proxy`.

Sprint 3 objective:

- Integrate a dedicated isolated executor service for high-risk tool execution
- Enforce runtime limits (CPU, memory, time), rootless execution, and filesystem restrictions
- Implement upstream provenance controls with controlled egress filtering
- Record attestation and executor evidence in audit telemetry

---

## 1. Isolated executor integration

The proxy can now forward execution-like tool calls to a dedicated isolated executor service instead of the standard upstream. This provides defense-in-depth for high-risk operations.

### Policy

```json
{
  "isolated_executor_profile": {
    "enabled": true,
    "action": "deny",
    "executor_url": "http://isolated-executor:8080/execute",
    "fallback_to_upstream": false,
    "require_for_tools": ["shell", "exec", "python_repl", "bash", "powershell"],
    "forward_on_success": true,
    "max_retries": 2,
    "timeout_seconds": 60
  }
}
```

- `enabled`: Whether isolated executor routing is active
- `action`: `deny` (default), `challenge`, or `monitor`
- `executor_url`: URL of the isolated executor service endpoint
- `fallback_to_upstream`: Whether to fall back to standard upstream if executor is unavailable
- `require_for_tools`: Tool name patterns that trigger isolated execution
- `forward_on_success`: Whether to forward executor results to upstream for post-processing
- `max_retries`: Number of retries on executor communication failures
- `timeout_seconds`: Request timeout for executor calls

### Behavior

- Matching tool without executor available: `isolated_executor_unavailable` (or `isolated_executor_challenge` when action=`challenge`)
- Executor returns error: `isolated_executor_error`
- Monitor mode: emits decision event `isolated_executor_monitor`
- Successful execution records executor evidence in decision telemetry

### Request transformation

Requests forwarded to the isolated executor are wrapped with additional security context:

```json
{
  "original_request": { /* original MCP tools/call request */ },
  "security_context": {
    "client_ip": "...",
    "request_id": "...",
    "timestamp": "...",
    "attestation": { /* sandbox attestation if present */ }
  }
}
```

---

## 2. Runtime limits enforcement

The isolated executor profile includes runtime resource limits to prevent resource exhaustion and ensure fair usage.

### Policy

```json
{
  "isolated_executor_profile": {
    "runtime_limits": {
      "max_cpu_seconds": 30,
      "max_memory_mb": 512,
      "max_wall_time_seconds": 60,
      "max_processes": 10,
      "max_file_descriptors": 100,
      "max_network_connections": 0
    }
  }
}
```

### Behavior

- Requests exceeding limits before execution: `runtime_limits_exceeded` (deny)
- Execution exceeding limits during run: `runtime_limits_violation` (terminate + deny)
- Violation details recorded in decision telemetry

---

## 3. Rootless execution verification

The proxy verifies that the isolated executor is running in rootless mode before allowing execution of high-risk tools.

### Policy

```json
{
  "isolated_executor_profile": {
    "require_rootless": true,
    "rootless_verification": {
      "verify_uid": true,
      "verify_gid": true,
      "verify_no_new_privs": true,
      "verify_seccomp": true,
      "verify_apparmor": false,
      "verify_selinux": false
    }
  }
}
```

### Behavior

- Rootless verification fails: `rootless_execution_required` (deny)
- Missing rootless evidence: `rootless_verification_failed`
- Verification results recorded in executor evidence

### Evidence schema

```json
{
  "rootless_verification": {
    "uid": 1000,
    "gid": 1000,
    "no_new_privs": true,
    "seccomp_enabled": true,
    "apparmor_enabled": false,
    "selinux_enabled": false,
    "verified_at": "2026-06-01T12:00:00Z"
  }
}
```

---

## 4. Filesystem restrictions

The isolated executor enforces filesystem access controls including read-only enforcement and path restrictions.

### Policy

```json
{
  "isolated_executor_profile": {
    "filesystem_restrictions": {
      "read_only_root": true,
      "allow_write_paths": ["/tmp", "/var/tmp"],
      "deny_read_paths": ["/etc/shadow", "/root/.ssh"],
      "deny_write_paths": ["/etc", "/usr", "/bin", "/sbin"],
      "max_file_size_mb": 100,
      "max_total_size_mb": 500,
      "required_mounts": ["/tmp"]
    }
  }
}
```

### Behavior

- Request violates restrictions: `filesystem_restriction_violation` (deny)
- Access to denied path: `filesystem_access_denied`
- Restriction check failures recorded in decision telemetry

---

## 5. Upstream provenance controls

The proxy now implements controlled egress filtering to enforce upstream provenance and prevent data exfiltration.

### Policy

```json
{
  "upstream_provenance_profile": {
    "enabled": true,
    "action": "deny",
    "allowed_destinations": [
      "https://api.wazuh.example.com",
      "https://internal-mcp.example.com"
    ],
    "blocked_destinations": [
      "*.pastebin.com",
      "*webhook*"
    ],
    "require_destination_attestation": true,
    "max_egress_bytes": 1048576,
    "log_all_egress": true,
    "egress_filter_patterns": [
      "(?i)password",
      "(?i)secret",
      "(?i)token",
      "(?i)api[_-]?key"
    ]
  }
}
```

### Behavior

- Upstream destination not in allowed list: `upstream_provenance_denied`
- Destination in blocked list: `upstream_dest_blocked`
- Egress size limit exceeded: `egress_size_limit_exceeded`
- Sensitive pattern detected: `egress_sensitive_content_detected`
- All egress logged when `log_all_egress` is true

---

## 6. Audit telemetry with executor evidence

Sprint 3 enriches audit telemetry with executor-specific evidence for compliance and forensics.

### Evidence fields

Decision events now include executor evidence when isolated execution occurs:

```json
{
  "executor_evidence": {
    "executor_url": "http://isolated-executor:8080/execute",
    "execution_id": "exec-uuid",
    "runtime_limits_applied": {
      "cpu_seconds": 30,
      "memory_mb": 512
    },
    "rootless_verified": true,
    "filesystem_restrictions_applied": ["read_only_root", "max_file_size_mb"],
    "start_time": "2026-06-01T12:00:00Z",
    "end_time": "2026-06-01T12:00:05Z",
    "exit_code": 0,
    "termination_reason": "completed"
  }
}
```

### Attestation chain

When both sandbox attestation and isolated execution are used, the audit trail links both:

```json
{
  "attestation_chain": {
    "sandbox_attestation": { /* from request */ },
    "executor_evidence": { /* from execution */ },
    "provenance_hash": "sha256:..."
  }
}
```

---

## New discovery signals (Sprint 3)

- `isolated_executor_failures` — fires on any isolated executor-related denial
- `runtime_limits_violations` — fires when runtime limits are exceeded
- `rootless_verification_failures` — fires on rootless verification failures
- `filesystem_violations` — fires on filesystem restriction violations
- `upstream_provenance_violations` — fires on egress/provenance denials
- `sensitive_egress_detected` — fires when sensitive patterns detected in egress

Default threshold for each: `1 event in 1 hour (default)`.

---

## Unit tests

Source: `mcp-security-proxy/tests/test_app.py`

Sprint 3 unit test cases:

- `test_isolated_executor_routes_high_risk_tools`
  - setup: enable `isolated_executor_profile` with `action=deny`, configure executor URL
  - action: call `tools/call` on `shell_exec` without executor available
  - expected deny reason: `isolated_executor_unavailable`
  - expected discovery signal: `isolated_executor_failures`

- `test_runtime_limits_enforced_before_execution`
  - setup: configure `runtime_limits.max_cpu_seconds=1`, prepare tool call exceeding limits
  - action: call execution tool with arguments that would exceed CPU limit
  - expected deny reason: `runtime_limits_exceeded`
  - expected discovery signal: `runtime_limits_violations`

- `test_rootless_verification_required`
  - setup: enable `require_rootless=true`, mock executor without rootless evidence
  - action: call execution tool
  - expected deny reason: `rootless_execution_required`
  - expected discovery signal: `rootless_verification_failures`

- `test_filesystem_restrictions_violation_blocked`
  - setup: configure `filesystem_restrictions.deny_write_paths=["/etc"]`
  - action: call execution tool attempting write to `/etc/passwd`
  - expected deny reason: `filesystem_restriction_violation`
  - expected discovery signal: `filesystem_violations`

- `test_upstream_provenance_blocked_destination`
  - setup: enable `upstream_provenance_profile`, configure `blocked_destinations=["*.pastebin.com"]`
  - action: forward request that would egress to `evil.pastebin.com`
  - expected deny reason: `upstream_dest_blocked`
  - expected discovery signal: `upstream_provenance_violations`

- `test_executor_evidence_recorded_in_audit_telemetry`
  - setup: enable isolated executor with monitor mode
  - action: execute tool via isolated executor
  - expected: decision event contains `executor_evidence` with execution details

Run:

```bash
.venv/bin/python -m pytest mcp-security-proxy/tests/test_app.py -q
```

---

## End-to-end scripts

See [MCP_PROXY_SPRINT_TESTING.md](MCP_PROXY_SPRINT_TESTING.md) for prerequisites,
policy sample `sprint-3`, and the consolidated scenario table.

**Recommended:**

```bash
bash tools/switch_mcp_policy_sample.sh sprint-3
bash tools/test_sprint3_no_restart.sh
```

- `tools/test_isolated_executor.sh`
- `tools/test_runtime_limits.sh`
- `tools/test_filesystem_restrictions.sh`
- `tools/test_upstream_provenance.sh`
- `tools/test_sprint3_no_restart.sh`

Detailed E2E test cases:

### `tools/test_isolated_executor.sh`
- preflight: checks running Docker container `mcp-security-proxy` includes Sprint 3 symbol `_isolated_executor_route`
- policy patch for test: enables `isolated_executor_profile` with unreachable executor URL, disables fallback
- request under test: `tools/call` for `shell_exec`
- expected result: JSON-RPC error `-32003` with `error.data.reason=isolated_executor_unavailable`
- telemetry assertions:
  - `/recent-denied` contains `isolated_executor*` reason
  - `/recent-discovery-alerts` contains `isolated_executor_failures`

### `tools/test_runtime_limits.sh`
- preflight: verifies `isolated_executor_profile.runtime_limits` is configurable
- policy patch: sets `runtime_limits.max_cpu_seconds=1`, `max_memory_mb=128`
- request under test: `tools/call` for execution tool
- expected result: Request blocked if limits would be exceeded

### `tools/test_filesystem_restrictions.sh`
- preflight: verifies `_filesystem_restrictions_check` symbol exists
- policy patch: configures restrictive `filesystem_restrictions`
- request under test: `tools/call` with path violations
- expected result: Denial with `filesystem_restriction_violation`

### `tools/test_upstream_provenance.sh`
- preflight: checks Sprint 3 egress filtering symbol
- policy patch: configures `upstream_provenance_profile.blocked_destinations`
- request under test: Forward to blocked destination
- expected result: Denial with `upstream_dest_blocked`

### `tools/test_sprint3_no_restart.sh`
- orchestration flow:
  - health preflight (`/health`)
  - Sprint 3 symbol check in running container
  - isolated executor, runtime limits, filesystem restrictions, upstream provenance scripts
  - optional pytest run (`-k` sprint3-related tests, including rootless behavior)
  - telemetry summary from denied reasons and discovery signals
- expected terminal trailer: `SPRINT 3 VERIFICATION PASSED`

Run all (without restarting profile):

```bash
bash tools/test_sprint3_no_restart.sh
```

Troubleshooting:

- symptom: expected Sprint 3 deny reason is replaced by unrelated reasons
  - likely cause: stale runtime image/container not running current Sprint 3 code
  - fix:

```bash
cd mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml build mcp-security-proxy
docker compose -f docker-compose.yml -f docker-compose.phase4.yml up -d mcp-security-proxy
```

---

## UI / observability expectations

During Sprint 3 tests, check `/ui` -> `Tuning Studio` -> `Evidence and Decisions`:

- `Recent Denied Calls` contains Sprint 3 reasons:
  - `isolated_executor_unavailable`
  - `runtime_limits_exceeded`
  - `rootless_execution_required`
  - `filesystem_restriction_violation`
  - `upstream_dest_blocked`
- `Recent Decision Events` contains `executor_evidence` for isolated executions
- Discovery alerts contain Sprint 3 signals

---

## Deny-reason quick reference (new in Sprint 3)

| Reason | Source | Trigger |
|---|---|---|
| `isolated_executor_unavailable` | isolated executor gate | Required executor not reachable (action=`deny`) |
| `isolated_executor_challenge` | isolated executor gate | Same, action=`challenge` |
| `isolated_executor_monitor` | decision event (not deny) | Same, action=`monitor` |
| `isolated_executor_error` | isolated executor gate | Executor returned error response |
| `runtime_limits_exceeded` | runtime limits gate | Request would exceed configured limits |
| `runtime_limits_violation` | runtime limits gate | Limits exceeded during execution |
| `rootless_execution_required` | rootless gate | Rootless verification failed (action=`deny`) |
| `rootless_verification_failed` | rootless gate | Verification check failed |
| `filesystem_restriction_violation` | filesystem gate | Access violates configured restrictions |
| `filesystem_access_denied` | filesystem gate | Specific path access denied |
| `upstream_provenance_denied` | provenance gate | Destination not in allowed list |
| `upstream_dest_blocked` | provenance gate | Destination in blocked list |
| `egress_size_limit_exceeded` | provenance gate | Response exceeds max egress size |
| `egress_sensitive_content_detected` | provenance gate | Sensitive pattern in egress |

All reasons appear in:

- `GET /recent-denied`
- `GET /recent-discovery-alerts` (via the corresponding discovery signals)
- Prometheus metric `mcp_security_proxy_denied_total{reason=...}`
- Existing UI panels at `/ui` (Discovery Alerts + MCP Proxy Denied Calls)

---

## End-to-end implementation checklist

Use this as an operator implementation sequence for Sprint 3.

1. Deploy isolated executor service
   - **Runbook:** [MCP_PROXY_PHASE_A1_DEPLOY.md](MCP_PROXY_PHASE_A1_DEPLOY.md)
   - **Repo reference:** `mcp-isolated-executor/` + `docker-compose.isolated-executor.yml`
   - Quick path: `bash tools/start-profile.sh C` then `bash tools/deploy_isolated_executor_a1.sh`
   - Or manual: `bash tools/start_isolated_executor.sh` then
     `bash tools/switch_mcp_policy_sample.sh sprint-3-executor`
   - Production: replace image with gVisor/Firecracker/Kata; keep `POST /execute` contract
   - Verify: `GET http://isolated-executor:8080/health` from proxy container
   - Policy: `isolated_executor_profile.executor_url` =
     `http://isolated-executor:8080/execute`

2. Configure isolated executor routing
   - Set `isolated_executor_profile.enabled=true`
   - Define `require_for_tools` patterns
   - Choose `action` (recommend `challenge` for staging, `deny` for production)

3. Configure runtime limits
   - Set appropriate `runtime_limits` based on workload requirements
   - Start restrictive and increase as needed

4. Configure rootless verification
   - Enable `require_rootless=true` for production
   - Select verification methods appropriate for your container runtime

5. Configure filesystem restrictions
   - Define `allow_write_paths` minimally
   - Add sensitive paths to `deny_read_paths` and `deny_write_paths`

6. Configure upstream provenance
   - Enumerate `allowed_destinations` explicitly
   - Add known-bad patterns to `blocked_destinations`
   - Enable `log_all_egress` for audit compliance

7. Configure discovery rules
   - Add/verify signals: `isolated_executor_failures`, `runtime_limits_violations`, `rootless_verification_failures`, `filesystem_violations`, `upstream_provenance_violations`

8. Runtime apply and validation
   - Apply policy through admin API
   - Execute Sprint 3 e2e tests
   - Verify `/recent-denied` and `/recent-discovery-alerts`

9. Promotion strategy
   - Stage in `monitor`/`challenge` where needed
   - Promote to `deny` after tuning

---

## Testing scenario matrix

| Feature | Scenario | Expected result | Evidence |
|---|---|---|---|
| Isolated executor | Tool matching pattern | Routed to executor | Executor URL called, `executor_evidence` in telemetry |
| Isolated executor | Executor unavailable + no fallback | Request blocked | `isolated_executor_unavailable` deny reason, `isolated_executor_failures` alert |
| Runtime limits | Limits within bounds | Execution allowed | Normal execution flow |
| Runtime limits | Limits exceeded | Request blocked | `runtime_limits_exceeded` deny reason, `runtime_limits_violations` alert |
| Rootless | Rootless verified | Execution allowed | `rootless_verified=true` in evidence |
| Rootless | Rootless required but not verified | Request blocked | `rootless_execution_required` deny reason |
| Filesystem | Access within allowed paths | Execution allowed | Normal execution flow |
| Filesystem | Access to denied path | Request blocked | `filesystem_restriction_violation` deny reason |
| Upstream provenance | Allowed destination | Request forwarded | Normal forwarding flow |
| Upstream provenance | Blocked destination | Request blocked | `upstream_dest_blocked` deny reason |
| Audit telemetry | Any isolated execution | Evidence recorded | `executor_evidence` in decision event |

Recommended evidence capture per run:

- Script output
- `/recent-denied?limit=...` snapshot
- `/recent-discovery-alerts?limit=...` snapshot
- `/recent-decisions?limit=...` with executor evidence
- Optional screenshot of `/ui` denied/discovery panels

---

## Reloading policy at runtime

Add the new fields to the active policy file and apply at runtime via:

```bash
curl -sS -X POST \
  -H "Authorization: Bearer $MCP_PROXY_API_KEY" \
  -H "Content-Type: application/json" \
  -d "$(jq -n --slurpfile p policy.json '{raw_policy: $p[0]}')" \
  http://localhost:8090/admin/policy-config | jq .summary
```

A timestamped backup of the previous policy is written next to the active file on every update.

---

## Architecture notes

### Isolated executor service

The isolated executor is a separate service that provides:

- Process isolation (containers, gvisor, firecracker)
- Resource quotas (cgroups)
- Filesystem namespaces (overlay, tmpfs)
- Network restrictions (iptables/nftables)
- Audit logging

Example executor implementations:

- **gvisor runsc**: Userspace kernel for container sandboxing
- **Firecracker**: MicroVMs for strong isolation
- **Kata Containers**: VM-based container runtime
- **Custom sandbox**: Docker with seccomp, AppArmor, capabilities drop

### Integration pattern

```
┌─────────────────┐      ┌──────────────────────┐      ┌─────────────────┐
│   MCP Client    │──────▶│  MCP Security Proxy  │──────▶│ Standard Upstream│
└─────────────────┘      └──────────────────────┘      └─────────────────┘
                                │
                                │ (high-risk tools)
                                ▼
                         ┌──────────────────────┐
                         │  Isolated Executor  │
                         │  (gvisor/firecracker)│
                         └──────────────────────┘
```

The proxy makes the routing decision based on `require_for_tools` patterns before any upstream forwarding.
