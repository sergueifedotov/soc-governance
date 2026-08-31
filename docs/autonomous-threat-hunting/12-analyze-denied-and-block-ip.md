# Analyze Denied — Incident Mechanics and Block-IP Justification

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 16. Analyze Denied — Incident and Approval Request Mechanics

### 16.1 When INC-proxy-deny-* IDs are created

Incident IDs of the form `INC-proxy-deny-<unix_timestamp>` are generated inside
`proxy_denied_llm_analysis` in `src/wazuh_mcp_server/phase4/server.py` the
moment the endpoint handles an Analyze Denied request:

```python
incident_id = payload.get("incident_id") or f"INC-proxy-deny-{int(time.time())}"
```

- The numeric suffix is the Unix epoch in seconds when the call arrived.
- Example: `INC-proxy-deny-1778858691` was created at **2026-05-15 11:24:51 EDT**.
- If the caller provides an `incident_id` field in the request body, that value
  is used instead (useful for correlating with a pre-existing ticket).

### 16.2 When an approval request is created

Approval requests are **not** created for every Analyze Denied call. They are
created only when all of the following are true simultaneously:

1. **Workflow mode is selected** — the UI dropdown defaults to
   `Workflow (Phase 3)` (`llm_mode=workflow`). Selecting
   `Analysis Only (No Approval)` skips Phase 3 entirely.
2. **Auto-approve is unchecked** — the `Auto-approve workflow` checkbox is
   unchecked by default. Checking it causes Phase 3 to skip the approval gate.
3. **Risk tier requires approval** — Phase 3 requires approval for `medium`,
   `high`, and `critical` risk tiers. `low` skips the gate.

Flow when all three conditions hold:

```
Analyze Denied (UI)
  └─► POST /soc/proxy-denied-llm-analysis  {llm_mode:"workflow", phase3_auto_approve:false}
        └─► POST /phase3/run               risk_tier=medium|high
              └─► node_approval_gate       approval_required=true, auto_approve=false
                    └─► node_pending_approval
                          └─► POST /approvals  (Phase 4 persists approval record)
```

Approval records are persisted in the Phase 4 SQLite/Postgres database via
`src/wazuh_mcp_server/phase4/incident_management/__init__.py` (`ApprovalRequest`
model). They expire in 30 minutes by default and contain the full proposed
action for analyst review.

### 16.3 Justification for approval gates

The design rationale is explicit in the code comments and model docstring:

> *"Created when a Phase 3 workflow reaches an approval gate for a
> medium/high/critical risk action. Analysts approve or reject via the Phase 4
> web UI; Phase 4 then resumes the Phase 3 workflow."*

Containment actions (firewall drops, host isolation) are irreversible or
service-impacting if applied to the wrong target. Requiring human confirmation
before execution prevents automated false-positive blocking.

---

## 17. Block-IP Action — IP Selection and Justification

### 17.1 Why `block_ip` is always proposed

`use_case = "block_ip"` is hardcoded in the Analyze Denied handler whenever
proxy-denied events are present. It is not derived from the deny reasons
dynamically:

```python
# src/wazuh_mcp_server/phase4/server.py
phase3_payload = {
    "use_case": "block_ip",   # hardcoded for proxy-denied flow
    ...
}
```

This maps to the following tool chain in Phase 3:

| Stage     | Tool                    |
|-----------|-------------------------|
| Action    | `wazuh_firewall_drop`   |
| Verify    | `wazuh_check_blocked_ip`|
| Rollback  | `wazuh_firewall_allow`  |

### 17.2 How the target IP is selected

The IP is the **most frequent client IP** across all denied proxy events in the
analysis window — `top_client_ip` from the deny-event summary:

```python
# src/wazuh_mcp_server/phase4/server.py
top_client_ip = max(client_counts.items(), key=lambda x: x[1])[0]

# Then in the Analyze Denied handler:
src_ip = summary["top_client_ip"] if summary["top_client_ip"] != "unknown" else "198.51.100.42"
```

- `192.168.65.1` appeared because it was the Docker host gateway address that
  generated the highest volume of denied proxy calls in that session.
- If no valid client IP is found, the fallback `198.51.100.42`
  (an IANA documentation/TEST-NET address) is used so the workflow can still
  demonstrate end-to-end execution without targeting a real address.

### 17.3 What the analyst sees in the approval request

The Phase 4 approval UI presents the full proposed action payload:

| Field            | Value (example)             |
|------------------|-----------------------------|
| `action_tool`    | `wazuh_firewall_drop`       |
| `args.src_ip`    | `192.168.65.1`              |
| `args.duration`  | 600 s (10-minute block)     |
| `args.agent_id`  | `000`                       |
| `risk_tier`      | `medium` or `high`          |
| `workflow_summary` | alert count, top rule, source IPs from Wazuh triage |

The analyst approves or rejects before any firewall change is made.

### 17.4 Known limitation — frequency ≠ maliciousness

`top_client_ip` is a frequency-based heuristic. A high-volume but legitimate
internal host (such as 192.168.65.1 — the Docker host gateway in a local dev
stack) can top the list without being genuinely malicious.

The approval gate is the primary safeguard against this false-positive scenario.
Operators should also tune the deny-event filter (e.g., enable
`llm_risk events only` in the UI) to restrict the candidate IP pool to
confirmed high-risk callers before triggering workflow mode.
