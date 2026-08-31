# Automated Quarantining Capability

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 11. Automated Quarantining Capability (Active Breach)

This section defines how to add automated quarantining in a controlled,
policy-gated way when the system detects an active breach.

### 11.1 Quarantine objective

Limit blast radius quickly while preserving service safety and reversibility.

### 11.2 Trigger conditions

Allow quarantine only when all required conditions are met:

- breach classification is active and confidence exceeds policy threshold
- independent evidence confirms compromise scope (not single noisy signal)
- target host identity is validated and mapped to an approved environment scope
- change window and incident policy allow automated containment

### 11.3 Recommended policy model

Use a tiered policy for quarantine authority:

- Tier 0 (read-only): no quarantine actions allowed
- Tier 1 (semi-auto): prepare quarantine plan and require analyst approval
- Tier 2 (auto-containment): execute quarantine for pre-approved high-risk cases

### 11.4 Execution flow

1. Detection and scoring node marks active breach candidate.
2. Policy gate evaluates confidence, scope, allowlists, and safety checks.
3. If allowed, execute containment tool call (for example host isolation).
4. Run verification tool call to confirm containment success.
5. Emit incident report update and quarantine audit record.
6. Keep rollback action prepared and callable.

### 11.5 Tooling and controls

Suggested containment and validation sequence:

- containment action: isolate affected endpoint
- verification action: check isolation state
- optional parallel controls: firewall deny for confirmed command-and-control IP
- rollback action: unisolate host when incident commander approves

Mandatory controls:

- strict allowlist of quarantine-capable tools
- deny quarantine on unknown or unmanaged assets
- one-quarantine-attempt lock to avoid repeated flapping
- cooldown and retry limits with analyst escalation on repeated failure

### 11.6 Failure handling

If quarantine or verification fails:

- mark incident status as containment_failed
- raise immediate analyst page/escalation
- attach error telemetry and last successful evidence snapshot
- block further automated destructive actions until human review

### 11.7 Audit and compliance requirements

For each quarantine decision, persist:

- decision inputs (signals, scores, policy checks)
- executed tool name, arguments, result, and verification result
- actor identity (autonomous agent mode and workflow run id)
- timestamps for detect, decide, execute, verify, rollback-ready

### 11.8 Guardrail interaction with LLM health metrics

Automatically reduce or disable quarantine autonomy when:

- LLM fallback rate is above threshold
- LLM divergence rate is above threshold
- injection-suspect signals are active

In degraded mode, switch to Tier 1 (approval required) regardless of confidence.

