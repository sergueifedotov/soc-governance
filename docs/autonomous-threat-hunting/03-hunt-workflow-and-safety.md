# Proposed Hunt Workflow and Safety Controls

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 5. Proposed Autonomous Hunt Workflow

### 5.1 Trigger

Run from one or more triggers:

- Time-based (every N minutes)
- Event-based (severity spike, repeated source IP, repeated rule bursts)
- IOC/watchlist updates

### 5.2 Hunt planning node (LLM)

Input:

- Recent telemetry summary
- Prior hunt outcomes
- Watchlist indicators
- Scope constraints (time, environments, limits)

Output (strict JSON contract):

- `hypotheses[]`
- `evidence_plan[]` (tool, args, rationale)
- `termination_conditions`
- `confidence_initial`

### 5.3 Evidence collection nodes (deterministic)

Execute only allowlisted read tools. Enforce hard limits for:

- max calls per run
- max records per call
- max hunt runtime

### 5.4 Correlation and scoring node

- Deterministic signal scoring first
- Optional LLM synthesis for analyst-facing explanation
- Output includes confidence, severity, and recommendation

### 5.5 Decision gate

- Low score: close as no finding
- Medium score: queue analyst review
- High score: escalate to Phase 3 playbook or response path
- Destructive actions remain policy-gated or approval-gated

### 5.6 Output and state persistence

Persist a hunt result artifact containing:

- hypothesis
- evidence links
- score/confidence
- recommended next action
- rollback note (if any action path selected)

## 6. Safety and Governance Controls

The autonomous hunt flow must enforce:

1. LLM never directly executes arbitrary actions.
2. Tool allowlist per node type.
3. Strict JSON schema validation for LLM outputs.
4. Read-only default for hunt mode.
5. Human approval for high-impact response actions.
6. Circuit-breakers from existing LLM health metrics.

### 6.1 Recommended circuit-breakers

Pause or degrade hunt autonomy when:

- fallback rate exceeds threshold
- verdict divergence remains above threshold
- injection-suspect metric is non-zero or rising

## 7. Local Model Guidance

The local runtime profiles, start and stop commands, and single-host
optimization guidance have been moved to
`docs/LOCAL_OPTIMIZATION_AND_PROFILES.md`.

Use that companion document for:

- profile A-D startup and shutdown commands
- local host sizing guidance for Apple Silicon development machines
- practical service enablement rules for OpenCTI, Langfuse, and autonomous
  overlays
- tuning defaults for hunt concurrency, tool budgets, and batch scheduling

