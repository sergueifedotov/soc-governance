# Operational Validation, Success Criteria, and Command Appendix

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 12. Operational Validation Checklist

Before enabling autonomy beyond read-only mode:

- Hunt graph retries and timeouts validated
- JSON contracts validated against malformed LLM output
- False-positive rate measured over baseline period
- Audit logging confirmed for every tool call
- Guardrail/circuit-breaker paths tested
- Human approval path tested end-to-end

Additional quarantine-specific checks:

- quarantine policy tiers validated in integration tests
- containment verification and rollback tested on lab agents
- failure escalation path validated for tool and transport errors

## 13. Minimal Success Criteria

Autonomous threat hunting is considered production-ready when:

- Agent can run unattended in read-only mode for defined period
- Findings are reproducible from stored evidence
- Policy-gated transitions are enforced without bypass
- Analyst acceptance rate and precision meet target thresholds

Additional requirement for automated quarantine mode:

- zero unauthorized quarantine executions in test and staging baselines
- successful verification rate meets policy target
- rollback readiness confirmed for every executed containment action

## 14. Command-Oriented Appendix (First Two Scenarios)

This appendix provides safe first-run commands for replaying two adversarial
simulation families in a lab setup.

### 14.1 Preconditions

- full stack running (including Phase 3 and Phase 4)
- local MCP endpoint reachable
- test data prepared for scenario replay

### 14.2 Scenario A run sequence (SQL injection-like telemetry)

1. Seed safe synthetic web-attack telemetry into test sources.
2. Trigger autonomous hunt run in adversarial test mode.
3. Query resulting hunt artifact and metrics snapshot.

Example sequence (adapt paths/scripts to your local harness):

```bash
# 1) Seed scenario data (safe synthetic replay)
./tools/seed_forensic_samples.py --scenario sqli --safe-mode

# 2) Trigger hunt workflow (read-only adversarial mode)
curl -s -X POST http://localhost:8081/phase3/hunt/run \
  -H "Content-Type: application/json" \
  -d '{"mode":"adversarial_test","scenario":"sqli"}' | python3 -m json.tool

# 3) Inspect latest hunt result
curl -s http://localhost:8081/phase3/hunt/latest | python3 -m json.tool
```

### 14.3 Scenario B run sequence (MCP abuse simulation)

1. Replay malformed and out-of-policy test requests in lab scope.
2. Run hunt workflow in adversarial test mode.
3. Validate policy blocks, rate-limit behavior, and audit entries.

Example sequence (safe boundary-testing only):

```bash
# 1) Replay safe MCP boundary tests
./tools/test_mcp_reverse_flow.sh --adversarial-boundary-only

# 2) Trigger hunt workflow
curl -s -X POST http://localhost:8081/phase3/hunt/run \
  -H "Content-Type: application/json" \
  -d '{"mode":"adversarial_test","scenario":"mcp_abuse"}' | python3 -m json.tool

# 3) Check LLM safety metrics snapshot
curl -s http://localhost:8082/metrics | grep -E "phase4_llm_(fallback|divergence|injection)"
```

### 14.4 Notes

- Command paths and endpoints above are reference patterns and may require
  adaptation to the final hunt route names implemented in Phase 3.
- Keep all adversarial simulation in isolated non-production environments.

