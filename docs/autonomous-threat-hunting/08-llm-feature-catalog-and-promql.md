# LLM Feature Catalog, PromQL Reference, and Test Cases

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

  - target metrics: analyst triage time reduction, summary coverage (% denied calls represented), recommendation acceptance rate
- ✅ `done` — Policy tuning recommendation assistant
  - propose candidate updates to `masking_rules`/`discovery_rules` from observed traffic drift
  - target metrics: accepted policy suggestions per review cycle, overblocking reduction, underblocking reduction
  - implementation: `POST /soc/proxy-policy-recommendations` in Phase 4 server (lines 1919–2036)
  - test script: `tools/test_policy_recommendations.sh`
- ✅ `done` — Adaptive masking recommendation
  - suggest sensitive argument paths per tool and optimal masking mode (`redact`/`hash`/`tokenize`)
  - target metrics: sensitive-field exposure reduction, forensic correlation retention rate, masking rule hit ratio
  - test script: `tools/test_adaptive_masking_recommendations.sh`
- ✅ `done` — Tool intent verification
  - compare request intent metadata against actual tool/arguments and flag intent drift
  - target metrics: intent-drift detection precision/recall, challenge rate for drifted calls, escaped drift incidents
  - test script: `tools/test_tool_intent_verification.sh`
- `next` — Safe rewrite suggestions for blocked calls
  - propose sanitized alternatives preserving analyst intent without violating policy
  - target metrics: successful sanitized retries, unsafe token removal rate, analyst override rate
- `later` — Shadow-AI behavior clustering
  - batch and cluster suspicious call sequences to identify autonomous probing campaigns
  - target metrics: cluster purity, campaign detection lead time, repeat-pattern suppression rate
- `later` — Risk-aware escalation routing
  - automatically map high-risk proxy findings to Phase 3 approval workflows and SOC incidents
  - target metrics: escalation accuracy, time-to-escalate, approval rejection/rollback rate
- `later` — Client reputation scoring
  - maintain per-client behavioral trust scores to tune challenge thresholds dynamically
  - target metrics: high-risk client containment rate, low-risk friction rate, score drift stability

Implementation status and priority roadmap (analyzed)

Completed and operational in current stack:

- ✅ Pre-call LLM risk scoring (opt-in)
  - config and rollout path documented in `07-llm-risk-scoring.md`
  - enforcement supports `challenge`/`deny` decision hints with telemetry-first rollout
- ✅ Policy tuning recommendation assistant
  - endpoint: `POST /soc/proxy-policy-recommendations`
- ✅ Adaptive masking recommendation assistant
  - endpoints: `POST /soc/proxy-adaptive-masking-recommendations`,
   `POST /soc/adaptive-masking-recommendations-action`,
   apply path via `POST /soc/proxy-policy-bundle-apply`
- ✅ Tool intent verification (opt-in)
  - config/admin endpoints:
    - `GET/POST /admin/tool-intent-config`
  - Phase 4 SOC bridge endpoints:
    - `GET/POST /soc/proxy-tool-intent-config`
    - `GET /soc/proxy-tool-intent-observability`
  - runtime enforcement in proxy request path:
    - deny reasons: `llm_intent_challenge`, `llm_intent_deny`
  - Phase 4 UI rollout controls:
    - report view includes a dedicated "Tool Intent rollout" card with steps:
      1) enable score-only, 2) observe metrics, 3) save thresholds, 4) enable enforcement
    - configurable thresholds: `min_monitor_score`, `min_challenge_score`, `min_deny_score`
    - includes refresh and disable-all controls for safe rollback
  - recommended smoke test:
    - `bash tools/test_tool_intent_verification.sh`

Operational note:

- If `/soc/proxy-tool-intent-config` returns `404` while the UI is running, the deployed Phase 4 service image/version is older than the latest server code.
- Restart/redeploy Phase 4 service/profile so new SOC bridge routes are loaded.

Priority P1 (implement next, highest impact / lowest integration risk):

1. Safe rewrite suggestions for blocked calls
  - generate policy-compliant alternatives preserving analyst intent
2. Prompt injection firewall (new)
  - classify injection-like instructions before tool execution
  - route to `monitor/challenge/deny` policy actions
3. Evidence-grounded action gating (new)
  - require telemetry evidence references for high-risk write actions
  - deny execute path when evidence is missing or weak

Priority P2 (implement after P1 baselines stabilize):

1. Risk-aware escalation routing
  - map high-risk findings to approval/incident workflows
2. Client reputation scoring
  - per-client trust score with decay/recovery and threshold tuning
3. Dual-model verification for high-risk decisions (new)
  - verifier model cross-check before sensitive tool actions

Priority P3 (stateful analytics / longer-horizon):

1. Shadow-AI behavior clustering
  - sequence-level campaign clustering and repeat-pattern suppression

Recommended implementation order (practical):

1. Keep `done` features stable with smoke coverage and staged policy enforcement.
2. Deliver P1 features behind feature flags in `monitor` mode first.
3. Promote P1 to `challenge` only after precision/false-positive targets are met.
4. Deliver P2 features with approval-gated rollout and drift monitoring.
5. Enable P3 sequence analytics after sustained baseline stability.

Local LLM compatibility tiers (existing stack):

- Seamless with existing local LLM path (recommended first):
  - denied-call root-cause summarization
  - pre-call risk scoring
  - policy tuning recommendation assistant
  - adaptive masking recommendation
  - safe rewrite suggestions for blocked calls
  - tool intent verification
- Moderate effort (LLM is easy, control-plane integration needed):
  - risk-aware escalation routing
  - prompt injection firewall
  - evidence-grounded action gating
  - dual-model verification
- Higher effort (requires additional state and sequence analytics):
  - shadow-AI behavior clustering
  - client reputation scoring

LangChain vs LangGraph mapping (recommended):

| Feature | Best fit | Why |
|---|---|---|
| Pre-call risk scoring | LangChain | Request-level, low-latency classification with structured output |
| Denied-call root-cause summarization | LangGraph | Multi-step SOC narrative and policy-aware reasoning |
| Policy tuning recommendation assistant | LangChain | Deterministic JSON recommendation extraction from telemetry summaries |
| Safe rewrite suggestions for blocked calls | LangChain | Prompt-to-transformation pattern with strict output schema |
| Tool intent verification | LangChain | Single-pass intent vs argument consistency scoring |
| Adaptive masking recommendation | LangChain | Candidate rule generation from argument semantics |
| Shadow-AI behavior clustering | LangGraph | Sequence/stateful analysis across windows with branching decisions |
| Risk-aware escalation routing | LangGraph | Workflow orchestration with approval and containment branches |
| Client reputation scoring | LangGraph | Stateful trust evolution and policy transitions over time |

Execution guidance:

- Use LangChain for stateless request-time classifiers and structured policy suggestions.
- Use LangGraph for stateful workflows, escalation paths, and human-in-the-loop controls.

Tool intent verification: implementation notes (Q&A)

- Does Tool intent verification currently contain LangChain or LangGraph calls?
  - Yes. Tool intent verification is implemented as an opt-in proxy path using LangChain-based scoring.
  - Runtime/admin surfaces:
    - `GET/POST /admin/tool-intent-config`
    - `GET/POST /soc/proxy-tool-intent-config`
    - `GET /soc/proxy-tool-intent-observability`
    - deny reasons under enforcement: `llm_intent_challenge`, `llm_intent_deny`
  - Smoke validation script:
    - `tools/test_tool_intent_verification.sh`

- Why LangChain rather than LangGraph for Tool intent verification?
  - Tool intent verification is modeled as a request-level, single-pass consistency check (declared intent vs selected tool + arguments).
  - The primary requirement is low-latency scoring in the request path with structured output (for example: score, labels, decision hint).
  - LangChain is a better fit for this stateless classifier pattern and simpler deterministic extraction.
  - LangGraph would be preferred if this evolves into multi-step, stateful, branching workflows across time windows (for example: sequence-level intent drift campaigns with approvals/escalations).

Tool intent verification: event generation and test set

Tool intent verification: rollout guidance

Operator statement:

> Tool Intent Verification should start in score-only mode, then move to
> enforcement after false-positive tuning.

Meaning in practice:

- Score-only mode (`enforce=false`) evaluates intent and records scores/hints,
  but does not block production traffic.
- This stage is used to tune thresholds and intent metadata requirements while
  reviewing false positives in telemetry and denied/dependency reports.
- Enforcement mode (`enforce=true`) applies challenge/deny decisions to live
  traffic and should be enabled only after tuning quality is acceptable.

How to run Tool Intent Verification rollout (UI flow):

1. Open `http://localhost:8090/ui`.
2. Go to `Tuning Studio` -> `SOC Functionality` -> `SCORE-ONLY` tab.
3. Run `1) Enable score-only`.
4. Generate representative proxy traffic (normal + suspicious examples).
5. Run `2) Observe Tool Intent Telemetry` and review decision/denied events.
6. Adjust thresholds/metadata requirements as needed, then run
   `3) Save Thresholds`.
7. During an approved change window, run `4) Enable Enforcement`.

What is LLM Risk Rollout?

- LLM Risk Rollout is the same staged rollout pattern applied to the `llm_risk`
  classifier path.
- It introduces LLM risk scoring in score-only mode first, validates observed
  behavior and thresholds, then enables live enforcement (`challenge`/`deny`) in
  a controlled change window.
- Practical sequence: `1) Enable score-only` -> `2) Observe Metrics` ->
  `3) Save Thresholds` -> `4) Enable Enforcement`.

- Quick event generation (score-only):
  1. Enable score-only:
     - `curl -sS -X POST -H "Content-Type: application/json" -d '{"tool_intent":{"enabled":true,"enforce":false}}' http://localhost:8082/soc/proxy-tool-intent-config`
  2. Send calls through proxy MCP endpoint (`http://localhost:8090/mcp`) with `metadata.intent` populated.
  3. Observe metrics:
     - `curl -sS http://localhost:8082/soc/proxy-tool-intent-observability`
     - `curl -sS http://localhost:8090/metrics | rg "mcp_security_proxy_tool_intent"`
  4. Restore safe state:
     - `curl -sS -X POST -H "Content-Type: application/json" -d '{"tool_intent":{"enabled":false,"enforce":false}}' http://localhost:8082/soc/proxy-tool-intent-config`

- Why the sample "mismatch" call is mismatched:
  - Tool used: `get_wazuh_alerts` (read-only retrieval).
  - Declared intent: containment/remediation action (isolate endpoints, terminate processes).
  - Classification signal: intent implies active write/disruptive operation, tool+args represent passive read telemetry.
  - Result: intent-tool drift (mismatch) by design, useful for validation.

- Small matched vs mismatched dataset:
  - file: `tools/tool_intent_test_set.json`
  - structure:
    - `matched`: intents aligned to read-only `get_wazuh_alerts`
    - `mismatched`: intents implying containment/write actions while still calling `get_wazuh_alerts`

- Second dataset (write-oriented tool path):
  - file: `tools/tool_intent_test_set_write_ops.json`
  - structure:
    - `matched`: intents aligned to write/update actions for `write_alert`
    - `mismatched`: read-only investigation intents paired with write action tool usage

- Latest verified runtime output (profile C):
  - `GET /soc/proxy-tool-intent-config` -> `200`, `status: ok`
  - `GET /soc/proxy-tool-intent-observability` -> `200`, `status: ok`
  - `POST /soc/proxy-tool-intent-config` (enable score-only) -> `200`
  - `POST /soc/proxy-tool-intent-config` (threshold update 0.45/0.65/0.82) -> `200`
  - final safe restore applied:
    - `enabled: false`, `enforce: false`

- One-command mismatch sanity script:
  - `tools/sanity_tool_intent_mismatch.sh`
  - strict mode now exercises three distinct request shapes in the same run:
    - `no_metadata`, which omits the metadata block entirely and yields a deterministic `llm_intent_challenge` row
    - `empty_intent_value`, which includes `metadata.intent: ""` and still maps to the same backend missing-intent label
    - `policy_denied_tool`, which uses `search_security_events` and produces a tool policy denial
  - the script prints direct summaries for each shape so you can compare request payload variants even when the backend collapses the first two into `missing_intent_metadata`
  - when the denied-event API is available, it also filters displayed denied rows to the current run start timestamp so the Step 2 panel shows fresh records instead of reusing old history

- Minimal replay helper (set API key first):
  - `export MCP_PROXY_API_KEY="mcp_proxy_local_demo_change_me"`
  - `python3 - <<'PY'`
  - `import json, os, urllib.request`
  - `p=json.load(open('tools/tool_intent_test_set.json'))`
  - `url='http://localhost:8090/mcp'`
  - `hdr={'Authorization':f"Bearer {os.environ.get('MCP_PROXY_API_KEY','')}",'Content-Type':'application/json'}`
  - `for bucket in ('matched','mismatched'):`
  - `    for row in p[bucket]:`
  - `        body={"jsonrpc":"2.0","id":row['id'],"method":"tools/call","params":{"name":p['tool'],"metadata":{"intent":row['intent']},"arguments":p['default_arguments']}}`
  - `        req=urllib.request.Request(url,data=json.dumps(body).encode(),headers=hdr,method='POST')`
  - `        with urllib.request.urlopen(req,timeout=30) as r: print(bucket,row['id'],r.status)`
  - `PY`

- Replay second dataset:
  - same helper, change file path to:
    - `tools/tool_intent_test_set_write_ops.json`

Adaptive masking recommendation: implementation notes (Q&A)

- Does Adaptive masking recommendation currently contain LangChain or LangGraph calls?
  - Yes. Adaptive masking is implemented as a dedicated feature path with:
    - `POST /soc/proxy-adaptive-masking-recommendations`
    - `POST /soc/adaptive-masking-recommendations-action`
    - explicit operator apply path through `POST /soc/proxy-policy-bundle-apply`
  - The endpoint uses deterministic proxy-specific recommendation generation with optional LLM enrichment when available, preserving safe fallback behavior and human-review gating.

- Why LangChain rather than LangGraph for Adaptive masking recommendation?
  - The target behavior is request/payload semantics to candidate masking rule generation (`redact`/`hash`/`tokenize`) with structured outputs.
  - This is primarily a stateless classification/transformation problem and fits LangChain's low-latency, schema-constrained extraction pattern.
  - LangGraph becomes preferable when masking decisions are sequence-aware or lifecycle-aware (for example: cross-session policy evolution, approval loops, drift remediation workflows).

Adaptive masking recommendation: concrete implementation add-on

Implementation status update (recent)

- ✅ Dedicated adaptive endpoint is implemented and active:
  - `POST /soc/proxy-adaptive-masking-recommendations`
- ✅ Adaptive accept/reject action logging endpoint is implemented and active:
  - `POST /soc/adaptive-masking-recommendations-action`
- ✅ Adaptive operator enforcement path is implemented (explicit, user-triggered):
  - accepted adaptive recommendations are converted into a policy bundle and applied through
    `POST /soc/proxy-policy-bundle-apply` (dry-run or apply)
- ✅ Phase 4 UI now includes visible adaptive action feedback:
  - in-card pending/success/failure state for Accept/Reject
  - review action counters and recent decision list
  - adaptive dry-run/apply/copy/download controls
- ✅ Adaptive smoke script now validates:
  - recommendation generation
  - action logging (accept/reject)
  - enforcement path (`dry_run: true`, optional real apply)
- ✅ Adaptive recommendation dedupe against active policy is implemented:
  - already-applied masking rules (including `client_ip -> redact`) are filtered out from new adaptive recommendations
  - filter reads active policy from `/admin/policy-config` using `policy` with fallback to `raw_policy`

1. API and control points
  - Dedicated endpoint (implemented): `POST /soc/proxy-adaptive-masking-recommendations`.
   - Keep `POST /soc/proxy-policy-recommendations` unchanged for broad policy tuning; use the new endpoint for masking-specific guidance only.
   - Implementation touchpoints:
     - `src/wazuh_mcp_server/phase4/server.py` (new route and response model)
     - `src/wazuh_mcp_server/mcp/handlers/tools.py` (register MCP tool schema)
     - `src/wazuh_mcp_server/mcp/tool_handlers/phase2.py` (tool execution and validation)
     - `src/wazuh_mcp_server/phase4/static/index.html` (new UI panel/cards)

2. Expected request/response contract
   - Input fields:
     - `time_range`, `limit`, `tool_filter` (optional), `mode` (`monitor` or `review`), `run_llm`.
   - Output fields:
     - `status`, `summary`, `recommendations`, `human_review_required`, `safety_model`.
   - Recommendation item fields:
     - `tool`, `argument_path`, `recommended_mode` (`redact`/`hash`/`tokenize`), `confidence`, `rationale`, `examples`, `expected_impact`.

3. Safety and rollout model
   - Default to recommendations-only (no auto-apply).
   - Gate all suggestions behind human review and change control.
   - Rollout stages:
     - `monitor`: generate recommendations and track quality metrics only.
     - `review`: allow operator acceptance workflow and staging validation.

4. Observability (recommended metrics)
   - `mcp_security_proxy_masking_recommendations_total`
   - `mcp_security_proxy_masking_recommendation_confidence`
   - `mcp_security_proxy_masking_recommendation_latency_seconds`
   - `mcp_security_proxy_masking_recommendation_accepted_total`

5. Acceptance criteria
   - Sensitive-field exposure decreases without reducing incident correlation quality.
   - Operator acceptance rate remains at or above agreed threshold.
   - False-positive masking suggestions remain below agreed threshold.
   - No regression in proxy throughput or p95 request latency SLO.

6. Smoke test checklist (staging)
   - one-command smoke script:
     - `bash tools/test_adaptive_masking_recommendations.sh`
     - discovery trigger validation (attack-pattern rule):
       - `bash tools/test_discovery_attack_pattern_denials.sh`
     - optional overrides: `PHASE4_BASE_URL`, `TIME_RANGE`, `LIMIT`, `MODE`, `TOOL_FILTER`
     - script coverage includes:
       - monitor-mode recommendation generation
       - review-mode recommendation generation with optional tool filter
       - invalid mode validation (`400`)
       - action logging endpoint checks for both `accept` and `reject`
       - adaptive apply-path validation via `POST /soc/proxy-policy-bundle-apply` dry-run
       - optional real apply path when `APPLY_CHANGES=1`
   - Baseline request (monitor mode):
     - `POST /soc/proxy-adaptive-masking-recommendations`
     - body example:

```json
{
  "time_range": "24h",
  "limit": 100,
  "mode": "monitor",
  "run_llm": true
}
```

   - Expected success assertions:
     - HTTP `200` with `status: "ok"`.
     - `summary` object present with deny/masking context fields.
     - `recommendations` is an array (possibly empty) with item-level keys:
       - `tool`, `argument_path`, `recommended_mode`, `confidence`, `rationale`.
     - `human_review_required` is `true`.
     - `safety_model` indicates recommendations-only behavior.

   - Mode validation checks:
     - `mode: "monitor"` returns recommendations without any auto-apply side effects.
     - `mode: "review"` returns review-ready recommendations and preserves human approval gating.

   - Input validation checks:
     - invalid `time_range` returns `400`.
     - `limit < 1` or oversized `limit` is rejected or clamped per API contract.
     - invalid `mode` returns `400`.
     - malformed JSON returns `400`.

   - Robustness checks:
     - LLM unavailable path still returns deterministic/recoverable response (no `5xx` regression in normal conditions).
     - empty telemetry window returns `status: "ok"` and empty/low-confidence recommendations.
     - high-volume window remains within target p95 latency envelope.

   - Security checks:
     - RBAC rejects unauthorized callers (`401`/`403` as configured).
     - response payload does not expose raw secrets in `examples` or rationale text.
     - audit trail records request outcome and recommendation generation path.

   - Action endpoint checks:
     - `POST /soc/adaptive-masking-recommendations-action` with `action: "accept"` returns HTTP `200` and `action_recorded: true`.
     - `POST /soc/adaptive-masking-recommendations-action` with `action: "reject"` returns HTTP `200` and `action_recorded: true`.
     - response includes `recommendation_index` and server timestamp.

   - Enforce-path checks:
     - dry-run apply: `POST /soc/proxy-policy-bundle-apply` with adaptive masking bundle and `dry_run: true` returns HTTP `200`.
     - optional real apply: run smoke script with `APPLY_CHANGES=1` to validate `dry_run: false` path in staging.

Adaptive masking + current policy tuning: how they combine

1. Shared telemetry foundation
  - Both flows consume the same proxy denied-call telemetry summaries (`reason_counts`, `tool_counts`, top offenders, root-cause hints).
  - This keeps recommendations consistent across governance and masking-specific views.

2. Separate endpoints by intent
  - Broad policy tuning remains on `POST /soc/proxy-policy-recommendations` (masking + discovery recommendations).
  - Adaptive masking uses `POST /soc/proxy-adaptive-masking-recommendations` (masking-only recommendation objects).

3. Shared safety and fallback model
  - Both are recommendations-only with `human_review_required: true`.
  - Both attempt LLM/MCP enrichment when available and fall back to deterministic proxy-specific logic when unavailable.
  - Both now support explicit operator decision logging (`accept`/`reject`).
  - Adaptive masking also supports explicit operator-triggered enforcement via policy bundle apply (dry-run first, then apply).

4. Output specialization
  - Policy tuning output optimizes for policy governance changes (`masking_rules` and `discovery_rules`).
  - Adaptive masking output optimizes for per-tool argument treatment (`argument_path`, `recommended_mode`, confidence, rationale).

5. UI-side coexistence
  - Both run from the same Policy Tuning view in Phase 4.
  - Existing policy actions remain unchanged; adaptive controls, presets, and action buttons are additive and optional.

6. Action logging endpoints
  - Policy tuning actions: `POST /soc/policy-recommendations-action`
  - Adaptive masking actions: `POST /soc/adaptive-masking-recommendations-action`
  - Both endpoints record `accept`/`reject` decisions for audit trails; they do not auto-apply policy changes.
  - Adaptive enforcement uses `POST /soc/proxy-policy-bundle-apply` as a separate, explicit operator step.

7. Dedupe behavior after apply
  - After a masking rule is applied and visible in active proxy policy, the adaptive endpoint suppresses equivalent recommendations in subsequent runs.
  - Example: if `client_ip` with mode `redact` already exists in policy, adaptive output should not re-suggest the same rule.
  - Operational note: if stale recommendations appear immediately after deployment, restart the Phase 4 service/profile so the latest filtering logic is active.

Recommended operator workflow:

1. Run Adaptive Masking in `monitor` mode to baseline suggestions.
2. Run Adaptive Masking in `review` mode for scoped tools and analyst approval.
3. Run Policy Tuning to align approved masking updates with discovery/governance changes.
4. Apply through change control after staging validation.

Current completed baseline (first 3 delivered):

1. ✅ Pre-call risk scoring
  - implementation point: `services/mcp_security_proxy/app.py` in `/mcp` flow before upstream forwarding
  - key metrics: `mcp_security_proxy_llm_risk_calls_total`, `mcp_security_proxy_llm_risk_latency_seconds`

2. ✅ Policy tuning recommendation assistant
  - endpoint: `POST /soc/proxy-policy-recommendations`
  - outputs policy-ready masking/discovery recommendations with confidence + rationale

3. ✅ Tool intent verification (opt-in)
  - runtime path: `services/mcp_security_proxy/app.py`
  - admin config: `GET/POST /admin/tool-intent-config`
  - deny reasons under enforce mode: `llm_intent_challenge`, `llm_intent_deny`
  - smoke test: `tools/test_tool_intent_verification.sh`

Next implementation 3-pack (recommended):

1. Safe rewrite suggestions for blocked calls
2. Prompt injection firewall
3. Evidence-grounded action gating

Acceptance criteria for the next 3-pack:

- no regression in normal SOC call success rate
- p95 latency remains within configured SLO for request-time classifiers
- false-positive challenge/deny rates remain below agreed threshold
- analyst acceptance rate for rewrite/policy suggestions meets target

Prometheus queries you can use in Grafana Explore:

```promql
sum by (tool, reason) (increase(mcp_security_proxy_denied_total[$__range]))
```

```promql
sum by (decision) (rate(mcp_security_proxy_calls_total[1m]))
```

```promql
sum by (tool) (rate(mcp_security_proxy_calls_total{decision="deny"}[1m]))
```

Recommended test cases:

- malformed tool argument structures
- out-of-policy tool attempts from read-only contexts
- high-rate repeated calls (rate-limit validation)
- prompt-injection style text in otherwise benign requests
- boundary checks for invalid parameter types and sizes

Security controls to validate:

- input validation rejection paths
- RBAC scope enforcement (`wazuh:read` vs `wazuh:write`)
- rate-limiting behavior and temporary blocking
- audit log completeness for denied and accepted calls
- LLM safety signal impact (fallback/divergence/injection-suspect)

