# Local Optimization and Runtime Profiles

This document collects the practical local runtime guidance for this repository:

- startup and shutdown profiles A-D
- single-workstation performance constraints
- model sizing and service selection guidance
- host-level tuning decisions for autonomous hunting experiments

It is the operational companion to
`docs/AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md`, which stays focused on
architecture, workflow, safety controls, and target-state functionality.

## 1. Local Model Guidance

For autonomous tool-planning quality, prefer stronger local tool-calling models
(e.g. Qwen class) over minimal-footprint models.

- Use larger context sizes for multi-step hunts with large evidence payloads.
- Keep deterministic fallback behavior for all critical decisions.
- Log prompt and output summaries (not sensitive raw data) for auditability.

## 2. Recommended Local Execution Matrix (Apple M1 Max, 32 GB RAM)

This section translates the architecture into a practical single-PC run
strategy for a host with these characteristics:

- Apple M1 Max
- 10 CPU cores
- 32 GB RAM

Conclusion for this host:

- the core platform plus a light autonomous hunting service is feasible
- OpenCTI should be treated as optional / on-demand
- larger local models and continuous heavy hunt schedules should be avoided
  unless other optional services are stopped

### Profile A: Everyday development baseline

Goal: stable local development with enough headroom for editing, testing, and
light investigations.

Keep running:

- Wazuh core stack
- `wazuh-mcp-server`
- `phase3-langgraph`
- `phase4-api`
- Prometheus
- Grafana
- light local model profile (`ai/gemma3-qat` or equivalent)

Keep off by default:

- OpenCTI overlay
- Langfuse
- autonomous adversarial simulation jobs
- DB/storage batch hunts

Recommended autonomy mode:

- read-only hunts only
- manual trigger or low-frequency schedule
- one active hunt at a time

Start and stop:

```bash
bash tools/start-profile.sh A --no-build
bash tools/stop-profile.sh A
```

### Profile B: Autonomous hunting development

Goal: validate the autonomous hunt service itself while keeping the machine
usable.

Keep running:

- everything from Profile A
- autonomous hunt service (`autonomous-hunt-rust` or prototype equivalent)

Keep constrained:

- hunt concurrency = 1
- small evidence windows
- strict tool-call and record budgets
- no DB/storage destructive actions

Recommended schedule:

- event-driven hunts preferred
- if scheduled, use coarse intervals rather than continuous polling

Start and stop:

```bash
bash tools/start-profile.sh B --no-build
bash tools/stop-profile.sh B
```

### Profile C: Investigation mode with OpenCTI

Goal: short-lived higher-context investigations that need threat-intel overlay.

Bring up on demand:

- OpenCTI platform
- OpenCTI worker
- OpenCTI connector

Recommended compensating actions:

- keep Langfuse disabled
- keep model on low-memory profile
- avoid simultaneous adversarial simulation runs
- stop autonomous background schedules while interactive investigations run

Start and stop:

```bash
bash tools/start-profile.sh C --no-build
bash tools/stop-profile.sh C
```

### Profile D: Heavy test / stress mode

Goal: validate orchestration under near-full architecture load.

Allowed only temporarily:

- OpenCTI enabled
- autonomous hunt service enabled
- DB/storage hunt modules enabled
- adversarial simulation enabled

Required constraints:

- single active scenario at a time
- no large-context model upgrades unless another optional subsystem is stopped
- manual supervision throughout the run

Start and stop:

```bash
bash tools/start-profile.sh D --no-build
bash tools/stop-profile.sh D
```

## 3. Startup and Shutdown Wrappers

Use the profile-aware wrappers in `tools/`:

```bash
bash tools/start-profile.sh --help
bash tools/stop-profile.sh --help
```

Implemented flags:

- `tools/start-profile.sh <A|B|C|D> [--no-build] [--autonomous-compose PATH]`
- `tools/stop-profile.sh <A|B|C|D> [--volumes] [--autonomous-compose PATH]`

Operational notes:

- **First run:** copy `.env.example` to `.env` and set `MCP_API_KEY` to
  `wazuh_` + `secrets.token_urlsafe(32)` **before** `start-profile.sh`. `CHANGE_ME` is
  rejected and breaks Phase 4 **Fetch Alerts**. Details:
  [OPERATIONS.md](OPERATIONS.md#first-run-local-stack).
- Profiles B and D look for an optional future autonomous overlay file named
  `compose.autonomous-hunt.yml` or `compose.autonomous.yml`.
- If no autonomous overlay exists yet, B and D still start the currently
  implemented stack and print a note that the autonomous service is not
  present.
- `--autonomous-compose=PATH` can be used to force a specific autonomous
  overlay file.
- Add `--volumes` to `tools/stop-profile.sh` only when you explicitly want to
  wipe persistent data for that profile.

## 4. Architectural Decisions Recommended for This Host

1. Separate always-on services from burst services.

- always-on: core Wazuh, MCP, Phase 3, Phase 4, Prometheus, Grafana
- burst: OpenCTI, autonomous simulations, DB/storage batch hunts

2. Keep the autonomous hunt service outside the default always-on startup path.

- run it as a separate service or overlay
- start it only when testing autonomous behavior or scheduled hunts

3. Prefer event-driven hunts over continuous polling.

- trigger on anomalies, spikes, watchlist updates, or explicit analyst request

4. Treat DB/storage hunts as batch jobs.

- these hunts need wider baselines and should not compete continuously with
  everyday SOC workflows

5. Keep the local model small and the context bounded.

- small model + strict schema + deterministic prefiltering is a better local
  tradeoff than a larger general-purpose model

## 5. Default Tuning Guidance for This Host

Recommended defaults for local autonomous runs:

- max active hunts: 1
- max tool calls per hunt: low double digits
- max records per call: capped aggressively
- default time window: short (for example 15 m to 60 m)
- DB/storage hunts: manual or coarse scheduled batches only
- adversarial simulation: one scenario per run

## 6. Service-Level Guidance

- Keep OpenCTI optional. It is the clearest candidate for on-demand startup.
- Keep Langfuse off locally unless tracing is the explicit task.
- Keep Neo4j memory bounded unless measurement shows a real bottleneck.
- Persist hunt baselines and prior results so repeated runs avoid expensive
  recomputation.

## 7. Practical Single-PC Rule

For this machine, do not optimize for "everything on all the time." Optimize
for:

- stable core observability and SOC workflows always on
- autonomous hunting enabled when needed
- heavy overlays and simulation paths enabled only for focused sessions

This gives the best balance of responsiveness, realism, and development speed
on a 32 GB Apple Silicon workstation.