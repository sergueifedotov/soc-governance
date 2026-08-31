# End-to-End Testing Guide

## Overview

The `tests/e2e_test_script.py` provides comprehensive end-to-end testing for the entire Wazuh MCP Server system, covering:

- **23 distinct test scenarios** across 7 categories
- **Authentication flows** (bearer token, API key validation)
- **MCP protocol compliance** (initialize, tools/list, tools/call)
- **All 51 security tools** (sampling key operations)
- **Performance testing** (response times, concurrency, rate limiting)
- **Error handling** (malformed JSON, timeouts, invalid inputs)
- **Session management** (creation, lifecycle)

## Quick Start

### Run All Tests

```bash
# From project root
python tests/e2e_test_script.py

# With custom server URL
python tests/e2e_test_script.py --server http://192.168.1.100:3000

# With custom API key
python tests/e2e_test_script.py --api-key your_actual_api_key

# Verbose output
python tests/e2e_test_script.py --verbose

# JSON output for CI/CD
python tests/e2e_test_script.py --json > results.json
```

### Run with pytest

```bash
# Run as pytest test class
pytest tests/e2e_test_script.py -v

# Run specific test
pytest tests/e2e_test_script.py::TestWazuhMCPServerE2E::test_all_e2e_scenarios -v
```

### Run in Docker

```bash
# Inside Docker container
cd /src && python tests/e2e_test_script.py --server http://localhost:3000
```

## Test Coverage

### Section 1: Health & Connectivity (3 tests)

**Purpose**: Verify server is alive and reachable

| Test | Purpose | Expected Result |
|------|---------|-----------------|
| `server_health` | `/health` endpoint | HTTP 200 with status field |
| `server_connectivity` | Basic TCP connectivity | HTTP 200/404/405 |
| `metrics_endpoint` | `/metrics` availability | HTTP 200 with metrics |

**Success Criteria**: All 3 pass

### Section 2: Authentication (3 tests)

**Purpose**: Validate all authentication modes work correctly

| Test | Purpose | Success Condition |
|------|---------|-------------------|
| `auth_bearer_token_generation` | Generate bearer token from API key | HTTP 200 + `access_token` in response |
| `auth_invalid_api_key` | Reject invalid API keys | HTTP 401/403 |
| `auth_missing_authorization` | Handle unauthenticated requests | HTTP 200 (authless), 401/403 (auth required) |

**Success Criteria**: All 3 pass

### Section 3: MCP Protocol (3 tests)

**Purpose**: Ensure MCP 2025-11-25 compliance

| Test | Purpose | Expected Result |
|------|---------|-----------------|
| `mcp_initialize` | Initialize MCP session | HTTP 200 + sessionId |
| `mcp_tools_list` | List available tools | HTTP 200 + 51 tools |
| `mcp_request_validation` | Reject invalid requests | HTTP 200 (error in result) or 400 |

**Success Criteria**: All 3 pass

### Section 4: Security Tools (8 tests)

**Purpose**: Verify core security tool functionality

| Test | Tool | Expected Result |
|------|------|-----------------|
| `tool_get_wazuh_alerts` | `get_wazuh_alerts` | HTTP 200/400/503 |
| `tool_get_wazuh_agents` | `get_wazuh_agents` | HTTP 200/400/503 |
| `tool_get_wazuh_vulnerabilities` | `get_wazuh_vulnerabilities` | HTTP 200/400/503 |
| `tool_validate_wazuh_connection` | `validate_wazuh_connection` | HTTP 200/400/503 |
| `tool_get_wazuh_statistics` | `get_wazuh_statistics` | HTTP 200/400/503 |
| `tool_check_wazuh_health` | `check_wazuh_health` | HTTP 200/400/503 |
| `tool_invalid_arguments` | Argument validation | HTTP 200/400 (graceful error) |
| `tool_nonexistent_tool` | Invalid tool rejection | HTTP 200/400 (error response) |

**Success Criteria**: All 8 pass (500-level errors expected if Wazuh not configured)

### Section 5: Performance & Reliability (3 tests)

**Purpose**: Verify system performance and scalability

| Test | Scenario | Thresholds |
|------|----------|-----------|
| `response_time_health_100ms` | Health endpoint latency | < 100ms |
| `concurrent_requests` | 5 concurrent requests | All succeed |
| `rate_limiting` | 20 requests in ~5 seconds | Proper rate limit enforcement or all pass |

**Success Criteria**: All 3 pass

**Note**: Performance thresholds assume a properly configured system. Adjust for your infrastructure.

### Section 6: Error Handling (2 tests)

**Purpose**: Validate graceful error handling

| Test | Scenario | Expected Behavior |
|------|----------|-------------------|
| `error_handling_malformed_json` | Send invalid JSON | HTTP 400/422 |
| `error_handling_timeout` | Slow request completion | Timeout or completion |

**Success Criteria**: All 2 pass

### Section 7: Session Management (1 test)

**Purpose**: Verify session lifecycle

| Test | Purpose | Expected Result |
|------|---------|-----------------|
| `session_creation` | Create new session | HTTP 200 + sessionId |

**Success Criteria**: Pass

### Section 8: LangChain Phase 2 Functionality (10 tests) ⭐ NEW

**Purpose**: Comprehensive testing of LangChain-backed Phase 2 SOC orchestration tools

| Test | Purpose | Scenario | Expected Result |
|------|---------|----------|-----------------|
| `langchain_config_detection` | Detect LLM configuration | Call triage tool | Response with or without synthesis |
| `phase2_triage_wazuh_alerts` | Alert triage synthesis | 24h time range | HTTP 200 + well-formed response |
| `phase2_enrich_wazuh_context` | Context enrichment | Search specific query | HTTP 200 + enriched data |
| `phase2_generate_soc_handoff_report` | Report generation | Shift report | HTTP 200 + structured report |
| `langchain_response_structure` | Response format validation | Check response schema | Valid JSON structure |
| `langchain_fallback_mode` | Fallback without LLM | Disabled PHASE2_LLM_ENABLED | Deterministic response or 503 |
| `langchain_timeout_handling` | Timeout resilience | 7d report generation | HTTP 200/400/503/504 |
| `langchain_parameter_validation` | Parameter checking | Invalid time_range | HTTP 200/400 (graceful) |
| `langchain_all_time_ranges` | All supported ranges | 1h, 6h, 12h, 1d, 24h, 7d, 30d | All succeed |
| `langchain_response_performance` | Synthesis performance | Standard query | < 60s completion |

**Success Criteria**: All 10 pass

**Notes**: 
- Tests pass whether LangChain is enabled or disabled
- With LLM enabled: Responses use LangChain synthesis (slower, ~5-45s)
- With LLM disabled: Responses use deterministic fallback (faster, ~0.5-2s)
- HTTP 503 expected if Wazuh backend not available
- Requires Phase 2 LLM configuration for full synthesis testing

## Test Results Report

The script generates a comprehensive report:

```
================================================================================
WAZUH MCP SERVER - END-TO-END TEST REPORT
================================================================================

Server: http://localhost:3000
Timestamp: 2024-12-11T10:30:45.123456

Test Results:
  Total:  33
  Passed: 33 ✓
  Failed: 0 ✗
  Pass Rate: 100.0%

Timing Summary:
  Total Time: 8.42s
  Avg Time: 0.26s
  Fastest: 0.012s
  Slowest: 2.341s

================================================================================
```

### JSON Output Format

When using `--json` flag, output follows this structure:

```json
{
  "total": 23,
  "passed": 23,
  "failed": 0,
  "skipped": 0,
  "errors": [],
  "timings": {
    "server_health": 0.015,
    "server_connectivity": 0.012,
    "auth_bearer_token_generation": 0.023,
    // ... etc
  }
}
```

## Common Issues & Troubleshooting

### Issue: "Connection refused" on localhost:3000

**Solution**: Ensure server is running
```bash
# Terminal 1: Start the server
python -m wazuh_mcp_server

# Terminal 2: Run tests
python tests/e2e_test_script.py
```

### Issue: All Wazuh tool tests return HTTP 503

**Solution**: Wazuh backend not configured. This is expected if:
- `WAZUH_URL` not set
- `WAZUH_USERNAME` / `WAZUH_PASSWORD` not configured
- Wazuh server not accessible from test environment

The test script handles this gracefully. HTTP 503 is a valid response indicating the backend is not available.

### Issue: Rate limiting test fails

**Solution**: Adjust expectations based on your rate limit configuration in `config.py`:
```python
RATE_LIMIT_REQUESTS = 100  # in RATE_LIMIT_WINDOW_SECONDS
RATE_LIMIT_WINDOW_SECONDS = 60
```

### Issue: Timeout errors

**Solution**: Increase timeout values in the script
```python
# In e2e_test_script.py
self._make_request("GET", "/health", timeout=30)  # Increase from default 30
```

### Issue: Bearer token test fails with 401

**Solution**: Verify API key
```bash
# Check .env file for correct MCP_API_KEY
grep MCP_API_KEY .env

# Or run with explicit API key
python tests/e2e_test_script.py --api-key $(grep ^MCP_API_KEY= .env | cut -d= -f2)
```

### Issue: LangChain Phase 2 tests timeout or slow

**Solution**: LangChain tests may be slower due to LLM synthesis. Check configuration:
```bash
# Check if Phase 2 LLM is enabled
grep PHASE2_LLM_ENABLED .env

# If enabled, verify the LLM endpoint is accessible
curl -s http://model-runner.docker.internal/engines/v1/models | jq '.data[0].id'

# Disable LLM for faster testing (uses deterministic fallback)
export PHASE2_LLM_ENABLED=false
python tests/e2e_test_script.py
```

Expected timings:
- **With LLM enabled**: Phase 2 tests take 5-45 seconds each
- **With LLM disabled**: Phase 2 tests take 0.5-2 seconds each

### Issue: Phase 2 tools return synthesis errors

**Solution**: Check LangChain configuration
```bash
# Verify all Phase 2 settings
grep PHASE2_LLM .env

# Required settings for LLM synthesis:
# PHASE2_LLM_ENABLED=true
# PHASE2_LLM_MODEL=ai/qwen3  (or your model)
# PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
# PHASE2_LLM_TIMEOUT_SECONDS=45
```

If LLM is not configured:
- Tests still pass (fallback mode)
- Tools return deterministic summaries instead of LLM-synthesized analysis
- No errors are generated

## Integration with CI/CD

### GitHub Actions Example

```yaml
name: E2E Tests
on: [push, pull_request]

jobs:
  e2e:
    runs-on: ubuntu-latest
    services:
      wazuh-mcp:
        image: wazuh-mcp-server:latest
        ports:
          - 3000:3000
        env:
          MCP_API_KEY: test_key_12345
    
    steps:
      - uses: actions/checkout@v2
      - uses: actions/setup-python@v2
        with:
          python-version: '3.11'
      - run: pip install -r requirements.txt requests
      - run: python tests/e2e_test_script.py --json > results.json
      - uses: actions/upload-artifact@v2
        with:
          name: e2e-results
          path: results.json
```

### GitLab CI Example

```yaml
e2e-test:
  stage: integration
  image: python:3.11
  services:
    - wazuh-mcp-server:latest
  before_script:
    - pip install -r requirements.txt requests
  script:
    - python tests/e2e_test_script.py --server http://wazuh-mcp-server:3000
  artifacts:
    when: always
    paths:
      - e2e-results.json
```

## Performance Benchmarking

To profile test performance:

```bash
# With timing details
python tests/e2e_test_script.py --verbose 2>&1 | grep -E "(PASS|FAIL|s\)$)"

# With Python profiling
python -m cProfile -s cumtime tests/e2e_test_script.py > profile.txt

# Extract timing per test
python tests/e2e_test_script.py --json | jq '.timings | to_entries | sort_by(.value) | reverse'
```

## Expected Timing

On a typical system (local or LAN):

| Category | Est. Time | Notes |
|----------|-----------|-------|
| Health & Connectivity | 0.05s | <10ms per test |
| Authentication | 0.15s | Token generation may be slower |
| MCP Protocol | 0.20s | Session initialization included |
| Security Tools (sample) | 2.0s | Depends on backend responsiveness |
| Performance & Reliability | 3.5s | Includes concurrent test load |
| Error Handling | 0.10s | Malformed JSON + timeout |
| Session Management | 0.05s | Session creation |
| **LangChain Phase 2 (LLM disabled)** | **1.5s** | Deterministic fallback mode |
| **LangChain Phase 2 (LLM enabled)** | **30-45s** | LangChain synthesis slowdown |
| **Total (no LLM)** | **~7.5s** | 33 tests |
| **Total (with LLM)** | **~40-50s** | Full synthesis mode |

**Note**: LangChain synthesis times depend on:
- LLM endpoint latency (typically 5-10s per tool)
- Timeout setting (PHASE2_LLM_TIMEOUT_SECONDS, default 30s)
- Model capabilities and hardware

| Non-contiguous lines require separate links. NEVER use comma-separated line references like #L10-L12, L20.
- Valid formats: [file.ts](file.ts#L10) only. Invalid: ([file.ts#L10]) or [file.ts](file.ts)#L10
- Only create links for files that exist in the workspace. Do not link to files you are suggesting to create or that do not exist yet.

## LangChain Phase 2 Testing

### Configuration for LangChain Testing

The E2E script automatically detects and tests LangChain Phase 2 configuration:

**With LLM Synthesis Enabled:**
```bash
export PHASE2_LLM_ENABLED=true
export PHASE2_LLM_MODEL=ai/qwen3
export PHASE2_LLM_BASE_URL=http://model-runner.docker.internal/engines/v1
export PHASE2_LLM_API_KEY=not-needed
export PHASE2_LLM_TIMEOUT_SECONDS=45
python tests/e2e_test_script.py --verbose
```

**With LLM Synthesis Disabled (Fallback Mode):**
```bash
export PHASE2_LLM_ENABLED=false
python tests/e2e_test_script.py --verbose
```

### What Gets Tested

The 10 LangChain Phase 2 tests verify:

1. **LLM Configuration Detection**
   - Detects whether synthesis is enabled
   - Logs configuration status
   - Works with or without LLM

2. **Phase 2 Tools Functionality**
   - `triage_wazuh_alerts`: Alert summarization
   - `enrich_wazuh_context`: Context enrichment with related data
   - `generate_soc_handoff_report`: Shift/daily report generation

3. **Response Quality**
   - Proper JSON structure
   - Required fields present
   - Data consistency

4. **Fallback Behavior**
   - Deterministic mode when LLM unavailable
   - Graceful degradation
   - No errors when synthesis disabled

5. **Performance**
   - Responsiveness under load
   - Timeout handling
   - Large time range handling (7d, 30d)

6. **Parameter Validation**
   - Supported time ranges: 1h, 6h, 12h, 1d, 24h, 7d, 30d
   - Invalid parameters rejection
   - Boundary value testing

### Interpreting LangChain Test Results

**All Passing (Fast ~7.5s):**
- LangChain is configured but disabled (deterministic mode)
- Or LLM is answering quickly (< 1s per tool)
- Status: ✅ Production Ready

**All Passing (Slower ~40-50s):**
- LangChain is enabled with active LLM synthesis
- Each tool takes 5-15s for LLM processing
- Status: ✅ Production Ready (with AI synthesis)

**Some Timeouts (> 60s):**
- LLM endpoint is slow or unreachable
- Reduce PHASE2_LLM_TIMEOUT_SECONDS or disable inference
- Status: ⚠️ Check LLM configuration

**All Phase 2 Tests Return HTTP 503:**
- Wazuh backend not configured
- Phase 2 tools can't fetch source data
- Status: ℹ️ Expected (no Wazuh configured)

### Advanced LangChain Testing

**Test with Mock LLM:**
```bash
# Use a fast local model
export PHASE2_LLM_MODEL=ai/gemma3-qat:latest
python tests/e2e_test_script.py --json | jq '.timings | map(select(.value > 5)) | length'
```

**Profile LLM Latency:**
```bash
python tests/e2e_test_script.py --json | \
  jq '.timings | to_entries[] | select(.key | contains("langchain")) | {key, value}'
```

**Compare Performance:**
```bash
# Without LLM
export PHASE2_LLM_ENABLED=false
python tests/e2e_test_script.py --quiet > results_no_llm.json

# With LLM
export PHASE2_LLM_ENABLED=true
python tests/e2e_test_script.py --quiet > results_with_llm.json

# Compare
diff <(jq '.timings.langchain_all_time_ranges' results_no_llm.json) \
     <(jq '.timings.langchain_all_time_ranges' results_with_llm.json)
```

## Extending the Test Suite

### Adding New Tool Tests

```python
def test_tool_my_new_tool(self) -> bool:
    """Test YY: my_new_tool."""
    start = time.time()
    
    request = {
        "jsonrpc": "2.0",
        "id": "YY",
        "method": "tools/call",
        "params": {
            "name": "my_new_tool",
            "arguments": {"param1": "value1"}
        }
    }
    
    headers = {}
    if self.bearer_token:
        headers["Authorization"] = f"Bearer {self.bearer_token}"
    
    status, data, elapsed = self._make_request("POST", "/mcp", request, headers)
    duration = time.time() - start
    
    passed = status in [200, 400, 503]
    self._record_test("tool_my_new_tool", passed, duration, f"Status: {status}" if not passed else None)
    return passed
```

### Adding New Sections

```python
def run_all_tests(self) -> bool:
    """Run all test categories."""
    # ... existing sections ...
    
    # New Section
    print("\n📍 Section 8: My New Feature")
    self.test_my_new_feature_1()
    self.test_my_new_feature_2()
    
    self.print_report()
    return self.test_results["failed"] == 0
```

## Test Execution Matrix

### By Environment

| Environment | Command | Expected Issues |
|-------------|---------|-----------------|
| Local dev | `python tests/e2e_test_script.py` | None (if configured) |
| docker-compose | `python tests/e2e_test_script.py --server http://wazuh-mcp:3000` | May have slow startup |
| Kubernetes | `kubectl exec pod -- python tests/e2e_test_script.py` | Network delays |
| CI/CD | `pytest tests/e2e_test_script.py -v` | No Wazuh backend (expected) |
| Production | `python tests/e2e_test_script.py --server https://prod.api.com` | High latency possible |

### By Configuration

| Config | Result | Notes |
|--------|--------|-------|
| `AUTH_MODE=none` | All auth tests pass | Authless scenarios |
| `AUTH_MODE=bearer` | Bearer tests pass | Standard JWT flow |
| `AUTH_MODE=oauth` | OAuth tests pass | Requires OAUTH_* config |
| `WAZUH_URL` configured | Tool tests pass | Full integration |
| `WAZUH_URL` not set | Tool tests return 503 | Expected behavior |
| `REDIS_URL` set | Session tests faster | With Redis backend |

## Next Steps

After running E2E tests:

1. **Pass all 23 tests** → System is ready
2. **Some tools return 503** → Configure Wazuh backend (see OPERATIONS.md)
3. **Performance issues** → Profile slow endpoints (see profiling section)
4. **Add more tests** → Customize for your use cases (see extending section)
5. **Set up monitoring** → Use results in CI/CD pipelines (see CI/CD section)

## Support

For test failures or questions:

1. Check the test output for specific error details
2. Run with `--verbose` flag for more logging
3. Check server logs: `tail -f logs/wazuh_mcp_server.log`
4. Verify configuration: `cat .env | grep -E "^(WAZUH|MCP|REDIS)_"`
5. Review troubleshooting section above
