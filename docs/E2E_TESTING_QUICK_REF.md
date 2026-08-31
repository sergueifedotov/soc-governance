# E2E Testing Quick Reference

## 🚀 Quick Start (30 seconds)

```bash
# 1. Start server (Terminal 1)
python -m wazuh_mcp_server

# 2. Run tests (Terminal 2)
python tests/e2e_test_script.py
```

## 📋 Test Cheat Sheet

### Common Commands

```bash
# Run all 33 tests
python tests/e2e_test_script.py

# Run with output
python tests/e2e_test_script.py --verbose

# JSON output for automation
python tests/e2e_test_script.py --json > results.json

# Custom server URL
python tests/e2e_test_script.py --server http://192.168.1.10:3000

# Custom API key
python tests/e2e_test_script.py --api-key your_key

# All options
python tests/e2e_test_script.py \
  --server http://localhost:3000 \
  --api-key your_key \
  --verbose \
  --json > results.json
```

### Using pytest

```bash
# Run as pytest
pytest tests/e2e_test_script.py -v

# Run with output capture
pytest tests/e2e_test_script.py -v -s

# Run specific test
pytest tests/e2e_test_script.py::TestWazuhMCPServerE2E::test_all_e2e_scenarios -v
```

### Docker / Container

```bash
# From within container
cd /src && python tests/e2e_test_script.py --server http://localhost:3000

# From host (docker-compose)
docker-compose exec wazuh-mcp python tests/e2e_test_script.py

# From host (Kubernetes)
kubectl exec deployment/wazuh-mcp -- python tests/e2e_test_script.py
```

## ✅ Test Categories (33 Tests)

### 1️⃣ Health & Connectivity (3 tests)
- Server health check
- TCP connectivity
- Metrics endpoint

### 2️⃣ Authentication (3 tests)
- Bearer token generation
- Invalid API key rejection
- Missing auth handling

### 3️⃣ MCP Protocol (3 tests)
- Initialize session
- List tools
- Request validation

### 4️⃣ Security Tools (8 tests)
- get_wazuh_alerts
- get_wazuh_agents
- get_wazuh_vulnerabilities
- validate_wazuh_connection
- get_wazuh_statistics
- check_wazuh_health
- Invalid arguments
- Nonexistent tool

### 5️⃣ Performance (3 tests)
- Response time (<100ms)
- Concurrent requests (5x)
- Rate limiting (20x)

### 6️⃣ Error Handling (2 tests)
- Malformed JSON
- Timeout handling

### 7️⃣ Session Management (1 test)
- Session creation

### 8️⃣ LangChain Phase 2 (10 tests) ⭐ NEW
- LAngChain config detection
- triage_wazuh_alerts tool
- enrich_wazuh_context tool
- generate_soc_handoff_report tool
- Response structure validation
- Fallback mode (no LLM)
- Timeout handling
- Parameter validation
- All time ranges (1h-30d)
- Response performance

## 🎯 Expected Results

```
✓ PASS: server_health (0.02s)
✓ PASS: server_connectivity (0.01s)
✓ PASS: metrics_endpoint (0.02s)
✓ PASS: auth_bearer_token_generation (0.03s)
✓ PASS: auth_invalid_api_key (0.02s)
✓ PASS: auth_missing_authorization (0.02s)
✓ PASS: mcp_initialize (0.05s)
✓ PASS: mcp_tools_list (0.03s)
✓ PASS: mcp_request_validation (0.02s)
✓ PASS: tool_get_wazuh_alerts (0.20s)
✓ PASS: tool_get_wazuh_agents (0.25s)
✓ PASS: tool_get_wazuh_vulnerabilities (0.22s)
✓ PASS: tool_validate_wazuh_connection (0.18s)
✓ PASS: tool_get_wazuh_statistics (0.19s)
✓ PASS: tool_check_wazuh_health (0.17s)
✓ PASS: tool_invalid_arguments (0.15s)
✓ PASS: tool_nonexistent_tool (0.13s)
✓ PASS: response_time_health_100ms (0.02s)
✓ PASS: concurrent_requests (0.08s)
✓ PASS: rate_limiting (2.34s)
✓ PASS: error_handling_malformed_json (0.02s)
✓ PASS: error_handling_timeout (1.05s)
✓ PASS: session_creation (0.04s)
✓ PASS: langchain_config_detection (0.15s)
✓ PASS: phase2_triage_wazuh_alerts (0.18s)
✓ PASS: phase2_enrich_wazuh_context (0.22s)
✓ PASS: phase2_generate_soc_handoff_report (0.25s)
✓ PASS: langchain_response_structure (0.16s)
✓ PASS: langchain_fallback_mode (0.14s)
✓ PASS: langchain_timeout_handling (0.12s)
✓ PASS: langchain_parameter_validation (0.13s)
✓ PASS: langchain_all_time_ranges (0.35s)
✓ PASS: langchain_response_performance (0.20s)

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

## 🔧 Troubleshooting

| Problem | Solution |
|---------|----------|
| Connection refused | Ensure server running: `python -m wazuh_mcp_server` |
| Token generation fails | Check API key in `.env`: `grep MCP_API_KEY .env` |
| Tools return HTTP 503 | Configure Wazuh: `export WAZUH_URL=http://wazuh-api:55000` |
| Rate limiting fails | Adjust limits in `config.py` or wait between runs |
| Timeout errors | Increase timeout in script to 60s |
| Tests hang | Stop tests with Ctrl+C, check for blocking operations |

## 📊 Parsing Results

### Extract pass rate
```bash
python tests/e2e_test_script.py --json | jq '.passed / .total * 100'
```

### Find slow tests
```bash
python tests/e2e_test_script.py --json | jq '.timings | to_entries | sort_by(.value) | reverse | .[0:5]'
```

### Check errors
```bash
python tests/e2e_test_script.py --json | jq '.errors'
```

### Export to CSV
```bash
python tests/e2e_test_script.py --json | jq -r '.timings | to_entries | .[] | [.key, .value] | @csv' > timings.csv
```

## 🔄 CI/CD Integration

### GitHub Actions
```bash
python tests/e2e_test_script.py --json > results.json
cat results.json | jq '.passed == .total' && echo "PASS" || echo "FAIL"
```

### GitLab CI
```bash
python tests/e2e_test_script.py --json | jq --exit-status '.failed == 0'
```

### Jenkins
```bash
python tests/e2e_test_script.py || exit 1
```

## 📈 Performance Baselines

| Test | Expected | Maximum |
|------|----------|---------|
| health check | 10ms | 50ms |
| token generation | 20ms | 100ms |
| tools/list | 20ms | 100ms |
| tool call (mock) | 100ms | 500ms |
| concurrent (5x) | 100ms | 500ms |
| rate limiting (20x) | 2s | 5s |

## 🛠️ Advanced Usage

### Profile test performance
```bash
python -m cProfile -s cumtime tests/e2e_test_script.py 2>&1 | head -30
```

### Run tests repeatedly (load test)
```bash
for i in {1..10}; do
  echo "=== Run $i ==="
  python tests/e2e_test_script.py --json | jq '.passed == .total' && echo "PASS" || echo "FAIL"
done
```

### Test with different auth modes
```bash
# Test bearer auth
export AUTH_MODE=bearer
python tests/e2e_test_script.py

# Test OAuth
export AUTH_MODE=oauth
python tests/e2e_test_script.py

# Test authless
export AUTH_MODE=none
python tests/e2e_test_script.py
```

### Monitor server during tests
```bash
# Terminal 1: Real-time server logs
tail -f logs/wazuh_mcp_server.log | grep -E "(ERROR|WARNING|INFO)"

# Terminal 2: Run tests with verbose
python tests/e2e_test_script.py --verbose

# Terminal 3: Monitor metrics
while true; do
  curl -s http://localhost:3000/metrics | jq '.active_connections'
  sleep 1
done
```

## 📞 Support Resources

- **Full Guide**: [docs/E2E_TESTING.md](E2E_TESTING.md)
- **Operations**: [docs/OPERATIONS.md](OPERATIONS.md)
- **API Reference**: [docs/api/README.md](api/README.md)
- **Configuration**: [docs/configuration.md](configuration.md)

## 📝 Test Results Definition

**PASS** = Test completed successfully with expected behavior
**FAIL** = Test did not meet pass criteria
**SKIP** = Test was skipped (reserved for future use)
**ERROR** = Test threw unexpected exception

All tests are considered **reliable** if they pass consistently across multiple runs.
