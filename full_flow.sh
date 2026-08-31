# 1) Clear discovery alerts
echo "--- Step 1: Clear discovery alerts ---"
curl -sS -X POST "http://localhost:8082/soc/proxy-discovery-alerts/clear" \
  -H "Content-Type: application/json" \
  -d '{"reset_cooldown": true}' | jq .

# 2) Trigger denied events
echo "--- Step 2: Trigger denied events ---"
bash tools/test_discovery_write_tool_abuse.sh || echo "Trigger script returned non-zero, continuing..."

# 3) Get sample denied events
echo "--- Step 3: Sample denied events ---"
MCP_PROXY_API_KEY="${MCP_PROXY_API_KEY:-mcp_proxy_local_demo_change_me}"
curl -sS "http://localhost:8090/recent-denied?limit=20" \
  -H "Authorization: Bearer ${MCP_PROXY_API_KEY}" | jq '{count, events: (.events[:5] | map({tool, reason, timestamp}))}'

# 4) Get discovery alerts
echo "--- Step 4: Discovery alerts ---"
curl -sS "http://localhost:8082/soc/proxy-discovery-alerts?limit=10" | jq '{count, alerts: (.alerts[:5] | map({signal, observed_count, threshold, action_on_trigger, timestamp}))}'

# 5) Generate discovery recommendations
echo "--- Step 5: Recommendations ---"
RECS_JSON=$(curl -sS -X POST "http://localhost:8082/soc/proxy-policy-recommendations" \
  -H "Content-Type: application/json" \
  -d '{"time_range":"1h","limit":100,"focus":"all","run_llm":true,"recommendation_types":["discovery"]}')

echo "$RECS_JSON" | jq '{status, llm, summary, rec_count: (.recommendations|length), recommendations: (.recommendations[:5] | map({type, signal, threshold, action_on_trigger, confidence, rationale, tool_scope}))}'

# 6) Record acceptance action
echo "--- Step 6: Record acceptance ---"
REC_IDX=$(echo "$RECS_JSON" | jq -r '.recommendations | to_entries[] | select(.value.type=="discovery" and .value.signal=="write_tool_abuse") | .key' | head -n1)
if [ -z "$REC_IDX" ] || [ "$REC_IDX" = "null" ]; then
  echo "No write_tool_abuse recommendation found in LLM output, using fallback."
  REC_IDX=0
  REC_DATA='{"type":"discovery","signal":"write_tool_abuse","threshold":"3 denials in 5 minutes","action_on_trigger":"challenge","tool_scope":["wazuh_block_ip","wazuh_isolate_host","wazuh_kill_process","wazuh_disable_user","wazuh_quarantine_file","wazuh_active_response","wazuh_firewall_drop","wazuh_host_deny","wazuh_restart","wazuh_unisolate_host","wazuh_enable_user","wazuh_restore_file","wazuh_firewall_allow","wazuh_host_allow"],"confidence":0.7,"rationale":"Tool search_security_events has highest deny rate; recommend challenge rule for repeated attempts","source":"policy_tuning_change_bundle"}'
else
  REC_DATA=$(echo "$RECS_JSON" | jq -c --argjson idx "$REC_IDX" '.recommendations[$idx]')
fi

ACTION_PAYLOAD=$(jq -cn --argjson idx "$REC_IDX" --argjson rec "$REC_DATA" '{recommendation_index:$idx, action:"accept", recommendation_data:$rec}')
curl -sS -X POST "http://localhost:8082/soc/policy-recommendations-action" \
  -H "Content-Type: application/json" \
  -d "$ACTION_PAYLOAD" | jq .

# 7) Apply accepted bundle
echo "--- Step 7: Apply bundle ---"
APPLY_PAYLOAD=$(jq -cn --argjson idx "$REC_IDX" --argjson rec "$REC_DATA" '{dry_run:false, policy_bundle:{accepted_recommendations:[{recommendation_index:$idx, recommendation:$rec}]}}')
curl -sS -X POST "http://localhost:8082/soc/proxy-policy-bundle-apply" \
  -H "Content-Type: application/json" \
  -d "$APPLY_PAYLOAD" | jq .

# 8) Verify policy
echo "--- Step 8: Verify policy ---"
jq '.discovery_rules[] | select(.signal=="write_tool_abuse")' config/phase4/mcp_proxy/policy.json
