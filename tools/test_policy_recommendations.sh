#!/bin/bash
# Quick test script for Policy tuning recommendation assistant endpoint

set -e

# Environment variables with defaults
PHASE4_BASE_URL="${PHASE4_BASE_URL:-http://localhost:8082}"
TIME_RANGE="${TIME_RANGE:-24h}"
LIMIT="${LIMIT:-100}"
FOCUS="${FOCUS:-all}"

echo "Policy Tuning Recommendation Assistant — Test Script"
echo "========================================================"
echo ""
echo "Configuration:"
echo "  PHASE4_BASE_URL: $PHASE4_BASE_URL"
echo "  TIME_RANGE: $TIME_RANGE"
echo "  LIMIT: $LIMIT"
echo "  FOCUS: $FOCUS (all|overblocking|underblocking)"
echo ""

# Test 1: Basic recommendations (all types, all focus)
echo "Test 1: Basic policy recommendations (no focus)"
echo "-----------------------------------------------"
curl -sS -X POST "$PHASE4_BASE_URL/soc/proxy-policy-recommendations" \
  -H 'Content-Type: application/json' \
  -d "{
    \"time_range\": \"$TIME_RANGE\",
    \"limit\": $LIMIT,
    \"focus\": \"$FOCUS\",
    \"recommendation_types\": [\"masking\", \"discovery\"]
  }" | jq '.'

echo ""
echo ""

# Test 2: Overblocking focus (false positives)
echo "Test 2: Focus on overblocking (false positives)"
echo "-----------------------------------------------"
curl -sS -X POST "$PHASE4_BASE_URL/soc/proxy-policy-recommendations" \
  -H 'Content-Type: application/json' \
  -d "{
    \"time_range\": \"$TIME_RANGE\",
    \"limit\": $LIMIT,
    \"focus\": \"overblocking\",
    \"recommendation_types\": [\"masking\"]
  }" | jq '{status, summary, recommendations, human_review_required}'

echo ""
echo ""

# Test 3: Discovery rules only
echo "Test 3: Discovery rules only"
echo "----------------------------"
curl -sS -X POST "$PHASE4_BASE_URL/soc/proxy-policy-recommendations" \
  -H 'Content-Type: application/json' \
  -d "{
    \"time_range\": \"7d\",
    \"limit\": 50,
    \"focus\": \"all\",
    \"recommendation_types\": [\"discovery\"]
  }" | jq '{status, recommendations, next_steps}'

echo ""
echo "Tests completed!"
