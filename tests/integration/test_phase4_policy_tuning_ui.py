#!/usr/bin/env python3
"""Regression tests for the Phase 4 Policy Tuning UI wiring."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from fastapi.testclient import TestClient


# Force local SQLite so importing Phase 4 server does not require Postgres.
os.environ.setdefault("DATABASE_URL", "sqlite:///./phase4_test.db")

# Add Phase 4 service path so local imports in server.py resolve correctly.
PHASE4_ROOT = Path(__file__).resolve().parents[2] / "src" / "wazuh_mcp_server" / "phase4"
sys.path.insert(0, str(PHASE4_ROOT))

import server as phase4_server  # type: ignore  # noqa: E402


def test_policy_tuning_ui_elements_and_hooks_present():
    """Served UI includes Policy Tuning tab, controls, and JS wiring."""

    client = TestClient(phase4_server.app)
    response = client.get("/ui")

    assert response.status_code == 200
    html = response.text

    # View switcher and panel
    assert 'id="vbtn-policy"' in html
    assert "switchView('policy')" in html
    assert 'id="policy-view"' in html

    # Policy assistant inputs and actions
    assert 'id="pol-time-range"' in html
    assert 'id="pol-focus"' in html
    assert 'id="pol-limit"' in html
    assert 'id="pol-type-masking"' in html
    assert 'id="pol-type-discovery"' in html
    assert 'id="pol-generate-btn"' in html
    assert 'id="pol-clear-btn"' in html
    assert 'id="pol-use-cases"' in html
    assert 'id="pol-use-case-overblocking"' in html
    assert 'id="pol-use-case-probing"' in html
    assert 'id="pol-use-case-drift"' in html
    assert 'id="pol-use-case-rollout"' in html

    # JS flow: generate + clear + render + endpoint wiring
    assert "async function generatePolicyRecommendations()" in html
    assert "const POLICY_USE_CASES =" in html
    assert "function applyPolicyUseCase(useCaseId, runAfter = false)" in html
    assert "function clearPolicyRecommendations()" in html
    assert "function renderPolicyRecommendationsOutput(result)" in html
    assert "'/soc/proxy-policy-recommendations'" in html


def test_policy_tuning_ui_full_management_cycle():
    """Test Policy Tuning UI includes full recommendation management UI."""

    client = TestClient(phase4_server.app)
    response = client.get("/ui")

    assert response.status_code == 200
    html = response.text

    # Card rendering helpers (confidence, impact, styling)
    assert "_getConfidenceBadge" in html, "Confidence badge helper missing"
    assert "_getImpactColor" in html, "Impact color helper missing"
    assert "class=\"recommendation-card\"" in html or "recommendation-card" in html, "Card styling missing"

    # User action tracking
    assert "handleRecAction" in html, "Recommendation action handler missing"
    assert "recordPolicyRecommendationAction" in html, "Recommendation action recorder missing"
    assert "'/soc/policy-recommendations-action'" in html, "Action endpoint wiring missing"

    # Copy-to-clipboard functionality
    assert "copyToClipboard" in html, "Copy-to-clipboard function missing"
    assert "navigator.clipboard" in html, "Clipboard API usage missing"

    # LLM/fallback provenance is surfaced in the UI
    assert "Recommendation Engine" in html, "Recommendation engine card missing"
    assert "Deterministic Fallback" in html or "LLM Invoked" in html, "LLM provenance text missing"
    assert "policy-engine-summary" in html, "Recommendation engine summary styling missing"
    assert "function _formatPolicyFocusLabel(focus)" in html, "Policy focus label helper missing"
    assert "Focus:" in html, "Policy focus badge label missing"
    assert "Fallback reason:" in html, "Fallback reason label missing"
    assert "function getPolicySafeLlmSummary(llm, recommendations)" in html, "Policy-safe LLM summary filter missing"
    assert "not policy-tuning specific" in html, "Policy-safe summary fallback copy missing"

    # Accept/reject buttons wired
    assert "✓ Accept" in html, "Accept button missing"
    assert "✗ Reject" in html, "Reject button missing"
    assert "📋 Copy JSON" in html, "Copy JSON button missing"

    # Use case content is visible in the UI
    assert "Overblocking on Sensitive Write Tools" in html
    assert "Discovery Rules for Probing Campaigns" in html
    assert "Weekly Policy Drift Review" in html
    assert "Rapid Post-Change Sanity Check" in html
    assert "policy-use-case-title-row" in html
    assert "policy-use-case-icon" in html
    assert "policy-use-case-when" in html
    assert "Recommended when:" in html

    # switchView integration includes policy pane/button active state
    assert "view === 'policy'" in html
    assert "vbtn-policy" in html
