#!/usr/bin/env python3
"""Browser regression test for Phase 4 Policy Tuning UI using Playwright.

This test verifies:
- Tab navigation to Policy Tuning view
- Request payload wiring to /soc/proxy-policy-recommendations
- Rendered recommendation content from mocked API response

The test skips automatically if:
- Playwright is not installed
- A running Phase 4 UI is not reachable (default: http://localhost:8082/ui)
"""

from __future__ import annotations

import json
import os
import time
from urllib import error, request

import pytest

playwright = pytest.importorskip("playwright.sync_api")


def _is_url_reachable(url: str, timeout: float = 3.0, retries: int = 5, delay_s: float = 1.0) -> bool:
    req = request.Request(url, method="GET")
    for _ in range(max(1, retries)):
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                if 200 <= int(resp.status) < 500:
                    return True
        except error.URLError:
            pass
        time.sleep(delay_s)
    return False


def test_policy_tuning_ui_browser_flow() -> None:
    ui_url = os.getenv("PHASE4_UI_URL", "http://localhost:8082/ui")

    if not _is_url_reachable(ui_url):
        pytest.skip(f"Phase 4 UI not reachable at {ui_url}")

    mocked_response = {
        "status": "ok",
        "summary": {
            "time_range": "24h",
            "total_denied": 3,
        },
        "recommendations": [
            {
                "title": "Mask secrets in write_alert payloads",
                "type": "masking",
                "impact": "high",
                "rationale": "Repeated tool_denied events indicate over-blocking due to sensitive fields.",
                "proposed_change": "Mask token/password fields before write_alert dispatch.",
            }
        ],
        "human_review_required": True,
        "safety_model": "recommendations_only_no_auto_apply",
        "next_steps": [
            "Review with SOC lead",
            "Apply in canary mode",
        ],
    }

    captured: dict[str, object] = {}

    def _handle_policy_request(route):
        body_text = route.request.post_data or "{}"
        try:
            captured["body"] = json.loads(body_text)
        except json.JSONDecodeError:
            captured["body"] = body_text

        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(mocked_response),
        )

    with playwright.sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        page.route("**/soc/proxy-policy-recommendations", _handle_policy_request)

        page.goto(ui_url, wait_until="domcontentloaded", timeout=30000)

        page.click("#vbtn-policy")
        assert page.locator("#policy-view").is_visible()

        page.select_option("#pol-time-range", "24h")
        page.select_option("#pol-focus", "overblocking")
        page.fill("#pol-limit", "50")

        # Keep only one recommendation type selected to validate payload wiring.
        page.uncheck("#pol-type-discovery")

        page.click("#pol-generate-btn")

        page.wait_for_selector("#pol-content .report-card", timeout=10000)

        # Assert rendered output from mocked response.
        rendered = page.locator("#pol-content").inner_text()
        assert "Mask secrets in write_alert payloads" in rendered
        assert "Denied Events" in rendered or "DENIED EVENTS" in rendered
        assert "Review Required" in rendered or "REVIEW REQUIRED" in rendered
        assert "recommendations_only_no_auto_apply" in rendered

        # Assert request payload from UI controls.
        assert "body" in captured
        body = captured["body"]
        assert isinstance(body, dict)
        assert body.get("time_range") == "24h"
        assert body.get("focus") == "overblocking"
        assert body.get("limit") == 50
        assert body.get("recommendation_types") == ["masking"]

        browser.close()
