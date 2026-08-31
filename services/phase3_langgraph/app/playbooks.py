"""Use-case-specific investigation playbooks for Phase 3 LangGraph.

Each playbook is a deterministic LangGraph workflow that:

1. ``collect_evidence``  - pulls structured evidence from Wazuh MCP tools
   (no LLM calls). The exact queries are playbook-specific.
2. ``score_and_classify`` - applies deterministic thresholds to the evidence
   and produces a ``risk_tier`` and a list of rationale strings.
3. ``recommend_action`` - maps the classified risk to a Phase 3 response
   action (``block_ip`` / ``isolate_host`` / ``quarantine_file`` /
   ``disable_user``) reusing the same action plan helpers used by
   ``/phase3/run``.
4. ``safety_gate`` - branches based on risk tier:
   - ``low``                       -> finalize as ``read_only``
   - ``medium`` / ``high`` / ``critical`` and not ``auto_approve``
                                    -> pause as ``pending_confirmation``
                                       (analyst must resume)
   - approved (auto or manual)      -> recommendation is finalized.
5. ``finalize`` - produces a stable response shape the UI / clients can
   consume.

Importantly: this module **never executes** the recommended action by
itself. Execution / verify / rollback continues to live in the
``/phase3/run`` workflow and must be triggered explicitly with the
returned ``proposed_action``. The playbook is an investigation +
recommendation graph with safety gates; it is not a write path.

The five supported playbooks are: ``brute_force``, ``beaconing``,
``malware``, ``privilege_escalation``, ``exfiltration``.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, TypedDict, cast

import httpx
from fastapi import APIRouter, HTTPException
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field

PlaybookName = Literal[
    "brute_force",
    "beaconing",
    "malware",
    "privilege_escalation",
    "exfiltration",
]

RiskTier = Literal["low", "medium", "high", "critical"]
ApprovalDecision = Literal["approved", "rejected"]

PLAYBOOK_NAMES: List[str] = [
    "brute_force",
    "beaconing",
    "malware",
    "privilege_escalation",
    "exfiltration",
]


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class PlaybookEvidenceHints(BaseModel):
    """Optional pivot points the analyst already knows.

    If a hint is missing, the playbook still runs but its scoring is more
    conservative (no high-confidence pivot).
    """

    src_ip: Optional[str] = Field(None, description="Source IP for brute force / privilege escalation")
    dst_ip: Optional[str] = Field(None, description="Destination IP for beaconing / exfiltration")
    agent_id: Optional[str] = Field(None, description="Wazuh agent id of the affected host")
    user: Optional[str] = Field(None, description="Username for privilege escalation / brute force")
    file_path: Optional[str] = Field(None, description="Suspicious file path for malware playbook")
    file_hash: Optional[str] = Field(None, description="SHA256 of the suspicious file")
    domain: Optional[str] = Field(None, description="Suspicious domain for beaconing")


class RunPlaybookRequest(BaseModel):
    incident_id: str = Field(..., description="Incident or ticket identifier")
    playbook: PlaybookName = Field(..., description="Which investigation playbook to run")
    time_range: str = Field("24h", description="Time window for evidence collection")
    evidence: PlaybookEvidenceHints = Field(default_factory=PlaybookEvidenceHints)
    auto_approve: bool = Field(
        False,
        description="If true, classifications above 'low' do not pause for analyst approval",
    )
    analyst_decision: Optional[ApprovalDecision] = Field(
        None,
        description="Inline analyst decision. If provided, takes precedence over the safety gate pause.",
    )
    threshold_overrides: Dict[str, float] = Field(
        default_factory=dict,
        description="Optional per-playbook threshold overrides (advanced). Keys depend on the playbook.",
    )


class RunPlaybookResponse(BaseModel):
    incident_id: str
    playbook: PlaybookName
    workflow_status: str
    risk_tier: RiskTier
    rationale: List[str]
    evidence: Dict[str, Any]
    signals: Dict[str, Any]
    proposed_action: Dict[str, Any]
    confirmation: Dict[str, Any]
    steps: List[str]
    error: Optional[str] = None


class ResumePlaybookRequest(BaseModel):
    decision: ApprovalDecision = Field(..., description="Analyst approval decision")
    actor: str = Field("analyst", description="Actor performing the decision")


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------


class PlaybookState(TypedDict, total=False):
    request: Dict[str, Any]
    mcp_base_url: str
    mcp_api_key: str
    evidence: Dict[str, Any]
    signals: Dict[str, Any]
    risk_tier: RiskTier
    rationale: List[str]
    proposed_action: Dict[str, Any]
    confirmation: Dict[str, Any]
    pending_confirmation: bool
    workflow_status: str
    steps: List[str]


PENDING_PLAYBOOKS: Dict[str, PlaybookState] = {}
PENDING_PLAYBOOKS_LOCK = asyncio.Lock()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _append_step(state: PlaybookState, step: str) -> None:
    state.setdefault("steps", []).append(step)


def _coerce_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _extract_event_count(mcp_response: Dict[str, Any]) -> int:
    """Return the number of hits encoded in an ``search_security_events`` MCP response."""
    if not isinstance(mcp_response, dict):
        return 0

    result = mcp_response.get("result", mcp_response)
    if not isinstance(result, dict):
        return 0

    # MCP tools/call response shape: {"content": [{"type": "text", "text": "<json>"}]}
    content = result.get("content") or []
    if content and isinstance(content[0], dict):
        text = str(content[0].get("text", ""))
        # Try to parse as JSON; fall back to "events" key.
        import json as _json

        try:
            parsed = _json.loads(text)
        except Exception:
            return 0
        if isinstance(parsed, dict):
            for key in ("total", "count", "hits_total", "total_hits"):
                if isinstance(parsed.get(key), (int, float)):
                    return int(parsed[key])
            events = parsed.get("events") or parsed.get("hits") or parsed.get("alerts")
            if isinstance(events, list):
                return len(events)
        if isinstance(parsed, list):
            return len(parsed)
    return 0


def _extract_event_sample(mcp_response: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
    if not isinstance(mcp_response, dict):
        return []
    result = mcp_response.get("result", mcp_response)
    content = result.get("content") if isinstance(result, dict) else None
    if not (content and isinstance(content[0], dict)):
        return []
    import json as _json

    try:
        parsed = _json.loads(str(content[0].get("text", "")))
    except Exception:
        return []
    events: List[Dict[str, Any]] = []
    if isinstance(parsed, dict):
        for key in ("events", "hits", "alerts"):
            value = parsed.get(key)
            if isinstance(value, list):
                events = [v for v in value if isinstance(v, dict)]
                break
    elif isinstance(parsed, list):
        events = [v for v in parsed if isinstance(v, dict)]
    return events[:limit]


async def _safe_mcp_call(
    base_url: str, api_key: str, tool: str, arguments: Dict[str, Any]
) -> Dict[str, Any]:
    """Call MCP and never raise. Returns ``{"error": ..., "tool": ...}`` on failure.

    Playbooks must remain resilient: if a single evidence query fails (e.g.
    OpenCTI down), classification continues with the remaining signals.
    """
    # Late import to avoid circular dependency on main.py at module-load time.
    from .main import _mcp_call, _unwrap_retry_error

    try:
        return await _mcp_call(base_url, api_key, tool, arguments)
    except Exception as exc:  # noqa: BLE001 - intentionally broad
        return {"error": _unwrap_retry_error(exc), "tool": tool, "arguments": arguments}


def _build_action_for(use_case: str, args_override: Dict[str, Any]) -> Dict[str, Any]:
    """Map a Phase 3 ``use_case`` into a fully-populated ``proposed_action``.

    Re-uses the helpers in ``main.py`` so that the resulting dict matches
    the schema accepted by ``/phase3/run``'s execute / verify / rollback
    nodes.
    """
    from .main import (
        _build_action_plan,
        _build_rollback_args,
        _build_verify_args,
        _default_action_args,
    )

    plan = _build_action_plan(use_case)
    args = {**_default_action_args(use_case), **{k: v for k, v in args_override.items() if v is not None}}
    return {
        "use_case": use_case,
        "action_tool": plan["action_tool"],
        "verify_tool": plan["verify_tool"],
        "rollback_tool": plan["rollback_tool"],
        "args": args,
        "verify_args": _build_verify_args(use_case, args),
        "rollback_args": _build_rollback_args(use_case, args),
    }


# ---------------------------------------------------------------------------
# Playbook implementations
# ---------------------------------------------------------------------------


def _bf_thresholds(overrides: Dict[str, float]) -> Dict[str, int]:
    return {
        "medium": int(overrides.get("medium", 20)),
        "high": int(overrides.get("high", 100)),
    }


async def _collect_brute_force(state: PlaybookState) -> Dict[str, Any]:
    req = state["request"]
    hints = req.get("evidence", {}) or {}
    base_url = state["mcp_base_url"]
    api_key = state["mcp_api_key"]
    time_range = req.get("time_range", "24h")
    src_ip = hints.get("src_ip") or ""
    user = hints.get("user") or ""

    # Failed authentication events
    failed_args: Dict[str, Any] = {
        "query": "rule.groups:authentication_failed OR rule.id:5710 OR rule.id:5712 OR rule.id:60122",
        "time_range": time_range,
        "limit": 200,
    }
    if src_ip:
        failed_args["srcip"] = src_ip

    # Successful authentication events (signal of credential success after attack)
    success_args: Dict[str, Any] = {
        "query": "rule.groups:authentication_success OR rule.id:5715 OR rule.id:5501",
        "time_range": time_range,
        "limit": 50,
    }
    if src_ip:
        success_args["srcip"] = src_ip

    failed_resp, success_resp = await asyncio.gather(
        _safe_mcp_call(base_url, api_key, "search_security_events", failed_args),
        _safe_mcp_call(base_url, api_key, "search_security_events", success_args),
    )

    failed_count = _extract_event_count(failed_resp)
    success_count = _extract_event_count(success_resp)
    sample_failures = _extract_event_sample(failed_resp, limit=3)

    distinct_users: set[str] = set()
    distinct_agents: set[str] = set()
    for evt in _extract_event_sample(failed_resp, limit=200):
        data = evt.get("data") if isinstance(evt.get("data"), dict) else {}
        agent = evt.get("agent") if isinstance(evt.get("agent"), dict) else {}
        u = data.get("dstuser") or data.get("user") or data.get("srcuser")
        if isinstance(u, str) and u:
            distinct_users.add(u)
        if isinstance(agent.get("id"), str):
            distinct_agents.add(agent["id"])
    if user:
        distinct_users.add(user)

    return {
        "queries": {"failed": failed_args, "success": success_args},
        "counts": {"failed": failed_count, "success": success_count},
        "distinct_users": sorted(distinct_users),
        "distinct_agents": sorted(distinct_agents),
        "sample_failures": sample_failures,
    }


def _classify_brute_force(evidence: Dict[str, Any], hints: Dict[str, Any], overrides: Dict[str, float]) -> Dict[str, Any]:
    counts = evidence.get("counts", {})
    failed = _coerce_int(counts.get("failed"))
    success = _coerce_int(counts.get("success"))
    distinct_users = evidence.get("distinct_users") or []

    th = _bf_thresholds(overrides)
    rationale: List[str] = []
    risk: RiskTier = "low"

    if failed >= th["high"]:
        risk = "high"
        rationale.append(f"{failed} failed auth events exceed high threshold ({th['high']})")
    elif failed >= th["medium"]:
        risk = "medium"
        rationale.append(f"{failed} failed auth events exceed medium threshold ({th['medium']})")
    else:
        rationale.append(f"{failed} failed auth events below medium threshold ({th['medium']})")

    if failed >= th["medium"] and success > 0:
        # Successful login after a flood of failures = credential compromise.
        risk = "critical"
        rationale.append(f"{success} successful logins observed after failed attempts (likely credential compromise)")

    if len(distinct_users) >= 5:
        rationale.append(f"{len(distinct_users)} distinct usernames probed (password-spraying pattern)")
        if risk == "low":
            risk = "medium"

    if not hints.get("src_ip"):
        rationale.append("no src_ip hint provided - results are aggregate (consider re-running with a pivot IP)")

    return {
        "risk_tier": risk,
        "rationale": rationale,
        "signals": {
            "failed_count": failed,
            "success_count": success,
            "distinct_user_count": len(distinct_users),
            "distinct_agent_count": len(evidence.get("distinct_agents") or []),
            "credential_compromise_suspected": failed >= th["medium"] and success > 0,
        },
    }


def _recommend_brute_force(hints: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    args = {
        "agent_id": hints.get("agent_id"),
        "src_ip": hints.get("src_ip"),
        "duration": 3600,
    }
    return _build_action_for("block_ip", args)


# --- beaconing -----------------------------------------------------------------

def _bcn_thresholds(overrides: Dict[str, float]) -> Dict[str, int]:
    return {
        "medium": int(overrides.get("medium", 30)),
        "high": int(overrides.get("high", 100)),
    }


async def _collect_beaconing(state: PlaybookState) -> Dict[str, Any]:
    req = state["request"]
    hints = req.get("evidence", {}) or {}
    base_url = state["mcp_base_url"]
    api_key = state["mcp_api_key"]
    time_range = req.get("time_range", "24h")
    dst_ip = hints.get("dst_ip") or ""
    domain = hints.get("domain") or ""

    netflow_args: Dict[str, Any] = {
        "query": "rule.groups:firewall OR rule.groups:network OR rule.groups:dns",
        "time_range": time_range,
        "limit": 500,
    }
    if dst_ip:
        netflow_args["dstip"] = dst_ip

    dns_args: Dict[str, Any] = {
        "query": (
            f"rule.groups:dns AND data.query:{domain}" if domain
            else "rule.groups:dns"
        ),
        "time_range": time_range,
        "limit": 300,
    }

    cti_args: Dict[str, Any] = {"value": dst_ip or domain, "limit": 5}

    netflow_resp, dns_resp, cti_resp = await asyncio.gather(
        _safe_mcp_call(base_url, api_key, "search_security_events", netflow_args),
        _safe_mcp_call(base_url, api_key, "search_security_events", dns_args),
        _safe_mcp_call(base_url, api_key, "opencti_query_indicators", cti_args)
        if (dst_ip or domain) else _noop_response(),
    )

    netflow_count = _extract_event_count(netflow_resp)
    dns_count = _extract_event_count(dns_resp)

    # Periodicity check: timestamps of the netflow sample.
    sample = _extract_event_sample(netflow_resp, limit=200)
    intervals = _interval_jitter([evt.get("timestamp") for evt in sample if isinstance(evt, dict)])

    cti_known_bad = _opencti_known_bad(cti_resp)

    return {
        "queries": {"netflow": netflow_args, "dns": dns_args, "cti": cti_args},
        "counts": {"netflow": netflow_count, "dns": dns_count},
        "interval_jitter": intervals,
        "opencti_known_bad": cti_known_bad,
        "sample": sample[:5],
    }


def _classify_beaconing(evidence: Dict[str, Any], hints: Dict[str, Any], overrides: Dict[str, float]) -> Dict[str, Any]:
    th = _bcn_thresholds(overrides)
    counts = evidence.get("counts", {})
    netflow = _coerce_int(counts.get("netflow"))
    jitter = evidence.get("interval_jitter") or {}
    known_bad = bool(evidence.get("opencti_known_bad"))

    rationale: List[str] = []
    risk: RiskTier = "low"

    if netflow >= th["high"]:
        risk = "high"
        rationale.append(f"{netflow} network events to/from pivot exceed high threshold ({th['high']})")
    elif netflow >= th["medium"]:
        risk = "medium"
        rationale.append(f"{netflow} network events exceed medium threshold ({th['medium']})")
    else:
        rationale.append(f"{netflow} network events below medium threshold ({th['medium']})")

    coefficient = float(jitter.get("coefficient_of_variation", 1.0))
    if jitter.get("samples", 0) >= 6 and coefficient < 0.25:
        rationale.append(
            f"low interval jitter (CoV={coefficient:.2f}) suggests automated periodic beacon"
        )
        if risk in {"low", "medium"}:
            risk = "high"

    if known_bad:
        risk = "critical"
        rationale.append("destination matches known-bad indicator in OpenCTI")

    if not (hints.get("dst_ip") or hints.get("domain")):
        rationale.append("no dst_ip / domain hint - jitter and CTI lookups skipped or partial")

    return {
        "risk_tier": risk,
        "rationale": rationale,
        "signals": {
            "netflow_count": netflow,
            "interval_samples": int(jitter.get("samples", 0)),
            "interval_cov": coefficient,
            "opencti_known_bad": known_bad,
        },
    }


def _recommend_beaconing(hints: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    return _build_action_for(
        "block_ip",
        {"agent_id": hints.get("agent_id"), "src_ip": hints.get("dst_ip"), "duration": 3600},
    )


# --- malware -------------------------------------------------------------------

def _mw_thresholds(overrides: Dict[str, float]) -> Dict[str, int]:
    return {
        "medium": int(overrides.get("medium", 1)),
        "high": int(overrides.get("high", 3)),
    }


async def _collect_malware(state: PlaybookState) -> Dict[str, Any]:
    req = state["request"]
    hints = req.get("evidence", {}) or {}
    base_url = state["mcp_base_url"]
    api_key = state["mcp_api_key"]
    time_range = req.get("time_range", "24h")
    agent_id = hints.get("agent_id") or ""
    file_path = hints.get("file_path") or ""
    file_hash = hints.get("file_hash") or ""

    av_args: Dict[str, Any] = {
        "query": "rule.groups:malware OR rule.groups:virus OR rule.groups:rootcheck",
        "time_range": time_range,
        "limit": 200,
    }
    if agent_id:
        av_args["agent_id"] = agent_id

    rootkit_args: Dict[str, Any] = {
        "query": "rule.groups:rootcheck OR rule.id:510 OR rule.id:511 OR rule.id:512",
        "time_range": time_range,
        "limit": 100,
    }
    if agent_id:
        rootkit_args["agent_id"] = agent_id

    cti_args: Dict[str, Any] = {"value": file_hash or "", "limit": 5}

    av_resp, rootkit_resp, cti_resp = await asyncio.gather(
        _safe_mcp_call(base_url, api_key, "search_security_events", av_args),
        _safe_mcp_call(base_url, api_key, "search_security_events", rootkit_args),
        _safe_mcp_call(base_url, api_key, "opencti_query_indicators", cti_args)
        if file_hash else _noop_response(),
    )

    av_count = _extract_event_count(av_resp)
    rootkit_count = _extract_event_count(rootkit_resp)
    cti_known_bad = _opencti_known_bad(cti_resp)

    return {
        "queries": {"av": av_args, "rootkit": rootkit_args, "cti": cti_args},
        "counts": {"av": av_count, "rootkit": rootkit_count},
        "opencti_known_bad": cti_known_bad,
        "file_path": file_path,
        "file_hash": file_hash,
        "sample": _extract_event_sample(av_resp, limit=3),
    }


def _classify_malware(evidence: Dict[str, Any], hints: Dict[str, Any], overrides: Dict[str, float]) -> Dict[str, Any]:
    th = _mw_thresholds(overrides)
    counts = evidence.get("counts", {})
    av = _coerce_int(counts.get("av"))
    rootkit = _coerce_int(counts.get("rootkit"))
    known_bad = bool(evidence.get("opencti_known_bad"))

    rationale: List[str] = []
    risk: RiskTier = "low"

    if av >= th["high"]:
        risk = "high"
        rationale.append(f"{av} AV / malware events exceed high threshold ({th['high']})")
    elif av >= th["medium"]:
        risk = "medium"
        rationale.append(f"{av} AV / malware events exceed medium threshold ({th['medium']})")
    else:
        rationale.append(f"{av} AV / malware events below medium threshold ({th['medium']})")

    if rootkit > 0:
        risk = "critical"
        rationale.append(f"{rootkit} rootcheck events detected (rootkit-class compromise)")

    if known_bad:
        risk = "critical"
        rationale.append("file hash matches known-bad indicator in OpenCTI")

    if not (hints.get("agent_id") and (hints.get("file_path") or hints.get("file_hash"))):
        rationale.append("missing agent_id+file hint - quarantine recommendation will be best-effort")

    return {
        "risk_tier": risk,
        "rationale": rationale,
        "signals": {
            "av_count": av,
            "rootkit_count": rootkit,
            "opencti_known_bad": known_bad,
        },
    }


def _recommend_malware(hints: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    return _build_action_for(
        "quarantine_file",
        {"agent_id": hints.get("agent_id"), "file_path": hints.get("file_path")},
    )


# --- privilege escalation ------------------------------------------------------

def _pe_thresholds(overrides: Dict[str, float]) -> Dict[str, int]:
    return {
        "medium": int(overrides.get("medium", 3)),
        "high": int(overrides.get("high", 10)),
    }


async def _collect_privilege_escalation(state: PlaybookState) -> Dict[str, Any]:
    req = state["request"]
    hints = req.get("evidence", {}) or {}
    base_url = state["mcp_base_url"]
    api_key = state["mcp_api_key"]
    time_range = req.get("time_range", "24h")
    agent_id = hints.get("agent_id") or ""
    user = hints.get("user") or ""

    privesc_args: Dict[str, Any] = {
        "query": (
            "rule.groups:privilege_escalation OR rule.id:5402 OR rule.id:5403 OR rule.id:5404 "
            "OR rule.id:40111 OR rule.id:92005 OR rule.id:92006"
        ),
        "time_range": time_range,
        "limit": 200,
    }
    if agent_id:
        privesc_args["agent_id"] = agent_id

    sudo_args: Dict[str, Any] = {
        "query": "rule.groups:sudo OR rule.id:5402 OR rule.id:5403 OR rule.id:5407",
        "time_range": time_range,
        "limit": 200,
    }
    if agent_id:
        sudo_args["agent_id"] = agent_id

    privesc_resp, sudo_resp = await asyncio.gather(
        _safe_mcp_call(base_url, api_key, "search_security_events", privesc_args),
        _safe_mcp_call(base_url, api_key, "search_security_events", sudo_args),
    )

    privesc_count = _extract_event_count(privesc_resp)
    sudo_count = _extract_event_count(sudo_resp)

    # Heuristic: sample sudo events for "command not allowed" + root shell spawn.
    sudo_sample = _extract_event_sample(sudo_resp, limit=200)
    root_shell_spawn = 0
    sudo_denied = 0
    target_users: set[str] = set()
    for evt in sudo_sample:
        data = evt.get("data") if isinstance(evt.get("data"), dict) else {}
        cmd = str(data.get("command") or "")
        if re.search(r"\b(?:bash|sh|zsh|cmd\.exe|powershell)\b", cmd):
            root_shell_spawn += 1
        if "not allowed" in str(evt.get("rule", {}).get("description", "")).lower():
            sudo_denied += 1
        target = data.get("dstuser") or data.get("user")
        if isinstance(target, str) and target:
            target_users.add(target)
    if user:
        target_users.add(user)

    return {
        "queries": {"privesc": privesc_args, "sudo": sudo_args},
        "counts": {"privesc": privesc_count, "sudo": sudo_count},
        "root_shell_spawn_count": root_shell_spawn,
        "sudo_denied_count": sudo_denied,
        "target_users": sorted(target_users),
        "sample": sudo_sample[:5],
    }


def _classify_privilege_escalation(
    evidence: Dict[str, Any], hints: Dict[str, Any], overrides: Dict[str, float]
) -> Dict[str, Any]:
    th = _pe_thresholds(overrides)
    counts = evidence.get("counts", {})
    privesc = _coerce_int(counts.get("privesc"))
    sudo = _coerce_int(counts.get("sudo"))
    root_shell = _coerce_int(evidence.get("root_shell_spawn_count"))
    sudo_denied = _coerce_int(evidence.get("sudo_denied_count"))

    rationale: List[str] = []
    risk: RiskTier = "low"

    if privesc >= th["high"]:
        risk = "high"
        rationale.append(f"{privesc} privilege-escalation events exceed high threshold ({th['high']})")
    elif privesc >= th["medium"] or sudo >= th["high"]:
        risk = "medium"
        rationale.append(
            f"{privesc} privilege-escalation events / {sudo} sudo events exceed medium threshold"
        )
    else:
        rationale.append(f"{privesc} privesc + {sudo} sudo events below medium threshold ({th['medium']})")

    if sudo_denied >= 3:
        rationale.append(f"{sudo_denied} 'sudo not allowed' denials suggest probing for sudoers misconfig")
        if risk == "low":
            risk = "medium"

    if root_shell >= 1:
        risk = "critical"
        rationale.append(f"{root_shell} root-shell spawn(s) observed via sudo - active privilege escalation")

    return {
        "risk_tier": risk,
        "rationale": rationale,
        "signals": {
            "privesc_count": privesc,
            "sudo_count": sudo,
            "sudo_denied_count": sudo_denied,
            "root_shell_spawn_count": root_shell,
            "target_user_count": len(evidence.get("target_users") or []),
        },
    }


def _recommend_privilege_escalation(hints: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    # Containment for privesc = isolate host; user disablement is a secondary step.
    return _build_action_for("isolate_host", {"agent_id": hints.get("agent_id")})


# --- exfiltration --------------------------------------------------------------

def _ex_thresholds(overrides: Dict[str, float]) -> Dict[str, int]:
    return {
        "medium": int(overrides.get("medium", 50)),
        "high": int(overrides.get("high", 250)),
    }


async def _collect_exfiltration(state: PlaybookState) -> Dict[str, Any]:
    req = state["request"]
    hints = req.get("evidence", {}) or {}
    base_url = state["mcp_base_url"]
    api_key = state["mcp_api_key"]
    time_range = req.get("time_range", "24h")
    dst_ip = hints.get("dst_ip") or ""
    agent_id = hints.get("agent_id") or ""

    netflow_args: Dict[str, Any] = {
        "query": (
            "rule.groups:firewall OR rule.groups:network OR data.action:upload "
            "OR rule.description:exfiltration"
        ),
        "time_range": time_range,
        "limit": 500,
    }
    if dst_ip:
        netflow_args["dstip"] = dst_ip
    if agent_id:
        netflow_args["agent_id"] = agent_id

    archive_args: Dict[str, Any] = {
        "query": "data.command:zip OR data.command:tar OR data.command:rar OR rule.description:archive",
        "time_range": time_range,
        "limit": 200,
    }
    if agent_id:
        archive_args["agent_id"] = agent_id

    cti_args: Dict[str, Any] = {"value": dst_ip, "limit": 5}

    netflow_resp, archive_resp, cti_resp = await asyncio.gather(
        _safe_mcp_call(base_url, api_key, "search_security_events", netflow_args),
        _safe_mcp_call(base_url, api_key, "search_security_events", archive_args),
        _safe_mcp_call(base_url, api_key, "opencti_query_indicators", cti_args)
        if dst_ip else _noop_response(),
    )

    netflow_count = _extract_event_count(netflow_resp)
    archive_count = _extract_event_count(archive_resp)
    cti_known_bad = _opencti_known_bad(cti_resp)

    bytes_out = 0
    for evt in _extract_event_sample(netflow_resp, limit=500):
        data = evt.get("data") if isinstance(evt.get("data"), dict) else {}
        for key in ("bytes", "bytes_out", "out_bytes", "tx_bytes"):
            try:
                bytes_out += int(data.get(key) or 0)
            except (TypeError, ValueError):
                continue

    return {
        "queries": {"netflow": netflow_args, "archive": archive_args, "cti": cti_args},
        "counts": {"netflow": netflow_count, "archive": archive_count},
        "estimated_bytes_out": bytes_out,
        "opencti_known_bad": cti_known_bad,
        "sample": _extract_event_sample(netflow_resp, limit=5),
    }


def _classify_exfiltration(
    evidence: Dict[str, Any], hints: Dict[str, Any], overrides: Dict[str, float]
) -> Dict[str, Any]:
    th = _ex_thresholds(overrides)
    counts = evidence.get("counts", {})
    netflow = _coerce_int(counts.get("netflow"))
    archive = _coerce_int(counts.get("archive"))
    bytes_out = _coerce_int(evidence.get("estimated_bytes_out"))
    known_bad = bool(evidence.get("opencti_known_bad"))

    rationale: List[str] = []
    risk: RiskTier = "low"

    if netflow >= th["high"]:
        risk = "high"
        rationale.append(f"{netflow} outbound events exceed high threshold ({th['high']})")
    elif netflow >= th["medium"]:
        risk = "medium"
        rationale.append(f"{netflow} outbound events exceed medium threshold ({th['medium']})")
    else:
        rationale.append(f"{netflow} outbound events below medium threshold ({th['medium']})")

    if archive >= 1 and netflow >= th["medium"]:
        rationale.append(f"{archive} archive/compress events combined with outbound traffic = staging+exfil pattern")
        if risk in {"low", "medium"}:
            risk = "high"

    if known_bad:
        risk = "critical"
        rationale.append("destination matches known-bad indicator in OpenCTI")

    if bytes_out > 0:
        rationale.append(f"~{bytes_out} bytes outbound across the sampled events")

    if not hints.get("dst_ip"):
        rationale.append("no dst_ip hint - results aggregate egress, not a single channel")

    return {
        "risk_tier": risk,
        "rationale": rationale,
        "signals": {
            "netflow_count": netflow,
            "archive_count": archive,
            "estimated_bytes_out": bytes_out,
            "opencti_known_bad": known_bad,
        },
    }


def _recommend_exfiltration(hints: Dict[str, Any], signals: Dict[str, Any]) -> Dict[str, Any]:
    # If we know the destination, blocking the IP is the highest-leverage action.
    # Otherwise fall back to isolating the host.
    if hints.get("dst_ip"):
        return _build_action_for(
            "block_ip",
            {"agent_id": hints.get("agent_id"), "src_ip": hints.get("dst_ip"), "duration": 3600},
        )
    return _build_action_for("isolate_host", {"agent_id": hints.get("agent_id")})


# ---------------------------------------------------------------------------
# Shared utilities used by collectors above
# ---------------------------------------------------------------------------


async def _noop_response() -> Dict[str, Any]:
    return {"result": {"content": [{"type": "text", "text": "{}"}]}}


def _opencti_known_bad(mcp_response: Dict[str, Any]) -> bool:
    """Detect 'this observable is known-bad' from a best-effort OpenCTI lookup.

    Treats any of the following as known-bad:
    - confidence >= 70
    - presence of any kill-chain phase
    - any label containing apt / malicious / c2 / phishing / ransomware
    """
    if not isinstance(mcp_response, dict) or "error" in mcp_response:
        return False
    sample = _extract_event_sample(mcp_response, limit=10)
    if not sample:
        # OpenCTI tools may put the data under "indicators" / "stixCoreObjects" keys.
        result = mcp_response.get("result", mcp_response)
        content = result.get("content") if isinstance(result, dict) else None
        if not (content and isinstance(content[0], dict)):
            return False
        import json as _json

        try:
            parsed = _json.loads(str(content[0].get("text", "")))
        except Exception:
            return False
        for key in ("indicators", "stixCoreObjects", "data", "results"):
            value = parsed.get(key) if isinstance(parsed, dict) else None
            if isinstance(value, list):
                sample = [v for v in value if isinstance(v, dict)]
                break
    bad_label_re = re.compile(r"apt|malicious|c2|phishing|ransomware|botnet", re.IGNORECASE)
    for entry in sample:
        if int(entry.get("confidence") or 0) >= 70:
            return True
        if entry.get("kill_chain_phases"):
            return True
        labels = entry.get("labels") or entry.get("objectLabel") or []
        if isinstance(labels, list):
            for lbl in labels:
                text = lbl if isinstance(lbl, str) else str(lbl.get("value", "")) if isinstance(lbl, dict) else ""
                if bad_label_re.search(text):
                    return True
    return False


def _interval_jitter(timestamps: List[Any]) -> Dict[str, Any]:
    """Compute mean and coefficient of variation for inter-event intervals.

    Lower coefficient = more periodic (stronger beaconing signal).
    """
    parsed: List[datetime] = []
    for ts in timestamps:
        if not isinstance(ts, str) or not ts.strip():
            continue
        text = ts.strip().replace("Z", "+00:00")
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            continue
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        parsed.append(dt)
    parsed.sort()
    if len(parsed) < 4:
        return {"samples": len(parsed), "coefficient_of_variation": 1.0}

    intervals = [
        (parsed[i] - parsed[i - 1]).total_seconds() for i in range(1, len(parsed))
    ]
    if not intervals or all(v <= 0 for v in intervals):
        return {"samples": len(parsed), "coefficient_of_variation": 1.0}
    mean = sum(intervals) / len(intervals)
    if mean <= 0:
        return {"samples": len(parsed), "coefficient_of_variation": 1.0}
    variance = sum((v - mean) ** 2 for v in intervals) / len(intervals)
    stddev = variance ** 0.5
    return {
        "samples": len(parsed),
        "mean_seconds": round(mean, 2),
        "stddev_seconds": round(stddev, 2),
        "coefficient_of_variation": round(stddev / mean, 3),
    }


# ---------------------------------------------------------------------------
# Playbook registry
# ---------------------------------------------------------------------------


PLAYBOOKS: Dict[str, Dict[str, Any]] = {
    "brute_force": {
        "description": "Authentication brute-force / password-spraying detection",
        "collect": _collect_brute_force,
        "classify": _classify_brute_force,
        "recommend": _recommend_brute_force,
    },
    "beaconing": {
        "description": "C2 beaconing: periodic outbound traffic / DNS / OpenCTI match",
        "collect": _collect_beaconing,
        "classify": _classify_beaconing,
        "recommend": _recommend_beaconing,
    },
    "malware": {
        "description": "Malware / rootkit detection on a host with optional file context",
        "collect": _collect_malware,
        "classify": _classify_malware,
        "recommend": _recommend_malware,
    },
    "privilege_escalation": {
        "description": "Sudo / privesc / root-shell-spawn detection",
        "collect": _collect_privilege_escalation,
        "classify": _classify_privilege_escalation,
        "recommend": _recommend_privilege_escalation,
    },
    "exfiltration": {
        "description": "Data exfiltration: outbound volume + archive staging + CTI match",
        "collect": _collect_exfiltration,
        "classify": _classify_exfiltration,
        "recommend": _recommend_exfiltration,
    },
}


# ---------------------------------------------------------------------------
# LangGraph nodes
# ---------------------------------------------------------------------------


async def node_collect_evidence(state: PlaybookState) -> PlaybookState:
    req = state["request"]
    name = str(req.get("playbook", ""))
    pb = PLAYBOOKS.get(name)
    if pb is None:
        raise ValueError(f"Unknown playbook '{name}'")

    state["evidence"] = await pb["collect"](state)
    _append_step(state, f"collect_evidence:{name}")
    return state


async def node_score_and_classify(state: PlaybookState) -> PlaybookState:
    req = state["request"]
    name = str(req.get("playbook", ""))
    pb = PLAYBOOKS[name]
    overrides = req.get("threshold_overrides") or {}
    hints = req.get("evidence", {}) or {}

    classification = pb["classify"](state.get("evidence") or {}, hints, overrides)
    state["risk_tier"] = cast(RiskTier, classification.get("risk_tier", "low"))
    state["rationale"] = classification.get("rationale", [])
    state["signals"] = classification.get("signals", {})
    _append_step(state, f"classify:{state['risk_tier']}")
    return state


async def node_recommend_action(state: PlaybookState) -> PlaybookState:
    req = state["request"]
    name = str(req.get("playbook", ""))
    pb = PLAYBOOKS[name]
    hints = req.get("evidence", {}) or {}
    state["proposed_action"] = pb["recommend"](hints, state.get("signals") or {})
    state["proposed_action"]["recommended_for_risk_tier"] = state.get("risk_tier", "low")
    _append_step(state, f"recommend:{state['proposed_action'].get('action_tool')}")
    return state


async def node_safety_gate(state: PlaybookState) -> PlaybookState:
    req = state["request"]
    incident_id = str(req.get("incident_id", "INC-UNKNOWN"))
    risk = state.get("risk_tier", "low")
    auto_approve = bool(req.get("auto_approve", False))
    analyst_decision = req.get("analyst_decision")

    decision: str
    actor: str
    if risk == "low":
        decision = "approved"
        actor = "system"
    elif auto_approve:
        decision = "approved"
        actor = "auto-approval"
    elif analyst_decision in {"approved", "rejected"}:
        decision = str(analyst_decision)
        actor = "inline-analyst"
    else:
        decision = "pending"
        actor = "awaiting-analyst"

    state["confirmation"] = {
        "required": risk != "low",
        "decision": decision,
        "actor": actor,
        "risk_tier": risk,
    }

    if decision == "pending":
        state["pending_confirmation"] = True
        state["workflow_status"] = "pending_confirmation"
        _append_step(state, "safety_gate_pending")
        async with PENDING_PLAYBOOKS_LOCK:
            PENDING_PLAYBOOKS[incident_id] = cast(PlaybookState, dict(state))

        # Audit log via late import (best-effort)
        try:
            from .audit_logging import log_approval_pending

            log_approval_pending(
                incident_id=incident_id,
                risk_tier=risk,
                approvals_needed=1,
            )
        except Exception:
            pass
        return state

    if decision == "rejected":
        state["workflow_status"] = "completed_rejected"
        _append_step(state, "safety_gate_rejected")
    else:
        state["workflow_status"] = "completed_recommended"
        _append_step(state, f"safety_gate_approved:{actor}")

    try:
        from .audit_logging import log_approval_gate

        log_approval_gate(
            decision=decision,
            actor=actor,
            risk_tier=risk,
            incident_id=incident_id,
            approvals_needed=1,
        )
    except Exception:
        pass

    return state


async def node_finalize(state: PlaybookState) -> PlaybookState:
    if state.get("workflow_status") not in {
        "pending_confirmation",
        "completed_rejected",
        "completed_recommended",
    }:
        state["workflow_status"] = "completed_recommended"
    _append_step(state, "finalize")
    return state


def route_after_safety_gate(state: PlaybookState) -> str:
    if state.get("pending_confirmation"):
        return "end"
    return "finalize"


def build_playbook_workflow() -> Any:
    graph = StateGraph(PlaybookState)
    graph.add_node("collect", node_collect_evidence)
    graph.add_node("classify", node_score_and_classify)
    graph.add_node("recommend", node_recommend_action)
    graph.add_node("gate", node_safety_gate)
    graph.add_node("finalize", node_finalize)

    graph.set_entry_point("collect")
    graph.add_edge("collect", "classify")
    graph.add_edge("classify", "recommend")
    graph.add_edge("recommend", "gate")
    graph.add_conditional_edges(
        "gate",
        route_after_safety_gate,
        {"finalize": "finalize", "end": END},
    )
    graph.add_edge("finalize", END)
    return graph.compile()


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------


playbook_router = APIRouter(prefix="/phase3/playbooks", tags=["phase3-playbooks"])
_workflow = build_playbook_workflow()


def _build_response(state: PlaybookState, incident_id: str, playbook: str) -> RunPlaybookResponse:
    return RunPlaybookResponse(
        incident_id=incident_id,
        playbook=cast(PlaybookName, playbook),
        workflow_status=state.get("workflow_status", "failed"),
        risk_tier=cast(RiskTier, state.get("risk_tier", "low")),
        rationale=state.get("rationale", []),
        evidence=state.get("evidence", {}),
        signals=state.get("signals", {}),
        proposed_action=state.get("proposed_action", {}),
        confirmation=state.get("confirmation", {}),
        steps=state.get("steps", []),
        error=None,
    )


@playbook_router.get("/list")
async def list_playbooks() -> Dict[str, Any]:
    return {
        "playbooks": [
            {"name": name, "description": pb["description"]} for name, pb in PLAYBOOKS.items()
        ]
    }


@playbook_router.post("/run", response_model=RunPlaybookResponse)
async def run_playbook(request: RunPlaybookRequest) -> RunPlaybookResponse:
    if request.playbook not in PLAYBOOKS:
        raise HTTPException(status_code=400, detail=f"Unknown playbook '{request.playbook}'")

    # Late import so unit tests of this module don't drag in main.py at import.
    from .main import MCP_API_KEY, MCP_BASE_URL

    initial_state: PlaybookState = {
        "request": request.model_dump(),
        "mcp_base_url": MCP_BASE_URL,
        "mcp_api_key": MCP_API_KEY,
        "workflow_status": "running",
        "steps": [],
    }

    try:
        final_state = await _workflow.ainvoke(initial_state)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"MCP connectivity error: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Playbook workflow failed: {exc}") from exc

    return _build_response(final_state, request.incident_id, request.playbook)


@playbook_router.get("/pending/{incident_id}")
async def get_pending_playbook(incident_id: str) -> Dict[str, Any]:
    async with PENDING_PLAYBOOKS_LOCK:
        state = PENDING_PLAYBOOKS.get(incident_id)
    if not state:
        raise HTTPException(status_code=404, detail=f"No pending playbook for incident_id={incident_id}")
    return {
        "incident_id": incident_id,
        "playbook": state.get("request", {}).get("playbook"),
        "workflow_status": state.get("workflow_status", "pending_confirmation"),
        "risk_tier": state.get("risk_tier", "low"),
        "rationale": state.get("rationale", []),
        "signals": state.get("signals", {}),
        "proposed_action": state.get("proposed_action", {}),
        "confirmation": state.get("confirmation", {}),
        "steps": state.get("steps", []),
    }


@playbook_router.post("/pending/{incident_id}/resume", response_model=RunPlaybookResponse)
async def resume_pending_playbook(
    incident_id: str, request: ResumePlaybookRequest
) -> RunPlaybookResponse:
    async with PENDING_PLAYBOOKS_LOCK:
        state = PENDING_PLAYBOOKS.pop(incident_id, None)
    if not state:
        raise HTTPException(status_code=404, detail=f"No pending playbook for incident_id={incident_id}")

    state["pending_confirmation"] = False
    state["confirmation"] = {
        **state.get("confirmation", {}),
        "decision": request.decision,
        "actor": request.actor,
    }
    _append_step(state, f"playbook_resumed:{request.decision}")

    if request.decision == "rejected":
        state["workflow_status"] = "completed_rejected"
    else:
        state["workflow_status"] = "completed_recommended"

    try:
        from .audit_logging import log_approval_resumed

        log_approval_resumed(incident_id=incident_id, decision=request.decision, actor=request.actor)
    except Exception:
        pass

    state = await node_finalize(state)
    return _build_response(state, incident_id, str(state.get("request", {}).get("playbook", "")))
