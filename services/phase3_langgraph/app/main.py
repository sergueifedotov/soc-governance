from __future__ import annotations

import asyncio
import importlib
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Literal, Optional, TypedDict, cast


import httpx
from fastapi import FastAPI, HTTPException
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, Field
from tenacity import retry, wait_exponential, stop_after_attempt
from .audit_logging import (
    log_action_execution,
    log_approval_gate,
    log_approval_pending,
    log_approval_resumed,
    log_rollback,
    log_verification,
)

RiskTier = Literal["low", "medium", "high", "critical"]
ApprovalDecision = Literal["approved", "rejected"]


class RunPhase3Request(BaseModel):
    incident_id: str = Field(..., description="Incident or ticket identifier")
    risk_tier: RiskTier = Field("medium", description="Risk tier controlling workflow path")
    use_case: Literal["block_ip", "isolate_host", "quarantine_file"] = Field(
        "block_ip", description="Primary response use case"
    )
    time_range: str = Field("24h", description="Time window used for Phase 2 context collection")
    query: str = Field("sqlmap OR nikto OR brute force", description="Context enrichment search query")
    min_level: int = Field(10, ge=1, le=15, description="Minimum alert level")
    triage_limit: int = Field(20, ge=1, le=200, description="Max alerts for triage")
    enrich_limit: int = Field(20, ge=1, le=100, description="Max alerts for enrichment")
    include_agent_health: bool = True
    auto_approve: bool = False
    approval_decision: ApprovalDecision = "rejected"
    force_verify_fail: bool = False
    action_args: Dict[str, Any] = Field(default_factory=dict, description="Arguments for response action")
    proposed_actions: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Optional explicit list of actions to run in parallel",
    )
    enrichment_source: Literal["wazuh_alerts", "mcp_proxy_denied"] = Field(
        "wazuh_alerts",
        description="Select enrichment evidence source while keeping the same LangGraph workflow",
    )
    proxy_denied_context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional MCP proxy denied-call context used when enrichment_source=mcp_proxy_denied",
    )


class RunPhase3Response(BaseModel):
    incident_id: str
    risk_tier: RiskTier
    workflow_status: str
    steps: List[str]
    approval: Dict[str, Any]
    proposed_action: Dict[str, Any]
    outputs: Dict[str, Any]
    error: Optional[str] = None


class ResumeApprovalRequest(BaseModel):
    decision: ApprovalDecision = Field(..., description="Analyst approval decision to resume pending workflow")
    actor: str = Field("analyst", description="Actor performing resume decision")


class IncidentGroupingRequest(BaseModel):
    incident_id: str = Field(..., description="Incident or ticket identifier")
    alerts: List[Dict[str, Any]] = Field(default_factory=list, description="Raw alerts to deduplicate and group")
    confidence_threshold: float = Field(
        0.65,
        ge=0.0,
        le=1.0,
        description="Minimum confidence required to include an alert in an existing cluster",
    )
    window_minutes: int = Field(
        60,
        ge=1,
        le=1440,
        description="Maximum time distance used when considering alerts for the same cluster",
    )
    require_analyst_confirmation: bool = Field(
        False,
        description="If true, cluster output is paused pending analyst approval",
    )
    auto_confirm: bool = Field(
        False,
        description="Automatically approve when confirmation is required",
    )
    analyst_decision: Optional[ApprovalDecision] = Field(
        None,
        description="Optional direct analyst decision for one-shot requests",
    )


class GroupingResumeRequest(BaseModel):
    decision: ApprovalDecision = Field(..., description="Analyst decision for pending grouping workflow")
    actor: str = Field("analyst", description="Actor performing resume decision")


class IncidentGroupingResponse(BaseModel):
    incident_id: str
    workflow_status: str
    steps: List[str]
    confirmation: Dict[str, Any]
    groups: List[Dict[str, Any]]
    summary: Dict[str, Any]
    error: Optional[str] = None


class Phase3StateBase(TypedDict):
    request: Dict[str, Any]
    mcp_base_url: str
    mcp_api_key: str


class Phase3State(Phase3StateBase, total=False):
    triage: Dict[str, Any]
    enrichment: Dict[str, Any]
    proxy_enrichment: Dict[str, Any]
    handoff: Dict[str, Any]
    proposed_action: Dict[str, Any]
    approval: Dict[str, Any]
    execution: Dict[str, Any]
    verify: Dict[str, Any]
    rollback: Dict[str, Any]
    pending_approval: bool
    workflow_status: str
    steps: List[str]
    trace_info: Dict[str, Any]


class GroupingState(TypedDict, total=False):
    request: Dict[str, Any]
    normalized_alerts: List[Dict[str, Any]]
    groups: List[Dict[str, Any]]
    confirmation: Dict[str, Any]
    summary: Dict[str, Any]
    workflow_status: str
    pending_confirmation: bool
    steps: List[str]


PENDING_APPROVALS: Dict[str, Phase3State] = {}
PENDING_APPROVALS_LOCK = asyncio.Lock()
PENDING_GROUPINGS: Dict[str, GroupingState] = {}
PENDING_GROUPINGS_LOCK = asyncio.Lock()

# Optional Phase 4 integration: persist approvals to the Phase 4 DB via REST.
PHASE4_API_URL = os.getenv("PHASE4_API_URL", "").rstrip("/")

LANGFUSE_ENABLED = os.getenv("LANGFUSE_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
LANGFUSE_HOST = os.getenv("LANGFUSE_HOST", "http://langfuse-web:3000")
LANGFUSE_PUBLIC_KEY = os.getenv("LANGFUSE_PUBLIC_KEY", "")
LANGFUSE_SECRET_KEY = os.getenv("LANGFUSE_SECRET_KEY", "")
LANGFUSE_TRACE_NAME = os.getenv("LANGFUSE_TRACE_NAME", "phase3_workflow")
_LANGFUSE_CLIENT: Optional[Any] = None


def _default_action_args(use_case: str) -> Dict[str, Any]:
    if use_case == "block_ip":
        return {"agent_id": "002", "src_ip": "198.51.100.27", "duration": 3600}
    if use_case == "isolate_host":
        return {"agent_id": "002"}
    return {"agent_id": "002", "file_path": "/tmp/suspicious.bin"}


def _build_action_plan(use_case: str) -> Dict[str, str]:
    if use_case == "block_ip":
        return {
            "action_tool": "wazuh_firewall_drop",
            "verify_tool": "wazuh_check_blocked_ip",
            "rollback_tool": "wazuh_firewall_allow",
        }
    if use_case == "isolate_host":
        return {
            "action_tool": "wazuh_isolate_host",
            "verify_tool": "wazuh_check_agent_isolation",
            "rollback_tool": "wazuh_unisolate_host",
        }
    return {
        "action_tool": "wazuh_quarantine_file",
        "verify_tool": "wazuh_check_file_quarantine",
        "rollback_tool": "wazuh_restore_file",
    }


def _build_verify_args(use_case: str, action_args: Dict[str, Any]) -> Dict[str, Any]:
    if use_case == "block_ip":
        src_ip = action_args.get("src_ip") or action_args.get("ip_address")
        verify_args: Dict[str, Any] = {}
        if src_ip:
            verify_args["ip_address"] = src_ip
        if action_args.get("agent_id"):
            verify_args["agent_id"] = action_args["agent_id"]
        return verify_args
    if use_case == "isolate_host":
        return {"agent_id": action_args.get("agent_id")}
    return {
        "agent_id": action_args.get("agent_id"),
        "file_path": action_args.get("file_path"),
    }


def _build_rollback_args(use_case: str, action_args: Dict[str, Any]) -> Dict[str, Any]:
    if use_case == "block_ip":
        src_ip = action_args.get("src_ip") or action_args.get("ip_address")
        rollback_args: Dict[str, Any] = {}
        if action_args.get("agent_id"):
            rollback_args["agent_id"] = action_args["agent_id"]
        if src_ip:
            rollback_args["src_ip"] = src_ip
        return rollback_args
    if use_case == "isolate_host":
        return {"agent_id": action_args.get("agent_id")}
    return {
        "agent_id": action_args.get("agent_id"),
        "file_path": action_args.get("file_path"),
    }



# Tenacity retry logic for MCP calls
@retry(wait=wait_exponential(multiplier=1, min=2, max=10), stop=stop_after_attempt(3))
async def _mcp_call(base_url: str, api_key: str, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    payload = {
        "jsonrpc": "2.0",
        "id": f"phase3-{tool_name}",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments},
    }
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(base_url.rstrip('/'), json=payload, headers=headers)
        response.raise_for_status()
        body = response.json()

    result = body.get("result", {})
    if result.get("isError"):
        text = ""
        content = result.get("content") or []
        if content and isinstance(content[0], dict):
            text = str(content[0].get("text", ""))
        raise RuntimeError(f"MCP tool {tool_name} failed: {text[:500]}")

    return body


def _unwrap_retry_error(exc: BaseException) -> str:
    """Extract the root cause message from a tenacity RetryError.

    tenacity surfaces a ``RetryError`` whose ``last_attempt`` attribute holds
    the last concurrent.futures.Future.  Calling ``last_attempt.exception()``
    returns the original exception so we report its message instead of the
    opaque ``RetryError[<Future …>]`` string.
    """
    last_attempt = getattr(exc, "last_attempt", None)
    if last_attempt is not None:
        try:
            inner = last_attempt.exception()
            if inner is not None:
                return str(inner)
        except Exception:
            pass
    return str(exc)


def _append_step(state: Phase3State, step: str) -> None:
    state.setdefault("steps", []).append(step)


def _append_grouping_step(state: GroupingState, step: str) -> None:
    state.setdefault("steps", []).append(step)


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_alert(alert: Dict[str, Any]) -> Dict[str, Any]:
    rule = alert.get("rule", {}) if isinstance(alert.get("rule"), dict) else {}
    agent = alert.get("agent", {}) if isinstance(alert.get("agent"), dict) else {}
    data = alert.get("data", {}) if isinstance(alert.get("data"), dict) else {}

    normalized = {
        "timestamp": alert.get("timestamp"),
        "timestamp_dt": _parse_timestamp(alert.get("timestamp")),
        "rule_id": str(rule.get("id", "")),
        "rule_level": int(rule.get("level", 0) or 0),
        "rule_description": str(rule.get("description", "")),
        "agent_id": str(agent.get("id", "")),
        "agent_name": str(agent.get("name", "")),
        "srcip": str(data.get("srcip", "")),
        "raw": alert,
    }
    normalized["fingerprint"] = "|".join(
        [
            normalized["rule_id"],
            normalized["srcip"],
            normalized["agent_id"],
            str(normalized["rule_level"]),
        ]
    )
    return normalized


def _alert_similarity(left: Dict[str, Any], right: Dict[str, Any]) -> float:
    if left.get("fingerprint") and left.get("fingerprint") == right.get("fingerprint"):
        return 1.0

    score = 0.0
    if left.get("rule_id") and left.get("rule_id") == right.get("rule_id"):
        score += 0.45
    if left.get("srcip") and left.get("srcip") == right.get("srcip"):
        score += 0.35
    if left.get("agent_id") and left.get("agent_id") == right.get("agent_id"):
        score += 0.15
    if abs(int(left.get("rule_level", 0)) - int(right.get("rule_level", 0))) <= 1:
        score += 0.05
    return min(score, 1.0)


def _within_window(alert: Dict[str, Any], group: Dict[str, Any], window_minutes: int) -> bool:
    ts = alert.get("timestamp_dt")
    first_seen = group.get("first_seen_dt")
    last_seen = group.get("last_seen_dt")
    if not isinstance(ts, datetime) or not isinstance(first_seen, datetime) or not isinstance(last_seen, datetime):
        return True
    window = timedelta(minutes=window_minutes)
    return abs(ts - first_seen) <= window or abs(ts - last_seen) <= window


def _build_group_summary(group: Dict[str, Any], incident_id: str, index: int) -> Dict[str, Any]:
    alerts: List[Dict[str, Any]] = group.get("alerts", [])
    rule_ids = sorted({alert.get("rule_id", "") for alert in alerts if alert.get("rule_id")})
    srcips = sorted({alert.get("srcip", "") for alert in alerts if alert.get("srcip")})
    agent_ids = sorted({alert.get("agent_id", "") for alert in alerts if alert.get("agent_id")})

    first_seen = group.get("first_seen_dt")
    last_seen = group.get("last_seen_dt")
    confidence = float(group.get("confidence", 0.0))

    representative = alerts[0].get("raw") if alerts else {}
    return {
        "group_id": f"{incident_id}-G{index}",
        "confidence": round(confidence, 3),
        "alert_count": len(alerts),
        "rule_ids": rule_ids,
        "source_ips": srcips,
        "agent_ids": agent_ids,
        "first_seen": first_seen.isoformat() if isinstance(first_seen, datetime) else None,
        "last_seen": last_seen.isoformat() if isinstance(last_seen, datetime) else None,
        "representative_alert": representative,
    }


def _group_alerts(alerts: List[Dict[str, Any]], threshold: float, window_minutes: int, incident_id: str) -> List[Dict[str, Any]]:
    if not alerts:
        return []

    sorted_alerts = sorted(
        alerts,
        key=lambda item: item.get("timestamp_dt") or datetime.min.replace(tzinfo=timezone.utc),
    )
    groups: List[Dict[str, Any]] = []

    for alert in sorted_alerts:
        best_group: Optional[Dict[str, Any]] = None
        best_score = -1.0
        for group in groups:
            if not _within_window(alert, group, window_minutes):
                continue

            centroid = group.get("centroid")
            if not isinstance(centroid, dict):
                continue

            score = _alert_similarity(alert, centroid)
            if score > best_score:
                best_score = score
                best_group = group

        if best_group is not None and best_score >= threshold:
            best_group.setdefault("alerts", []).append(alert)
            similarities = best_group.setdefault("similarities", [])
            similarities.append(best_score)

            ts = alert.get("timestamp_dt")
            if isinstance(ts, datetime):
                if not isinstance(best_group.get("first_seen_dt"), datetime) or ts < best_group["first_seen_dt"]:
                    best_group["first_seen_dt"] = ts
                if not isinstance(best_group.get("last_seen_dt"), datetime) or ts > best_group["last_seen_dt"]:
                    best_group["last_seen_dt"] = ts

            similarity_values = [float(value) for value in similarities if isinstance(value, (int, float))]
            if similarity_values:
                best_group["confidence"] = sum(similarity_values) / len(similarity_values)
        else:
            groups.append(
                {
                    "centroid": alert,
                    "alerts": [alert],
                    "similarities": [1.0],
                    "confidence": 1.0,
                    "first_seen_dt": alert.get("timestamp_dt"),
                    "last_seen_dt": alert.get("timestamp_dt"),
                }
            )

    summaries = [_build_group_summary(group, incident_id, idx + 1) for idx, group in enumerate(groups)]
    summaries.sort(key=lambda item: (item["alert_count"], item["confidence"]), reverse=True)
    return summaries


async def node_grouping_normalize(state: GroupingState) -> GroupingState:
    req = state["request"]
    raw_alerts = req.get("alerts") or []
    normalized = [_normalize_alert(alert) for alert in raw_alerts if isinstance(alert, dict)]
    state["normalized_alerts"] = normalized
    _append_grouping_step(state, f"normalize_alerts:{len(normalized)}")
    return state


async def node_grouping_cluster(state: GroupingState) -> GroupingState:
    req = state["request"]
    incident_id = str(req.get("incident_id", "INC-UNKNOWN"))
    threshold = float(req.get("confidence_threshold", 0.65))
    window_minutes = int(req.get("window_minutes", 60))
    normalized = state.get("normalized_alerts", [])

    grouped = _group_alerts(normalized, threshold, window_minutes, incident_id)
    state["groups"] = grouped
    _append_grouping_step(state, f"cluster_alerts:{len(grouped)}")
    return state


async def node_grouping_confirmation_gate(state: GroupingState) -> GroupingState:
    req = state["request"]
    incident_id = str(req.get("incident_id", "INC-UNKNOWN"))
    required = bool(req.get("require_analyst_confirmation", False))
    auto_confirm = bool(req.get("auto_confirm", False))
    analyst_decision = req.get("analyst_decision")

    decision: str
    actor: str
    if not required:
        decision = "approved"
        actor = "system"
    elif auto_confirm:
        decision = "approved"
        actor = "auto-confirm"
    elif analyst_decision in {"approved", "rejected"}:
        decision = str(analyst_decision)
        actor = "inline-analyst"
    else:
        decision = "pending"
        actor = "awaiting-analyst"

    state["confirmation"] = {
        "required": required,
        "decision": decision,
        "actor": actor,
    }

    if decision == "pending":
        state["pending_confirmation"] = True
        state["workflow_status"] = "pending_confirmation"
        _append_grouping_step(state, "grouping_pending_confirmation")
        async with PENDING_GROUPINGS_LOCK:
            PENDING_GROUPINGS[incident_id] = cast(GroupingState, dict(state))
        return state

    if decision == "rejected":
        state["workflow_status"] = "completed_rejected"
        _append_grouping_step(state, "grouping_rejected")
        return state

    state["workflow_status"] = "completed_grouped"
    _append_grouping_step(state, "grouping_approved")
    return state


async def node_grouping_finalize(state: GroupingState) -> GroupingState:
    groups = state.get("groups", [])
    unique_alerts = sum(1 for group in groups if group.get("alert_count", 0) == 1)
    deduplicated_total = sum(max(int(group.get("alert_count", 0)) - 1, 0) for group in groups)

    state["summary"] = {
        "total_alerts": len(state.get("normalized_alerts", [])),
        "group_count": len(groups),
        "unique_alert_groups": unique_alerts,
        "deduplicated_alerts": deduplicated_total,
        "max_group_size": max((int(group.get("alert_count", 0)) for group in groups), default=0),
    }
    _append_grouping_step(state, "grouping_finalize")
    return state


def route_grouping_after_confirmation(state: GroupingState) -> str:
    if state.get("pending_confirmation"):
        return "end"
    return "finalize"


def build_grouping_workflow() -> Any:
    graph = StateGraph(GroupingState)
    graph.add_node("normalize", node_grouping_normalize)
    graph.add_node("cluster", node_grouping_cluster)
    graph.add_node("confirm", node_grouping_confirmation_gate)
    graph.add_node("finalize", node_grouping_finalize)

    graph.set_entry_point("normalize")
    graph.add_edge("normalize", "cluster")
    graph.add_edge("cluster", "confirm")
    graph.add_conditional_edges("confirm", route_grouping_after_confirmation, {"finalize": "finalize", "end": END})
    graph.add_edge("finalize", END)
    return graph.compile()


def _get_langfuse_client() -> Optional[Any]:
    global _LANGFUSE_CLIENT

    if not LANGFUSE_ENABLED:
        return None
    if not LANGFUSE_PUBLIC_KEY or not LANGFUSE_SECRET_KEY:
        return None
    if _LANGFUSE_CLIENT is None:
        try:
            langfuse_module = importlib.import_module("langfuse")
            langfuse_cls = getattr(langfuse_module, "Langfuse")
            _LANGFUSE_CLIENT = langfuse_cls(
                public_key=LANGFUSE_PUBLIC_KEY,
                secret_key=LANGFUSE_SECRET_KEY,
                host=LANGFUSE_HOST,
            )
        except Exception:
            return None
    return _LANGFUSE_CLIENT


def _start_langfuse_trace(request: RunPhase3Request) -> Dict[str, Any]:
    trace_info: Dict[str, Any] = {
        "provider": "langfuse",
        "enabled": False,
        "trace_id": None,
    }

    client = _get_langfuse_client()
    if not client:
        return trace_info

    try:
        metadata = {
            "incident_id": request.incident_id,
            "risk_tier": request.risk_tier,
            "use_case": request.use_case,
        }

        # Support both Langfuse v2 (trace API) and v3+ (observation API).
        if hasattr(client, "trace"):
            observation = client.trace(
                name=LANGFUSE_TRACE_NAME,
                input=request.model_dump(),
                metadata=metadata,
            )
            trace_info["_mode"] = "trace"
        else:
            observation = client.start_observation(
                name=LANGFUSE_TRACE_NAME,
                as_type="span",
                input=request.model_dump(),
                metadata=metadata,
            )
            trace_info["_mode"] = "observation"

        trace_info["enabled"] = True
        trace_info["trace_id"] = str(getattr(observation, "trace_id", "") or getattr(observation, "id", "") or "")
        trace_info["_observation"] = observation
        trace_info["_client"] = client
        trace_info["child_observations"] = []
    except Exception as exc:
        trace_info["error"] = str(exc)

    return trace_info


def _finish_langfuse_trace(trace_info: Dict[str, Any], final_state: Phase3State) -> None:
    if not trace_info.get("enabled"):
        return

    observation = trace_info.get("_observation")
    client = trace_info.get("_client")
    mode = trace_info.get("_mode")
    if not observation or not client:
        return

    try:
        observation.update(
            output={
                "workflow_status": final_state.get("workflow_status"),
                "steps": final_state.get("steps", []),
                "approval": final_state.get("approval", {}),
            }
        )
        if mode == "observation" and hasattr(observation, "end"):
            observation.end()
        client.flush()
    except Exception as exc:
        trace_info["error"] = str(exc)


def _start_langfuse_child_observation(
    trace_info: Optional[Dict[str, Any]],
    name: str,
    input_payload: Optional[Dict[str, Any]] = None,
    metadata: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    if not trace_info or not trace_info.get("enabled"):
        return None

    client = trace_info.get("_client")
    parent = trace_info.get("_observation")
    trace_id = trace_info.get("trace_id")

    if not client:
        return None

    span_info: Dict[str, Any] = {"name": name}
    try:
        # Langfuse v2 trace object supports creating child spans directly.
        if parent is not None and hasattr(parent, "span"):
            child = parent.span(name=name, input=input_payload, metadata=metadata)
            span_info["_observation"] = child
            span_info["_mode"] = "parent_span"
        # Langfuse v2 client can create spans by trace_id.
        elif hasattr(client, "span") and trace_id:
            child = client.span(name=name, trace_id=trace_id, input=input_payload, metadata=metadata)
            span_info["_observation"] = child
            span_info["_mode"] = "client_span"
        # Langfuse v3+ observation API fallback.
        elif hasattr(client, "start_observation"):
            kwargs: Dict[str, Any] = {
                "name": name,
                "as_type": "span",
                "input": input_payload,
                "metadata": metadata,
            }
            if trace_id:
                kwargs["trace_id"] = trace_id
            child = client.start_observation(**kwargs)
            span_info["_observation"] = child
            span_info["_mode"] = "start_observation"
        else:
            return None

        trace_info.setdefault("child_observations", []).append(name)
        return span_info
    except Exception as exc:
        trace_info["error"] = str(exc)
        return None


def _finish_langfuse_child_observation(
    trace_info: Optional[Dict[str, Any]],
    span_info: Optional[Dict[str, Any]],
    output_payload: Optional[Dict[str, Any]] = None,
    error_text: Optional[str] = None,
) -> None:
    if not trace_info or not span_info:
        return

    observation = span_info.get("_observation")
    mode = span_info.get("_mode")
    if not observation:
        return

    try:
        update_payload: Dict[str, Any] = {}
        if output_payload is not None:
            update_payload["output"] = output_payload
        if error_text:
            update_payload["level"] = "ERROR"
            update_payload["status_message"] = error_text[:500]

        if update_payload:
            observation.update(**update_payload)

        if mode == "start_observation" and hasattr(observation, "end"):
            observation.end()
    except Exception as exc:
        trace_info["error"] = str(exc)


def _extract_state_error(state: Phase3State) -> Optional[str]:
    """Return the first human-readable error found across execution, verify, and rollback nodes."""
    for key in ("execution", "verify", "rollback"):
        node = state.get(key)  # type: ignore[call-overload]
        if isinstance(node, dict) and node.get("status") == "failed":
            err = node.get("error")
            if err:
                return str(err)
    return None


def _top_count_pairs(counts: Dict[str, Any], limit: int = 3) -> List[tuple[str, int]]:
    pairs: List[tuple[str, int]] = []
    for key, value in counts.items():
        try:
            pairs.append((str(key), int(value or 0)))
        except Exception:
            continue
    pairs.sort(key=lambda item: item[1], reverse=True)
    return pairs[:limit]


def _build_proxy_triage_next_steps(summary: Dict[str, Any], root_cause: Dict[str, Any]) -> List[str]:
    reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
    tool_counts = summary.get("tool_counts") if isinstance(summary.get("tool_counts"), dict) else {}
    label_counts = summary.get("llm_risk_labels") if isinstance(summary.get("llm_risk_labels"), dict) else {}

    total_denied = int(summary.get("total", 0) or 0)
    llm_risk_deny = int(reason_counts.get("llm_risk_deny", 0) or 0)
    llm_risk_challenge = int(reason_counts.get("llm_risk_challenge", 0) or 0)
    top_tools = _top_count_pairs(tool_counts, limit=2)
    top_labels = _top_count_pairs(label_counts, limit=3)
    policy_action = str(root_cause.get("recommended_policy_action", "review")).strip() or "review"

    if llm_risk_deny > 0:
        first = f"Prioritize {llm_risk_deny} llm_risk_deny events for immediate analyst review."
    elif llm_risk_challenge > 0:
        first = f"Review {llm_risk_challenge} llm_risk_challenge events to confirm enforcement confidence."
    else:
        first = f"Review all {total_denied} denied calls and confirm risk classification coverage."

    if top_labels:
        labels_text = ", ".join(f"{label} ({count})" for label, count in top_labels)
        first = first.rstrip(".") + f" — top LLM risk signals: {labels_text}."

    if top_tools:
        tools_text = ", ".join(f"{tool} ({count})" for tool, count in top_tools)
        second = f"Compare denied tool mix against expected autonomous hunt behavior, focusing on {tools_text}."
    else:
        second = "Compare denied tool mix against expected autonomous hunt behavior to detect drift."

    third = f"Validate policy thresholds and action mapping before broadening enforcement scope ({policy_action})."
    return [first, second, third]


def _build_proxy_enrichment_next_steps(summary: Dict[str, Any], root_cause: Dict[str, Any]) -> List[str]:
    reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
    label_counts = summary.get("llm_risk_labels") if isinstance(summary.get("llm_risk_labels"), dict) else {}
    rationale_samples = summary.get("llm_risk_rationale_samples") if isinstance(summary.get("llm_risk_rationale_samples"), list) else []

    top_reasons = _top_count_pairs(reason_counts, limit=2)
    top_labels = _top_count_pairs(label_counts, limit=3)
    attack_pattern = str(root_cause.get("attack_pattern", "unknown")).strip() or "unknown"
    false_positive_candidate = bool(root_cause.get("false_positive_candidate", False))

    if top_reasons:
        reasons_text = ", ".join(f"{reason} ({count})" for reason, count in top_reasons)
        first = f"Review top denied reasons for policy drift: {reasons_text}."
    else:
        first = "Review top denied reasons and tools for policy drift."

    if top_labels:
        labels_text = ", ".join(f"{label} ({count})" for label, count in top_labels)
        first = first.rstrip(".") + f" LLM-flagged signals: {labels_text}."

    second = (
        "Correlate denied-call patterns with active Wazuh hunts before escalation, "
        f"with emphasis on {attack_pattern}."
    )
    if rationale_samples:
        sample = rationale_samples[0][:120]
        second = second.rstrip(".") + f". Sample LLM rationale: \"{sample}\"."

    if false_positive_candidate:
        third = "Tune llm_risk thresholds after validating false-positive candidates and documenting rollback criteria."
    else:
        third = "Keep llm_risk thresholds stable until additional false-positive evidence justifies tuning."

    return [first, second, third]


def _build_outputs(state: Phase3State, trace_info: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    outputs: Dict[str, Any] = {
        "triage": state.get("triage"),
        "enrichment": state.get("enrichment"),
        "proxy_enrichment": state.get("proxy_enrichment"),
        "execution": state.get("execution"),
        "verify": state.get("verify"),
        "rollback": state.get("rollback"),
        "handoff": state.get("handoff"),
    }

    if trace_info is not None:
        outputs["trace"] = {
            "provider": trace_info.get("provider", "langfuse"),
            "enabled": bool(trace_info.get("enabled", False)),
            "trace_id": trace_info.get("trace_id"),
            "child_observations_started": len(trace_info.get("child_observations", [])),
            "child_observation_names": trace_info.get("child_observations", []),
            "error": trace_info.get("error"),
        }
    else:
        outputs["trace"] = {
            "provider": "langfuse",
            "enabled": False,
            "trace_id": None,
            "child_observations_started": 0,
            "child_observation_names": [],
            "error": None,
        }

    return outputs


async def node_triage(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_triage",
        input_payload={"time_range": req["time_range"], "min_level": req["min_level"], "limit": req["triage_limit"]},
        metadata={"node": "triage"},
    )
    source = req.get("enrichment_source", "wazuh_alerts")
    triage_args = {
        "time_range": req["time_range"],
        "min_level": req["min_level"],
        "limit": req["triage_limit"],
        "include_agent_health": req["include_agent_health"],
    }
    try:
        if source == "mcp_proxy_denied":
            context = req.get("proxy_denied_context") if isinstance(req.get("proxy_denied_context"), dict) else {}
            summary = context.get("summary") if isinstance(context.get("summary"), dict) else {}
            root_cause = context.get("root_cause") if isinstance(context.get("root_cause"), dict) else {}
            reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
            tool_counts = summary.get("tool_counts") if isinstance(summary.get("tool_counts"), dict) else {}
            label_counts = summary.get("llm_risk_labels") if isinstance(summary.get("llm_risk_labels"), dict) else {}
            rationale_samples = summary.get("llm_risk_rationale_samples") if isinstance(summary.get("llm_risk_rationale_samples"), list) else []

            top_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            top_labels = sorted(label_counts.items(), key=lambda x: x[1], reverse=True)[:3]
            reasons_txt = ", ".join(f"{k}:{v}" for k, v in top_reasons) if top_reasons else "none"
            tools_txt = ", ".join(f"{k}:{v}" for k, v in top_tools) if top_tools else "none"
            labels_txt = ", ".join(f"{k}:{v}" for k, v in top_labels) if top_labels else ""
            attack_pattern = str(root_cause.get("attack_pattern", "unknown"))

            analysis = (
                "Proxy-denied triage context for autonomous threat hunting. "
                f"Top denied reasons: {reasons_txt}. Top denied tools: {tools_txt}. "
                f"Attack pattern category: {attack_pattern}."
            )
            if labels_txt:
                analysis += f" LLM risk signals: {labels_txt}."
            if rationale_samples:
                analysis += f" Sample rationale: \"{rationale_samples[0][:100]}\"."

            state["triage"] = {
                "data": {
                    "workflow": "phase3_proxy_denied_triage",
                    "analysis": analysis,
                    "total_alerts": int(summary.get("total", 0) or 0),
                    "severity_breakdown": {
                        "critical": int(reason_counts.get("llm_risk_deny", 0) or 0),
                        "high": int(reason_counts.get("llm_risk_challenge", 0) or 0),
                    },
                    "time_range": str(req.get("time_range", "24h")),
                    "recommended_next_steps": _build_proxy_triage_next_steps(summary, root_cause),
                    "supporting_context": {
                        "proxy_denied_summary": summary,
                        "proxy_root_cause": root_cause,
                    },
                    "orchestration": {
                        "engine": "langgraph",
                        "status": "ok",
                    },
                }
            }
            _append_step(state, "triage_proxy_denied_context")
        else:
            state["triage"] = await _mcp_call(state["mcp_base_url"], state["mcp_api_key"], "triage_wazuh_alerts", triage_args)
            _append_step(state, "triage_wazuh_alerts")
        _finish_langfuse_child_observation(state.get("trace_info"), span, output_payload={"status": "ok"})
        return state
    except Exception as exc:
        _finish_langfuse_child_observation(state.get("trace_info"), span, output_payload={"status": "error"}, error_text=str(exc))
        raise


async def node_enrichment(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_enrichment",
        input_payload={"time_range": req["time_range"], "limit": req["enrich_limit"], "query": req["query"]},
        metadata={"node": "enrichment"},
    )
    enrich_args = {
        "time_range": req["time_range"],
        "limit": req["enrich_limit"],
        "query": req["query"],
    }
    try:
        state["enrichment"] = await _mcp_call(state["mcp_base_url"], state["mcp_api_key"], "enrich_wazuh_context", enrich_args)
        _append_step(state, "enrich_wazuh_context")
        _finish_langfuse_child_observation(state.get("trace_info"), span, output_payload={"status": "ok"})
        return state
    except Exception as exc:
        _finish_langfuse_child_observation(state.get("trace_info"), span, output_payload={"status": "error"}, error_text=str(exc))
        raise


async def node_proxy_enrichment(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_proxy_enrichment",
        input_payload={"time_range": req["time_range"], "limit": req["enrich_limit"], "query": req["query"]},
        metadata={"node": "proxy_enrichment"},
    )
    context = req.get("proxy_denied_context") if isinstance(req.get("proxy_denied_context"), dict) else {}
    summary = context.get("summary") if isinstance(context.get("summary"), dict) else {}
    root_cause = context.get("root_cause") if isinstance(context.get("root_cause"), dict) else {}
    reason_counts = summary.get("reason_counts") if isinstance(summary.get("reason_counts"), dict) else {}
    tool_counts = summary.get("tool_counts") if isinstance(summary.get("tool_counts"), dict) else {}
    label_counts = summary.get("llm_risk_labels") if isinstance(summary.get("llm_risk_labels"), dict) else {}
    rationale_samples = summary.get("llm_risk_rationale_samples") if isinstance(summary.get("llm_risk_rationale_samples"), list) else []

    top_reasons = sorted(reason_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    top_tools = sorted(tool_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    top_labels = sorted(label_counts.items(), key=lambda x: x[1], reverse=True)[:3]
    reasons_txt = ", ".join(f"{k}:{v}" for k, v in top_reasons) if top_reasons else "none"
    tools_txt = ", ".join(f"{k}:{v}" for k, v in top_tools) if top_tools else "none"
    labels_txt = ", ".join(f"{k}:{v}" for k, v in top_labels) if top_labels else ""
    attack_pattern = str(root_cause.get("attack_pattern", "unknown"))
    policy_action = str(root_cause.get("recommended_policy_action", "review"))

    analysis = (
        f"Proxy-denied enrichment context for autonomous threat hunting. "
        f"Top denied reasons: {reasons_txt}. Top denied tools: {tools_txt}. "
        f"Root-cause attack pattern: {attack_pattern}. "
        f"Recommended policy action: {policy_action}."
    )
    if labels_txt:
        analysis += f" LLM risk signals observed: {labels_txt}."
    if rationale_samples:
        analysis += f" Sample LLM rationale: \"{rationale_samples[0][:100]}\"."

    patterns = [
        {"rule_id": str(reason), "description": str(reason), "count": int(count)}
        for reason, count in top_reasons
    ]

    state["proxy_enrichment"] = {
        "data": {
            "workflow": "phase3_proxy_denied_enrichment",
            "analysis": analysis,
            "match_count": int(summary.get("total", 0) or 0),
            "recommended_next_steps": _build_proxy_enrichment_next_steps(summary, root_cause),
            "supporting_context": {
                "patterns": {
                    "patterns": patterns,
                },
                "proxy_denied_summary": summary,
                "proxy_root_cause": root_cause,
            },
            "orchestration": {
                "engine": "langgraph",
                "status": "ok",
            },
        }
    }
    _append_step(state, "enrich_proxy_denied_context")
    _finish_langfuse_child_observation(state.get("trace_info"), span, output_payload={"status": "ok"})
    return state


def route_after_triage(state: Phase3State) -> str:
    req = state.get("request", {})
    source = req.get("enrichment_source", "wazuh_alerts") if isinstance(req, dict) else "wazuh_alerts"
    if source == "mcp_proxy_denied":
        return "proxy_enrich"
    return "enrich"


async def node_propose_action(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_propose_action",
        input_payload={"risk_tier": req["risk_tier"], "use_case": req["use_case"]},
        metadata={"node": "propose_action"},
    )
    plan = _build_action_plan(req["use_case"])
    action_args = req["action_args"] or _default_action_args(req["use_case"])
    verify_args = _build_verify_args(req["use_case"], action_args)
    rollback_args = _build_rollback_args(req["use_case"], action_args)

    approval_required = req["risk_tier"] in {"medium", "high", "critical"}
    approvals_needed = 2 if req["risk_tier"] in {"high", "critical"} else 1

    state["proposed_action"] = {
        "use_case": req["use_case"],
        "action_tool": plan["action_tool"],
        "verify_tool": plan["verify_tool"],
        "rollback_tool": plan["rollback_tool"],
        "args": action_args,
        "verify_args": verify_args,
        "rollback_args": rollback_args,
        "approval_required": approval_required,
        "approvals_needed": approvals_needed,
    }
    if req.get("proposed_actions"):
        state["proposed_action"]["proposed_actions"] = req["proposed_actions"]
    _append_step(state, "propose_action")
    _finish_langfuse_child_observation(
        state.get("trace_info"),
        span,
        output_payload={
            "status": "ok",
            "approval_required": approval_required,
            "approvals_needed": approvals_needed,
            "action_tool": plan["action_tool"],
        },
    )
    return state


async def node_approval_gate(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_approval_gate",
        input_payload={"risk_tier": req["risk_tier"], "auto_approve": req.get("auto_approve", False)},
        metadata={"node": "approval_gate"},
    )
    proposed = state.get("proposed_action", {})
    required = bool(proposed.get("approval_required", False))

    incident_id = req["incident_id"]

    if not required:
        decision = "approved"
        actor = "system"
    elif req["auto_approve"]:
        decision = "approved"
        actor = "auto-approval"
    else:
        decision = "rejected" if req.get("approval_decision") == "rejected" else "approved"
        actor = "manual-decision"

    state["approval"] = {
        "required": required,
        "decision": decision,
        "actor": actor,
        "approvals_needed": proposed.get("approvals_needed", 0),
    }
    # Audit log for approval gate
    log_approval_gate(
        decision=decision,
        actor=actor,
        risk_tier=req["risk_tier"],
        incident_id=incident_id,
        approvals_needed=proposed.get("approvals_needed", 0),
    )
    # Human-in-the-loop: Pause workflow until analyst resumes with decision.
    if required and not req.get("auto_approve", False):
        state["pending_approval"] = True
        state["approval"]["decision"] = "pending"
        state["approval"]["actor"] = "awaiting-analyst"
        state["workflow_status"] = "pending_approval"
        log_approval_pending(
            incident_id=incident_id,
            risk_tier=req["risk_tier"],
            approvals_needed=proposed.get("approvals_needed", 0),
        )
        _append_step(state, "approval_paused_for_human")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "pending", "decision": "pending"},
        )
        return state
    _append_step(state, f"approval_gate:{decision}")
    _finish_langfuse_child_observation(
        state.get("trace_info"),
        span,
        output_payload={"status": "ok", "decision": decision, "required": required},
    )
    return state


async def node_execute_action(state: Phase3State) -> Phase3State:
    proposed = state.get("proposed_action", {})
    incident_id = state["request"]["incident_id"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_execute_action",
        input_payload={
            "has_parallel_actions": bool(proposed.get("proposed_actions")),
            "action_tool": proposed.get("action_tool"),
        },
        metadata={"node": "execute_action"},
    )
    # Support for multi-action workflows (parallel execution)
    actions = proposed.get("proposed_actions")
    if actions and isinstance(actions, list):
        results = await asyncio.gather(*[
            _mcp_call(state["mcp_base_url"], state["mcp_api_key"], a["tool"], a.get("args", {}))
            for a in actions
        ], return_exceptions=True)
        status = "passed" if all(not isinstance(r, Exception) for r in results) else "failed"
        state["execution"] = {
            "status": status,
            "actions": actions,
            "results": [str(r) if isinstance(r, Exception) else r for r in results],
        }
        log_action_execution(
            incident_id=incident_id,
            tool="parallel_actions",
            status=status,
            args={"actions": actions},
            error=None if status == "passed" else "one_or_more_parallel_actions_failed",
            parallel=True,
        )
        _append_step(state, f"execute:parallel:{state['execution']['status']}")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": state["execution"]["status"], "parallel_count": len(actions)},
        )
        return state
    tool = proposed.get("action_tool")
    if not isinstance(tool, str) or not tool:
        raise RuntimeError("Missing action_tool in proposed action")
    args = proposed.get("args", {})
    try:
        response = await _mcp_call(state["mcp_base_url"], state["mcp_api_key"], tool, args)
        state["execution"] = {"status": "passed", "tool": tool, "args": args, "response": response}
        log_action_execution(incident_id=incident_id, tool=tool, status="passed", args=args)
        _append_step(state, f"execute:{tool}:passed")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "passed", "tool": tool},
        )
    except Exception as exc:
        error_msg = _unwrap_retry_error(exc)
        state["execution"] = {"status": "failed", "tool": tool, "args": args, "error": error_msg}
        log_action_execution(incident_id=incident_id, tool=tool, status="failed", args=args, error=error_msg)
        _append_step(state, f"execute:{tool}:failed")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "failed", "tool": tool},
            error_text=error_msg,
        )
    return state


async def node_verify_action(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_verify_action",
        input_payload={"force_verify_fail": bool(req.get("force_verify_fail", False))},
        metadata={"node": "verify_action"},
    )
    proposed = state.get("proposed_action", {})
    verify_tool = proposed.get("verify_tool")
    if not isinstance(verify_tool, str) or not verify_tool:
        raise RuntimeError("Missing verify_tool in proposed action")
    args = proposed.get("verify_args") or proposed.get("args", {})

    if req.get("force_verify_fail"):
        state["verify"] = {"forced": True, "status": "failed"}
        log_verification(
            incident_id=req["incident_id"],
            tool=verify_tool,
            status="failed",
            forced=True,
            error="forced_verify_fail",
        )
        _append_step(state, f"verify:{verify_tool}:failed(forced)")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "failed", "tool": verify_tool, "forced": True},
            error_text="forced_verify_fail",
        )
        return state

    try:
        verify_response = await _mcp_call(state["mcp_base_url"], state["mcp_api_key"], verify_tool, args)
        state["verify"] = {"forced": False, "status": "passed", "response": verify_response}
        log_verification(incident_id=req["incident_id"], tool=verify_tool, status="passed", forced=False)
        _append_step(state, f"verify:{verify_tool}:passed")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "passed", "tool": verify_tool, "forced": False},
        )
    except Exception as exc:
        error_msg = _unwrap_retry_error(exc)
        state["verify"] = {"forced": False, "status": "failed", "error": error_msg}
        log_verification(
            incident_id=req["incident_id"],
            tool=verify_tool,
            status="failed",
            forced=False,
            error=error_msg,
        )
        _append_step(state, f"verify:{verify_tool}:failed")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "failed", "tool": verify_tool, "forced": False},
            error_text=error_msg,
        )
    return state


async def node_rollback_action(state: Phase3State) -> Phase3State:
    proposed = state.get("proposed_action", {})
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_rollback_action",
        input_payload={"rollback_tool": proposed.get("rollback_tool")},
        metadata={"node": "rollback_action"},
    )
    rollback_tool = proposed.get("rollback_tool")
    if not isinstance(rollback_tool, str) or not rollback_tool:
        raise RuntimeError("Missing rollback_tool in proposed action")
    args = proposed.get("rollback_args") or proposed.get("args", {})
    try:
        state["rollback"] = await _mcp_call(state["mcp_base_url"], state["mcp_api_key"], rollback_tool, args)
        log_rollback(incident_id=state["request"]["incident_id"], tool=rollback_tool, status="passed")
        _append_step(state, f"rollback:{rollback_tool}")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "passed", "tool": rollback_tool},
        )
    except Exception as exc:
        error_msg = _unwrap_retry_error(exc)
        state["rollback"] = {"status": "failed", "error": error_msg, "tool": rollback_tool, "args": args}
        log_rollback(
            incident_id=state["request"]["incident_id"],
            tool=rollback_tool,
            status="failed",
            error=error_msg,
        )
        _append_step(state, f"rollback:{rollback_tool}:failed")
        _finish_langfuse_child_observation(
            state.get("trace_info"),
            span,
            output_payload={"status": "failed", "tool": rollback_tool},
            error_text=error_msg,
        )
    return state


async def node_handoff(state: Phase3State) -> Phase3State:
    req = state["request"]
    span = _start_langfuse_child_observation(
        state.get("trace_info"),
        "node_handoff",
        input_payload={"report_type": "incident", "time_range": req["time_range"]},
        metadata={"node": "handoff"},
    )
    handoff_args = {
        "report_type": "incident",
        "time_range": req["time_range"],
        "include_recommendations": True,
    }
    state["handoff"] = await _mcp_call(
        state["mcp_base_url"], state["mcp_api_key"], "generate_soc_handoff_report", handoff_args
    )
    _append_step(state, "generate_soc_handoff_report")
    if state.get("rollback"):
        state["workflow_status"] = "completed_with_rollback"
    elif state.get("approval", {}).get("decision") == "rejected":
        state["workflow_status"] = "completed_rejected"
    elif state.get("execution", {}).get("status") == "failed":
        state["workflow_status"] = "completed_action_failed"
    elif state.get("execution"):
        state["workflow_status"] = "completed_actioned"
    else:
        state["workflow_status"] = "completed_read_only"
    _finish_langfuse_child_observation(
        state.get("trace_info"),
        span,
        output_payload={"status": "ok", "workflow_status": state["workflow_status"]},
    )
    return state


def route_by_risk(state: Phase3State) -> str:
    risk = state["request"]["risk_tier"]
    if risk == "low":
        return "handoff"
    return "propose"


def route_after_approval(state: Phase3State) -> str:
    if state.get("pending_approval"):
        return "pending"
    decision = state.get("approval", {}).get("decision")
    if decision == "approved":
        return "execute"
    return "handoff"


async def node_pending_approval(state: Phase3State) -> Phase3State:
    incident_id = state["request"]["incident_id"]
    async with PENDING_APPROVALS_LOCK:
        PENDING_APPROVALS[incident_id] = cast(Phase3State, dict(state))
    state["workflow_status"] = "pending_approval"
    _append_step(state, "pending_approval_stored")

    # Fire-and-forget: persist approval to Phase 4 DB if configured
    if PHASE4_API_URL:
        approval_state = state.get("approval", {})
        proposed = state.get("proposed_action", {})
        triage = state.get("triage", {})
        risk_tier = state["request"].get("risk_tier", "medium")
        approvals_needed = approval_state.get("approvals_needed", 1)

        # Build a concise triage summary string for display in the UI
        triage_summary_parts: List[str] = []
        if triage.get("alert_count"):
            triage_summary_parts.append(f"Alerts: {triage['alert_count']}")
        if triage.get("top_rule"):
            triage_summary_parts.append(f"Rule: {triage['top_rule']}")
        if triage.get("source_ips"):
            triage_summary_parts.append(f"Source IPs: {', '.join(str(ip) for ip in triage['source_ips'][:3])}")
        workflow_summary = " | ".join(triage_summary_parts) if triage_summary_parts else ""

        phase4_payload = {
            "phase3_incident_id": incident_id,
            "risk_tier": risk_tier,
            "approvals_needed": approvals_needed,
            "requested_by": "phase3-langgraph",
            "proposed_action": proposed,
            "workflow_summary": workflow_summary,
            "expires_minutes": 30,
        }
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                await client.post(
                    f"{PHASE4_API_URL}/approvals",
                    json=phase4_payload,
                )
        except Exception as exc:  # pragma: no cover
            # Phase 4 integration is optional — never block the workflow
            pass

    return state


def route_after_execute(state: Phase3State) -> str:
    execution_state = state.get("execution", {})
    if execution_state.get("status") == "failed":
        return "handoff"
    return "verify"


def route_after_verify(state: Phase3State) -> str:
    verify_state = state.get("verify", {})
    if verify_state.get("status") == "failed":
        return "rollback"
    return "handoff"


def build_workflow() -> Any:
    graph = StateGraph(Phase3State)

    graph.add_node("triage", node_triage)
    graph.add_node("enrich", node_enrichment)
    graph.add_node("proxy_enrich", node_proxy_enrichment)
    graph.add_node("propose", node_propose_action)
    graph.add_node("approval", node_approval_gate)
    graph.add_node("pending", node_pending_approval)
    graph.add_node("execute", node_execute_action)
    graph.add_node("verify", node_verify_action)
    graph.add_node("rollback", node_rollback_action)
    graph.add_node("handoff", node_handoff)

    graph.set_entry_point("triage")
    graph.add_conditional_edges("triage", route_after_triage, {"enrich": "enrich", "proxy_enrich": "proxy_enrich"})
    graph.add_conditional_edges("enrich", route_by_risk, {"handoff": "handoff", "propose": "propose"})
    graph.add_conditional_edges("proxy_enrich", route_by_risk, {"handoff": "handoff", "propose": "propose"})
    graph.add_edge("propose", "approval")
    graph.add_conditional_edges("approval", route_after_approval, {"execute": "execute", "handoff": "handoff", "pending": "pending"})
    graph.add_edge("pending", END)
    graph.add_conditional_edges("execute", route_after_execute, {"verify": "verify", "handoff": "handoff"})
    graph.add_conditional_edges("verify", route_after_verify, {"rollback": "rollback", "handoff": "handoff"})
    graph.add_edge("rollback", "handoff")
    graph.add_edge("handoff", END)

    return graph.compile()


MCP_BASE_URL = os.getenv("MCP_BASE_URL", "http://wazuh-mcp-server:3000")
MCP_API_KEY = os.getenv("MCP_API_KEY", "")
SERVICE_NAME = "phase3-langgraph-service"
workflow = build_workflow()
grouping_workflow = build_grouping_workflow()

app = FastAPI(title="Phase 3 LangGraph Orchestrator", version="0.1.0")

# Use-case-specific investigation playbooks (brute force, beaconing, malware,
# privilege escalation, exfiltration). The router is defined in a separate
# module to keep main.py focused on the core Phase 3 workflow.
from .playbooks import playbook_router as _playbook_router  # noqa: E402

app.include_router(_playbook_router)


@app.get("/health")
async def health() -> Dict[str, Any]:
    return {
        "status": "healthy",
        "service": SERVICE_NAME,
        "mcp_base_url": MCP_BASE_URL,
        "graph": "phase3_guarded_write",
    }


@app.get("/use-cases")
async def use_cases() -> Dict[str, Any]:
    return {
        "levels": {
            "low": {
                "behavior": "read-only triage, enrichment, and handoff",
                "example": "No write action for low-confidence indicator clusters",
            },
            "medium": {
                "behavior": "single-approval gated action",
                "use_case": "block_ip",
                "action": "wazuh_firewall_drop",
            },
            "high": {
                "behavior": "approval + execute + verify + rollback on failure",
                "use_case": "isolate_host",
                "action": "wazuh_isolate_host",
            },
            "critical": {
                "behavior": "strict approval and containment with rollback guarantees",
                "use_case": "quarantine_file",
                "action": "wazuh_quarantine_file",
            },
        }
    }


@app.post("/phase3/run", response_model=RunPhase3Response)
async def run_phase3(request: RunPhase3Request) -> RunPhase3Response:
    trace_info = _start_langfuse_trace(request)

    initial_state: Phase3State = {
        "request": request.model_dump(),
        "mcp_base_url": MCP_BASE_URL,
        "mcp_api_key": MCP_API_KEY,
        "workflow_status": "running",
        "steps": [],
        "trace_info": trace_info,
    }

    try:
        final_state = await workflow.ainvoke(initial_state)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"MCP connectivity error: {exc}") from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Phase 3 workflow failed: {exc}") from exc

    _finish_langfuse_trace(trace_info, final_state)

    return RunPhase3Response(
        incident_id=request.incident_id,
        risk_tier=request.risk_tier,
        workflow_status=final_state.get("workflow_status", "failed"),
        steps=final_state.get("steps", []),
        approval=final_state.get("approval", {}),
        proposed_action=final_state.get("proposed_action", {}),
        outputs=_build_outputs(final_state, trace_info),
        error=_extract_state_error(final_state),
    )


@app.post("/phase3/incident-grouping/run", response_model=IncidentGroupingResponse)
async def run_incident_grouping(request: IncidentGroupingRequest) -> IncidentGroupingResponse:
    initial_state: GroupingState = {
        "request": request.model_dump(),
        "workflow_status": "running",
        "steps": [],
    }

    try:
        final_state = await grouping_workflow.ainvoke(initial_state)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Incident grouping workflow failed: {exc}") from exc

    return IncidentGroupingResponse(
        incident_id=request.incident_id,
        workflow_status=final_state.get("workflow_status", "failed"),
        steps=final_state.get("steps", []),
        confirmation=final_state.get("confirmation", {}),
        groups=final_state.get("groups", []),
        summary=final_state.get("summary", {}),
        error=None,
    )


@app.get("/phase3/incident-grouping/pending/{incident_id}")
async def get_pending_grouping(incident_id: str) -> Dict[str, Any]:
    async with PENDING_GROUPINGS_LOCK:
        state = PENDING_GROUPINGS.get(incident_id)

    if not state:
        raise HTTPException(status_code=404, detail=f"No pending grouping for incident_id={incident_id}")

    return {
        "incident_id": incident_id,
        "workflow_status": state.get("workflow_status", "pending_confirmation"),
        "confirmation": state.get("confirmation", {}),
        "groups": state.get("groups", []),
        "steps": state.get("steps", []),
    }


@app.post("/phase3/incident-grouping/pending/{incident_id}/resume", response_model=IncidentGroupingResponse)
async def resume_pending_grouping(incident_id: str, request: GroupingResumeRequest) -> IncidentGroupingResponse:
    async with PENDING_GROUPINGS_LOCK:
        state = PENDING_GROUPINGS.pop(incident_id, None)

    if not state:
        raise HTTPException(status_code=404, detail=f"No pending grouping for incident_id={incident_id}")

    state["pending_confirmation"] = False
    state["confirmation"] = {
        "required": True,
        "decision": request.decision,
        "actor": request.actor,
    }
    _append_grouping_step(state, f"grouping_resumed:{request.decision}")

    if request.decision == "rejected":
        state["workflow_status"] = "completed_rejected"
        state.setdefault("summary", {})
    else:
        state = await node_grouping_finalize(state)
        state["workflow_status"] = "completed_grouped"

    return IncidentGroupingResponse(
        incident_id=incident_id,
        workflow_status=state.get("workflow_status", "failed"),
        steps=state.get("steps", []),
        confirmation=state.get("confirmation", {}),
        groups=state.get("groups", []),
        summary=state.get("summary", {}),
        error=None,
    )


async def _continue_after_approval(state: Phase3State) -> Phase3State:
    route = route_after_approval(state)
    if route == "handoff":
        return await node_handoff(state)

    if route == "execute":
        state = await node_execute_action(state)
        route = route_after_execute(state)
        if route == "handoff":
            return await node_handoff(state)

        state = await node_verify_action(state)
        route = route_after_verify(state)
        if route == "rollback":
            state = await node_rollback_action(state)
        return await node_handoff(state)

    return state


@app.get("/phase3/approvals/{incident_id}")
async def get_pending_approval(incident_id: str) -> Dict[str, Any]:
    async with PENDING_APPROVALS_LOCK:
        state = PENDING_APPROVALS.get(incident_id)

    if not state:
        raise HTTPException(status_code=404, detail=f"No pending approval for incident_id={incident_id}")

    return {
        "incident_id": incident_id,
        "workflow_status": state.get("workflow_status", "pending_approval"),
        "approval": state.get("approval", {}),
        "proposed_action": state.get("proposed_action", {}),
        "steps": state.get("steps", []),
    }


@app.post("/phase3/approvals/{incident_id}/resume", response_model=RunPhase3Response)
async def resume_pending_approval(incident_id: str, request: ResumeApprovalRequest) -> RunPhase3Response:
    async with PENDING_APPROVALS_LOCK:
        state = PENDING_APPROVALS.pop(incident_id, None)

    if not state:
        raise HTTPException(status_code=404, detail=f"No pending approval for incident_id={incident_id}")

    state["pending_approval"] = False
    approval = state.setdefault("approval", {})
    approval["decision"] = request.decision
    approval["actor"] = request.actor
    _append_step(state, f"approval_resumed:{request.decision}")
    log_approval_resumed(incident_id=incident_id, decision=request.decision, actor=request.actor)

    final_state = await _continue_after_approval(state)
    req = final_state.get("request", {})

    return RunPhase3Response(
        incident_id=incident_id,
        risk_tier=req.get("risk_tier", "medium"),
        workflow_status=final_state.get("workflow_status", "failed"),
        steps=final_state.get("steps", []),
        approval=final_state.get("approval", {}),
        proposed_action=final_state.get("proposed_action", {}),
        outputs=_build_outputs(final_state),
        error=_extract_state_error(final_state),
    )
