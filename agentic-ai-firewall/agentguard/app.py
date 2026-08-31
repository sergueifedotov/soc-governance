"""FastAPI application factory for AgentGuard."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Dict

import httpx
import yaml
from fastapi import Body, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from agentguard import __version__
from agentguard.audit import recent
from agentguard.config import Policy, load_policy
from agentguard.guardrails import scan_input, scan_output, scan_tool_call
from agentguard.metrics import AG_PROXY_UPSTREAM_ERRORS
from agentguard.models import (
    InputScanRequest,
    InputScanResponse,
    OutputScanRequest,
    OutputScanResponse,
    ToolCallScanRequest,
    ToolCallScanResponse,
)


logger = logging.getLogger("agentguard")
logging.basicConfig(
    level=os.getenv("AGENTGUARD_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)


_OPENAI_UPSTREAM = os.getenv("AGENTGUARD_OPENAI_UPSTREAM", "https://api.openai.com")
_ANTHROPIC_UPSTREAM = os.getenv("AGENTGUARD_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")


def _policy_file_path() -> Path:
    return Path(os.getenv("AGENTGUARD_POLICY_FILE", "./policy.yaml"))


def _policy_to_yaml_dict(policy: Policy) -> Dict[str, Any]:
    return {
        "version": policy.version,
        "input": {
            "challenge_threshold": policy.input.challenge_threshold,
            "block_threshold": policy.input.block_threshold,
            "strip_hidden_chars": policy.input.strip_hidden_chars,
            "strip_html_comments": policy.input.strip_html_comments,
            "redact_pii": policy.input.redact_pii,
            "redact_secrets": policy.input.redact_secrets,
        },
        "output": {
            "default": {
                "challenge_threshold": policy.default_tool.challenge_threshold,
                "block_threshold": policy.default_tool.block_threshold,
                "require_approval": policy.default_tool.require_approval,
            },
            "tools": {
                tool_name: {
                    "challenge_threshold": tool_policy.challenge_threshold,
                    "block_threshold": tool_policy.block_threshold,
                    "require_approval": tool_policy.require_approval,
                }
                for tool_name, tool_policy in policy.tools.items()
            },
        },
        "network": {
            "allowed_domains": list(policy.network.allowed_domains),
            "block_private_ranges": policy.network.block_private_ranges,
        },
    }


def _policy_fingerprint(policy_dict: Dict[str, Any]) -> str:
    canonical = json.dumps(policy_dict, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12]


def _policy_status(app: FastAPI) -> Dict[str, Any]:
    policy_path = _policy_file_path()
    policy_dict = _policy_to_yaml_dict(app.state.policy)
    stat = policy_path.stat() if policy_path.exists() else None
    return {
        "status": "ok",
        "policy_path": str(policy_path),
        "policy_exists": policy_path.exists(),
        "policy_file_mtime": int(stat.st_mtime) if stat else None,
        "applied_at": int(getattr(app.state, "policy_applied_at", int(time.time()))),
        "policy_fingerprint": getattr(app.state, "policy_fingerprint", _policy_fingerprint(policy_dict)),
        "policy": policy_dict,
    }


def _resolve_upstream(provider: str) -> tuple[str, str]:
    upstream = _OPENAI_UPSTREAM if provider == "openai" else _ANTHROPIC_UPSTREAM
    normalized = upstream.rstrip("/")

    if provider == "openai":
        if normalized.endswith("/v1"):
            return normalized, "/chat/completions"
        if normalized.endswith("/engines"):
            return normalized, "/v1/chat/completions"
        return normalized, "/v1/chat/completions"

    if normalized.endswith("/v1"):
        return normalized, "/messages"
    return normalized, "/v1/messages"


def create_app() -> FastAPI:
    app = FastAPI(
        title="AgentGuard",
        version=__version__,
        description="The Firewall for Autonomous AI Agents.",
    )

    # Mutable policy holder so /v1/admin/reload-policy works.
    app.state.policy = load_policy()
    app.state.policy_applied_at = int(time.time())
    app.state.policy_fingerprint = _policy_fingerprint(_policy_to_yaml_dict(app.state.policy))

    static_dir = Path(__file__).parent / "ui" / "static"
    if static_dir.exists():
        app.mount("/ui/static", StaticFiles(directory=str(static_dir)), name="ui-static")

    # ---------------- Health + version ----------------

    @app.get("/healthz")
    def healthz() -> Dict[str, Any]:
        return {"status": "ok", "version": __version__}

    @app.get("/version")
    def version() -> Dict[str, str]:
        return {"version": __version__}

    # ---------------- Scan endpoints ----------------

    @app.post("/v1/scan/input", response_model=InputScanResponse)
    def api_scan_input(req: InputScanRequest) -> InputScanResponse:
        return scan_input(req, app.state.policy)

    @app.post("/v1/scan/output", response_model=OutputScanResponse)
    def api_scan_output(req: OutputScanRequest) -> OutputScanResponse:
        return scan_output(req, app.state.policy)

    @app.post("/v1/scan/tool-call", response_model=ToolCallScanResponse)
    def api_scan_tool_call(req: ToolCallScanRequest) -> ToolCallScanResponse:
        return scan_tool_call(req, app.state.policy)

    # ---------------- LLM proxies (drop-in) ----------------

    @app.post("/v1/proxy/openai/v1/chat/completions")
    async def proxy_openai(request: Request) -> Response:
        return await _proxy_llm(request, provider="openai")

    @app.post("/v1/proxy/anthropic/v1/messages")
    async def proxy_anthropic(request: Request) -> Response:
        return await _proxy_llm(request, provider="anthropic")

    # ---------------- Audit + admin ----------------

    @app.get("/audit/recent")
    def api_audit_recent(limit: int = 100):
        return {"events": [e.model_dump(mode="json") for e in recent(limit=limit)]}

    @app.post("/v1/admin/reload-policy")
    def api_reload_policy() -> Dict[str, Any]:
        app.state.policy = load_policy()
        app.state.policy_applied_at = int(time.time())
        app.state.policy_fingerprint = _policy_fingerprint(_policy_to_yaml_dict(app.state.policy))
        status = _policy_status(app)
        status["status"] = "reloaded"
        return status

    @app.get("/v1/admin/policy")
    def api_get_policy() -> Dict[str, Any]:
        return _policy_status(app)

    @app.get("/v1/admin/policy/raw")
    def api_get_policy_raw() -> Dict[str, Any]:
        policy_path = _policy_file_path()
        if policy_path.exists():
            return {
                "status": "ok",
                "policy_path": str(policy_path),
                "yaml": policy_path.read_text(encoding="utf-8"),
            }
        return {
            "status": "ok",
            "policy_path": str(policy_path),
            "yaml": yaml.safe_dump(_policy_to_yaml_dict(app.state.policy), sort_keys=False),
        }

    @app.put("/v1/admin/policy")
    def api_update_policy(payload: Dict[str, Any] = Body(...)) -> Dict[str, Any]:
        yaml_text = payload.get("yaml") if isinstance(payload, dict) else None
        if not isinstance(yaml_text, str) or not yaml_text.strip():
            raise HTTPException(status_code=400, detail="request body must include non-empty 'yaml' string")

        try:
            parsed = yaml.safe_load(yaml_text)
            if parsed is None:
                parsed = {}
            if not isinstance(parsed, dict):
                raise ValueError("policy YAML must parse to an object")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"invalid policy YAML: {exc}")

        policy_path = _policy_file_path()
        policy_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = policy_path.with_suffix(policy_path.suffix + ".tmp")
        tmp_path.write_text(yaml_text, encoding="utf-8")

        try:
            loaded = load_policy(str(tmp_path))
        except Exception as exc:  # noqa: BLE001
            try:
                tmp_path.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass
            raise HTTPException(status_code=400, detail=f"policy validation failed: {exc}")

        tmp_path.replace(policy_path)
        app.state.policy = loaded
        app.state.policy_applied_at = int(time.time())
        app.state.policy_fingerprint = _policy_fingerprint(_policy_to_yaml_dict(app.state.policy))

        status = _policy_status(app)
        status["status"] = "updated"
        return status

    # ---------------- Metrics ----------------

    @app.get("/metrics")
    def metrics() -> Response:
        return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

    # ---------------- UI ----------------

    @app.get("/ui", response_class=HTMLResponse)
    def ui() -> HTMLResponse:
        html_path = static_dir / "index.html"
        if html_path.exists():
            return HTMLResponse(html_path.read_text())
        return HTMLResponse("<h1>AgentGuard</h1><p>UI not bundled.</p>")

    @app.get("/", response_class=HTMLResponse)
    def root() -> HTMLResponse:
        return HTMLResponse(
            f"<h1>AgentGuard {__version__}</h1>"
            f'<p>See <a href="/ui">/ui</a>, <a href="/metrics">/metrics</a>, '
            f'<a href="/docs">/docs</a>.</p>'
        )

    return app


# ---------------- Internal LLM proxy logic ----------------


async def _proxy_llm(request: Request, provider: str) -> Response:
    """Drop-in proxy: scan inbound messages (untrusted user content) and outbound
    LLM responses for prompt-injection / PII / secret leaks."""
    policy: Policy = request.app.state.policy
    upstream, target_path = _resolve_upstream(provider)

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="invalid JSON body")

    # Inbound scan: walk messages.content (OpenAI/Anthropic structure).
    blocked = _scan_inbound_messages(body, policy)
    if blocked is not None:
        return JSONResponse(status_code=400, content={
            "error": "agentguard.blocked",
            "reason": blocked,
        })

    # Forward
    url = upstream.rstrip("/") + target_path
    headers = {k: v for k, v in request.headers.items() if k.lower() not in {"host", "content-length"}}
    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            upstream_resp = await client.post(url, json=body, headers=headers)
    except httpx.RequestError as exc:
        AG_PROXY_UPSTREAM_ERRORS.labels(provider=provider, category="network").inc()
        return JSONResponse(status_code=502, content={"error": "upstream_unreachable", "detail": str(exc)})

    # Outbound scan
    out_blocked = _scan_outbound_response(
        upstream_resp.json() if upstream_resp.headers.get("content-type", "").startswith("application/json") else None,
        policy,
    )
    if out_blocked is not None:
        AG_PROXY_UPSTREAM_ERRORS.labels(provider=provider, category="output_blocked").inc()
        return JSONResponse(status_code=502, content={"error": "agentguard.output_blocked", "reason": out_blocked})

    return Response(
        content=upstream_resp.content,
        status_code=upstream_resp.status_code,
        media_type=upstream_resp.headers.get("content-type", "application/json"),
    )


def _scan_inbound_messages(body: Dict[str, Any], policy: Policy) -> str | None:
    msgs = body.get("messages") or []
    for m in msgs:
        content = m.get("content")
        if isinstance(content, str):
            resp = scan_input(InputScanRequest(text=content, source=f"llm:{m.get('role','user')}"), policy)
            if resp.verdict.blocked:
                return resp.verdict.reason
            m["content"] = resp.sanitized_text
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") in {"text", "input_text"} and isinstance(part.get("text"), str):
                    resp = scan_input(InputScanRequest(text=part["text"], source=f"llm:{m.get('role','user')}"), policy)
                    if resp.verdict.blocked:
                        return resp.verdict.reason
                    part["text"] = resp.sanitized_text
    return None


def _scan_outbound_response(payload: Any, policy: Policy) -> str | None:
    if not isinstance(payload, dict):
        return None
    # OpenAI shape
    for choice in payload.get("choices") or []:
        msg = (choice or {}).get("message") or {}
        text = msg.get("content")
        if isinstance(text, str):
            resp = scan_output(OutputScanRequest(text=text), policy)
            if resp.verdict.blocked:
                return resp.verdict.reason
            msg["content"] = resp.sanitized_text
    # Anthropic shape
    for block in payload.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "text" and isinstance(block.get("text"), str):
            resp = scan_output(OutputScanRequest(text=block["text"]), policy)
            if resp.verdict.blocked:
                return resp.verdict.reason
            block["text"] = resp.sanitized_text
    return None
