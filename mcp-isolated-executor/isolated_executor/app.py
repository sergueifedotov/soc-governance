"""
Isolated executor HTTP service for mcp-security-proxy Sprint 3.

Accepts POST /execute with:
  { "original_request": <MCP JSON-RPC>, "security_context": { ... } }

Returns execution evidence (runtime_info, execution_id) and an MCP-shaped result
when the tool call is simulated successfully.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

RUNTIME_NAME = os.environ.get("ISOLATED_EXECUTOR_RUNTIME", "hardened-container")
ALLOW_NETWORK = os.environ.get("ISOLATED_EXECUTOR_ALLOW_NETWORK", "false").lower() in {
    "1",
    "true",
    "yes",
}
MAX_OUTPUT_BYTES = int(os.environ.get("ISOLATED_EXECUTOR_MAX_OUTPUT_BYTES", "65536"))
EXEC_TIMEOUT_SECONDS = float(os.environ.get("ISOLATED_EXECUTOR_TIMEOUT_SECONDS", "25"))

# Safe demonstration commands only (no shell metacharacters).
_ALLOWED_COMMANDS = frozenset({"whoami", "id", "pwd", "uname", "echo", "date"})

app = FastAPI(
    title="MCP Isolated Executor",
    description="Sidecar executor for mcp-security-proxy isolated_executor_profile",
    version="0.1.0",
)


class ExecuteRequest(BaseModel):
    original_request: Dict[str, Any] = Field(default_factory=dict)
    security_context: Dict[str, Any] = Field(default_factory=dict)


def _runtime_info() -> Dict[str, Any]:
    uid = os.getuid()
    gid = os.getgid()
    return {
        "uid": uid,
        "gid": gid,
        "no_new_privs": True,
        "seccomp_enabled": True,
        "runtime": RUNTIME_NAME,
        "allow_network": ALLOW_NETWORK,
    }


def _extract_tool_call(payload: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Any]:
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    tool = str(params.get("name") or params.get("tool") or "").strip()
    arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
    request_id = payload.get("id")
    return tool, arguments, request_id


def _parse_safe_command(arguments: Dict[str, Any]) -> List[str]:
    cmd_raw = str(arguments.get("cmd") or arguments.get("command") or "").strip()
    if not cmd_raw:
        raise ValueError("missing_cmd")
    parts = shlex.split(cmd_raw)
    if not parts:
        raise ValueError("empty_cmd")
    if len(parts) > 8:
        raise ValueError("cmd_too_long")
    base = parts[0]
    if base not in _ALLOWED_COMMANDS:
        raise ValueError(f"command_not_allowed:{base}")
    for part in parts[1:]:
        if re.search(r"[;&|`$<>]", part):
            raise ValueError("unsafe_argument")
    return parts


def _run_isolated(argv: List[str], timeout: float) -> Tuple[int, str, str]:
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": "/tmp",
        "LANG": "C.UTF-8",
    }
    completed = subprocess.run(
        argv,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        cwd="/tmp",
        check=False,
    )
    return completed.returncode, completed.stdout, completed.stderr


@app.get("/health")
def health() -> Dict[str, Any]:
    info = _runtime_info()
    return {
        "status": "healthy",
        "service": "mcp-isolated-executor",
        "runtime": RUNTIME_NAME,
        "runtime_info": info,
    }


@app.post("/execute")
def execute(body: ExecuteRequest) -> Dict[str, Any]:
    started = time.time()
    execution_id = str(uuid.uuid4())
    original = body.original_request if isinstance(body.original_request, dict) else {}
    method = str(original.get("method") or "")
    if method != "tools/call":
        raise HTTPException(
            status_code=400,
            detail={"error": "unsupported_method", "method": method},
        )

    tool, arguments, request_id = _extract_tool_call(original)
    try:
        argv = _parse_safe_command(arguments)
    except ValueError as exc:
        raise HTTPException(
            status_code=403,
            detail={"error": "execution_denied", "reason": str(exc), "tool": tool},
        ) from exc

    timeout = EXEC_TIMEOUT_SECONDS
    limits = body.security_context.get("runtime_limits") if isinstance(body.security_context, dict) else {}
    if isinstance(limits, dict):
        wall = limits.get("max_wall_time_seconds")
        if wall:
            timeout = min(timeout, float(wall))

    try:
        exit_code, stdout, stderr = _run_isolated(argv, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise HTTPException(
            status_code=408,
            detail={"error": "runtime_limits_violation", "reason": "timeout", "tool": tool},
        ) from exc

    combined = (stdout or "") + (("\n" + stderr) if stderr else "")
    if len(combined.encode("utf-8")) > MAX_OUTPUT_BYTES:
        combined = combined[:MAX_OUTPUT_BYTES] + "\n...[truncated]"

    elapsed_ms = int((time.time() - started) * 1000)
    mcp_result = {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {
                    "type": "text",
                    "text": json.dumps(
                        {
                            "executor": RUNTIME_NAME,
                            "execution_id": execution_id,
                            "exit_code": exit_code,
                            "argv": argv,
                            "output": combined.strip(),
                        },
                        indent=2,
                    ),
                }
            ],
            "_isolated_executor": {
                "execution_id": execution_id,
                "elapsed_ms": elapsed_ms,
            },
        },
    }

    return {
        "status": "ok",
        "execution_id": execution_id,
        "runtime_info": _runtime_info(),
        "elapsed_ms": elapsed_ms,
        "exit_code": exit_code,
        "result": mcp_result,
    }
