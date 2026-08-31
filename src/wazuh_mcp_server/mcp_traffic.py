"""
MCP Agent Traffic Observability
================================

Real-time, low-overhead recorder for every JSON-RPC call hitting the MCP
server. Complements Prometheus/Grafana (aggregate metrics) by giving
analysts a per-call view: method, tool, params summary, status, latency,
client IP/user-agent, auth subject, session, error message.

Endpoints (mounted under /observability):

  GET  /observability/ui            Self-contained HTML dashboard
  GET  /observability/recent        JSON list of recent calls (filterable)
  GET  /observability/stats         Aggregate stats (per tool, timeline, top clients)
  GET  /observability/stream        SSE live event feed
  GET  /observability/health        Lightweight liveness probe

Authentication
--------------
Reads `MCP_OBSERVABILITY_TOKEN` (preferred) or falls back to `MCP_API_KEY`.
Pass it as `Authorization: Bearer <token>` or `?token=<token>`. Set
`MCP_OBSERVABILITY_OPEN=1` to disable auth (local dev only).

Configuration
-------------
  MCP_OBSERVABILITY_CAPACITY   Ring-buffer size (default 1000)
  MCP_OBSERVABILITY_TOKEN      Bearer token for the /observability/* routes
  MCP_OBSERVABILITY_OPEN       1/true → no auth (dev)
"""
from __future__ import annotations

import asyncio
import contextvars
import json
import os
import time
import uuid
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse

# Prometheus metrics for MCP traffic — exposed via /metrics so Grafana can
# query them through Prometheus. Persistence is provided by Prometheus's
# TSDB (retention configured in compose.phase4.yml).
try:
    from wazuh_mcp_server.monitoring import REGISTRY as _METRICS_REGISTRY  # type: ignore
    from prometheus_client import Counter as _PCounter, Histogram as _PHistogram

    MCP_CALLS_TOTAL = _PCounter(
        "wazuh_mcp_calls_total",
        "Total MCP JSON-RPC calls observed by the traffic recorder.",
        ["method", "tool", "status"],
        registry=_METRICS_REGISTRY,
    )
    MCP_CALL_DURATION_SECONDS = _PHistogram(
        "wazuh_mcp_call_duration_seconds",
        "MCP JSON-RPC call duration in seconds.",
        ["method", "tool"],
        buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0),
        registry=_METRICS_REGISTRY,
    )
    MCP_CALL_ERRORS_TOTAL = _PCounter(
        "wazuh_mcp_call_errors_total",
        "Total MCP JSON-RPC call errors by code.",
        ["method", "tool", "error_code"],
        registry=_METRICS_REGISTRY,
    )
    _METRICS_AVAILABLE = True
except Exception:  # pragma: no cover - metrics best-effort
    MCP_CALLS_TOTAL = None  # type: ignore
    MCP_CALL_DURATION_SECONDS = None  # type: ignore
    MCP_CALL_ERRORS_TOTAL = None  # type: ignore
    _METRICS_AVAILABLE = False

# ---------------------------------------------------------------------------
# Context vars set by the /mcp endpoint per request, consumed by record_mcp_call
# ---------------------------------------------------------------------------
client_ip_var: contextvars.ContextVar[str] = contextvars.ContextVar("mcp_obs_client_ip", default="")
client_ua_var: contextvars.ContextVar[str] = contextvars.ContextVar("mcp_obs_client_ua", default="")
auth_subject_var: contextvars.ContextVar[str] = contextvars.ContextVar("mcp_obs_auth_subject", default="")
session_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("mcp_obs_session_id", default="")


# ---------------------------------------------------------------------------
# Recorder
# ---------------------------------------------------------------------------
class MCPTrafficRecorder:
    """In-memory ring buffer + aggregator. Bounded, thread-safe via asyncio.Lock."""

    def __init__(self, capacity: int = 1000) -> None:
        self._events: deque = deque(maxlen=capacity)
        self._lock = asyncio.Lock()
        self._listeners: set = set()  # asyncio.Queue subscribers

    async def record(self, event: Dict[str, Any]) -> None:
        async with self._lock:
            self._events.append(event)
            for q in list(self._listeners):
                try:
                    q.put_nowait(event)
                except asyncio.QueueFull:
                    # Slow consumer; drop event for them
                    pass

    def list_recent(
        self,
        limit: int = 100,
        tool: Optional[str] = None,
        method: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for e in reversed(self._events):
            if tool and e.get("tool") != tool:
                continue
            if method and e.get("method") != method:
                continue
            if status and e.get("status") != status:
                continue
            out.append(e)
            if len(out) >= limit:
                break
        return out

    def stats(self) -> Dict[str, Any]:
        agg: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"count": 0, "success": 0, "error": 0, "durations": []}
        )
        clients: Dict[str, int] = defaultdict(int)
        per_minute: Dict[int, Dict[str, int]] = defaultdict(lambda: {"count": 0, "errors": 0})
        recent_errors: List[Dict[str, Any]] = []
        now_min = int(time.time() // 60)

        for e in self._events:
            key = e.get("tool") or e.get("method") or "unknown"
            a = agg[key]
            a["count"] += 1
            if e.get("status") == "success":
                a["success"] += 1
            else:
                a["error"] += 1
            d = e.get("duration_ms")
            if isinstance(d, (int, float)):
                a["durations"].append(d)
            clients[e.get("client_ip") or "unknown"] += 1
            m = int((e.get("ts") or 0) // 60)
            if 0 <= now_min - m < 60:
                per_minute[m]["count"] += 1
                if e.get("status") != "success":
                    per_minute[m]["errors"] += 1

        # most recent errors first
        for e in reversed(self._events):
            if e.get("status") != "success" and len(recent_errors) < 25:
                recent_errors.append(e)

        by_key = []
        for k, v in agg.items():
            ds = sorted(v["durations"])
            n = len(ds)
            if n:
                p50 = ds[n // 2]
                p95_idx = max(0, min(n - 1, int(round(n * 0.95)) - 1))
                p95 = ds[p95_idx]
                avg = sum(ds) / n
            else:
                p50 = p95 = avg = 0
            cnt = v["count"]
            by_key.append(
                {
                    "key": k,
                    "count": cnt,
                    "success": v["success"],
                    "error": v["error"],
                    "error_rate": (v["error"] / cnt) if cnt else 0,
                    "p50_ms": round(p50, 2),
                    "p95_ms": round(p95, 2),
                    "avg_ms": round(avg, 2),
                }
            )
        by_key.sort(key=lambda x: -x["count"])

        timeline = []
        for m in range(now_min - 59, now_min + 1):
            d = per_minute.get(m, {"count": 0, "errors": 0})
            timeline.append({"minute": m, "count": d["count"], "errors": d["errors"]})

        total = len(self._events)
        total_errors = sum(v["error"] for v in agg.values())
        total_durations = [d for v in agg.values() for d in v["durations"]]
        total_durations.sort()
        n = len(total_durations)
        overall_p95 = (
            total_durations[max(0, min(n - 1, int(round(n * 0.95)) - 1))] if n else 0
        )

        return {
            "total_events": total,
            "total_errors": total_errors,
            "overall_error_rate": (total_errors / total) if total else 0,
            "overall_p95_ms": round(overall_p95, 2),
            "capacity": self._events.maxlen,
            "by_key": by_key,
            "top_clients": [
                {"client_ip": k, "count": v}
                for k, v in sorted(clients.items(), key=lambda x: -x[1])[:10]
            ],
            "timeline": timeline,
            "recent_errors": recent_errors,
        }

    async def subscribe(self) -> "asyncio.Queue":
        q: asyncio.Queue = asyncio.Queue(maxsize=200)
        self._listeners.add(q)
        return q

    def unsubscribe(self, q: "asyncio.Queue") -> None:
        self._listeners.discard(q)


_capacity = int(os.environ.get("MCP_OBSERVABILITY_CAPACITY", "1000"))
recorder = MCPTrafficRecorder(capacity=_capacity)


# ---------------------------------------------------------------------------
# Public recording API (called from server.py / tool handlers)
# ---------------------------------------------------------------------------
def _summarize_params(method: str, params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Produce a compact, secret-free summary of the request params."""
    params = params or {}
    if method == "tools/call":
        args = params.get("arguments") or {}
        return {
            "name": params.get("name"),
            "args_keys": list(args.keys())[:20] if isinstance(args, dict) else None,
            "args_count": len(args) if isinstance(args, dict) else None,
        }
    if method == "resources/read":
        return {"uri": params.get("uri")}
    if method == "prompts/get":
        return {"name": params.get("name")}
    if method == "logging/setLevel":
        return {"level": params.get("level")}
    if method in ("tools/list", "prompts/list", "resources/list", "ping", "initialize"):
        return {}
    # Generic fallback - keys only, no values
    if isinstance(params, dict):
        return {"keys": list(params.keys())[:20]}
    return {}


def _result_size(result: Any) -> Optional[int]:
    if result is None:
        return None
    try:
        return len(json.dumps(result, default=str))
    except Exception:
        return None


async def record_mcp_call(
    *,
    method: str,
    params: Optional[Dict[str, Any]],
    request_id: Any,
    status: str,
    duration_ms: float,
    error_code: Optional[int] = None,
    error_message: Optional[str] = None,
    result: Any = None,
) -> None:
    """Record a single MCP JSON-RPC call. Status: 'success' or 'error'."""
    event = {
        "id": str(uuid.uuid4()),
        "ts": time.time(),
        "iso": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "tool": (params or {}).get("name") if method == "tools/call" else None,
        "request_id": str(request_id) if request_id is not None else None,
        "status": status,
        "duration_ms": round(duration_ms, 2),
        "error_code": error_code,
        "error_message": (error_message[:500] if error_message else None),
        "result_size": _result_size(result),
        "params_summary": _summarize_params(method, params),
        "client_ip": client_ip_var.get(),
        "user_agent": (client_ua_var.get() or "")[:200],
        "auth_subject": auth_subject_var.get(),
        "session_id": session_id_var.get(),
    }
    await recorder.record(event)

    # Mirror to Prometheus so Grafana / persistent TSDB has the same data.
    if _METRICS_AVAILABLE:
        try:
            tool_label = (event["tool"] or "-")[:80]
            method_label = (method or "-")[:40]
            MCP_CALLS_TOTAL.labels(method=method_label, tool=tool_label, status=status).inc()
            MCP_CALL_DURATION_SECONDS.labels(method=method_label, tool=tool_label).observe(
                max(duration_ms, 0.0) / 1000.0
            )
            if status != "success":
                code_label = str(error_code if error_code is not None else "unknown")
                MCP_CALL_ERRORS_TOTAL.labels(
                    method=method_label, tool=tool_label, error_code=code_label
                ).inc()
        except Exception:
            # Metrics must never break request handling.
            pass


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------
router = APIRouter(prefix="/observability", tags=["observability"])


def _check_auth(request: Request) -> None:
    if os.environ.get("MCP_OBSERVABILITY_OPEN", "").lower() in ("1", "true", "yes"):
        return
    expected = (
        os.environ.get("MCP_OBSERVABILITY_TOKEN")
        or os.environ.get("MCP_API_KEY")
    )
    if not expected:
        return  # nothing to check against; treat as open
    auth_hdr = request.headers.get("authorization") or ""
    token = ""
    if auth_hdr.lower().startswith("bearer "):
        token = auth_hdr.split(" ", 1)[1].strip()
    if not token:
        token = request.query_params.get("token", "") or request.headers.get("x-observability-token", "")
    if token != expected:
        raise HTTPException(status_code=401, detail="Unauthorized")


@router.get("/health")
async def obs_health() -> Dict[str, Any]:
    return {"status": "ok", "buffered_events": len(recorder._events), "capacity": recorder._events.maxlen}


@router.get("/recent")
async def recent(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    tool: Optional[str] = None,
    method: Optional[str] = None,
    status: Optional[str] = None,
) -> JSONResponse:
    _check_auth(request)
    return JSONResponse({"events": recorder.list_recent(limit, tool, method, status)})


@router.get("/stats")
async def stats(request: Request) -> JSONResponse:
    _check_auth(request)
    return JSONResponse(recorder.stats())


@router.get("/stream")
async def stream(request: Request) -> StreamingResponse:
    _check_auth(request)

    async def gen():
        q = await recorder.subscribe()
        try:
            # Prime the client
            yield f": connected\n\nretry: 3000\n\n"
            while True:
                if await request.is_disconnected():
                    break
                try:
                    ev = await asyncio.wait_for(q.get(), timeout=15.0)
                    yield f"data: {json.dumps(ev, default=str)}\n\n"
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            recorder.unsubscribe(q)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/ui")
async def ui(request: Request):
    """Redirect to the Grafana 'MCP Agent Traffic' dashboard.

    Persistent observability now lives in Prometheus + Grafana. The legacy
    in-page dashboard is still available at /observability/ui/legacy for
    debugging when Grafana is not running.
    """
    target = os.environ.get(
        "MCP_OBSERVABILITY_GRAFANA_URL",
        "http://localhost:3002/d/mcp-agent-traffic/mcp-agent-traffic",
    )
    return RedirectResponse(url=target, status_code=302)


@router.get("/ui/legacy", response_class=HTMLResponse)
async def ui_legacy() -> HTMLResponse:
    # Fallback in-memory dashboard. Use only when Grafana is unavailable.
    return HTMLResponse(_DASHBOARD_HTML)


# ---------------------------------------------------------------------------
# Self-contained dashboard
# ---------------------------------------------------------------------------
_DASHBOARD_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<title>MCP Agent Traffic — Observability</title>
<meta name="viewport" content="width=device-width, initial-scale=1" />
<style>
  :root {
    --bg:#0b1020; --panel:#131a30; --line:#26314f; --fg:#e6edf3;
    --muted:#94a3b8; --ok:#22c55e; --err:#ef4444; --warn:#f59e0b; --accent:#60a5fa;
  }
  * { box-sizing: border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:14px/1.45 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; }
  header { padding:14px 20px; background:#0e1530; border-bottom:1px solid var(--line);
           display:flex; align-items:center; gap:14px; flex-wrap:wrap; }
  header h1 { font-size:16px; margin:0; font-weight:600; letter-spacing:.2px; }
  header .pill { font-size:11px; padding:3px 8px; border-radius:999px;
                 background:#1e293b; color:var(--muted); border:1px solid var(--line); }
  header .grow { flex:1; }
  header input, header select, header button {
    background:#0e1530; color:var(--fg); border:1px solid var(--line);
    padding:6px 10px; border-radius:6px; font:inherit;
  }
  header button { cursor:pointer; }
  header button:hover { border-color:var(--accent); }
  .grid { display:grid; gap:14px; padding:14px;
          grid-template-columns: repeat(4, 1fr); }
  .grid > .wide { grid-column: span 2; }
  .grid > .full { grid-column: 1 / -1; }
  .card { background:var(--panel); border:1px solid var(--line);
          border-radius:10px; padding:14px; }
  .card h2 { margin:0 0 10px 0; font-size:12px; font-weight:600;
             text-transform:uppercase; letter-spacing:1px; color:var(--muted); }
  .kpi { display:flex; flex-direction:column; gap:4px; }
  .kpi .num { font-size:24px; font-weight:700; }
  .kpi .sub { font-size:11px; color:var(--muted); }
  table { width:100%; border-collapse:collapse; font-size:13px; }
  th, td { text-align:left; padding:7px 8px; border-bottom:1px solid var(--line); white-space:nowrap; }
  th { font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.5px; font-weight:600; }
  tr:hover td { background:#1a2240; }
  .status-success { color:var(--ok); }
  .status-error   { color:var(--err); }
  .badge { display:inline-block; padding:1px 6px; border-radius:4px; font-size:11px;
           background:#1e293b; border:1px solid var(--line); }
  .feed { max-height: 420px; overflow:auto; font-size:12.5px; }
  .feed .row { padding:6px 4px; border-bottom:1px solid var(--line); display:grid;
               grid-template-columns: 78px 110px 1fr 70px 60px; gap:8px; align-items:center; }
  .feed .row:last-child { border-bottom:0; }
  .feed .ts { color:var(--muted); font-variant-numeric:tabular-nums; }
  .feed .meth { color:var(--accent); }
  .feed .ms { text-align:right; color:var(--muted); font-variant-numeric:tabular-nums; }
  .timeline { display:flex; align-items:flex-end; gap:2px; height:80px; }
  .timeline .bar { flex:1; background:#1e293b; border-radius:2px 2px 0 0; position:relative; min-height:1px; }
  .timeline .bar.err { background:var(--err); }
  .small { color:var(--muted); font-size:11px; }
  .scroll { max-height: 300px; overflow:auto; }
  details summary { cursor:pointer; user-select:none; }
  code { background:#0e1530; padding:1px 4px; border-radius:3px; font-size:12px; }
  .filter { display:flex; gap:6px; flex-wrap:wrap; align-items:center; }
  .dot { display:inline-block; width:8px; height:8px; border-radius:50%; background:var(--muted); margin-right:6px; }
  .dot.live { background:var(--ok); box-shadow:0 0 6px var(--ok); }
  #banner { display:none; margin:10px 14px 0 14px; padding:10px 14px; border-radius:8px;
            background:#3b1d1d; color:#fecaca; border:1px solid #7f1d1d; font-size:13px; }
  #banner.show { display:block; }
  #banner code { background:#1f0d0d; color:#fecaca; }
  #banner .hl { color:#fff; font-weight:600; }
  #token.flash { border-color:#ef4444; box-shadow:0 0 0 2px rgba(239,68,68,.3); }
</style>
</head>
<body>
<header>
  <h1>MCP Agent Traffic</h1>
  <span class="pill" id="conn"><span class="dot" id="conn-dot"></span><span id="conn-label">connecting…</span></span>
  <span class="pill">capacity <span id="cap">–</span></span>
  <span class="pill">buffered <span id="buf">–</span></span>
  <span class="grow"></span>
  <div class="filter">
    <input id="token" placeholder="bearer token" size="22" />
    <select id="f-method">
      <option value="">any method</option>
      <option>tools/call</option><option>tools/list</option>
      <option>initialize</option><option>ping</option>
      <option>resources/read</option><option>resources/list</option>
      <option>prompts/list</option><option>prompts/get</option>
    </select>
    <input id="f-tool" placeholder="tool name (filter)" size="20" />
    <select id="f-status">
      <option value="">any status</option>
      <option value="success">success</option>
      <option value="error">error</option>
    </select>
    <button id="refresh">Refresh</button>
    <button id="pause">Pause feed</button>
  </div>
</header>

<div id="banner"></div>

<div class="grid">
  <div class="card kpi"><h2>Total calls</h2><div class="num" id="kpi-total">–</div><div class="sub">in ring buffer</div></div>
  <div class="card kpi"><h2>Errors</h2><div class="num status-error" id="kpi-errors">–</div><div class="sub" id="kpi-errrate">–</div></div>
  <div class="card kpi"><h2>Overall p95</h2><div class="num" id="kpi-p95">–</div><div class="sub">milliseconds</div></div>
  <div class="card kpi"><h2>Active live feed</h2><div class="num" id="kpi-live">0</div><div class="sub">events since open</div></div>

  <div class="card full">
    <h2>Calls per minute (last 60 min) — red = errors</h2>
    <div class="timeline" id="timeline"></div>
  </div>

  <div class="card wide">
    <h2>By tool / method</h2>
    <div class="scroll">
      <table id="t-byKey">
        <thead><tr><th>Key</th><th>Count</th><th>Success</th><th>Error</th><th>Err%</th><th>p50</th><th>p95</th><th>avg</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
  <div class="card wide">
    <h2>Top clients</h2>
    <div class="scroll">
      <table id="t-clients">
        <thead><tr><th>Client IP</th><th>Calls</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>

  <div class="card full">
    <h2>Live feed</h2>
    <div class="feed" id="feed"><div class="small">connecting…</div></div>
  </div>

  <div class="card full">
    <h2>Recent errors</h2>
    <div class="scroll">
      <table id="t-errors">
        <thead><tr><th>Time</th><th>Method</th><th>Tool</th><th>Code</th><th>Message</th><th>Client</th><th>Subject</th></tr></thead>
        <tbody></tbody>
      </table>
    </div>
  </div>
</div>

<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const qsToken = new URLSearchParams(location.search).get("token");
  const tokenInput = $("token");
  // Only use ?token= if non-empty; otherwise fall back to localStorage.
  if (qsToken && qsToken.length > 0) tokenInput.value = qsToken;
  else tokenInput.value = localStorage.getItem("mcpObsToken") || "";
  tokenInput.addEventListener("change", () => localStorage.setItem("mcpObsToken", tokenInput.value));

  const banner = $("banner");
  function showBanner(html) {
    banner.innerHTML = html;
    banner.classList.add("show");
    tokenInput.classList.add("flash");
    tokenInput.focus();
  }
  function hideBanner() {
    banner.classList.remove("show");
    tokenInput.classList.remove("flash");
  }
  function showAuthBanner(status) {
    const msg = status === 401
      ? `<span class="hl">Authentication required (HTTP 401).</span> Paste the bearer token from <code>$MCP_API_KEY</code> (or the <code>MCP_API_KEY</code> line in <code>.env</code>) into the <span class="hl">bearer token</span> field above and press <span class="hl">Enter</span>. The token is saved to <code>localStorage</code> for next time.`
      : `<span class="hl">Failed to load (HTTP ${status}).</span> Check the bearer token and that the MCP server is reachable at <code>${location.origin}</code>.`;
    showBanner(msg);
  }
  function showEmptyTokenBanner() {
    showBanner(`<span class="hl">No bearer token set.</span> Paste your <code>MCP_API_KEY</code> into the <span class="hl">bearer token</span> field above and press <span class="hl">Enter</span>, or open this page as <code>${location.pathname}?token=YOUR_TOKEN</code>.`);
  }

  const authHeaders = () => {
    const t = tokenInput.value.trim();
    return t ? { "Authorization": "Bearer " + t } : {};
  };
  const withToken = (url) => {
    const t = tokenInput.value.trim();
    if (!t) return url;
    const sep = url.includes("?") ? "&" : "?";
    return url + sep + "token=" + encodeURIComponent(t);
  };

  let liveCount = 0;
  let paused = false;
  let es = null;

  function fmtTime(iso) { try { return new Date(iso).toLocaleTimeString(); } catch { return iso; } }
  function safe(s) { return (s == null ? "" : String(s)).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[c])); }

  async function loadStats() {
    if (!tokenInput.value.trim()) { showEmptyTokenBanner(); return; }
    try {
      const r = await fetch("/observability/stats", { headers: authHeaders() });
      if (!r.ok) { showAuthBanner(r.status); return; }
      hideBanner();
      const d = await r.json();
      $("kpi-total").textContent = d.total_events;
      $("kpi-errors").textContent = d.total_errors;
      $("kpi-errrate").textContent = (d.overall_error_rate*100).toFixed(2) + "% error rate";
      $("kpi-p95").textContent = d.overall_p95_ms.toFixed(0);
      $("cap").textContent = d.capacity;
      $("buf").textContent = d.total_events;

      // timeline
      const tl = $("timeline"); tl.innerHTML = "";
      const max = Math.max(1, ...d.timeline.map(x => x.count));
      d.timeline.forEach(x => {
        const bar = document.createElement("div");
        const isErr = x.errors > 0 && x.errors === x.count;
        bar.className = "bar" + (isErr ? " err" : "");
        const h = (x.count / max) * 100;
        bar.style.height = (h || 1) + "%";
        bar.title = `min=${x.minute} count=${x.count} errors=${x.errors}`;
        if (x.errors > 0 && !isErr) {
          // overlay with err portion
          const err = document.createElement("div");
          err.style.position = "absolute"; err.style.left = 0; err.style.right = 0; err.style.bottom = 0;
          err.style.background = "var(--err)";
          err.style.height = ((x.errors/x.count)*100) + "%";
          err.style.borderRadius = "2px 2px 0 0";
          bar.appendChild(err);
        }
        tl.appendChild(bar);
      });

      // by-key table
      const tb = $("t-byKey").querySelector("tbody"); tb.innerHTML = "";
      d.by_key.forEach(r => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><code>${safe(r.key)}</code></td>
          <td>${r.count}</td>
          <td class="status-success">${r.success}</td>
          <td class="status-error">${r.error}</td>
          <td>${(r.error_rate*100).toFixed(1)}%</td>
          <td>${r.p50_ms.toFixed(0)}</td>
          <td>${r.p95_ms.toFixed(0)}</td>
          <td>${r.avg_ms.toFixed(0)}</td>`;
        tb.appendChild(tr);
      });

      // clients
      const ct = $("t-clients").querySelector("tbody"); ct.innerHTML = "";
      d.top_clients.forEach(c => {
        const tr = document.createElement("tr");
        tr.innerHTML = `<td><code>${safe(c.client_ip)}</code></td><td>${c.count}</td>`;
        ct.appendChild(tr);
      });

      // errors
      const et = $("t-errors").querySelector("tbody"); et.innerHTML = "";
      d.recent_errors.forEach(e => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="small">${safe(fmtTime(e.iso))}</td>
          <td><code>${safe(e.method)}</code></td>
          <td>${safe(e.tool || "")}</td>
          <td>${safe(e.error_code || "")}</td>
          <td>${safe(e.error_message || "")}</td>
          <td class="small">${safe(e.client_ip || "")}</td>
          <td class="small">${safe(e.auth_subject || "")}</td>`;
        et.appendChild(tr);
      });
    } catch (e) {
      console.error("stats failed", e);
    }
  }

  function matchFilter(ev) {
    const m = $("f-method").value, t = $("f-tool").value.trim(), s = $("f-status").value;
    if (m && ev.method !== m) return false;
    if (t && (ev.tool || "").indexOf(t) < 0) return false;
    if (s && ev.status !== s) return false;
    return true;
  }

  function appendFeed(ev, prepend) {
    if (!matchFilter(ev)) return;
    const feed = $("feed");
    if (feed.firstElementChild && feed.firstElementChild.classList.contains("small")) feed.innerHTML = "";
    const row = document.createElement("div");
    row.className = "row";
    row.innerHTML = `
      <span class="ts">${safe(fmtTime(ev.iso))}</span>
      <span class="meth">${safe(ev.method)}</span>
      <span>${safe(ev.tool || "")} <span class="small">${safe(ev.params_summary && ev.params_summary.args_keys ? "args:["+ev.params_summary.args_keys.join(",")+"]" : "")}</span> <span class="small">${safe(ev.client_ip||"")}</span></span>
      <span class="ms">${(ev.duration_ms||0).toFixed(0)} ms</span>
      <span class="status-${ev.status}">${safe(ev.status)}</span>`;
    if (prepend) feed.insertBefore(row, feed.firstChild); else feed.appendChild(row);
    while (feed.children.length > 200) feed.removeChild(feed.lastChild);
  }

  function connectStream() {
    if (es) try { es.close(); } catch {}
    $("conn-dot").classList.remove("live");
    $("conn-label").textContent = "connecting…";
    es = new EventSource(withToken("/observability/stream"));
    es.onopen = () => { $("conn-dot").classList.add("live"); $("conn-label").textContent = "live"; };
    es.onerror = () => { $("conn-dot").classList.remove("live"); $("conn-label").textContent = "disconnected"; };
    es.onmessage = (m) => {
      if (paused) return;
      try {
        const ev = JSON.parse(m.data);
        liveCount++;
        $("kpi-live").textContent = liveCount;
        appendFeed(ev, true);
      } catch {}
    };
  }

  async function loadRecent() {
    if (!tokenInput.value.trim()) return;
    try {
      const params = new URLSearchParams({ limit: "100" });
      const m = $("f-method").value, t = $("f-tool").value.trim(), s = $("f-status").value;
      if (m) params.set("method", m);
      if (t) params.set("tool", t);
      if (s) params.set("status", s);
      const r = await fetch("/observability/recent?" + params.toString(), { headers: authHeaders() });
      if (!r.ok) { showAuthBanner(r.status); return; }
      const d = await r.json();
      $("feed").innerHTML = "";
      d.events.forEach(ev => appendFeed(ev, false));
    } catch (e) { console.error(e); }
  }

  $("refresh").onclick = () => { loadStats(); loadRecent(); };
  $("pause").onclick = (e) => {
    paused = !paused;
    e.target.textContent = paused ? "Resume feed" : "Pause feed";
  };
  ["f-method","f-tool","f-status"].forEach(id => $(id).addEventListener("change", () => { loadRecent(); }));
  $("token").addEventListener("change", () => { connectStream(); loadStats(); loadRecent(); });

  loadStats();
  loadRecent();
  connectStream();
  setInterval(loadStats, 5000);
})();
</script>
</body>
</html>
"""
