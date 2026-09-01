#!/usr/bin/env python3
"""
Wazuh MCP Server - Complete MCP-Compliant Remote Server
Full compliance with Model Context Protocol 2025-11-25 specification
Production-ready with Streamable HTTP and legacy SSE transport, authentication, and monitoring
"""

import asyncio
import json
import logging
import os
import re as _re
import time
import uuid
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
from urllib.parse import urlparse

from fastapi import FastAPI, Header, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from wazuh_mcp_server import __version__
from wazuh_mcp_server.api.wazuh_client import WazuhClient
from wazuh_mcp_server.api.wazuh_indexer import IndexerNotConfiguredError
from wazuh_mcp_server.auth import create_access_token
from wazuh_mcp_server.config import WazuhConfig, get_config
from wazuh_mcp_server.mcp.auth import AuthenticationService
from wazuh_mcp_server.mcp.handlers import (
    handle_completion_complete,
    handle_initialized_notification,
    handle_initialize,
    handle_logging_set_level,
    handle_ping,
    handle_prompts_get,
    handle_prompts_list,
    handle_resources_list,
    handle_resources_read,
    handle_resources_templates_list,
    handle_tools_call,
    handle_tools_list,
    set_wazuh_client_tools,
)
from wazuh_mcp_server.mcp.models import MCPError, MCPRequest, MCPResponse
from wazuh_mcp_server.mcp.session import MCPSession, SessionManager
from wazuh_mcp_server.monitoring import ACTIVE_CONNECTIONS, setup_monitoring_middleware
from wazuh_mcp_server.mcp_traffic import (
    auth_subject_var as _obs_auth_subject_var,
    client_ip_var as _obs_client_ip_var,
    client_ua_var as _obs_client_ua_var,
    record_mcp_call as _obs_record_mcp_call,
    router as _obs_router,
    session_id_var as _obs_session_id_var,
)
from wazuh_mcp_server.resilience import GracefulShutdown
from wazuh_mcp_server.security import (
    RateLimiter,
    security_middleware,
    validate_input,
)
from wazuh_mcp_server.session_store import create_session_store

# MCP Protocol Version Support
# Latest: 2025-11-25, also supports backwards compatibility with older versions
MCP_PROTOCOL_VERSION = "2025-11-25"
SUPPORTED_PROTOCOL_VERSIONS = ["2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"]

# Production Constants
SESSION_TIMEOUT_MINUTES = 30
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_WINDOW_SECONDS = 60
CORS_MAX_AGE_SECONDS = 600
DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000

logger = logging.getLogger(__name__)

# OAuth manager (initialized on startup if needed)
_oauth_manager = None
_auth_service = AuthenticationService()


async def verify_authentication(authorization: Optional[str], config) -> Optional[Any]:
    """
    Verify authentication based on configured auth mode.

    Returns AuthToken if authenticated (None for authless mode).
    Raises HTTPException if authentication fails.
    Supports: authless (none), bearer token, and OAuth modes.
    """
    return await _auth_service.verify(authorization, config, oauth_manager=_oauth_manager)


# Initialize session manager with pluggable backend
# Will use Redis if REDIS_URL is set, otherwise in-memory
_session_store = create_session_store()
sessions = SessionManager(_session_store)

# Track last session cleanup time (run at most every 60 seconds, not every request)
_last_session_cleanup: float = 0.0


async def get_or_create_session(session_id: Optional[str], origin: Optional[str]) -> MCPSession:
    """Get existing session or create new one."""
    global _last_session_cleanup

    if session_id:
        existing_session = await sessions.get(session_id)
        if existing_session:
            existing_session.update_activity()
            await sessions.set(session_id, existing_session)
            return existing_session

    # Always generate server-side session IDs to prevent session fixation attacks.
    # Client-provided session IDs are only used to look up existing sessions above.
    new_session_id = str(uuid.uuid4())
    session = MCPSession(new_session_id, origin)
    await sessions.set(new_session_id, session)

    # Cleanup expired sessions periodically (at most every 60 seconds)
    now = time.time()
    if now - _last_session_cleanup > 60:
        _last_session_cleanup = now
        try:
            expired_count = await sessions.cleanup_expired()
            if expired_count > 0:
                logger.debug(f"Cleaned up {expired_count} expired sessions")
                # Sync _initialized_sessions with active sessions
                active = await sessions.get_all()
                stale_keys = [k for k in _initialized_sessions if k not in active]
                for k in stale_keys:
                    _initialized_sessions.pop(k, None)
        except Exception as e:
            logger.error(f"Session cleanup error: {e}")

    return session


# Lifespan context manager for startup/shutdown events (modern FastAPI pattern)
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifecycle with proper startup and shutdown handling."""
    global _oauth_manager

    # === STARTUP ===
    # Attach log sanitization filter to prevent credential leakage
    from wazuh_mcp_server.security import SanitizingLogFilter

    logging.getLogger().addFilter(SanitizingLogFilter())

    logger.info(f"Wazuh MCP Server v{__version__} starting up...")
    logger.info(f"📡 MCP Protocol: {MCP_PROTOCOL_VERSION}")
    logger.info(f"🔗 Wazuh Host: {get_config().WAZUH_HOST}")
    logger.info(f"🌐 CORS Origins: {get_config().ALLOWED_ORIGINS}")
    logger.info(f"🔐 Auth Mode: {get_config().AUTH_MODE}")

    # Log Indexer configuration status
    cfg = get_config()
    if cfg.WAZUH_INDEXER_HOST:
        logger.info(f"📊 Wazuh Indexer: {cfg.WAZUH_INDEXER_HOST}:{cfg.WAZUH_INDEXER_PORT}")
    else:
        logger.warning("⚠️  Wazuh Indexer not configured. Vulnerability tools require Wazuh 4.8.0+")
        logger.warning("   Set WAZUH_INDEXER_HOST, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASS to enable.")

    # Initialize OAuth if enabled
    if cfg.is_oauth:
        try:
            from wazuh_mcp_server.oauth import create_oauth_router, init_oauth_manager

            _oauth_manager = init_oauth_manager(cfg)
            oauth_router = create_oauth_router(_oauth_manager)
            app.include_router(oauth_router)
            logger.info("✅ OAuth 2.0 with DCR initialized")
            logger.info("   OAuth endpoints: /oauth/authorize, /oauth/token, /oauth/register")
            logger.info("   Discovery: /.well-known/oauth-authorization-server")
        except Exception as e:
            logger.error(f"❌ OAuth initialization failed: {e}")

    # Log auth mode status
    if cfg.is_authless:
        logger.warning("⚠️  Running in AUTHLESS mode - no authentication required!")
    elif cfg.is_bearer:
        logger.info("🔐 Bearer token authentication enabled")
        # Display auto-generated API key when MCP_API_KEY is missing or invalid
        from wazuh_mcp_server.auth import auth_manager

        default_key = auth_manager.get_default_api_key()
        if default_key:
            logger.info("=" * 60)
            logger.info("🔑 AUTO-GENERATED API KEY (save this for client auth):")
            logger.info(f"   {default_key}")
            logger.info("   MCP_API_KEY was missing or not wazuh_<43-char-base64>; this generated key is the one that works.")
            logger.info("   Set MCP_API_KEY in .env to a valid wazuh_ key to make this stable across restarts.")
            logger.info("=" * 60)

    # Start background session cleanup task (runs every 5 minutes regardless of traffic)
    async def _background_session_cleanup():
        while True:
            await asyncio.sleep(300)
            try:
                expired = await sessions.cleanup_expired()
                if expired > 0:
                    logger.debug(f"Background cleanup: removed {expired} expired sessions")
                    active = await sessions.get_all()
                    stale = [k for k in _initialized_sessions if k not in active]
                    for k in stale:
                        _initialized_sessions.pop(k, None)
            except Exception as e:
                logger.error(f"Background session cleanup error: {e}")

    _cleanup_task = asyncio.create_task(_background_session_cleanup())

    # Initialize Wazuh client (will be available after yield)
    logger.info("✅ Server startup complete with high availability features enabled")

    yield  # Server is running

    # === SHUTDOWN ===
    logger.info("🛑 Wazuh MCP Server initiating graceful shutdown...")

    # Cancel background session cleanup
    _cleanup_task.cancel()
    try:
        await _cleanup_task
    except asyncio.CancelledError:
        pass

    try:
        # Initiate graceful shutdown (waits for active connections)
        await shutdown_manager.initiate_shutdown()

        # Clear and cleanup auth manager
        from wazuh_mcp_server.auth import auth_manager

        auth_manager.cleanup_expired()
        auth_manager.tokens.clear()
        logger.info("Authentication tokens cleared")

        # Clear sessions with proper cleanup
        await sessions.clear()
        # Close session store backend (e.g., Redis connection)
        store_close = getattr(sessions._store, "close", None)
        if callable(store_close):
            close_result = store_close()
            if asyncio.iscoroutine(close_result):
                await close_result
        logger.info("Sessions cleared")

        # Close Wazuh client to release HTTP connections
        if wazuh_client and hasattr(wazuh_client, "close"):
            await wazuh_client.close()
            logger.info("Wazuh client closed")

        # Cleanup rate limiter
        if hasattr(rate_limiter, "cleanup"):
            rate_limiter.cleanup()

        # Close connection pools
        from wazuh_mcp_server.security import connection_pool_manager

        await connection_pool_manager.close_all()
        logger.info("Connection pools closed")

        # Force garbage collection
        import gc

        gc.collect()
        logger.info("Garbage collection completed")

    except Exception as e:
        logger.error(f"Error during shutdown: {e}")
    finally:
        logger.info("✅ Graceful shutdown completed")


# Initialize FastAPI app for MCP compliance
app = FastAPI(
    title="Wazuh MCP Server",
    description="MCP-compliant remote server for Wazuh SIEM integration. Supports Streamable HTTP, SSE, OAuth, and authless modes.",
    version=__version__,
    docs_url="/docs",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Get configuration
config = get_config()

# Create Wazuh configuration from server config
wazuh_config = WazuhConfig(
    wazuh_host=config.WAZUH_HOST,
    wazuh_user=config.WAZUH_USER,
    wazuh_pass=config.WAZUH_PASS,
    wazuh_port=config.WAZUH_PORT,
    verify_ssl=config.WAZUH_VERIFY_SSL,
    # Wazuh Indexer settings (required for vulnerability tools in Wazuh 4.8.0+)
    wazuh_indexer_host=config.WAZUH_INDEXER_HOST if config.WAZUH_INDEXER_HOST else None,
    wazuh_indexer_port=config.WAZUH_INDEXER_PORT,
    wazuh_indexer_user=config.WAZUH_INDEXER_USER if config.WAZUH_INDEXER_USER else None,
    wazuh_indexer_pass=config.WAZUH_INDEXER_PASS if config.WAZUH_INDEXER_PASS else None,
)

# Initialize Wazuh client
wazuh_client = WazuhClient(wazuh_config)

# Inject WazuhClient into handler modules
set_wazuh_client_tools(wazuh_client)
from wazuh_mcp_server.mcp.handlers import set_wazuh_client_resources
set_wazuh_client_resources(wazuh_client)


async def get_wazuh_client() -> WazuhClient:
    """Get the global Wazuh client instance.

    Used by monitoring health checks to access client state.
    """
    return wazuh_client


# Initialize rate limiter
rate_limiter = RateLimiter(max_requests=RATE_LIMIT_REQUESTS, window_seconds=RATE_LIMIT_WINDOW_SECONDS)

# Initialize graceful shutdown manager
shutdown_manager = GracefulShutdown()
logger.info("Graceful shutdown manager initialized")


# CORS middleware for remote access with security
def validate_cors_origins(origins_config: str) -> List[str]:
    """Validate and parse CORS origins configuration."""
    if not origins_config or origins_config.strip() == "*":
        # Only allow wildcard in development
        if os.getenv("ENVIRONMENT") == "development":
            return ["*"]
        else:
            # In production, default to common Claude origins
            return ["https://claude.ai", "https://claude.anthropic.com"]

    origins = []
    for origin in origins_config.split(","):
        origin = origin.strip()
        # Validate origin format
        if origin.startswith(("http://", "https://")) or origin == "*":
            # Parse and validate URL structure
            if origin != "*":
                try:
                    parsed = urlparse(origin)
                    if parsed.netloc:
                        origins.append(origin)
                except ValueError as e:
                    logger.debug(f"Skipping invalid origin '{origin}': {e}")
                    continue
            else:
                origins.append(origin)

    return origins if origins else ["https://claude.ai"]


def validate_origin_header(origin: Optional[str], allowed_origins_config: str) -> None:
    """
    Validate Origin header per MCP 2025-11-25 spec.

    Per spec: "Servers MUST validate the Origin header on all incoming connections
    to prevent DNS rebinding attacks. If the Origin header is present and invalid,
    servers MUST respond with HTTP 403 Forbidden."

    Note: If Origin header is NOT present, that's acceptable (no 403).
    Only reject if Origin IS present but invalid.

    Args:
        origin: The Origin header value (may be None)
        allowed_origins_config: Comma-separated list of allowed origins

    Raises:
        HTTPException: 403 if Origin is present but not in allowed list
    """
    # Per 2025-11-25 spec: only validate if Origin is present
    if not origin:
        return  # No Origin header = acceptable

    # Parse allowed origins
    allowed_origins_list = allowed_origins_config.split(",") if allowed_origins_config else []

    # Check if origin is allowed (exact match only for security)
    for allowed in allowed_origins_list:
        allowed = allowed.strip()
        if allowed == "*":
            return  # Wildcard allows everything
        if allowed == origin:
            return  # Exact match

    # Origin present but not in allowed list - per spec MUST return 403
    raise HTTPException(status_code=403, detail=f"Origin not allowed: {origin}")


# Register monitoring middleware for request tracking and correlation IDs
app.middleware("http")(setup_monitoring_middleware())

# Register security middleware for security headers and request validation
app.middleware("http")(security_middleware)

# Register MCP agent traffic observability router (/observability/*)
app.include_router(_obs_router)

allowed_origins = validate_cors_origins(config.ALLOWED_ORIGINS)

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],  # Added DELETE for session management
    allow_headers=[
        "Accept",
        "Accept-Language",
        "Content-Language",
        "Content-Type",
        "Authorization",
        "X-Requested-With",
        "MCP-Protocol-Version",  # MCP protocol version header
        "MCP-Session-Id",  # Session ID header
        "Last-Event-ID",  # SSE reconnection header
    ],  # Specific headers only, no wildcard
    expose_headers=["MCP-Session-Id", "MCP-Protocol-Version", "Content-Type"],
    max_age=CORS_MAX_AGE_SECONDS,
)

# MCP Protocol Error Codes
MCP_ERRORS = {
    "PARSE_ERROR": -32700,
    "INVALID_REQUEST": -32600,
    "METHOD_NOT_FOUND": -32601,
    "INVALID_PARAMS": -32602,
    "INTERNAL_ERROR": -32603,
    "TIMEOUT": -32001,
    "CANCELLED": -32002,
    "RESOURCE_NOT_FOUND": -32003,
}


# Import response helpers from mcp.responses
from wazuh_mcp_server.mcp.responses import (
    create_error_response,
    create_success_response,
    validate_protocol_version,
)


# Track initialized sessions (OrderedDict for O(1) eviction of oldest entries)
_initialized_sessions: OrderedDict[str, bool] = OrderedDict()

# Current log level for logging/setLevel
_current_log_level: str = "info"


# Batch request size limit to prevent resource exhaustion
MAX_BATCH_SIZE = 100

# Formatting helpers imported from mcp.formatting
from wazuh_mcp_server.mcp.formatting import (
    add_truncation_warning,
    compact_alerts_result,
    compact_vulns_result,
    sanitize_output_text,
)




# MCP Method Registry - Full MCP 2025-03-26 Compliance
MCP_METHODS = {
    # Lifecycle methods
    "initialize": handle_initialize,
    "ping": handle_ping,
    # Tools methods
    "tools/list": handle_tools_list,
    "tools/call": handle_tools_call,
    # Prompts methods
    "prompts/list": handle_prompts_list,
    "prompts/get": handle_prompts_get,
    # Resources methods
    "resources/list": handle_resources_list,
    "resources/read": handle_resources_read,
    "resources/templates/list": handle_resources_templates_list,
    # Logging methods
    "logging/setLevel": handle_logging_set_level,
    # Completion methods
    "completion/complete": handle_completion_complete,
}


# Notification handlers (don't return responses)
async def handle_cancelled_notification(params: Dict[str, Any], session: MCPSession) -> None:
    """Handle notifications/cancelled - acknowledge cancellation request."""
    request_id = params.get("requestId")
    reason = params.get("reason", "Unknown")
    logger.debug(f"Request {request_id} cancelled: {reason}")


MCP_NOTIFICATIONS = {
    "notifications/initialized": handle_initialized_notification,
    "notifications/cancelled": handle_cancelled_notification,
}


async def process_mcp_notification(method: str, params: Dict[str, Any], session: MCPSession) -> None:
    """
    Process MCP notification (no response expected).
    Per MCP spec, notifications MUST NOT receive responses.
    """
    if method in MCP_NOTIFICATIONS:
        handler = MCP_NOTIFICATIONS[method]
        try:
            await handler(params, session)
        except Exception as e:
            # Log but don't return error - notifications don't get responses
            logger.error(f"Error processing notification {method}: {e}")
    else:
        logger.debug(f"Received unknown notification: {method}")


async def process_mcp_request(request: MCPRequest, session: MCPSession) -> MCPResponse:
    """Process individual MCP request per JSON-RPC 2.0 specification."""
    _obs_session_id_var.set(getattr(session, "session_id", "") or "")
    _obs_start = time.time()
    _obs_status = "success"
    _obs_err_code: Optional[int] = None
    _obs_err_msg: Optional[str] = None
    _obs_result_for_size: Any = None
    try:
        # Check if method exists
        if request.method not in MCP_METHODS:
            # Check if it's a notification method being called as request
            if request.method in MCP_NOTIFICATIONS:
                resp = create_error_response(
                    request.id,
                    MCP_ERRORS["INVALID_REQUEST"],
                    f"'{request.method}' is a notification, not a request method",
                )
                _obs_status = "error"
                _obs_err_code = MCP_ERRORS["INVALID_REQUEST"]
                _obs_err_msg = f"'{request.method}' is a notification, not a request method"
                return resp
            resp = create_error_response(
                request.id, MCP_ERRORS["METHOD_NOT_FOUND"], f"Method '{request.method}' not found"
            )
            _obs_status = "error"
            _obs_err_code = MCP_ERRORS["METHOD_NOT_FOUND"]
            _obs_err_msg = f"Method '{request.method}' not found"
            return resp

        # Execute method handler
        handler = MCP_METHODS[request.method]
        result = await handler(request.params or {}, session)
        _obs_result_for_size = result

        return create_success_response(request.id, result)

    except ValueError as e:
        _obs_status = "error"
        _obs_err_code = MCP_ERRORS["INVALID_PARAMS"]
        _obs_err_msg = str(e)
        return create_error_response(request.id, MCP_ERRORS["INVALID_PARAMS"], str(e))
    except Exception as e:
        from wazuh_mcp_server.monitoring import structured_logger

        structured_logger.error(
            f"Internal error processing {request.method}",
            exc_info=True,
            method=request.method,
            request_id=str(request.id) if request.id else None,
            error_type=type(e).__name__,
            error_message=str(e),
        )
        _obs_status = "error"
        _obs_err_code = MCP_ERRORS["INTERNAL_ERROR"]
        _obs_err_msg = f"{type(e).__name__}: {e}"
        return create_error_response(request.id, MCP_ERRORS["INTERNAL_ERROR"], "Internal server error")
    finally:
        try:
            await _obs_record_mcp_call(
                method=request.method,
                params=request.params,
                request_id=request.id,
                status=_obs_status,
                duration_ms=(time.time() - _obs_start) * 1000.0,
                error_code=_obs_err_code,
                error_message=_obs_err_msg,
                result=_obs_result_for_size,
            )
        except Exception:
            # Observability MUST NOT break request handling
            logger.debug("mcp_traffic record failed", exc_info=True)


async def generate_sse_events(session: MCPSession, event_id_counter: int = 0, track_connection: bool = False):
    """
    Generate Server-Sent Events for MCP Streamable HTTP transport.

    Per MCP 2025-11-25 spec:
    - SSE events MUST include an 'id' field for resumability
    - Server SHOULD immediately send a priming event with event ID and empty data
    - Server SHOULD send retry field to indicate reconnection delay

    Args:
        session: The MCP session
        event_id_counter: Starting event ID
        track_connection: If True, decrement ACTIVE_CONNECTIONS when stream ends
    """
    event_id = event_id_counter

    try:
        # Per 2025-11-25 spec: "The server SHOULD immediately send an SSE event
        # consisting of an event ID and an empty data field in order to prime
        # the client to reconnect (using that event ID as Last-Event-ID)"
        event_id += 1
        yield f"id: {event_id}\nretry: 3000\ndata: \n\n"

        # Keep the SSE stream alive with comments only. Some MCP clients reject
        # non-standard JSON-RPC notifications on the event stream.
        while True:
            yield ": keepalive\n\n"
            await asyncio.sleep(30)
    except (asyncio.CancelledError, GeneratorExit):
        logger.debug(f"SSE connection closed for session {session.session_id}")
    finally:
        if track_connection:
            ACTIVE_CONNECTIONS.dec()


def is_json_rpc_notification(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a notification (no 'id' field)."""
    return "method" in message and "id" not in message


def is_json_rpc_response(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a response (has 'result' or 'error', no 'method')."""
    return ("result" in message or "error" in message) and "method" not in message


def is_json_rpc_request(message: Dict[str, Any]) -> bool:
    """Check if a JSON-RPC message is a request (has 'method' and 'id')."""
    return "method" in message and "id" in message


@app.get("/")
@app.post("/")
async def mcp_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    accept: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Main MCP protocol endpoint supporting both GET and POST.
    GET: Returns SSE stream for real-time communication
    POST: Handles JSON-RPC requests
    """
    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Track active connections (request counting handled by monitoring middleware)
    ACTIVE_CONNECTIONS.inc()
    _sse_returned = False  # Track if SSE stream was returned (generator handles decrement)

    try:
        # Origin validation per MCP 2025-11-25 spec
        validate_origin_header(origin, config.ALLOWED_ORIGINS)

        # Rate limiting
        client_ip = request.client.host if request.client else "unknown"
        allowed, retry_after = rate_limiter.is_allowed(client_ip)
        if not allowed:
            headers = {"Retry-After": str(retry_after)} if retry_after else {}
            raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

        # Session validation per MCP Streamable HTTP spec
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            if existing_session.is_expired():
                await sessions.remove(mcp_session_id)
                _initialized_sessions.pop(mcp_session_id, None)
                raise HTTPException(
                    status_code=404, detail="Session expired. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            session = await get_or_create_session(None, origin)

        session._auth_token = auth_token  # Store token for scope checks in tool handlers

        # Handle GET request (SSE)
        if request.method == "GET":
            if accept and "text/event-stream" in accept:
                # track_connection=True: decrement happens when stream closes
                _sse_returned = True
                response = StreamingResponse(
                    generate_sse_events(session, track_connection=True),
                    media_type="text/event-stream",
                    headers={
                        "Cache-Control": "no-cache",
                        "Connection": "keep-alive",
                        "MCP-Session-Id": session.session_id,
                        "Access-Control-Expose-Headers": "MCP-Session-Id",
                    },
                )
                return response
            else:
                # Return JSON response for non-SSE clients
                return JSONResponse(
                    content={
                        "jsonrpc": "2.0",
                        "id": None,
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "serverInfo": {"name": "Wazuh MCP Server", "version": __version__},
                            "session": session.to_dict(),
                        },
                    },
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                )

            # Handle batch requests
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                    )
                if len(body) > MAX_BATCH_SIZE:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], f"Batch too large (max {MAX_BATCH_SIZE})"
                        ).dict(),
                        status_code=400,
                    )

                # Per MCP Streamable HTTP spec: If the input consists solely of
                # notifications or responses, return HTTP 202 Accepted with no body
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed batch of {len(body)} notifications/responses")
                    return Response(
                        status_code=202,
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )

                # Process batch containing requests
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        if not isinstance(item, dict):
                            raise ValidationError.from_exception_data(
                                "MCPRequest", line_errors=[], input_type="python"
                            )
                        mcp_request = MCPRequest(**item)
                        response = await process_mcp_request(mcp_request, session)
                        responses.append(response.dict())
                    except (ValidationError, TypeError) as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(
                    content=responses,
                    headers={"MCP-Session-Id": session.session_id, "Access-Control-Expose-Headers": "MCP-Session-Id"},
                )

            # Handle single message
            else:
                # Per MCP spec: notifications and responses return HTTP 202 Accepted
                if isinstance(body, dict):
                    if is_json_rpc_notification(body):
                        # Process the notification (no response)
                        method = body.get("method", "")
                        params = body.get("params", {})
                        await process_mcp_notification(method, params, session)
                        logger.debug(f"Processed notification: {method}")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )
                    elif is_json_rpc_response(body):
                        # Client sending a response - just acknowledge
                        logger.debug("Received client response")
                        return Response(
                            status_code=202,
                            headers={
                                "MCP-Session-Id": session.session_id,
                                "Access-Control-Expose-Headers": "MCP-Session-Id",
                            },
                        )

                # Handle request
                try:
                    mcp_request = MCPRequest(**body)
                    response = await process_mcp_request(mcp_request, session)
                    return JSONResponse(
                        content=response.dict(),
                        headers={
                            "MCP-Session-Id": session.session_id,
                            "Access-Control-Expose-Headers": "MCP-Session-Id",
                        },
                    )
                except ValidationError as e:
                    return JSONResponse(
                        content=create_error_response(
                            body.get("id") if isinstance(body, dict) else None,
                            MCP_ERRORS["INVALID_REQUEST"],
                            f"Invalid request format: {e}",
                        ).dict(),
                        status_code=400,
                    )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    finally:
        # Only decrement for non-SSE responses; SSE generator handles its own decrement
        if not _sse_returned:
            ACTIVE_CONNECTIONS.dec()


# Official MCP Remote Server SSE endpoint - as per Anthropic standards
@app.get("/sse")
async def mcp_sse_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Official MCP SSE endpoint following Anthropic standards.
    URL format: https://<server_address>/sse
    This is the standard endpoint that Claude Desktop connects to.

    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Origin validation per MCP 2025-11-25 spec
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Session validation: if client provides session ID but session doesn't exist, return 404
    # Done BEFORE incrementing ACTIVE_CONNECTIONS to avoid counter leak on early errors.
    if mcp_session_id:
        existing_session = await sessions.get(mcp_session_id)
        if not existing_session:
            raise HTTPException(status_code=404, detail="Session not found")
        session = existing_session
        session.update_activity()
        await sessions.set(mcp_session_id, session)
    else:
        session = await get_or_create_session(None, origin)
    session.authenticated = True  # Mark as authenticated via bearer token
    session._auth_token = auth_token  # Store token for scope checks in tool handlers

    # Track active connections — only after validation passes.
    # The SSE generator will decrement when the stream closes (track_connection=True).
    ACTIVE_CONNECTIONS.inc()

    try:
        response = StreamingResponse(
            generate_sse_events(session, track_connection=True),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "MCP-Session-Id": session.session_id,
                "Access-Control-Expose-Headers": "MCP-Session-Id",
            },
        )
        return response

    except Exception as e:
        ACTIVE_CONNECTIONS.dec()
        logger.error(f"SSE endpoint error: {e}")
        raise HTTPException(status_code=500, detail="SSE stream error")


# Standard MCP Endpoint - Streamable HTTP Transport (2025-11-25 Specification)
@app.post("/mcp")
@app.get("/mcp")
async def mcp_streamable_http_endpoint(
    request: Request,
    authorization: str = Header(None),
    origin: Optional[str] = Header(None),
    mcp_protocol_version: Optional[str] = Header(None, alias="MCP-Protocol-Version"),
    mcp_session_id: Optional[str] = Header(None, alias="MCP-Session-Id"),
    accept: Optional[str] = Header("application/json"),
    last_event_id: Optional[str] = Header(None, alias="Last-Event-ID"),
):
    """
    Standard MCP endpoint using Streamable HTTP transport (2025-11-25 spec).

    Supports:
    - POST: JSON-RPC requests (single message per 2025-11-25 spec)
    - GET: SSE stream initiation (requires Accept: text/event-stream)
    - DELETE: Session termination (see separate endpoint)

    This is the RECOMMENDED endpoint for MCP clients. Legacy /sse remains for backwards compatibility.
    Supports authentication modes: bearer (default), oauth, none (authless)
    """
    # Validate protocol version per 2025-11-25 spec (strict mode returns 400 for invalid)
    protocol_version = validate_protocol_version(mcp_protocol_version, strict=True)

    # Verify authentication based on configured mode
    auth_token = await verify_authentication(authorization, config)

    # Origin validation per 2025-11-25 spec
    # Only validate if Origin is present; if present and invalid, return 403
    validate_origin_header(origin, config.ALLOWED_ORIGINS)

    # Rate limiting
    client_ip = request.client.host if request.client else "unknown"
    allowed, retry_after = rate_limiter.is_allowed(client_ip)
    if not allowed:
        headers = {"Retry-After": str(retry_after)} if retry_after else {}
        raise HTTPException(status_code=429, detail="Rate limit exceeded", headers=headers)

    # Populate observability context vars (consumed by mcp_traffic.record_mcp_call)
    _obs_client_ip_var.set(client_ip)
    _obs_client_ua_var.set(request.headers.get("user-agent", ""))
    _obs_auth_subject_var.set(
        getattr(auth_token, "subject", None)
        or getattr(auth_token, "client_id", None)
        or ("authless" if auth_token is None else "")
    )

    # Track active connections (metrics tracked after processing)
    ACTIVE_CONNECTIONS.inc()
    _sse_returned = False  # Track if SSE stream was returned (generator handles decrement)
    _status_code = 200  # Track actual status code for metrics

    try:
        # Session validation per MCP Streamable HTTP spec:
        # If client provides session ID but session doesn't exist, return 404
        if mcp_session_id:
            existing_session = await sessions.get(mcp_session_id)
            if not existing_session:
                raise HTTPException(
                    status_code=404, detail="Session not found. Please start a new session with InitializeRequest."
                )
            if existing_session.is_expired():
                await sessions.remove(mcp_session_id)
                _initialized_sessions.pop(mcp_session_id, None)
                raise HTTPException(
                    status_code=404, detail="Session expired. Please start a new session with InitializeRequest."
                )
            session = existing_session
            session.update_activity()
            await sessions.set(mcp_session_id, session)
        else:
            # Create new session only if no session ID provided
            session = await get_or_create_session(None, origin)

        session.authenticated = True  # Mark as authenticated
        session._auth_token = auth_token  # Store token for scope checks in tool handlers

        # Common response headers
        response_headers = {
            "MCP-Session-Id": session.session_id,
            "MCP-Protocol-Version": protocol_version,
            "Access-Control-Expose-Headers": "MCP-Session-Id, MCP-Protocol-Version",
        }

        # Handle GET request per MCP Streamable HTTP spec
        if request.method == "GET":
            # Per spec: server MUST return text/event-stream OR HTTP 405
            if accept and "text/event-stream" in accept:
                # track_connection=True: decrement happens when stream closes
                _sse_returned = True
                response = StreamingResponse(
                    generate_sse_events(session, track_connection=True),
                    media_type="text/event-stream",
                    headers={**response_headers, "Cache-Control": "no-cache", "Connection": "keep-alive"},
                )
                return response
            else:
                # Per MCP spec: GET without Accept: text/event-stream MUST return 405
                raise HTTPException(
                    status_code=405, detail="GET requires Accept: text/event-stream header for SSE stream"
                )

        # Handle POST request (JSON-RPC)
        elif request.method == "POST":
            try:
                body = await request.json()
            except json.JSONDecodeError:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["PARSE_ERROR"], "Invalid JSON").dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Handle batch messages per MCP Streamable HTTP spec
            if isinstance(body, list):
                if not body:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], "Empty batch request"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )
                if len(body) > MAX_BATCH_SIZE:
                    return JSONResponse(
                        content=create_error_response(
                            None, MCP_ERRORS["INVALID_REQUEST"], f"Batch too large (max {MAX_BATCH_SIZE})"
                        ).dict(),
                        status_code=400,
                        headers=response_headers,
                    )

                # Check if batch contains any requests
                has_requests = any(is_json_rpc_request(item) if isinstance(item, dict) else False for item in body)

                if not has_requests:
                    # Process all notifications before returning 202
                    for item in body:
                        if isinstance(item, dict) and is_json_rpc_notification(item):
                            method = item.get("method", "")
                            params = item.get("params", {})
                            await process_mcp_notification(method, params, session)
                    return Response(status_code=202, headers=response_headers)

                # Process requests in batch
                responses = []
                for item in body:
                    # Process notifications but don't add to responses
                    if isinstance(item, dict) and is_json_rpc_notification(item):
                        method = item.get("method", "")
                        params = item.get("params", {})
                        await process_mcp_notification(method, params, session)
                        continue
                    # Skip responses
                    if isinstance(item, dict) and is_json_rpc_response(item):
                        continue
                    try:
                        if not isinstance(item, dict):
                            raise TypeError(f"Expected dict, got {type(item).__name__}")
                        mcp_request = MCPRequest(**item)
                        resp = await process_mcp_request(mcp_request, session)
                        responses.append(resp.dict())
                    except (ValidationError, TypeError) as e:
                        responses.append(
                            create_error_response(
                                item.get("id") if isinstance(item, dict) else None,
                                MCP_ERRORS["INVALID_REQUEST"],
                                f"Invalid request format: {e}",
                            ).dict()
                        )

                return JSONResponse(content=responses, headers=response_headers)

            # Handle single message
            if isinstance(body, dict):
                # Notifications and responses return 202 Accepted
                if is_json_rpc_notification(body):
                    # Process the notification (no response)
                    method = body.get("method", "")
                    params = body.get("params", {})
                    await process_mcp_notification(method, params, session)
                    logger.debug(f"Processed notification: {method}")
                    return Response(status_code=202, headers=response_headers)
                elif is_json_rpc_response(body):
                    # Client sending a response - just acknowledge
                    return Response(status_code=202, headers=response_headers)

            # Validate JSON-RPC request
            try:
                mcp_request = MCPRequest(**body) if isinstance(body, dict) else None
            except ValidationError as e:
                return JSONResponse(
                    content=create_error_response(
                        None, MCP_ERRORS["INVALID_REQUEST"], f"Invalid MCP request: {str(e)}"
                    ).dict(),
                    status_code=400,
                    headers=response_headers,
                )

            # Process the request
            if mcp_request:
                mcp_response = await process_mcp_request(mcp_request, session)

                # Check if client accepts SSE for streaming response
                # (For long-running operations, we could upgrade to SSE here)
                if accept and "text/event-stream" in accept:
                    # Optional: Stream the response via SSE for long operations
                    # For now, return JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
                else:
                    # Standard JSON response
                    return JSONResponse(content=mcp_response.dict(), headers=response_headers)
            else:
                return JSONResponse(
                    content=create_error_response(None, MCP_ERRORS["INVALID_REQUEST"], "Invalid request format").dict(),
                    status_code=400,
                    headers=response_headers,
                )

        else:
            raise HTTPException(status_code=405, detail="Method not allowed")

    except HTTPException as exc:
        _status_code = exc.status_code
        raise
    except Exception as e:
        _status_code = 500
        logger.error(f"MCP endpoint error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

    finally:
        # REQUEST_COUNT is already tracked by the monitoring middleware — no need to duplicate here.
        # Only decrement for non-SSE responses; SSE generator handles its own decrement.
        if not _sse_returned:
            ACTIVE_CONNECTIONS.dec()


@app.delete("/mcp")
async def close_mcp_session(
    mcp_session_id: str = Header(..., alias="MCP-Session-Id"), authorization: str = Header(None)
):
    """
    Close MCP session explicitly (2025-11-25 spec).
    Allows clients to cleanly terminate sessions.
    """
    # Use the same auth logic as other endpoints (respects authless mode)
    await verify_authentication(authorization, config)

    # Remove session
    existing = await sessions.get(mcp_session_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Session not found")
    await sessions.remove(mcp_session_id)
    _initialized_sessions.pop(mcp_session_id, None)
    logger.info(f"Session {mcp_session_id} closed via DELETE")
    return Response(status_code=204)  # No content


@app.get("/health")
async def health_check():
    """Health check endpoint with detailed status."""
    try:
        # Test Wazuh connectivity
        wazuh_status = "healthy"
        try:
            await wazuh_client.get_manager_info()
        except Exception:
            wazuh_status = "unhealthy"

        # Test Wazuh Indexer connectivity (if configured)
        indexer_status = "not_configured"
        if wazuh_client._indexer_client:
            try:
                health = await wazuh_client._indexer_client.health_check()
                if health.get("status") in ("green", "yellow"):
                    indexer_status = "healthy"
                elif health.get("status") == "red":
                    indexer_status = "degraded"
                else:
                    indexer_status = "unknown"
            except Exception:
                indexer_status = "unhealthy"

        # Check session count
        all_sessions = await sessions.get_all()
        active_sessions = len([s for s in all_sessions.values() if not s.is_expired()])

        # Build auth info
        auth_info = {
            "mode": config.AUTH_MODE,
            "bearer_enabled": config.is_bearer,
            "oauth_enabled": config.is_oauth,
            "authless": config.is_authless,
        }
        if config.is_oauth:
            auth_info["oauth_dcr"] = config.OAUTH_ENABLE_DCR
            auth_info["oauth_endpoints"] = ["/oauth/authorize", "/oauth/token", "/oauth/register"]
            auth_info["oauth_discovery"] = "/.well-known/oauth-authorization-server"

        # Determine overall status from component health
        if wazuh_status != "healthy":
            overall_status = "degraded"
        elif isinstance(indexer_status, str) and indexer_status.startswith("unhealthy"):
            overall_status = "degraded"
        else:
            overall_status = "healthy"

        status_code = 200 if overall_status == "healthy" else 503
        return JSONResponse(
            content={
                "status": overall_status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "version": __version__,
                "mcp_protocol_version": MCP_PROTOCOL_VERSION,
                "supported_protocol_versions": SUPPORTED_PROTOCOL_VERSIONS,
                "transport": {
                    "streamable_http": "enabled",
                    "legacy_sse": "enabled",
                },
                "authentication": auth_info,
                "services": {"wazuh_manager": wazuh_status, "wazuh_indexer": indexer_status, "mcp": "healthy"},
                "vulnerability_tools": {
                    "available": wazuh_client._indexer_client is not None,
                    "note": (
                        "Vulnerability tools require Wazuh Indexer (4.8.0+). Set WAZUH_INDEXER_HOST to enable."
                        if not wazuh_client._indexer_client
                        else "Wazuh Indexer configured"
                    ),
                },
                "metrics": {"active_sessions": active_sessions, "total_sessions": len(all_sessions)},
                "endpoints": {
                    "recommended": "/mcp (Streamable HTTP - 2025-11-25)",
                    "legacy": "/sse (SSE only)",
                    "authentication": (
                        "/auth/token" if config.is_bearer else ("/oauth/token" if config.is_oauth else None)
                    ),
                    "monitoring": ["/health", "/metrics"],
                },
            },
            status_code=status_code,
        )
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            content={"status": "unhealthy", "timestamp": datetime.now(timezone.utc).isoformat()},
            status_code=503,
        )


@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

    from wazuh_mcp_server.monitoring import REGISTRY

    return Response(content=generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


# OAuth 2.0 Discovery Endpoint (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Required for Claude Desktop OAuth integration.
    """
    global _oauth_manager
    if not config.is_oauth or not _oauth_manager:
        raise HTTPException(status_code=404, detail="OAuth not enabled. Set AUTH_MODE=oauth to enable.")

    return JSONResponse(_oauth_manager.get_metadata(request))


# Authentication endpoint for API key validation
@app.post("/auth/token")
async def get_auth_token(request: Request):
    """Get JWT token using API key.

    Accepts API key in request body as JSON: {"api_key": "wazuh_..."}
    Validates against configured API keys (MCP_API_KEY env var or auto-generated).
    """
    try:
        body = await request.json()
        api_key = body.get("api_key")

        if not api_key:
            raise HTTPException(status_code=400, detail="API key required")

        # Validate API key format
        if not isinstance(api_key, str) or not api_key.startswith("wazuh_"):
            raise HTTPException(status_code=401, detail="Invalid API key format")

        # Validate against auth_manager (handles MCP_API_KEY env var and auto-generated keys)
        from wazuh_mcp_server.auth import auth_manager

        if not auth_manager.validate_api_key(api_key):
            raise HTTPException(status_code=401, detail="Invalid API key")

        # Create JWT token with safe payload (no API key exposure)
        token = create_access_token(
            data={
                "sub": "wazuh_mcp_user",
                "iat": datetime.now(timezone.utc).timestamp(),
                "scope": "wazuh:read wazuh:write",
            },
            secret_key=config.AUTH_SECRET_KEY,
        )

        return {"access_token": token, "token_type": "bearer", "expires_in": 86400}  # 24 hours

    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        logger.error(f"Token generation error: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


if __name__ == "__main__":
    import uvicorn

    config = get_config()

    uvicorn.run(app, host=config.MCP_HOST, port=config.MCP_PORT, log_level=config.LOG_LEVEL.lower(), access_log=True)
