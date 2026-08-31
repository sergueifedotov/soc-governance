"""Session primitives and storage-backed manager for MCP transport."""

import asyncio
import logging
import threading
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from wazuh_mcp_server.session_store import SessionStore

logger = logging.getLogger(__name__)


class MCPSession:
    """MCP Session Management for Remote MCP Server."""

    def __init__(self, session_id: str, origin: Optional[str] = None):
        self.session_id = session_id
        self.origin = origin
        self.created_at = datetime.now(timezone.utc)
        self.last_activity = self.created_at
        self.capabilities = {}
        self.client_info = {}
        self.authenticated = False
        # Populated after auth checks for downstream scope validation in tool handlers.
        self._auth_token: Any = None

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = datetime.now(timezone.utc)

    def is_expired(self, timeout_minutes: int = 30) -> bool:
        """Check if session is expired."""
        timeout = timedelta(minutes=timeout_minutes)
        return datetime.now(timezone.utc) - self.last_activity > timeout

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to dictionary."""
        return {
            "session_id": self.session_id,
            "origin": self.origin,
            "created_at": self.created_at.isoformat(),
            "last_activity": self.last_activity.isoformat(),
            "capabilities": self.capabilities,
            "client_info": self.client_info,
            "authenticated": self.authenticated,
        }


class SessionManager:
    """
    Session manager with pluggable storage backend.
    Supports both in-memory (default) and Redis (serverless-ready) backends.
    """

    def __init__(self, store: SessionStore):
        self._store = store
        self._lock = threading.RLock()  # For synchronous operations
        logger.info(f"SessionManager initialized with {type(store).__name__}")

    def _session_from_dict(self, data: Dict[str, Any]) -> MCPSession:
        """Reconstruct MCPSession from dictionary."""
        session = MCPSession(data["session_id"], data.get("origin"))
        session.created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        session.last_activity = datetime.fromisoformat(data["last_activity"].replace("Z", "+00:00"))
        session.capabilities = data.get("capabilities", {})
        session.client_info = data.get("client_info", {})
        session.authenticated = data.get("authenticated", False)
        return session

    async def get(self, session_id: str) -> Optional[MCPSession]:
        """Get session by ID."""
        data = await self._store.get(session_id)
        if data:
            return self._session_from_dict(data)
        return None

    async def set(self, session_id: str, session: MCPSession) -> bool:
        """Store session."""
        return await self._store.set(session_id, session.to_dict())

    def _run_sync(self, coro):
        """Run coroutine synchronously, handling existing event loop safely."""
        try:
            asyncio.get_running_loop()
            # If we get here, there's a running loop - this is not safe
            raise RuntimeError(
                "Synchronous SessionManager methods cannot be called from async context. "
                "Use async methods like 'await sessions.get()' instead."
            )
        except RuntimeError as e:
            # Re-raise if this is our own "cannot be called from async" error
            if "Synchronous SessionManager" in str(e):
                raise
            # No running loop - safe to create one
            loop = asyncio.new_event_loop()
            try:
                return loop.run_until_complete(coro)
            finally:
                loop.close()

    def __getitem__(self, session_id: str) -> MCPSession:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        session = self._run_sync(self.get(session_id))
        if session is None:
            raise KeyError(f"Session {session_id} not found")
        return session

    def __setitem__(self, session_id: str, session: MCPSession) -> None:
        """Synchronous dict-like access (blocks). Not for use in async context."""
        self._run_sync(self.set(session_id, session))

    def __delitem__(self, session_id: str) -> None:
        """Synchronous delete (blocks). Not for use in async context."""
        self._run_sync(self.remove(session_id))

    def __contains__(self, session_id: str) -> bool:
        """Check if session exists (synchronous for use with 'in' operator)."""
        return self._run_sync(self._store.exists(session_id))

    async def remove(self, session_id: str) -> bool:
        """Remove session by ID."""
        return await self._store.delete(session_id)

    def pop(self, session_id: str, default=None) -> Optional[MCPSession]:
        """Remove and return session (synchronous, blocks). Not for use in async context."""

        async def _pop():
            session = await self.get(session_id)
            if session:
                await self.remove(session_id)
                return session
            return default

        return self._run_sync(_pop())

    async def clear(self) -> bool:
        """Clear all sessions."""
        return await self._store.clear()

    def values(self) -> List[MCPSession]:
        """Get all session values (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.values())

    def keys(self) -> List[str]:
        """Get all session keys (synchronous, blocks). Not for use in async context."""
        sessions_dict = self._run_sync(self.get_all())
        return list(sessions_dict.keys())

    async def get_all(self) -> Dict[str, MCPSession]:
        """Get all sessions as dictionary."""
        data_dict = await self._store.get_all()
        return {sid: self._session_from_dict(data) for sid, data in data_dict.items()}

    async def cleanup_expired(self, timeout_minutes: int = 30) -> int:
        """Remove expired sessions and return count."""
        return await self._store.cleanup_expired(timeout_minutes=timeout_minutes)
