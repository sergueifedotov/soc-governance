"""Authentication service for MCP request handlers."""

import os
from datetime import datetime, timezone
from typing import Any, Optional

from fastapi import HTTPException


class AuthenticationService:
    """Validates request authentication across authless, bearer, and OAuth modes."""

    async def verify(
        self,
        authorization: Optional[str],
        config: Any,
        oauth_manager: Optional[Any] = None,
    ) -> Optional[Any]:
        """
        Verify authentication based on configured auth mode.

        Returns AuthToken if authenticated (None for authless mode).
        Raises HTTPException if authentication fails.
        """
        from wazuh_mcp_server.auth import AuthToken

        # Authless mode - no authentication required
        if config.is_authless:
            # Return a synthetic token with scopes based on AUTHLESS_ALLOW_WRITE
            allow_write = os.getenv("AUTHLESS_ALLOW_WRITE", "false").lower() in ("true", "1", "yes")
            scopes = ["wazuh:read", "wazuh:write"] if allow_write else ["wazuh:read"]
            return AuthToken(
                token="authless",
                api_key_id="authless",
                created_at=datetime.now(timezone.utc),
                scopes=scopes,
            )

        # Authentication required
        if not authorization:
            raise HTTPException(
                status_code=401,
                detail="Authorization header required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # OAuth mode
        if config.is_oauth:
            if oauth_manager:
                token = authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else authorization
                token_obj = oauth_manager.validate_access_token(token)
                if token_obj:
                    scope_str = getattr(token_obj, "scope", "wazuh:read wazuh:write")
                    scopes = scope_str.split() if scope_str else ["wazuh:read", "wazuh:write"]
                    return AuthToken(
                        token=token,
                        api_key_id="oauth",
                        created_at=datetime.now(timezone.utc),
                        scopes=scopes,
                    )
            raise HTTPException(
                status_code=401,
                detail="Invalid or expired OAuth token",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Bearer token mode (default)
        try:
            from wazuh_mcp_server.auth import verify_bearer_token

            return await verify_bearer_token(authorization)
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e), headers={"WWW-Authenticate": "Bearer"})
