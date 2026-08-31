"""JSON-RPC models used by MCP HTTP handlers."""

from typing import Any, Dict, Optional, Union

from pydantic import BaseModel, Field


class MCPRequest(BaseModel):
    """MCP JSON-RPC 2.0 Request."""

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    method: str = Field(description="Method name")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Method parameters")


class MCPResponse(BaseModel):
    """
    MCP JSON-RPC 2.0 Response.

    Compliant with JSON-RPC 2.0 specification:
    - On success: includes 'result', excludes 'error'
    - On error: includes 'error', excludes 'result'
    """

    jsonrpc: str = Field(default="2.0", description="JSON-RPC version")
    id: Optional[Union[str, int]] = Field(default=None, description="Request ID")
    result: Optional[Any] = Field(default=None, description="Result data")
    error: Optional[Dict[str, Any]] = Field(default=None, description="Error object")

    def model_dump(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Override model_dump() to comply with JSON-RPC 2.0 specification.

        Per JSON-RPC 2.0 spec:
        - "result" and "error" MUST NOT both exist in the same response
        - On success: include 'result', exclude 'error'
        - On error: include 'error', exclude 'result'
        """
        d = super().model_dump(*args, **kwargs)

        # Determine which field was explicitly set.
        # error takes precedence: if error is set, this is an error response.
        if d.get("error") is not None:
            d.pop("result", None)
        else:
            # Success response: result may be any JSON value including None, 0, "", [].
            # Remove the error field since it's not an error response.
            d.pop("error", None)

        return d

    def dict(self, *args, **kwargs) -> Dict[str, Any]:
        """Backwards-compatible wrapper for model_dump()."""
        return self.model_dump(*args, **kwargs)


class MCPError(BaseModel):
    """MCP JSON-RPC 2.0 Error object."""

    code: int = Field(description="Error code")
    message: str = Field(description="Error message")
    data: Optional[Any] = Field(default=None, description="Additional error data")
