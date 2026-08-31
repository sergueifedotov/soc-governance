"""AgentGuard CLI entrypoint: `python -m agentguard`."""

from __future__ import annotations

import os

import uvicorn


def main() -> None:
    host = os.getenv("AGENTGUARD_HOST", "0.0.0.0")
    port = int(os.getenv("AGENTGUARD_PORT", "8088"))
    log_level = os.getenv("AGENTGUARD_LOG_LEVEL", "info").lower()
    uvicorn.run(
        "agentguard.app:create_app",
        host=host,
        port=port,
        log_level=log_level,
        factory=True,
        reload=os.getenv("AGENTGUARD_RELOAD") == "1",
    )


if __name__ == "__main__":
    main()
