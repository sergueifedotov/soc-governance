"""Wazuh API integration."""

try:
    from .wazuh_client import WazuhClient
except ImportError:
    WazuhClient = None  # type: ignore[assignment]  # not available in phase4-api container

try:
    from .wazuh_indexer import IndexerNotConfiguredError, WazuhIndexerClient
except ImportError:
    IndexerNotConfiguredError = None  # type: ignore[assignment]
    WazuhIndexerClient = None  # type: ignore[assignment]

__all__ = ["WazuhClient", "WazuhIndexerClient", "IndexerNotConfiguredError"]
