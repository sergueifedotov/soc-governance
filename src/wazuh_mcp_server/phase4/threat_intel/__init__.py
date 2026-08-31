"""Layer 6: Threat Intelligence - Periodic feed sync.

Sync data from GreyNoise, abuse.ch, MISP, and custom feeds.
"""

import logging
import requests
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Optional, Any
from apscheduler.schedulers.background import BackgroundScheduler

logger = logging.getLogger(__name__)


class ThreatFeedProvider(ABC):
    """Abstract threat feed provider."""

    @abstractmethod
    async def fetch(self) -> List[Dict[str, Any]]:
        """Fetch threat intelligence from source."""
        pass


class GreyNoiseFeedProvider(ThreatFeedProvider):
    """GreyNoise IP reputation feed."""

    def __init__(self, api_key: str):
        """Initialize with GreyNoise API key."""
        self.api_key = api_key
        self.base_url = "https://api.greynoise.io/v3/enterprise"

    async def fetch(self) -> List[Dict[str, Any]]:
        """Fetch malicious IPs from GreyNoise."""
        headers = {"key": self.api_key}

        try:
            # Fetch IPs added in last 24 hours
            response = requests.get(
                f"{self.base_url}/hotips",
                headers=headers,
                params={"limit": 10000},
            )
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched {len(data['data'])} IPs from GreyNoise")

            return [
                {
                    "type": "ip",
                    "value": ip["ip"],
                    "severity": self._severity_from_classification(ip.get("classification")),
                    "description": ip.get("last_seen_classification_tags", []),
                    "source": "greynoise",
                    "fetch_timestamp": datetime.utcnow().isoformat(),
                }
                for ip in data.get("data", [])
            ]

        except requests.RequestException as e:
            logger.error(f"GreyNoise fetch failed: {e}")
            return []

    @staticmethod
    def _severity_from_classification(classification: Optional[str]) -> int:
        """Map GreyNoise classification to severity."""
        severity_map = {
            "malicious": 9,
            "suspicious": 6,
            "benign": 2,
            "unknown": 3,
        }
        return severity_map.get(classification or "unknown", 3)


class AbuseCHFeedProvider(ThreatFeedProvider):
    """Malware hash feed from abuse.ch."""

    async def fetch(self) -> List[Dict[str, Any]]:
        """Fetch malware hashes from abuse.ch."""
        try:
            response = requests.get("https://urlhaus-api.abuse.ch/v1/urls/recent/")
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched {len(data['results'])} URLs from abuse.ch")

            return [
                {
                    "type": "url",
                    "value": url["url"],
                    "severity": 8,
                    "threat_type": url.get("threat_type", "unknown"),
                    "source": "abuse_ch",
                    "fetch_timestamp": datetime.utcnow().isoformat(),
                }
                for url in data.get("results", [])[:1000]  # Limit to 1000
            ]

        except requests.RequestException as e:
            logger.error(f"abuse.ch fetch failed: {e}")
            return []


class MISPFeedProvider(ThreatFeedProvider):
    """Threat intelligence from MISP instance."""

    def __init__(self, url: str, api_key: str):
        """Initialize with MISP instance."""
        self.url = url
        self.api_key = api_key

    async def fetch(self) -> List[Dict[str, Any]]:
        """Fetch events from MISP."""
        try:
            headers = {"Authorization": self.api_key, "Content-Type": "application/json"}

            response = requests.get(
                f"{self.url}/events/index",
                headers=headers,
                params={"limit": 100},
            )
            response.raise_for_status()

            data = response.json()
            logger.info(f"Fetched {len(data)} events from MISP")

            threats = []
            for event in data.get("Event", []):
                for attribute in event.get("Attribute", []):
                    threats.append({
                        "type": attribute["type"],
                        "value": attribute["value"],
                        "severity": self._severity_from_misp_tag(event.get("info", "")),
                        "description": event.get("info", ""),
                        "source": "misp",
                        "fetch_timestamp": datetime.utcnow().isoformat(),
                    })

            return threats

        except requests.RequestException as e:
            logger.error(f"MISP fetch failed: {e}")
            return []

    @staticmethod
    def _severity_from_misp_tag(info: str) -> int:
        """Infer severity from event info."""
        high_severity_keywords = ["ransomware", "exploit", "zero-day", "apt"]
        if any(kw in info.lower() for kw in high_severity_keywords):
            return 9
        return 5


class ThreatIntelManager:
    """Manage threat intelligence aggregation and storage."""

    def __init__(self, db_connection):
        """Initialize threat intel manager."""
        self.db = db_connection
        self.providers: List[ThreatFeedProvider] = []
        self.scheduler = BackgroundScheduler()

    def register_provider(self, provider: ThreatFeedProvider) -> None:
        """Register a threat feed provider."""
        self.providers.append(provider)

    async def sync_all_feeds(self) -> Dict[str, int]:
        """Synchronize all threat feeds."""
        results = {}

        for provider in self.providers:
            try:
                threats = await provider.fetch()
                count = await self._store_threats(threats)
                results[provider.__class__.__name__] = count
                logger.info(f"Stored {count} threats from {provider.__class__.__name__}")

            except Exception as e:
                logger.error(f"Error syncing {provider.__class__.__name__}: {e}")
                results[provider.__class__.__name__] = 0

        return results

    async def _store_threats(self, threats: List[Dict[str, Any]]) -> int:
        """Store threat intelligence in database."""
        # Would insert into threat_intel table
        for threat in threats:
            # INSERT INTO threat_intel (type, value, severity, ...) VALUES (...)
            pass

        return len(threats)

    def start_scheduler(self) -> None:
        """Start background scheduler for periodic syncs."""
        # Sync feeds every 4 hours
        self.scheduler.add_job(
            self.sync_all_feeds,
            'interval',
            hours=4,
            id='threat_intel_sync',
            name='Threat Intelligence Sync',
            replace_existing=True,
        )

        self.scheduler.start()
        logger.info("Threat intelligence scheduler started")

    def query_reputation(self, indicator: str) -> Optional[Dict[str, Any]]:
        """Query reputation for an indicator (IP, URL, hash)."""
        # Would query threat_intel table
        # SELECT * FROM threat_intel WHERE value = indicator
        pass

    def get_latest_feeds(self, feed_type: str = None) -> List[Dict[str, Any]]:
        """Get latest threat intelligence."""
        # Would query threat_intel with recent timestamps
        pass
