"""Feature engineering for ML models.

Transforms raw Wazuh alerts into feature vectors for ML models.
Handles:
- Alert properties extraction
- Context enrichment (reputation, privilege levels)
- Temporal features
- Historical baselines
- Statistical anomaly scoring
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from scipy.stats import entropy, zscore

logger = logging.getLogger(__name__)


@dataclass
class AlertFeatures:
    """Feature vector for a single alert."""

    # Alert properties
    rule_severity: int
    rule_category: int  # Encoded
    alert_text_tokens: int
    contains_executable: bool

    # Context enrichment
    src_ip_reputation: float  # 0-100
    dest_user_privilege: int  # 0=user, 1=admin, 2=system
    target_is_critical: bool
    src_ip_in_whitelist: bool

    # Temporal
    hour_of_day_utc: int
    day_of_week: int
    alert_frequency_per_hour: float

    # Historical
    src_ip_incident_count_30d: int
    agent_alert_count_7d: int
    rule_false_positive_rate: float
    time_since_last_alert_seconds: Optional[int]

    # Statistical
    zscore_volume: float
    entropy_rule_distribution: float
    geographic_anomaly: bool

    # Raw alert data for reference
    alert_id: str
    agent_id: str
    rule_id: int
    src_ip: str
    dest_ip: str
    user_id: Optional[str]
    timestamp: datetime

    # Optional: analyst labels (for training)
    is_false_positive: Optional[bool] = None
    true_severity: Optional[str] = None  # "low", "medium", "high", "critical"
    attack_pattern: Optional[str] = None  # "brute_force", "port_scan", etc.

    def to_vector(self) -> np.ndarray:
        """Convert to feature vector for model prediction.
        
        Returns:
            array of shape (19,) with normalized features
        """
        vector = np.array([
            # Alert properties (4 features)
            self.rule_severity / 10.0,
            self.rule_category / 100.0,
            min(self.alert_text_tokens / 1000.0, 1.0),
            float(self.contains_executable),

            # Context enrichment (4 features)
            self.src_ip_reputation / 100.0,
            self.dest_user_privilege / 2.0,
            float(self.target_is_critical),
            float(self.src_ip_in_whitelist),

            # Temporal (3 features)
            self.hour_of_day_utc / 24.0,
            self.day_of_week / 7.0,
            min(self.alert_frequency_per_hour / 60.0, 1.0),

            # Historical (4 features)
            min(self.src_ip_incident_count_30d / 100.0, 1.0),
            min(self.agent_alert_count_7d / 1000.0, 1.0),
            self.rule_false_positive_rate,
            min((self.time_since_last_alert_seconds or 3600) / 86400.0, 1.0),

            # Statistical (3 features)
            (self.zscore_volume + 10.0) / 20.0,  # Normalize from -10..+10
            min(self.entropy_rule_distribution / 5.0, 1.0),
            float(self.geographic_anomaly),

            # Derived feature (1 feature)
            min((self.src_ip_reputation / 100.0) ** 2, 1.0),
        ], dtype=np.float32)

        assert len(vector) == 19, f"Expected 19 features, got {len(vector)}"
        return vector

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/logging."""
        return {
            "rule_severity": self.rule_severity,
            "rule_category": self.rule_category,
            "alert_text_tokens": self.alert_text_tokens,
            "contains_executable": self.contains_executable,
            "src_ip_reputation": self.src_ip_reputation,
            "dest_user_privilege": self.dest_user_privilege,
            "target_is_critical": self.target_is_critical,
            "src_ip_in_whitelist": self.src_ip_in_whitelist,
            "hour_of_day_utc": self.hour_of_day_utc,
            "day_of_week": self.day_of_week,
            "alert_frequency_per_hour": self.alert_frequency_per_hour,
            "src_ip_incident_count_30d": self.src_ip_incident_count_30d,
            "agent_alert_count_7d": self.agent_alert_count_7d,
            "rule_false_positive_rate": self.rule_false_positive_rate,
            "time_since_last_alert_seconds": self.time_since_last_alert_seconds,
            "zscore_volume": self.zscore_volume,
            "entropy_rule_distribution": self.entropy_rule_distribution,
            "geographic_anomaly": self.geographic_anomaly,
            "alert_id": self.alert_id,
            "agent_id": self.agent_id,
            "rule_id": self.rule_id,
            "src_ip": self.src_ip,
            "dest_ip": self.dest_ip,
            "user_id": self.user_id,
            "timestamp": self.timestamp.isoformat(),
            "is_false_positive": self.is_false_positive,
            "true_severity": self.true_severity,
            "attack_pattern": self.attack_pattern,
        }


class FeatureEngineer:
    """Transforms raw alerts into feature vectors."""

    SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    CATEGORY_ENCODING = {
        "malware": 10,
        "intrusion": 20,
        "exploitation": 30,
        "policy": 40,
        "authentication": 50,
        "account_management": 60,
        "network": 70,
        "system": 80,
        "other": 0,
    }

    def __init__(
        self,
        reputation_provider,  # e.g., GreyNoise API
        historical_db,  # Database for historical queries
        geolocation_db,  # IP geolocation database
    ):
        """Initialize feature engineer.
        
        Args:
            reputation_provider: Interface to query IP reputation (score 0-100)
            historical_db: Database with historical incident/alert data
            geolocation_db: Database with IP geolocation info
        """
        self.reputation_provider = reputation_provider
        self.historical_db = historical_db
        self.geolocation_db = geolocation_db

    async def engineer_features(
        self,
        alert: Dict[str, Any],
        user_privilege: Optional[int] = None,
        target_is_critical: Optional[bool] = None,
    ) -> AlertFeatures:
        """Engineer features for a single alert.
        
        Args:
            alert: Raw alert dict with keys:
                - alert_id, agent_id, rule_id, src_ip, dest_ip, user_id
                - severity, rule_name, full_log, timestamp
            user_privilege: (cached) destination user privilege level
            target_is_critical: (cached) whether target is critical asset
        
        Returns:
            AlertFeatures with all 19 features computed
        """
        now = datetime.now()

        # Extract alert properties
        rule_severity = alert.get("severity", 3)
        rule_id = alert.get("rule_id", 0)
        rule_name = alert.get("rule_name", "").lower()

        # Encode rule category
        rule_category = self._encode_category(rule_name, rule_id)

        # Alert text features
        full_log = alert.get("full_log", "")
        alert_text_tokens = len(full_log.split())
        contains_executable = any(
            ext in full_log.lower()
            for ext in [".exe", ".dll", ".sys", ".com", ".scr", ".vbs", ".ps1"]
        )

        # Context enrichment (parallelized)
        (
            src_ip_reputation,
            dest_user_privilege,
            target_is_critical_val,
            src_ip_in_whitelist,
            src_ip_incident_count,
            agent_alert_count,
            rule_fp_rate,
            time_since_last,
            geographic_anomaly,
        ) = await asyncio.gather(
            self.reputation_provider.query_async(alert["src_ip"]),
            self._get_user_privilege(alert.get("user_id"), user_privilege),
            self._get_target_is_critical(alert["dest_ip"], target_is_critical),
            self._check_ip_whitelist(alert["src_ip"]),
            self.historical_db.count_incidents(alert["src_ip"], days=30),
            self.historical_db.count_alerts(alert["agent_id"], days=7),
            self.historical_db.get_fp_rate(rule_id),
            self.historical_db.time_since_last_alert(alert["agent_id"]),
            self._check_geographic_anomaly(alert["src_ip"], alert.get("geolocation")),
        )

        # Temporal features
        timestamp = alert.get("timestamp", now)
        hour_of_day = timestamp.hour
        day_of_week = timestamp.weekday()

        # Alert frequency (for this rule, at this hour)
        hourly_baseline = await self.historical_db.get_hourly_baseline(
            rule_id, hour_of_day
        )
        current_hour_count = await self.historical_db.count_alerts_this_hour(rule_id)
        
        if hourly_baseline.std > 0:
            zscore_volume = (
                current_hour_count - hourly_baseline.mean
            ) / hourly_baseline.std
        else:
            zscore_volume = 0.0

        alert_frequency = current_hour_count / 3600.0 if current_hour_count > 0 else 0.0

        # Rule distribution entropy (diversity of rules firing now)
        rule_distribution = await self.historical_db.get_current_rule_distribution()
        if len(rule_distribution) > 0:
            entropy_val = entropy(list(rule_distribution.values()))
        else:
            entropy_val = 0.0

        return AlertFeatures(
            rule_severity=rule_severity,
            rule_category=rule_category,
            alert_text_tokens=alert_text_tokens,
            contains_executable=contains_executable,
            src_ip_reputation=src_ip_reputation,
            dest_user_privilege=dest_user_privilege,
            target_is_critical=target_is_critical_val,
            src_ip_in_whitelist=src_ip_in_whitelist,
            hour_of_day_utc=hour_of_day,
            day_of_week=day_of_week,
            alert_frequency_per_hour=alert_frequency,
            src_ip_incident_count_30d=src_ip_incident_count,
            agent_alert_count_7d=agent_alert_count,
            rule_false_positive_rate=rule_fp_rate,
            time_since_last_alert_seconds=time_since_last,
            zscore_volume=min(max(zscore_volume, -10.0), 10.0),  # Clip
            entropy_rule_distribution=entropy_val,
            geographic_anomaly=geographic_anomaly,
            alert_id=alert.get("alert_id", ""),
            agent_id=alert.get("agent_id", ""),
            rule_id=rule_id,
            src_ip=alert.get("src_ip", ""),
            dest_ip=alert.get("dest_ip", ""),
            user_id=alert.get("user_id"),
            timestamp=timestamp,
        )

    async def engineer_batch(
        self, alerts: List[Dict[str, Any]]
    ) -> List[AlertFeatures]:
        """Engineer features for multiple alerts in parallel.
        
        Args:
            alerts: List of raw alert dicts
        
        Returns:
            List of AlertFeatures
        """
        return await asyncio.gather(
            *[self.engineer_features(alert) for alert in alerts]
        )

    def _encode_category(self, rule_name: str, rule_id: int) -> int:
        """Encode rule category from rule name/id."""
        for category, code in self.CATEGORY_ENCODING.items():
            if category in rule_name.lower():
                return code
        return self.CATEGORY_ENCODING["other"]

    async def _get_user_privilege(
        self, user_id: Optional[str], cached: Optional[int] = None
    ) -> int:
        """Get user privilege level (0=user, 1=admin, 2=system)."""
        if cached is not None:
            return cached
        if not user_id:
            return 0
        return await self.historical_db.get_user_privilege(user_id)

    async def _get_target_is_critical(
        self, dest_ip: str, cached: Optional[bool] = None
    ) -> bool:
        """Check if destination IP is critical asset."""
        if cached is not None:
            return cached
        return await self.historical_db.is_critical_asset(dest_ip)

    async def _check_ip_whitelist(self, src_ip: str) -> bool:
        """Check if source IP is whitelisted."""
        return await self.historical_db.is_whitelisted_ip(src_ip)

    async def _check_geographic_anomaly(
        self, src_ip: str, cached_geolocation: Optional[Dict] = None
    ) -> bool:
        """Detect geographic anomaly (e.g., impossible travel)."""
        if cached_geolocation:
            current_location = cached_geolocation
        else:
            current_location = await self.geolocation_db.lookup(src_ip)

        if not current_location:
            return False

        # Get last login location for impossible travel check
        last_location = await self.historical_db.get_last_login_location()
        if not last_location:
            return False

        # Simple check: if distance > 500km and time < 1 hour = anomaly
        distance = self._calculate_distance(current_location, last_location)
        time_delta = (datetime.now() - last_location.get("timestamp", datetime.now())).total_seconds() / 3600.0
        
        if distance > 500 and time_delta < 1.0:
            return True

        return False

    @staticmethod
    def _calculate_distance(
        loc1: Dict[str, float], loc2: Dict[str, float]
    ) -> float:
        """Calculate distance between two coordinates (haversine, km)."""
        from math import radians, cos, sin, asin, sqrt

        lon1, lat1, lon2, lat2 = map(
            radians,
            [
                loc1.get("longitude", 0),
                loc1.get("latitude", 0),
                loc2.get("longitude", 0),
                loc2.get("latitude", 0),
            ],
        )

        dlon = lon2 - lon1
        dlat = lat2 - lat1
        a = sin(dlat / 2) ** 2 + cos(lat1) * cos(lat2) * sin(dlon / 2) ** 2
        c = 2 * asin(sqrt(a))
        km = 6371 * c
        return km
