"""Model monitoring and drift detection for Phase 4 ML models.

Detects:
- Feature drift (distribution changes)
- Prediction drift (output changes)
- Analyst override rate increases
- Performance degradation
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import numpy as np
from scipy.stats import entropy, ks_2samp

logger = logging.getLogger(__name__)


@dataclass
class DriftDetectionResult:
    """Result of drift detection."""

    detected: bool
    features_with_drift: List[str]
    drift_scores: Dict[str, float]  # Feature -> drift score
    kl_divergence: float  # Prediction distribution divergence
    override_rate: float  # Analyst override rate
    actionable_incident_rate: float
    timestamp: datetime


@dataclass
class FeatureStats:
    """Statistics for a feature."""

    mean: float
    std: float
    min: float
    max: float
    p25: float
    p50: float
    p75: float


class ModelMonitor:
    """Monitor deployed ML models for degradation."""

    # Feature names and indices for 19-feature vector
    FEATURE_NAMES = [
        "rule_severity",
        "rule_category",
        "alert_text_tokens",
        "contains_executable",
        "src_ip_reputation",
        "dest_user_privilege",
        "target_is_critical",
        "src_ip_in_whitelist",
        "hour_of_day_utc",
        "day_of_week",
        "alert_frequency_per_hour",
        "src_ip_incident_count_30d",
        "agent_alert_count_7d",
        "rule_false_positive_rate",
        "time_since_last_alert_seconds",
        "zscore_volume",
        "entropy_rule_distribution",
        "geographic_anomaly",
        "src_ip_reputation_squared",
    ]

    def __init__(self):
        """Initialize model monitor."""
        self.baseline_stats: Dict[str, FeatureStats] = {}
        self.baseline_prediction_dist: Optional[Dict[str, float]] = None
        self.last_check: Optional[datetime] = None

    def set_baseline(
        self,
        feature_vectors: List[np.ndarray],
        predictions: List[str],
    ) -> None:
        """Set baseline statistics from training data.
        
        Args:
            feature_vectors: List of feature arrays
            predictions: List of prediction labels
        """
        X = np.array(feature_vectors)

        # Compute baseline stats for each feature
        self.baseline_stats = {}
        for i, name in enumerate(self.FEATURE_NAMES):
            feature_values = X[:, i]
            self.baseline_stats[name] = FeatureStats(
                mean=float(np.mean(feature_values)),
                std=float(np.std(feature_values)),
                min=float(np.min(feature_values)),
                max=float(np.max(feature_values)),
                p25=float(np.percentile(feature_values, 25)),
                p50=float(np.percentile(feature_values, 50)),
                p75=float(np.percentile(feature_values, 75)),
            )

        # Baseline prediction distribution
        unique, counts = np.unique(predictions, return_counts=True)
        total = len(predictions)
        self.baseline_prediction_dist = {
            label: float(count / total) for label, count in zip(unique, counts)
        }

        logger.info(f"Baseline set from {len(feature_vectors)} samples")

    async def check_drift(
        self,
        current_features: List[np.ndarray],
        current_predictions: List[str],
        query_db,  # Database query interface
    ) -> DriftDetectionResult:
        """Check for feature and prediction drift.
        
        Args:
            current_features: List of recent feature vectors
            current_predictions: List of recent predictions
            query_db: Database interface for override/incident queries
        
        Returns:
            DriftDetectionResult with detected anomalies
        """
        now = datetime.now()
        self.last_check = now

        X_current = np.array(current_features)

        # Feature drift detection (KS test)
        features_with_drift = []
        drift_scores = {}

        for i, name in enumerate(self.FEATURE_NAMES):
            if name not in self.baseline_stats:
                continue

            current_values = X_current[:, i]
            baseline = self.baseline_stats[name]

            # KS test
            statistic, pvalue = ks_2samp(current_values, [baseline.mean] * len(current_values))

            # Flag if significantly different (p < 0.05)
            if pvalue < 0.05:
                features_with_drift.append(name)

            drift_scores[name] = float(statistic)

        # Prediction drift (KL divergence)
        current_unique, current_counts = np.unique(
            current_predictions, return_counts=True
        )
        current_total = len(current_predictions)
        current_pred_dist = {
            label: float(count / current_total)
            for label, count in zip(current_unique, current_counts)
        }

        kl_div = self._compute_kl_divergence(
            self.baseline_prediction_dist or {}, current_pred_dist
        )

        # Analyst override rate
        override_rate = await query_db.get_analyst_override_rate(
            hours=24
        )

        # Actionable incident rate
        actionable_rate = await query_db.get_actionable_incident_rate(
            hours=24
        )

        detected = (
            len(features_with_drift) > 0
            or kl_div > 0.5
            or override_rate > 0.15
        )

        result = DriftDetectionResult(
            detected=detected,
            features_with_drift=features_with_drift,
            drift_scores=drift_scores,
            kl_divergence=kl_div,
            override_rate=override_rate,
            actionable_incident_rate=actionable_rate,
            timestamp=now,
        )

        if detected:
            logger.warning(f"Drift detected: {result}")

        return result

    @staticmethod
    def _compute_kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
        """Compute KL divergence between two distributions.
        
        KL(P||Q) = sum(p(x) * log(p(x) / q(x)))
        """
        # Ensure all keys are in both dicts
        all_keys = set(p.keys()) | set(q.keys())
        p_full = np.array([p.get(k, 1e-10) for k in all_keys])
        q_full = np.array([q.get(k, 1e-10) for k in all_keys])

        # Normalize
        p_full /= p_full.sum()
        q_full /= q_full.sum()

        # Compute KL divergence
        kl = np.sum(p_full * (np.log(p_full + 1e-10) - np.log(q_full + 1e-10)))
        return float(np.clip(kl, 0, 10))

    async def get_performance_summary(
        self, query_db
    ) -> Dict[str, Any]:
        """Get current performance summary.
        
        Args:
            query_db: Database interface
        
        Returns:
            Summary metrics
        """
        last_24h_metrics = await query_db.get_prediction_metrics(hours=24)

        return {
            "timestamp": datetime.now().isoformat(),
            "last_check": self.last_check.isoformat() if self.last_check else None,
            "predictions_last_24h": last_24h_metrics.get("count", 0),
            "override_rate": last_24h_metrics.get("override_rate", 0),
            "actionable_incident_rate": last_24h_metrics.get("actionable_rate", 0),
        }


class DriftDetector:
    """Detect data/concept drift with multiple strategies."""

    def __init__(self, sensitivity: str = "medium"):
        """Initialize drift detector.
        
        Args:
            sensitivity: "low", "medium", or "high"
        """
        self.sensitivity = sensitivity
        self.thresholds = self._get_thresholds(sensitivity)

    def _get_thresholds(self, sensitivity: str) -> Dict[str, float]:
        """Get drift thresholds based on sensitivity."""
        thresholds = {
            "low": {
                "ks_pvalue": 0.01,
                "kl_divergence": 1.0,
                "override_rate": 0.20,
            },
            "medium": {
                "ks_pvalue": 0.05,
                "kl_divergence": 0.5,
                "override_rate": 0.15,
            },
            "high": {
                "ks_pvalue": 0.10,
                "kl_divergence": 0.25,
                "override_rate": 0.10,
            },
        }
        return thresholds.get(sensitivity, thresholds["medium"])

    def detect_feature_drift(
        self,
        baseline_X: np.ndarray,
        current_X: np.ndarray,
    ) -> Dict[str, bool]:
        """Detect feature drift using KS test.
        
        Args:
            baseline_X: Baseline feature matrix
            current_X: Current feature matrix
        
        Returns:
            Dict {feature_name: is_drifted}
        """
        drifted = {}
        threshold = self.thresholds["ks_pvalue"]

        for i in range(baseline_X.shape[1]):
            statistic, pvalue = ks_2samp(baseline_X[:, i], current_X[:, i])
            drifted[f"feature_{i}"] = pvalue < threshold

        return drifted

    def detect_label_drift(
        self,
        baseline_labels: List[str],
        current_labels: List[str],
    ) -> bool:
        """Detect label/prediction drift.
        
        Returns:
            True if significant drift detected
        """
        baseline_dist = self._get_distribution(baseline_labels)
        current_dist = self._get_distribution(current_labels)

        kl_div = self._compute_kl_divergence(baseline_dist, current_dist)
        return kl_div > self.thresholds["kl_divergence"]

    @staticmethod
    def _get_distribution(labels: List[str]) -> Dict[str, float]:
        """Get label distribution."""
        unique, counts = np.unique(labels, return_counts=True)
        total = len(labels)
        return {label: float(count / total) for label, count in zip(unique, counts)}

    @staticmethod
    def _compute_kl_divergence(p: Dict[str, float], q: Dict[str, float]) -> float:
        """Compute KL(P||Q)."""
        all_keys = set(p.keys()) | set(q.keys())
        p_vals = np.array([p.get(k, 1e-10) for k in all_keys])
        q_vals = np.array([q.get(k, 1e-10) for k in all_keys])

        p_vals /= p_vals.sum()
        q_vals /= q_vals.sum()

        kl = np.sum(p_vals * (np.log(p_vals + 1e-10) - np.log(q_vals + 1e-10)))
        return float(np.clip(kl, 0, 10))
