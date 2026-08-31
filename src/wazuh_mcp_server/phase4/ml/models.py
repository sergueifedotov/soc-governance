"""ML Models for Phase 4 anomaly detection and incident classification.

Models:
1. Severity Predictor: Multi-class (low, medium, high, critical)
2. False-Positive Detector: Binary classification
3. Attack Pattern Classifier: Multi-class attack type detection
"""

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import numpy as np
from xgboost import XGBClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler

from .feature_engineering import AlertFeatures

logger = logging.getLogger(__name__)


@dataclass
class PredictionResult:
    """Result of model prediction."""

    label: str
    confidence: float  # 0.0 - 1.0
    probabilities: Dict[str, float]  # All class probs
    feature_importance: Dict[str, float]  # Top 10 features


@dataclass
class SeverityPrediction(PredictionResult):
    """Severity prediction (low/medium/high/critical)."""

    label: str  # "low", "medium", "high", "critical"
    confidence: float
    probabilities: Dict[str, float]  # {"low": 0.1, "medium": 0.3, ...}
    feature_importance: Dict[str, float]


@dataclass
class FalsePositivePrediction(PredictionResult):
    """False-positive prediction."""

    is_false_positive: bool
    confidence: float  # 0.0 - 1.0
    probabilities: Dict[str, float]  # {"true_positive": 0.8, "false_positive": 0.2}
    feature_importance: Dict[str, float]


@dataclass
class AttackPatternPrediction(PredictionResult):
    """Attack pattern prediction."""

    attack_type: str
    confidence: float
    probabilities: Dict[str, float]  # All attack type probs


class SeverityPredictor:
    """Predict incident severity from alert features.
    
    Classes: "low" (0), "medium" (1), "high" (2), "critical" (3)
    """

    SEVERITY_CLASSES = ["low", "medium", "high", "critical"]
    SEVERITY_MAP = {name: idx for idx, name in enumerate(SEVERITY_CLASSES)}

    def __init__(self):
        """Initialize severity predictor."""
        self.model: Optional[XGBClassifier] = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_names: List[str] = []

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: List[str],
        **xgb_kwargs,
    ) -> Dict[str, float]:
        """Train severity predictor.
        
        Args:
            X_train: Feature matrix (n_samples, n_features)
            y_train: Labels (0-3 for low/medium/high/critical)
            feature_names: List of feature names
            **xgb_kwargs: Additional XGBClassifier kwargs
        
        Returns:
            Training metrics dict
        """
        # Fit scaler
        X_scaled = self.scaler.fit_transform(X_train)

        # Configure model
        default_config = {
            "n_estimators": 100,
            "max_depth": 6,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "colsample_bytree": 0.8,
            "random_state": 42,
            "scale_pos_weight": 2,
            "objective": "multi:softprob",
            "num_class": 4,
        }
        default_config.update(xgb_kwargs)

        self.model = XGBClassifier(**default_config)
        self.model.fit(X_scaled, y_train)
        self.feature_names = feature_names
        self.is_fitted = True

        return {"train_samples": len(X_train), "n_features": X_train.shape[1]}

    def predict(self, features: AlertFeatures) -> SeverityPrediction:
        """Predict severity for a single alert.
        
        Args:
            features: AlertFeatures instance
        
        Returns:
            SeverityPrediction with label and confidence
        """
        if not self.is_fitted or self.model is None:
            raise ValueError("Model not trained. Call train() first.")

        X = features.to_vector().reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        pred_class = self.model.predict(X_scaled)[0]
        pred_proba = self.model.predict_proba(X_scaled)[0]

        label = self.SEVERITY_CLASSES[int(pred_class)]
        confidence = float(pred_proba[int(pred_class)])

        # Feature importance
        importance = self._get_feature_importance(X_scaled[0])

        return SeverityPrediction(
            label=label,
            confidence=confidence,
            probabilities={
                name: float(prob)
                for name, prob in zip(self.SEVERITY_CLASSES, pred_proba)
            },
            feature_importance=importance,
        )

    def predict_batch(self, features_list: List[AlertFeatures]) -> List[SeverityPrediction]:
        """Predict severity for multiple alerts."""
        return [self.predict(f) for f in features_list]

    def _get_feature_importance(self, sample: np.ndarray) -> Dict[str, float]:
        """Get feature importance for a sample."""
        if not self.model or not self.feature_names:
            return {}

        importance_dict = {
            name: float(score)
            for name, score in zip(
                self.feature_names, self.model.feature_importances_
            )
        }
        # Return top 10
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)[:10])

    def save(self, filepath: str) -> None:
        """Save model to file."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        import pickle

        with open(filepath, "wb") as f:
            pickle.dump(
                {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names},
                f,
            )

    def load(self, filepath: str) -> None:
        """Load model from file."""
        import pickle

        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.feature_names = data["feature_names"]
            self.is_fitted = True


class FalsePositiveDetector:
    """Detect false-positive alerts using Random Forest.
    
    Binary classification: True Positive (0) vs False Positive (1)
    """

    def __init__(self):
        """Initialize false-positive detector."""
        self.model: Optional[RandomForestClassifier] = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_names: List[str] = []

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: List[str],
        **rf_kwargs,
    ) -> Dict[str, float]:
        """Train false-positive detector.
        
        Args:
            X_train: Feature matrix
            y_train: Labels (0=true_positive, 1=false_positive)
            feature_names: List of feature names
            **rf_kwargs: Additional RandomForestClassifier kwargs
        
        Returns:
            Training metrics
        """
        X_scaled = self.scaler.fit_transform(X_train)

        default_config = {
            "n_estimators": 50,
            "max_depth": 8,
            "min_samples_split": 10,
            "min_samples_leaf": 5,
            "random_state": 42,
        }
        default_config.update(rf_kwargs)

        self.model = RandomForestClassifier(**default_config)
        self.model.fit(X_scaled, y_train)
        self.feature_names = feature_names
        self.is_fitted = True

        return {"train_samples": len(X_train), "n_features": X_train.shape[1]}

    def predict(self, features: AlertFeatures) -> FalsePositivePrediction:
        """Predict if alert is false positive.
        
        Args:
            features: AlertFeatures instance
        
        Returns:
            FalsePositivePrediction
        """
        if not self.is_fitted or self.model is None:
            raise ValueError("Model not trained")

        X = features.to_vector().reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        pred_class = self.model.predict(X_scaled)[0]
        pred_proba = self.model.predict_proba(X_scaled)[0]

        is_fp = bool(pred_class == 1)
        confidence = float(pred_proba[1])  # Confidence in FP prediction

        importance = self._get_feature_importance()

        return FalsePositivePrediction(
            is_false_positive=is_fp,
            confidence=confidence,
            probabilities={
                "true_positive": float(pred_proba[0]),
                "false_positive": float(pred_proba[1]),
            },
            feature_importance=importance,
        )

    def predict_batch(self, features_list: List[AlertFeatures]) -> List[FalsePositivePrediction]:
        """Predict FP for multiple alerts."""
        return [self.predict(f) for f in features_list]

    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance."""
        if not self.model or not self.feature_names:
            return {}

        importance_dict = {
            name: float(score)
            for name, score in zip(
                self.feature_names, self.model.feature_importances_
            )
        }
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)[:10])

    def save(self, filepath: str) -> None:
        """Save model."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        import pickle

        with open(filepath, "wb") as f:
            pickle.dump(
                {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names},
                f,
            )

    def load(self, filepath: str) -> None:
        """Load model."""
        import pickle

        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.feature_names = data["feature_names"]
            self.is_fitted = True


class AttackPatternClassifier:
    """Classify attack patterns from alert clusters.
    
    Classes: brute_force, port_scan, lateral_movement, exfiltration, policy_violation, other
    """

    ATTACK_TYPES = [
        "brute_force",
        "port_scan",
        "lateral_movement",
        "exfiltration",
        "policy_violation",
        "other",
    ]
    ATTACK_MAP = {name: idx for idx, name in enumerate(ATTACK_TYPES)}

    def __init__(self):
        """Initialize attack pattern classifier."""
        self.model: Optional[XGBClassifier] = None
        self.scaler = StandardScaler()
        self.is_fitted = False
        self.feature_names: List[str] = []

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        feature_names: List[str],
        **xgb_kwargs,
    ) -> Dict[str, float]:
        """Train attack pattern classifier.
        
        Args:
            X_train: Feature matrix
            y_train: Attack type labels (0-5)
            feature_names: Feature names
            **xgb_kwargs: XGBClassifier kwargs
        
        Returns:
            Metrics
        """
        X_scaled = self.scaler.fit_transform(X_train)

        default_config = {
            "n_estimators": 100,
            "max_depth": 6,
            "learning_rate": 0.1,
            "subsample": 0.8,
            "random_state": 42,
            "objective": "multi:softprob",
            "num_class": len(self.ATTACK_TYPES),
        }
        default_config.update(xgb_kwargs)

        self.model = XGBClassifier(**default_config)
        self.model.fit(X_scaled, y_train)
        self.feature_names = feature_names
        self.is_fitted = True

        return {"train_samples": len(X_train), "n_features": X_train.shape[1]}

    def predict(self, features: AlertFeatures) -> AttackPatternPrediction:
        """Predict attack pattern.
        
        Args:
            features: AlertFeatures
        
        Returns:
            AttackPatternPrediction
        """
        if not self.is_fitted or self.model is None:
            raise ValueError("Model not trained")

        X = features.to_vector().reshape(1, -1)
        X_scaled = self.scaler.transform(X)

        pred_class = self.model.predict(X_scaled)[0]
        pred_proba = self.model.predict_proba(X_scaled)[0]

        attack_type = self.ATTACK_TYPES[int(pred_class)]
        confidence = float(pred_proba[int(pred_class)])

        importance = self._get_feature_importance()

        return AttackPatternPrediction(
            attack_type=attack_type,
            confidence=confidence,
            probabilities={
                name: float(prob)
                for name, prob in zip(self.ATTACK_TYPES, pred_proba)
            },
            feature_importance=importance,
        )

    def _get_feature_importance(self) -> Dict[str, float]:
        """Get feature importance."""
        if not self.model or not self.feature_names:
            return {}

        importance_dict = {
            name: float(score)
            for name, score in zip(
                self.feature_names, self.model.feature_importances_
            )
        }
        return dict(sorted(importance_dict.items(), key=lambda x: x[1], reverse=True)[:10])

    def save(self, filepath: str) -> None:
        """Save model."""
        if not self.is_fitted:
            raise ValueError("Model not fitted")
        import pickle

        with open(filepath, "wb") as f:
            pickle.dump(
                {"model": self.model, "scaler": self.scaler, "feature_names": self.feature_names},
                f,
            )

    def load(self, filepath: str) -> None:
        """Load model."""
        import pickle

        with open(filepath, "rb") as f:
            data = pickle.load(f)
            self.model = data["model"]
            self.scaler = data["scaler"]
            self.feature_names = data["feature_names"]
            self.is_fitted = True
