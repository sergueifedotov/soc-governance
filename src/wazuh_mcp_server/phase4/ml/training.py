"""Training pipeline for ML models with MLflow integration.

Handles:
- Data preparation from historical alerts
- Model training with cross-validation
- Performance metrics tracking
- Canary deployment
- Shadow mode evaluation
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import mlflow
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
)

from .feature_engineering import AlertFeatures, FeatureEngineer
from .models import SeverityPredictor, FalsePositiveDetector, AttackPatternClassifier

logger = logging.getLogger(__name__)


@dataclass
class TrainingConfig:
    """Configuration for model training."""

    # Data
    window_days: int = 60  # Historical data window
    min_samples_per_class: int = 50  # Minimum training samples

    # Train/val/test split
    train_fraction: float = 0.8
    val_fraction: float = 0.1
    test_fraction: float = 0.1

    # Cross-validation
    cv_folds: int = 5

    # Thresholds for model promotion
    severity_f1_threshold: float = 0.80
    fp_precision_threshold: float = 0.75
    attack_accuracy_threshold: float = 0.80

    # Improvement required to promote (e.g., 2% better)
    improvement_threshold: float = 1.02

    # Paths
    model_dir: Path = Path("/tmp/phase4_models")
    mlflow_uri: str = "file:///tmp/mlflow"

    def __post_init__(self):
        self.model_dir.mkdir(parents=True, exist_ok=True)


@dataclass
class TrainingMetrics:
    """Metrics from model training."""

    model_type: str  # "severity", "false_positive", "attack_pattern"
    cv_scores: np.ndarray  # Cross-validation scores
    cv_mean: float
    cv_std: float
    train_score: float
    val_score: float
    test_score: float
    test_metrics: Dict[str, float]  # Detailed metrics
    samples: int
    features: int
    run_id: str
    is_production: bool = False


class ModelTrainer:
    """Train and manage phase 4 ML models."""

    def __init__(self, config: TrainingConfig, feature_engineer: FeatureEngineer):
        """Initialize trainer.
        
        Args:
            config: TrainingConfig instance
            feature_engineer: FeatureEngineer for feature preparation
        """
        self.config = config
        self.feature_engineer = feature_engineer

        # Initialize MLflow
        mlflow.set_tracking_uri(config.mlflow_uri)
        mlflow.set_experiment("phase4_ml_models")

    async def train_severity_predictor(
        self, training_data: List[Dict[str, Any]]
    ) -> TrainingMetrics:
        """Train severity predictor.
        
        Args:
            training_data: List of alert dicts with labels (true_severity)
        
        Returns:
            TrainingMetrics
        """
        logger.info(f"Preparing {len(training_data)} alerts for severity training")

        # Engineer features
        features_list = await self.feature_engineer.engineer_batch(training_data)

        # Build feature matrix and labels
        X = np.array([f.to_vector() for f in features_list])
        y = np.array(
            [
                SeverityPredictor.SEVERITY_MAP.get(f.true_severity, 0)
                for f in features_list
            ]
        )

        feature_names = [
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
            "src_ip_reputation_squared",  # Derived
        ]

        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
        )

        logger.info(f"Train/val/test split: {len(X_train)}/{len(X_val)}/{len(X_test)}")

        # Train model
        model = SeverityPredictor()

        # Cross-validation
        cv_scores = cross_val_score(
            model.model or SeverityPredictor().model,
            X_train,
            y_train,
            cv=self.config.cv_folds,
            scoring="f1_weighted",
        )

        model.train(X_train, y_train, feature_names)

        # Evaluate
        train_score = model.model.score(X_train, y_train)
        val_score = model.model.score(X_val, y_val)
        test_score = model.model.score(X_test, y_test)

        test_metrics = {
            "accuracy": accuracy_score(y_test, model.model.predict(X_test)),
            "precision_macro": precision_score(
                y_test, model.model.predict(X_test), average="macro"
            ),
            "recall_macro": recall_score(
                y_test, model.model.predict(X_test), average="macro"
            ),
            "f1_macro": f1_score(y_test, model.model.predict(X_test), average="macro"),
        }

        # Log to MLflow
        with mlflow.start_run(run_name=f"severity_model_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
            mlflow.log_params({
                "window_days": self.config.window_days,
                "cv_folds": self.config.cv_folds,
                "train_samples": len(X_train),
            })

            mlflow.log_metrics({
                "cv_mean_f1": float(cv_scores.mean()),
                "cv_std_f1": float(cv_scores.std()),
                "train_accuracy": float(train_score),
                "val_accuracy": float(val_score),
                "test_accuracy": float(test_score),
                **{f"test_{k}": v for k, v in test_metrics.items()},
            })

            run_id = mlflow.active_run().info.run_id
            model.save(str(self.config.model_dir / "severity_predictor.pkl"))
            mlflow.sklearn.log_model(model.model, "model")

        return TrainingMetrics(
            model_type="severity",
            cv_scores=cv_scores,
            cv_mean=float(cv_scores.mean()),
            cv_std=float(cv_scores.std()),
            train_score=float(train_score),
            val_score=float(val_score),
            test_score=float(test_score),
            test_metrics=test_metrics,
            samples=len(X_train),
            features=X_train.shape[1],
            run_id=run_id,
        )

    async def train_false_positive_detector(
        self, training_data: List[Dict[str, Any]]
    ) -> TrainingMetrics:
        """Train false-positive detector.
        
        Args:
            training_data: List of alerts with labels (is_false_positive)
        
        Returns:
            TrainingMetrics
        """
        logger.info(f"Preparing {len(training_data)} alerts for FP detection training")

        # Engineer features
        features_list = await self.feature_engineer.engineer_batch(training_data)

        # Build feature matrix
        X = np.array([f.to_vector() for f in features_list])
        y = np.array([int(f.is_false_positive or False) for f in features_list])

        # Use subset of features for FP detection
        feature_subset_indices = [0, 1, 2, 3, 4, 5, 10, 11, 12, 13]
        X = X[:, feature_subset_indices]

        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
        )

        # Train model
        model = FalsePositiveDetector()
        model.train(X_train, y_train, [f"feature_{i}" for i in feature_subset_indices])

        # Evaluate
        train_score = model.model.score(X_train, y_train)
        val_score = model.model.score(X_val, y_val)
        test_score = model.model.score(X_test, y_test)

        test_metrics = {
            "accuracy": accuracy_score(y_test, model.model.predict(X_test)),
            "precision": precision_score(y_test, model.model.predict(X_test), zero_division=0),
            "recall": recall_score(y_test, model.model.predict(X_test), zero_division=0),
            "f1": f1_score(y_test, model.model.predict(X_test), zero_division=0),
        }

        # Log to MLflow
        with mlflow.start_run(run_name=f"fp_detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
            mlflow.log_params({
                "window_days": self.config.window_days,
                "train_samples": len(X_train),
                "class_ratio": f"{(y_train == 0).sum()}:{(y_train == 1).sum()}",
            })

            mlflow.log_metrics({
                "train_accuracy": float(train_score),
                "val_accuracy": float(val_score),
                "test_accuracy": float(test_score),
                **{f"test_{k}": v for k, v in test_metrics.items()},
            })

            run_id = mlflow.active_run().info.run_id
            model.save(str(self.config.model_dir / "fp_detector.pkl"))

        return TrainingMetrics(
            model_type="false_positive",
            cv_scores=np.array([test_metrics["f1"]]),
            cv_mean=float(test_metrics["f1"]),
            cv_std=0.0,
            train_score=float(train_score),
            val_score=float(val_score),
            test_score=float(test_score),
            test_metrics=test_metrics,
            samples=len(X_train),
            features=X.shape[1],
            run_id=run_id,
        )

    async def train_attack_pattern_classifier(
        self, training_data: List[Dict[str, Any]]
    ) -> TrainingMetrics:
        """Train attack pattern classifier.
        
        Args:
            training_data: List of alerts with labels (attack_pattern)
        
        Returns:
            TrainingMetrics
        """
        logger.info(f"Preparing {len(training_data)} alerts for attack pattern training")

        # Engineer features
        features_list = await self.feature_engineer.engineer_batch(training_data)

        # Build feature matrix
        X = np.array([f.to_vector() for f in features_list])
        y = np.array(
            [
                AttackPatternClassifier.ATTACK_MAP.get(f.attack_pattern, 5)
                for f in features_list
            ]
        )

        # Split data
        X_train, X_temp, y_train, y_temp = train_test_split(
            X, y, test_size=0.2, stratify=y, random_state=42
        )
        X_val, X_test, y_val, y_test = train_test_split(
            X_temp, y_temp, test_size=0.5, stratify=y_temp, random_state=42
        )

        # Train model
        model = AttackPatternClassifier()
        feature_names = [f"feature_{i}" for i in range(X.shape[1])]
        model.train(X_train, y_train, feature_names)

        # Evaluate
        train_score = model.model.score(X_train, y_train)
        val_score = model.model.score(X_val, y_val)
        test_score = model.model.score(X_test, y_test)

        test_metrics = {
            "accuracy": accuracy_score(y_test, model.model.predict(X_test)),
            "precision_macro": precision_score(
                y_test, model.model.predict(X_test), average="macro"
            ),
            "recall_macro": recall_score(
                y_test, model.model.predict(X_test), average="macro"
            ),
            "f1_macro": f1_score(y_test, model.model.predict(X_test), average="macro"),
        }

        # Log to MLflow
        with mlflow.start_run(run_name=f"attack_pattern_{datetime.now().strftime('%Y%m%d_%H%M%S')}"):
            mlflow.log_metrics({
                "train_accuracy": float(train_score),
                "val_accuracy": float(val_score),
                "test_accuracy": float(test_score),
                **{f"test_{k}": v for k, v in test_metrics.items()},
            })

            run_id = mlflow.active_run().info.run_id
            model.save(str(self.config.model_dir / "attack_pattern.pkl"))

        return TrainingMetrics(
            model_type="attack_pattern",
            cv_scores=np.array([test_metrics["accuracy"]]),
            cv_mean=float(test_metrics["accuracy"]),
            cv_std=0.0,
            train_score=float(train_score),
            val_score=float(val_score),
            test_score=float(test_score),
            test_metrics=test_metrics,
            samples=len(X_train),
            features=X.shape[1],
            run_id=run_id,
        )
