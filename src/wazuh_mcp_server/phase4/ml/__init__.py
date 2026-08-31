"""Phase 4 ML & Anomaly Detection Module.

Provides:
- Feature engineering for alerts
- Severity prediction
- False-positive filtering
- Attack pattern recognition
- Model training and monitoring
- MLflow integration
"""

from .feature_engineering import FeatureEngineer, AlertFeatures
from .models import SeverityPredictor, FalsePositiveDetector, AttackPatternClassifier
from .training import ModelTrainer, TrainingConfig
from .monitoring import ModelMonitor, DriftDetector
from .phase3_integration import Phase3MLIntegration

__all__ = [
    "FeatureEngineer",
    "AlertFeatures",
    "SeverityPredictor",
    "FalsePositiveDetector",
    "AttackPatternClassifier",
    "ModelTrainer",
    "TrainingConfig",
    "ModelMonitor",
    "DriftDetector",
    "Phase3MLIntegration",
]
