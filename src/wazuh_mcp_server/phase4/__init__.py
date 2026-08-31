"""Phase 4 Advanced SOC Architecture

Complete enterprise incident management system with:
- Incident Management (PostgreSQL + REST API)
- Case Management & Forensics (Neo4j)
- Playbook Orchestration (Prefect)
- Event Queue (Celery + RabbitMQ)
- Analytics & BI (DuckDB + Grafana)
- Threat Intelligence (APScheduler + feeds)
- ML & Anomaly Detection (XGBoost + MLflow)
"""

try:
    from .ml import (
        FeatureEngineer,
        AlertFeatures,
        SeverityPredictor,
        FalsePositiveDetector,
        AttackPatternClassifier,
        ModelTrainer,
        TrainingConfig,
        ModelMonitor,
        DriftDetector,
        Phase3MLIntegration,
    )
except ImportError:
    pass

try:
    from .incident_management import (
        IncidentTicket,
        IncidentStatus,
        RiskTier,
        IncidentActivity,
        IncidentEvidence,
        SLAPolicy,
    )
except ImportError:
    pass

try:
    from .orchestration.playbooks import PlaybookEngine, PlaybookDefinition
except ImportError:
    pass

try:
    from .forensics import ForensicCaseManager
except ImportError:
    pass

from .events import (
    create_incident_from_alert,
    trigger_phase3_workflow,
    aggregate_related_alerts,
)

try:
    from .analytics import SOCAnalytics
except ImportError:
    pass

try:
    from .threat_intel import ThreatIntelManager
except ImportError:
    pass

__version__ = "1.0.0"
__all__ = [
    # ML
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
    # Incident Management
    "IncidentTicket",
    "IncidentStatus",
    "RiskTier",
    "IncidentActivity",
    "IncidentEvidence",
    "SLAPolicy",
    # Orchestration
    "PlaybookEngine",
    "PlaybookDefinition",
    # Forensics
    "ForensicCaseManager",
    # Events
    "create_incident_from_alert",
    "trigger_phase3_workflow",
    "aggregate_related_alerts",
    # Analytics
    "SOCAnalytics",
    # Threat Intel
    "ThreatIntelManager",
]
