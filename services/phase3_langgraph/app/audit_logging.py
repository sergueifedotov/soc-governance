import structlog
from datetime import datetime

logger = structlog.get_logger()


def log_approval_gate(decision, actor, risk_tier, incident_id, approvals_needed):
    logger.info(
        "approval_gate",
        decision=decision,
        actor=actor,
        risk_tier=risk_tier,
        incident_id=incident_id,
        approvals_needed=approvals_needed,
        timestamp=datetime.now().isoformat()
    )


def log_approval_pending(incident_id, risk_tier, approvals_needed):
    logger.info(
        "approval_pending",
        incident_id=incident_id,
        risk_tier=risk_tier,
        approvals_needed=approvals_needed,
        timestamp=datetime.now().isoformat(),
    )


def log_approval_resumed(incident_id, decision, actor):
    logger.info(
        "approval_resumed",
        incident_id=incident_id,
        decision=decision,
        actor=actor,
        timestamp=datetime.now().isoformat(),
    )


def log_action_execution(incident_id, tool, status, args=None, error=None, parallel=False):
    logger.info(
        "action_execution",
        incident_id=incident_id,
        tool=tool,
        status=status,
        args=args or {},
        error=error,
        parallel=parallel,
        timestamp=datetime.now().isoformat(),
    )


def log_verification(incident_id, tool, status, forced=False, error=None):
    logger.info(
        "verification",
        incident_id=incident_id,
        tool=tool,
        status=status,
        forced=forced,
        error=error,
        timestamp=datetime.now().isoformat(),
    )


def log_rollback(incident_id, tool, status, error=None):
    logger.info(
        "rollback",
        incident_id=incident_id,
        tool=tool,
        status=status,
        error=error,
        timestamp=datetime.now().isoformat(),
    )
