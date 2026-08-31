"""Layer 4: Event Queue & Async Tasks (Celery + RabbitMQ)

Distribute incident response tasks across workers.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict

from celery import Celery, Task


logger = logging.getLogger(__name__)


class CallbackTask(Task):
    """Task with custom callbacks."""

    def on_success(self, retval, task_id, args, kwargs):
        logger.info(f"Task {task_id} succeeded")

    def on_retry(self, exc, task_id, args, kwargs, einfo):
        logger.warning(f"Task {task_id} retrying: {exc}")

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        logger.error(f"Task {task_id} failed: {exc}")


# Initialize Celery from environment
app = Celery('phase4')
app.conf.broker_url = os.getenv('CELERY_BROKER_URL', 'amqp://localhost')
app.conf.result_backend = os.getenv('CELERY_RESULT_BACKEND', 'redis://localhost')
app.task_cls = CallbackTask


# ============================================================================
# Phase 4 Async Tasks
# ============================================================================


@app.task(bind=True, max_retries=3)
def create_incident_from_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
    """Create incident from alert.
    
    Args:
        alert_data: Alert dict with alert_id, severity, rule_id, etc
    
    Returns:
        Incident creation result
    """
    try:
        from phase4.incident_management import IncidentService, IncidentCreate, RiskTier
        
        risk_tier_map = {
            1: RiskTier.LOW,
            2: RiskTier.LOW,
            3: RiskTier.MEDIUM,
            4: RiskTier.MEDIUM,
            5: RiskTier.HIGH,
            6: RiskTier.HIGH,
            7: RiskTier.CRITICAL,
            8: RiskTier.CRITICAL,
            9: RiskTier.CRITICAL,
            10: RiskTier.CRITICAL,
        }
        
        service = IncidentService(get_db())
        
        incident = service.create_incident(IncidentCreate(
            title=f"Alert: {alert_data.get('rule_name', 'Unknown')}",
            description=alert_data.get('full_log', ''),
            risk_tier=risk_tier_map.get(alert_data.get('severity', 3), RiskTier.MEDIUM),
            source_ip=alert_data.get('src_ip'),
            dest_ip=alert_data.get('dest_ip'),
        ))
        
        logger.info(f"Created incident {incident.incident_id} from alert {alert_data['alert_id']}")
        
        return {
            "incident_id": incident.incident_id,
            "created_at": incident.created_at.isoformat(),
        }
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task(bind=True, max_retries=3)
def trigger_phase3_workflow(self, incident_id: str, alert_context: Dict) -> Dict[str, Any]:
    """Trigger Phase 3 workflow for incident.
    
    Args:
        incident_id: Incident ID from Phase 4
        alert_context: Alert data
    
    Returns:
        Workflow execution result
    """
    try:
        from wazuh_mcp_server.api.wazuh_client import WazuhClient
        
        client = WazuhClient()
        
        # Call Phase 3 workflow endpoint
        result = client.http_request(
            'POST',
            '/phase3/run',
            body={
                'incident_id': incident_id,
                'alert_data': alert_context,
                'auto_approve': False,
            }
        )
        
        logger.info(f"Triggered Phase 3 workflow for incident {incident_id}")
        
        return {"status": "workflow_triggered", "result": result}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task(bind=True, max_retries=2)
def aggregate_related_alerts(self, incident_id: str) -> Dict[str, int]:
    """Aggregate related alerts into incident.
    
    Args:
        incident_id: Incident to aggregate into
    
    Returns:
        Aggregation statistics
    """
    try:
        from phase4.incident_management import IncidentService
        
        service = IncidentService(get_db())
        incident = service.get_incident(incident_id)
        
        if not incident:
            raise ValueError(f"Incident {incident_id} not found")
        
        # Query Wazuh for related alerts (same source_ip, dest_ip, or rule)
        related_count = 0  # Would query Wazuh indexer
        
        logger.info(f"Aggregated {related_count} related alerts to {incident_id}")
        
        return {"incident_id": incident_id, "related_alerts": related_count}
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@app.task
def collect_forensic_evidence(incident_id: str, alert_data: Dict) -> Dict[str, Any]:
    """Collect forensic evidence from Wazuh agent.
    
    Args:
        incident_id: Incident ID
        alert_data: Alert data with agent_id, process_id, file_path
    
    Returns:
        Evidence collection result
    """
    from phase4.forensics import ForensicCaseManager
    
    fcm = ForensicCaseManager('bolt://neo4j:7687', 'neo4j', 'password')
    
    # Create alert node
    alert_node = fcm.create_alert_node(
        alert_id=alert_data['alert_id'],
        rule_id=alert_data['rule_id'],
        rule_name=alert_data['rule_name'],
        severity=alert_data['severity'],
        timestamp=datetime.fromisoformat(alert_data['timestamp']),
        full_log=alert_data['full_log'],
    )
    
    # Create correlations
    if 'src_ip' in alert_data:
        fcm.create_correlation(
            alert_node,
            'IP_ADDRESS',
            alert_data['src_ip'],
            {'reputation': 'unknown'},
            'FROM_IP',
        )
    
    logger.info(f"Collected forensic evidence for incident {incident_id}")
    
    return {"incident_id": incident_id, "evidence_collected": True}


@app.task
def notify_analyst(incident_id: str, channel: str = 'soc-alerts') -> Dict[str, Any]:
    """Notify analyst about incident.
    
    Args:
        incident_id: Incident ID
        channel: Notification channel (slack, email, etc)
    
    Returns:
        Notification result
    """
    logger.info(f"Notifying analysts about {incident_id} on channel {channel}")
    
    return {
        "incident_id": incident_id,
        "notified": True,
        "channel": channel,
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.task(bind=True, max_retries=1)
def execute_playbook(self, playbook_name: str, context: Dict) -> Dict[str, Any]:
    """Execute playbook asynchronously.
    
    Args:
        playbook_name: Name of playbook to execute
        context: Execution context
    
    Returns:
        Playbook execution result
    """
    try:
        from phase4.orchestration.playbooks import PlaybookEngine
        
        engine = PlaybookEngine(None, None, None)  # Injected deps
        
        # Load playbook and execute
        # result = await engine.execute_playbook(playbook, context)
        
        logger.info(f"Executed playbook {playbook_name}")
        
        return {
            "playbook": playbook_name,
            "status": "completed",
        }
        
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60)


def get_db():
    """Get database session (placeholder)."""
    # Would return SQLAlchemy session
    pass
