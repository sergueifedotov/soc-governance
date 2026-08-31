"""Layer 3: Playbook Orchestration - Prefect workflow engine.

Playbooks define multi-step response sequences:
- Trigger definitions
- Sequential and parallel steps
- Conditional logic
- Integration with Phase 3 and L1 incidents
- Audit logging
"""

import logging
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


class PlaybookStatus(str, Enum):
    """Playbook execution status."""

    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SUSPENDED = "suspended"


class StepStatus(str, Enum):
    """Step execution status."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class PlaybookTrigger:
    """Trigger condition for playbook execution."""

    trigger_type: str  # "severity", "rule_id", "source_ip", "custom"
    condition: str  # e.g., "severity >= 8"
    description: Optional[str] = None


@dataclass
class PlaybookStep:
    """Single step in playbook execution."""

    name: str
    action: str  # "isolate_host", "block_ip", "notify", "manual_review"
    arguments: Dict[str, Any]
    on_failure: str = "abort"  # "abort", "continue", "retry"
    retry_count: int = 0
    timeout_minutes: int = 30
    status: StepStatus = StepStatus.PENDING
    result: Optional[str] = None
    error: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


@dataclass
class PlaybookDefinition:
    """Playbook YAML/dict definition."""

    name: str
    description: str
    triggers: List[PlaybookTrigger]
    steps: List[PlaybookStep]
    enabled: bool = True
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    version: str = "1.0"

    def __post_init__(self):
        if self.tags is None:
            self.tags = []


def to_playbook_definition(playbook: Any) -> PlaybookDefinition:
    """Convert a dict/object playbook payload into PlaybookDefinition."""
    if isinstance(playbook, PlaybookDefinition):
        return playbook

    if not isinstance(playbook, dict):
        raise TypeError("playbook must be a dict or PlaybookDefinition")

    triggers: List[PlaybookTrigger] = []
    for trigger in playbook.get("triggers", []):
        if isinstance(trigger, PlaybookTrigger):
            triggers.append(trigger)
        else:
            triggers.append(
                PlaybookTrigger(
                    trigger_type=trigger.get("trigger_type", "custom"),
                    condition=trigger.get("condition", ""),
                    description=trigger.get("description"),
                )
            )

    steps: List[PlaybookStep] = []
    for step in playbook.get("steps", []):
        if isinstance(step, PlaybookStep):
            steps.append(step)
        else:
            steps.append(
                PlaybookStep(
                    name=step.get("name", "unnamed_step"),
                    action=step.get("action", "manual_review"),
                    arguments=step.get("arguments", {}),
                    on_failure=step.get("on_failure", "abort"),
                    retry_count=step.get("retry_count", 0),
                    timeout_minutes=step.get("timeout_minutes", 30),
                )
            )

    return PlaybookDefinition(
        name=playbook.get("name", "unnamed_playbook"),
        description=playbook.get("description", ""),
        triggers=triggers,
        steps=steps,
        enabled=playbook.get("enabled", True),
        owner=playbook.get("owner"),
        tags=playbook.get("tags", []),
        version=playbook.get("version", "1.0"),
    )


# ============================================================================
# Example Playbooks (used in Phase 3/4 integration)
# ============================================================================


RANSOMWARE_RESPONSE_PLAYBOOK = {
    "name": "ransomware_response",
    "description": "Rapid response to ransomware detection",
    "triggers": [
        {
            "trigger_type": "rule_id",
            "condition": "rule_id in [rule_ids_for_ransomware]",
        },
        {
            "trigger_type": "severity",
            "condition": "severity >= 8",
        },
    ],
    "steps": [
        {
            "name": "isolate_host",
            "action": "wazuh_isolate_host",
            "arguments": {"agent_id": "$source_agent"},
            "on_failure": "abort",
        },
        {
            "name": "block_source_ip",
            "action": "wazuh_firewall_drop",
            "arguments": {"agent_id": "$source_agent", "src_ip": "$source_ip"},
            "on_failure": "continue",
        },
        {
            "name": "disable_user",
            "action": "wazuh_disable_user",
            "arguments": {"agent_id": "$source_agent", "username": "$compromised_user"},
            "on_failure": "continue",
        },
        {
            "name": "wait_for_isolation",
            "action": "wait",
            "arguments": {"seconds": 60},
        },
        {
            "name": "verify_isolation",
            "action": "wazuh_check_agent_isolation",
            "arguments": {"agent_id": "$source_agent", "expected": "disconnected"},
            "on_failure": "retry",
            "retry_count": 3,
        },
        {
            "name": "notify_soc",
            "action": "notify",
            "arguments": {
                "channel": "soc-alerts",
                "message": "Ransomware isolation complete: $source_agent",
            },
        },
        {
            "name": "create_incident",
            "action": "create_incident",
            "arguments": {
                "title": "Ransomware detected on $source_agent",
                "risk_tier": "critical",
            },
        },
    ],
}


BRUTE_FORCE_RESPONSE_PLAYBOOK = {
    "name": "brute_force_response",
    "description": "Mitigate brute force attack",
    "triggers": [
        {
            "trigger_type": "attack_pattern",
            "condition": "attack_pattern == 'brute_force' AND alert_count > 20",
        }
    ],
    "steps": [
        {
            "name": "block_attacker_ip",
            "action": "wazuh_firewall_drop",
            "arguments": {"agent_id": "$source_agent", "src_ip": "$attacker_ip"},
        },
        {
            "name": "reset_passwords",
            "action": "manual_review",
            "arguments": {
                "message": "Reset passwords for target accounts: $affected_users"
            },
        },
        {
            "name": "enable_mfa",
            "action": "manual_review",
            "arguments": {
                "message": "Enable MFA on accounts: $affected_users"
            },
        },
        {
            "name": "create_incident",
            "action": "create_incident",
            "arguments": {
                "title": f"Brute force attack from $attacker_ip",
                "risk_tier": "high",
            },
        },
    ],
}


class PlaybookEngine:
    """Execute playbooks in response to incidents."""

    def __init__(self, mcp_client, incident_service, audit_logger):
        """Initialize playbook engine.
        
        Args:
            mcp_client: MCP client for tool execution
            incident_service: Incident management service
            audit_logger: Audit logging service
        """
        self.mcp_client = mcp_client
        self.incident_service = incident_service
        self.audit_logger = audit_logger
        self.execution_history: List[Dict[str, Any]] = []

    async def execute_playbook(
        self,
        playbook_def: Any,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute playbook with given context.
        
        Args:
            playbook_def: Playbook definition
            context: Execution context (incident, alert data, variables)
        
        Returns:
            Execution result dict
        """
        playbook_def = to_playbook_definition(playbook_def)

        execution_id = f"exec_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"

        logger.info(
            f"Starting playbook execution: {playbook_def.name} "
            f"({execution_id})"
        )

        result = {
            "execution_id": execution_id,
            "playbook": playbook_def.name,
            "context": context,
            "status": PlaybookStatus.RUNNING,
            "steps_completed": 0,
            "steps_failed": 0,
            "started_at": datetime.utcnow(),
            "steps": [],
        }

        # Execute each step
        for step_idx, step in enumerate(playbook_def.steps):
            logger.info(f"  Executing step {step_idx + 1}/{len(playbook_def.steps)}: {step.name}")

            step_result = await self._execute_step(step, context)

            result["steps"].append(step_result)

            if step_result["status"] == StepStatus.COMPLETED:
                result["steps_completed"] += 1
            elif step_result["status"] == StepStatus.FAILED:
                result["steps_failed"] += 1

                if step.on_failure == "abort":
                    result["status"] = PlaybookStatus.FAILED
                    logger.error(
                        f"Step {step.name} failed, aborting playbook. "
                        f"Error: {step_result['error']}"
                    )
                    break
                # Continue if on_failure == "continue"

        # Finalize result
        if result["steps_failed"] == 0:
            result["status"] = PlaybookStatus.SUCCESS
        elif result["status"] != PlaybookStatus.FAILED:
            result["status"] = PlaybookStatus.SUCCESS  # Partial success

        result["completed_at"] = datetime.utcnow()
        result["duration_seconds"] = (
            result["completed_at"] - result["started_at"]
        ).total_seconds()

        # Log execution when an audit logger is available.
        if self.audit_logger is not None:
            await self.audit_logger.log_playbook_execution(result)
        else:
            logger.info("Audit logger unavailable; skipping playbook audit emission")

        logger.info(
            f"Playbook {playbook_def.name} execution complete: "
            f"{result['status'].value} "
            f"({result['steps_completed']} completed, {result['steps_failed']} failed)"
        )

        return result

    async def _execute_step(
        self,
        step: PlaybookStep,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute single step.
        
        Args:
            step: Step definition
            context: Execution context with variables
        
        Returns:
            Step execution result
        """
        step_result = {
            "name": step.name,
            "action": step.action,
            "status": StepStatus.PENDING,
            "started_at": datetime.utcnow(),
        }

        try:
            # Substitute variables (e.g., $source_agent -> value from context)
            resolved_args = self._resolve_variables(step.arguments, context)

            logger.debug(f"Executing {step.action} with args: {resolved_args}")

            # Execute action
            if step.action == "notify":
                await self._execute_notification(resolved_args)
            elif step.action == "wait":
                await self._execute_wait(resolved_args)
            elif step.action == "manual_review":
                await self._execute_manual_review(resolved_args)
            elif step.action == "create_incident":
                await self._execute_create_incident(resolved_args, context)
            else:
                if self.mcp_client is None:
                    raise RuntimeError("MCP client is not configured for playbook engine")

                # Normalize legacy aliases used in playbook templates.
                action_name = step.action
                if action_name == "wazuh_check_agent_status":
                    action_name = "wazuh_check_agent_isolation"

                # MCP tool execution
                result = await self.mcp_client.execute_tool(
                    action_name, resolved_args
                )
                step_result["result"] = result

            step_result["status"] = StepStatus.COMPLETED

        except Exception as e:
            logger.error(f"Step {step.name} failed: {e}")
            step_result["status"] = StepStatus.FAILED
            step_result["error"] = str(e)

        step_result["completed_at"] = datetime.utcnow()
        return step_result

    @staticmethod
    def _resolve_variables(
        args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Resolve variable placeholders ($variable_name) in arguments."""
        resolved = {}

        for key, value in args.items():
            if isinstance(value, str) and value.startswith("$"):
                var_name = value[1:]  # Remove $
                resolved[key] = context.get(var_name, value)
            else:
                resolved[key] = value

        return resolved

    @staticmethod
    async def _execute_notification(args: Dict[str, Any]) -> None:
        """Execute notification step."""
        logger.info(f"Notification: {args.get('message', 'N/A')}")

    @staticmethod
    async def _execute_wait(args: Dict[str, Any]) -> None:
        """Execute wait step."""
        import asyncio

        seconds = args.get("seconds", 0)
        logger.info(f"Waiting {seconds} seconds...")
        await asyncio.sleep(seconds)

    @staticmethod
    async def _execute_manual_review(args: Dict[str, Any]) -> None:
        """Execute manual review step."""
        logger.info(f"Manual review required: {args.get('message', 'N/A')}")

    async def _execute_create_incident(
        self,
        args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> None:
        """Execute create incident step."""
        from incident_management import RiskTier
        from incident_management.api import IncidentCreate

        if self.incident_service is None:
            logger.info("Incident service unavailable; skipping create_incident step")
            return

        incident_data = IncidentCreate(
            title=args.get("title", "Incident from playbook"),
            description=args.get("description", ""),
            risk_tier=RiskTier(args.get("risk_tier", "medium")),
        )

        self.incident_service.create_incident(incident_data)
        logger.info(f"Created incident: {incident_data.title}")
