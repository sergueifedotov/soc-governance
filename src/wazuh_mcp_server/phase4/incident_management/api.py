"""Layer 1 Incident Management - REST API and CRUD operations.

Endpoints:
- POST/GET /incidents
- PUT /incidents/{id}
- POST /incidents/{id}/activities
- POST /incidents/{id}/assign
- POST /incidents/{id}/resolve
- POST /incidents/{id}/escalate
"""

import logging
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from uuid import UUID

from fastapi import APIRouter, HTTPException, Query, Body
from pydantic import BaseModel
from sqlalchemy.orm import Session

from . import (
    IncidentTicket,
    IncidentStatus,
    RiskTier,
    IncidentActivity,
    IncidentEvidence,
    SLAPolicy,
    generate_incident_id,
    get_sla_hours_for_tier,
)

logger = logging.getLogger(__name__)

# ============================================================================
# Pydantic Models (Request/Response)
# ============================================================================


class IncidentCreate(BaseModel):
    """Create incident request."""

    title: str
    description: Optional[str] = None
    risk_tier: RiskTier
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    affected_agent_ids: Optional[str] = None


class IncidentUpdate(BaseModel):
    """Update incident request."""

    title: Optional[str] = None
    description: Optional[str] = None
    risk_tier: Optional[RiskTier] = None
    status: Optional[IncidentStatus] = None
    priority: Optional[int] = None
    assigned_to: Optional[str] = None


class IncidentResponse(BaseModel):
    """Incident response."""

    id: UUID
    incident_id: str
    title: str
    description: Optional[str]
    status: IncidentStatus
    risk_tier: RiskTier
    priority: int
    assigned_to: Optional[str]
    source_ip: Optional[str]
    dest_ip: Optional[str]
    alert_count: int
    created_at: datetime
    updated_at: datetime
    resolved_at: Optional[datetime]
    sla_breach: bool
    sla_hours: int
    external_ticket_id: Optional[str]
    ml_predicted_severity: Optional[str]
    ml_false_positive_prob: Optional[int]
    ml_attack_pattern: Optional[str]

    class Config:
        from_attributes = True


class IncidentActivityCreate(BaseModel):
    """Create activity log."""

    activity_type: str
    actor: str
    title: str
    description: Optional[str] = None
    previous_value: Optional[str] = None
    new_value: Optional[str] = None


class IncidentAssignRequest(BaseModel):
    """Assign incident request."""

    assigned_to: str
    actor: str


class IncidentResolveRequest(BaseModel):
    """Resolve incident request."""

    resolved_by: str
    notes: Optional[str] = None


class IncidentEscalateRequest(BaseModel):
    """Escalate incident request."""

    escalated_by: str
    reason: str


class IncidentCloseRequest(BaseModel):
    """Close incident request."""

    closed_by: str
    notes: Optional[str] = None


class IncidentArchiveRequest(BaseModel):
    """Archive incident request."""

    archived_by: str
    reason: Optional[str] = None


class IncidentEvidenceCreate(BaseModel):
    """Add evidence to incident request."""

    evidence_type: str
    title: str
    description: Optional[str] = None
    storage_path: Optional[str] = None
    storage_hash: Optional[str] = None
    collected_at: datetime
    relevance_score: Optional[int] = None
    is_primary: bool = False


class IncidentEvidenceResponse(BaseModel):
    """Evidence response."""

    id: UUID
    incident_id: UUID
    evidence_type: str
    title: str
    description: Optional[str]
    storage_path: Optional[str]
    storage_hash: Optional[str]
    collected_at: datetime
    added_to_incident_at: datetime
    relevance_score: Optional[int]
    is_primary: bool

    class Config:
        from_attributes = True


class IncidentActivityResponse(BaseModel):
    """Activity log response."""

    id: UUID
    incident_id: UUID
    activity_type: str
    actor: str
    title: str
    description: Optional[str]
    created_at: datetime
    previous_value: Optional[str]
    new_value: Optional[str]

    class Config:
        from_attributes = True


class IncidentStatsResponse(BaseModel):
    """Aggregate incident statistics response."""

    total_incidents: int
    by_status: Dict[str, int]
    by_risk_tier: Dict[str, int]
    sla_breaches: int
    sla_breach_rate: float
    unassigned_count: int
    critical_open_count: int


class SLAPolicyResponse(BaseModel):
    """SLA policy response."""

    id: UUID
    risk_tier: RiskTier
    response_time_hours: int
    resolution_time_hours: int
    escalation_time_hours: int
    default_priority: int
    approvals_required: int
    notify_on_breach: bool
    slack_channel: Optional[str]

    class Config:
        from_attributes = True


# ============================================================================
# Business Logic Service
# ============================================================================


class IncidentService:
    """Service for incident management business logic."""

    def __init__(self, db: Session):
        self.db = db

    def create_incident(self, data: IncidentCreate) -> IncidentTicket:
        """Create new incident."""
        incident_id = generate_incident_id(self.db)
        sla_hours = get_sla_hours_for_tier(data.risk_tier)

        incident = IncidentTicket(
            incident_id=incident_id,
            title=data.title,
            description=data.description,
            risk_tier=data.risk_tier,
            priority=self._priority_from_risk(data.risk_tier),
            status=IncidentStatus.OPEN,
            source_ip=data.source_ip,
            dest_ip=data.dest_ip,
            affected_agent_ids=data.affected_agent_ids,
            sla_hours=sla_hours,
        )

        self.db.add(incident)
        self.db.commit()

        logger.info(f"Created incident {incident_id}")
        return incident

    def get_incident(self, incident_id: str) -> Optional[IncidentTicket]:
        """Get incident by human-readable ID (e.g. INC-2026-00001)."""
        return self.db.query(IncidentTicket).filter(
            IncidentTicket.incident_id == incident_id
        ).first()

    def list_incidents(
        self,
        status: Optional[IncidentStatus] = None,
        risk_tier: Optional[RiskTier] = None,
        assigned_to: Optional[str] = None,
        skip: int = 0,
        limit: int = 100,
    ) -> List[IncidentTicket]:
        """List incidents with filtering."""
        query = self.db.query(IncidentTicket)

        if status:
            query = query.filter(IncidentTicket.status == status)
        if risk_tier:
            query = query.filter(IncidentTicket.risk_tier == risk_tier)
        if assigned_to:
            query = query.filter(IncidentTicket.assigned_to == assigned_to)

        return (
            query.order_by(IncidentTicket.created_at.desc())
            .offset(skip)
            .limit(limit)
            .all()
        )

    def update_incident(
        self, incident_id: str, data: IncidentUpdate
    ) -> IncidentTicket:
        """Update incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        if data.title is not None:
            incident.title = data.title
        if data.description is not None:
            incident.description = data.description
        if data.risk_tier is not None:
            incident.risk_tier = data.risk_tier
        if data.status is not None:
            incident.status = data.status
        if data.priority is not None:
            incident.priority = data.priority
        if data.assigned_to is not None:
            incident.assigned_to = data.assigned_to
            incident.assigned_at = datetime.utcnow()

        incident.updated_at = datetime.utcnow()
        self.db.commit()

        logger.info(f"Updated incident {incident.incident_id}")
        return incident

    def assign_incident(
        self, incident_id: str, req: IncidentAssignRequest
    ) -> IncidentTicket:
        """Assign incident to analyst."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        prev_assigned = incident.assigned_to or "unassigned"
        incident.assigned_to = req.assigned_to
        incident.assigned_at = datetime.utcnow()
        incident.status = IncidentStatus.ASSIGNED

        # Log activity
        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type="assignment",
            actor=req.actor,
            title=f"Assigned to {req.assigned_to}",
            previous_value=prev_assigned,
            new_value=req.assigned_to,
        )
        self.db.add(activity)
        self.db.commit()

        logger.info(f"Assigned {incident.incident_id} to {req.assigned_to}")
        return incident

    def resolve_incident(
        self, incident_id: str, req: IncidentResolveRequest
    ) -> IncidentTicket:
        """Resolve incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident.status = IncidentStatus.RESOLVED
        incident.resolved_at = datetime.utcnow()

        # Check if SLA breached
        sla_deadline = incident.created_at + timedelta(hours=incident.sla_hours)
        if incident.resolved_at > sla_deadline:
            incident.sla_breach = True
            incident.sla_breach_at = incident.resolved_at

        # Log activity
        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type="resolution",
            actor=req.resolved_by,
            title="Incident resolved",
            description=req.notes,
            new_value="resolved",
        )
        self.db.add(activity)
        self.db.commit()

        logger.info(f"Resolved {incident.incident_id}, SLA breach: {incident.sla_breach}")
        return incident

    def escalate_incident(
        self, incident_id: str, req: IncidentEscalateRequest
    ) -> IncidentTicket:
        """Escalate incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident.status = IncidentStatus.ESCALATED
        incident.priority = max(incident.priority - 1, 1)  # Increase priority (lower number)

        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type="escalation",
            actor=req.escalated_by,
            title="Incident escalated",
            description=req.reason,
        )
        self.db.add(activity)
        self.db.commit()

        logger.info(f"Escalated {incident.incident_id}: {req.reason}")
        return incident

    def add_activity(
        self, incident_id: str, data: IncidentActivityCreate
    ) -> IncidentActivity:
        """Add activity to incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type=data.activity_type,
            actor=data.actor,
            title=data.title,
            description=data.description,
            previous_value=data.previous_value,
            new_value=data.new_value,
        )
        self.db.add(activity)
        self.db.commit()

        return activity

    def close_incident(self, incident_id: str, req: "IncidentCloseRequest") -> IncidentTicket:
        """Close incident (final state after resolution)."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident.status = IncidentStatus.CLOSED

        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type="closure",
            actor=req.closed_by,
            title="Incident closed",
            description=req.notes,
            new_value="closed",
        )
        self.db.add(activity)
        self.db.commit()

        logger.info(f"Closed {incident.incident_id}")
        return incident

    def archive_incident(self, incident_id: str, req: "IncidentArchiveRequest") -> IncidentTicket:
        """Archive incident for long-term retention."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        incident.status = IncidentStatus.ARCHIVED

        activity = IncidentActivity(
            incident_id=incident.id,
            activity_type="archive",
            actor=req.archived_by,
            title="Incident archived",
            description=req.reason,
            new_value="archived",
        )
        self.db.add(activity)
        self.db.commit()

        logger.info(f"Archived {incident.incident_id}")
        return incident

    def get_stats(self) -> Dict[str, Any]:
        """Get aggregate incident statistics."""
        open_statuses = {IncidentStatus.OPEN, IncidentStatus.ASSIGNED, IncidentStatus.INVESTIGATING}

        all_incidents = self.db.query(IncidentTicket).all()

        by_status: Dict[str, int] = {}
        by_risk_tier: Dict[str, int] = {}
        sla_breaches = 0
        unassigned = 0
        critical_open = 0

        for inc in all_incidents:
            sk = inc.status.value if hasattr(inc.status, "value") else str(inc.status)
            by_status[sk] = by_status.get(sk, 0) + 1

            rk = inc.risk_tier.value if hasattr(inc.risk_tier, "value") else str(inc.risk_tier)
            by_risk_tier[rk] = by_risk_tier.get(rk, 0) + 1

            if inc.sla_breach:
                sla_breaches += 1
            if not inc.assigned_to:
                unassigned += 1
            if inc.risk_tier == RiskTier.CRITICAL and inc.status in open_statuses:
                critical_open += 1

        total = len(all_incidents)
        return {
            "total_incidents": total,
            "by_status": by_status,
            "by_risk_tier": by_risk_tier,
            "sla_breaches": sla_breaches,
            "sla_breach_rate": round(100.0 * sla_breaches / total, 2) if total else 0.0,
            "unassigned_count": unassigned,
            "critical_open_count": critical_open,
        }

    def list_activities(self, incident_id: str) -> List[IncidentActivity]:
        """List all activities for an incident, newest first."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return (
            self.db.query(IncidentActivity)
            .filter(IncidentActivity.incident_id == incident.id)
            .order_by(IncidentActivity.created_at.desc())
            .all()
        )

    def add_evidence(self, incident_id: str, data: "IncidentEvidenceCreate") -> IncidentEvidence:
        """Attach an evidence artifact to an incident."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        evidence = IncidentEvidence(
            incident_id=incident.id,
            evidence_type=data.evidence_type,
            title=data.title,
            description=data.description,
            storage_path=data.storage_path,
            storage_hash=data.storage_hash,
            collected_at=data.collected_at,
            relevance_score=data.relevance_score,
            is_primary=data.is_primary,
        )
        self.db.add(evidence)
        self.db.commit()

        logger.info(f"Added {data.evidence_type} evidence to {incident.incident_id}")
        return evidence

    def list_evidence(self, incident_id: str) -> List[IncidentEvidence]:
        """List all evidence for an incident, newest collected first."""
        incident = self.get_incident(incident_id)
        if not incident:
            raise HTTPException(status_code=404, detail="Incident not found")

        return (
            self.db.query(IncidentEvidence)
            .filter(IncidentEvidence.incident_id == incident.id)
            .order_by(IncidentEvidence.collected_at.desc())
            .all()
        )

    @staticmethod
    def _priority_from_risk(risk_tier: RiskTier) -> int:
        """Map risk tier to priority (1-5, 1=highest)."""
        priority_map = {
            RiskTier.LOW: 5,
            RiskTier.MEDIUM: 3,
            RiskTier.HIGH: 2,
            RiskTier.CRITICAL: 1,
        }
        return priority_map.get(risk_tier, 3)


# ============================================================================
# FastAPI Router
# ============================================================================


def create_incident_router(session_factory):
    """Create FastAPI router for incident management.

    ``session_factory`` must be a callable (e.g. SQLAlchemy ``sessionmaker``)
    that returns a new Session on each call so that every request gets its own
    isolated database session.
    """
    from contextlib import contextmanager

    router = APIRouter(prefix="/incidents", tags=["incidents"])

    @contextmanager
    def _db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    # ------------------------------------------------------------------
    # /incidents/stats  – must be declared BEFORE /{incident_id} so that
    # FastAPI does not match the literal "stats" as an incident UUID.
    # ------------------------------------------------------------------

    @router.get("/stats", response_model=IncidentStatsResponse)
    def get_stats():
        """Return aggregate incident statistics (counts by status, risk tier, SLA)."""
        with _db() as db:
            return IncidentService(db).get_stats()

    # ------------------------------------------------------------------
    # Standard CRUD
    # ------------------------------------------------------------------

    @router.post("", response_model=IncidentResponse)
    def create_incident(request: IncidentCreate):
        """Create a new incident."""
        with _db() as db:
            return IncidentService(db).create_incident(request)

    @router.get("", response_model=List[IncidentResponse])
    def list_incidents(
        status: Optional[str] = Query(None),
        risk_tier: Optional[str] = Query(None),
        assigned_to: Optional[str] = Query(None),
        skip: int = Query(0, ge=0),
        limit: int = Query(100, ge=1, le=500),
    ):
        """List incidents with optional filters."""
        parsed_status = IncidentStatus(status) if status else None
        parsed_risk = RiskTier(risk_tier) if risk_tier else None
        with _db() as db:
            return IncidentService(db).list_incidents(
                status=parsed_status,
                risk_tier=parsed_risk,
                assigned_to=assigned_to,
                skip=skip,
                limit=limit,
            )

    @router.get("/{incident_id}", response_model=IncidentResponse)
    def get_incident(incident_id: str):
        """Get a single incident by UUID."""
        with _db() as db:
            incident = IncidentService(db).get_incident(incident_id)
            if not incident:
                raise HTTPException(status_code=404, detail="Incident not found")
            return incident

    @router.put("/{incident_id}", response_model=IncidentResponse)
    def update_incident(incident_id: str, request: IncidentUpdate):
        """Update incident fields."""
        with _db() as db:
            return IncidentService(db).update_incident(incident_id, request)

    # ------------------------------------------------------------------
    # Lifecycle transitions
    # ------------------------------------------------------------------

    @router.post("/{incident_id}/assign", response_model=IncidentResponse)
    def assign_incident(incident_id: str, request: IncidentAssignRequest):
        """Assign incident to an analyst."""
        with _db() as db:
            return IncidentService(db).assign_incident(incident_id, request)

    @router.post("/{incident_id}/resolve", response_model=IncidentResponse)
    def resolve_incident(incident_id: str, request: IncidentResolveRequest):
        """Mark incident as resolved and compute SLA breach."""
        with _db() as db:
            return IncidentService(db).resolve_incident(incident_id, request)

    @router.post("/{incident_id}/escalate", response_model=IncidentResponse)
    def escalate_incident(incident_id: str, request: IncidentEscalateRequest):
        """Escalate incident priority."""
        with _db() as db:
            return IncidentService(db).escalate_incident(incident_id, request)

    @router.post("/{incident_id}/close", response_model=IncidentResponse)
    def close_incident(incident_id: str, request: IncidentCloseRequest):
        """Close a resolved incident."""
        with _db() as db:
            return IncidentService(db).close_incident(incident_id, request)

    @router.post("/{incident_id}/archive", response_model=IncidentResponse)
    def archive_incident(incident_id: str, request: IncidentArchiveRequest):
        """Archive an incident for long-term retention."""
        with _db() as db:
            return IncidentService(db).archive_incident(incident_id, request)

    # ------------------------------------------------------------------
    # Activities
    # ------------------------------------------------------------------

    @router.post("/{incident_id}/activities", response_model=Dict[str, Any])
    def add_activity(incident_id: str, request: IncidentActivityCreate):
        """Append an activity log entry to an incident."""
        with _db() as db:
            activity = IncidentService(db).add_activity(incident_id, request)
            return {"id": str(activity.id), "created_at": activity.created_at.isoformat()}

    @router.get("/{incident_id}/activities", response_model=List[IncidentActivityResponse])
    def list_activities(incident_id: str):
        """List all activity log entries for an incident (newest first)."""
        with _db() as db:
            return IncidentService(db).list_activities(incident_id)

    # ------------------------------------------------------------------
    # Evidence
    # ------------------------------------------------------------------

    @router.post("/{incident_id}/evidence", response_model=IncidentEvidenceResponse)
    def add_evidence(incident_id: str, request: IncidentEvidenceCreate):
        """Attach an evidence artifact to an incident."""
        with _db() as db:
            return IncidentService(db).add_evidence(incident_id, request)

    @router.get("/{incident_id}/evidence", response_model=List[IncidentEvidenceResponse])
    def list_evidence(incident_id: str):
        """List all evidence artifacts for an incident (newest collected first)."""
        with _db() as db:
            return IncidentService(db).list_evidence(incident_id)

    return router


# ============================================================================
# SLA Policy Router
# ============================================================================


_DEFAULT_SLA_POLICIES = [
    {
        "risk_tier": RiskTier.LOW,
        "response_time_hours": 8,
        "resolution_time_hours": 24,
        "escalation_time_hours": 16,
        "default_priority": 5,
        "approvals_required": 1,
        "notify_on_breach": True,
    },
    {
        "risk_tier": RiskTier.MEDIUM,
        "response_time_hours": 2,
        "resolution_time_hours": 8,
        "escalation_time_hours": 4,
        "default_priority": 3,
        "approvals_required": 1,
        "notify_on_breach": True,
    },
    {
        "risk_tier": RiskTier.HIGH,
        "response_time_hours": 1,
        "resolution_time_hours": 4,
        "escalation_time_hours": 2,
        "default_priority": 2,
        "approvals_required": 2,
        "notify_on_breach": True,
    },
    {
        "risk_tier": RiskTier.CRITICAL,
        "response_time_hours": 0,
        "resolution_time_hours": 1,
        "escalation_time_hours": 0,
        "default_priority": 1,
        "approvals_required": 2,
        "notify_on_breach": True,
    },
]


def create_sla_router(session_factory):
    """Create FastAPI router for SLA policy management."""
    from contextlib import contextmanager

    router = APIRouter(prefix="/sla-policies", tags=["sla-policies"])

    @contextmanager
    def _db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    @router.get("", response_model=List[SLAPolicyResponse])
    def list_sla_policies():
        """List all configured SLA policies."""
        with _db() as db:
            return db.query(SLAPolicy).order_by(SLAPolicy.risk_tier).all()

    @router.post("/seed", response_model=List[SLAPolicyResponse])
    def seed_sla_policies():
        """Upsert the default SLA policies for all four risk tiers.

        Safe to call repeatedly — existing policies are returned unchanged,
        only missing tiers are created.
        """
        with _db() as db:
            result = []
            for defaults in _DEFAULT_SLA_POLICIES:
                existing = (
                    db.query(SLAPolicy)
                    .filter(SLAPolicy.risk_tier == defaults["risk_tier"])
                    .first()
                )
                if existing:
                    result.append(existing)
                else:
                    policy = SLAPolicy(**defaults)
                    db.add(policy)
                    result.append(policy)
            db.commit()
            return result

    return router
