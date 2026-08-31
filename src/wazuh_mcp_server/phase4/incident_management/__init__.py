"""Layer 1: Incident Management - Database models and schema.

Incident tracking with:
- Incident tickets (UUID, status, priority, SLA)
- Risk tier classification
- Assignment and tagging
- Integration with external ticketing (Jira)
- SLA breach tracking
"""

from datetime import datetime, timedelta
from enum import Enum
from uuid import uuid4

from sqlalchemy import (
    Column,
    String,
    Integer,
    Boolean,
    DateTime,
    UUID,
    JSON,
    Text,
    Enum as SQLEnum,
    ForeignKey,
    Index,
    UniqueConstraint,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


class IncidentStatus(str, Enum):
    """Incident status values."""

    OPEN = "open"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    ESCALATED = "escalated"
    PENDING_APPROVAL = "pending_approval"
    RESOLVED = "resolved"
    CLOSED = "closed"
    ARCHIVED = "archived"


class RiskTier(str, Enum):
    """Incident risk/severity tier."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentTicket(Base):
    """Root incident ticket in Phase 4."""

    __tablename__ = "incidents"

    # Unique identifiers
    id = Column(UUID, primary_key=True, default=uuid4, index=True)
    incident_id = Column(String(32), unique=True, nullable=False, index=True)  # INC-2026-001
    
    # Status and severity
    status = Column(SQLEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True)
    risk_tier = Column(SQLEnum(RiskTier), nullable=False, index=True)
    priority = Column(Integer, nullable=False)  # 1-5, 1 = highest
    
    # Assignment
    assigned_to = Column(String(255), nullable=True, index=True)  # Username or analyst ID
    assigned_at = Column(DateTime, nullable=True)
    
    # Tracking
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    
    # SLA
    sla_hours = Column(Integer, nullable=False)  # SLA in hours
    sla_breach = Column(Boolean, default=False, index=True)
    sla_breach_at = Column(DateTime, nullable=True)
    
    # External integration
    external_ticket_id = Column(String(64), nullable=True)  # Jira issue key, etc
    external_ticket_url = Column(String(512), nullable=True)
    
    # ML context
    ml_predicted_severity = Column(String(32), nullable=True)
    ml_false_positive_prob = Column(Integer, nullable=True)  # 0-100
    ml_attack_pattern = Column(String(64), nullable=True)
    
    # Alert aggregation
    alert_count = Column(Integer, default=1, nullable=False)
    source_ip = Column(String(45), nullable=True)  # IPv4 or IPv6
    dest_ip = Column(String(45), nullable=True)
    affected_agent_ids = Column(String(1024), nullable=True)  # Comma-separated
    
    # Description/notes
    title = Column(String(512), nullable=False)
    description = Column(String(4096), nullable=True)
    
    # Relationships
    activities = relationship("IncidentActivity", back_populates="incident", cascade="all, delete-orphan")
    evidences = relationship("IncidentEvidence", back_populates="incident", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_incident_status_created", "status", "created_at"),
        Index("idx_incident_risk_sla", "risk_tier", "sla_breach"),
        Index("idx_incident_assigned", "assigned_to", "status"),
    )

    def __repr__(self):
        return f"<IncidentTicket {self.incident_id}>"

    @property
    def is_sla_breached(self) -> bool:
        """Check if SLA is breached."""
        if self.resolved_at:
            delta = self.resolved_at - self.created_at
        else:
            delta = datetime.utcnow() - self.created_at
        
        return delta > timedelta(hours=self.sla_hours)

    @property
    def time_to_resolution_hours(self) -> float:
        """Time from creation to resolution in hours."""
        if not self.resolved_at:
            return -1  # Not resolved
        delta = self.resolved_at - self.created_at
        return delta.total_seconds() / 3600.0


class IncidentActivity(Base):
    """Activity log for incident (approvals, actions, status changes)."""

    __tablename__ = "incident_activities"

    id = Column(UUID, primary_key=True, default=uuid4, index=True)
    incident_id = Column(UUID, ForeignKey("incidents.id"), nullable=False, index=True)
    
    # Activity type
    activity_type = Column(String(64), nullable=False, index=True)  # "approval", "action", "status_change", "comment"
    actor = Column(String(255), nullable=False)  # Username/system
    
    # Details
    title = Column(String(512), nullable=False)
    description = Column(String(2048), nullable=True)
    
    # Timeline
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    
    # Reference to what changed
    previous_value = Column(String(512), nullable=True)
    new_value = Column(String(512), nullable=True)
    
    # Relationship
    incident = relationship("IncidentTicket", back_populates="activities")
    
    __table_args__ = (
        Index("idx_activity_incident_type", "incident_id", "activity_type"),
    )

    def __repr__(self):
        return f"<IncidentActivity {self.activity_type} on {self.incident_id}>"


class IncidentEvidence(Base):
    """Evidence/artifacts linked to an incident."""

    __tablename__ = "incident_evidences"

    id = Column(UUID, primary_key=True, default=uuid4, index=True)
    incident_id = Column(UUID, ForeignKey("incidents.id"), nullable=False, index=True)
    
    # Evidence metadata
    evidence_type = Column(String(64), nullable=False, index=True)  # "alert", "log", "file", "network"
    title = Column(String(512), nullable=False)
    description = Column(String(2048), nullable=True)
    
    # Storage reference
    storage_path = Column(String(512), nullable=True)  # S3/MinIO path or local path
    storage_hash = Column(String(128), nullable=True)  # SHA256 for integrity (sha256:<64hex> = 71 chars)
    
    # Timeline
    collected_at = Column(DateTime, nullable=False, index=True)
    added_to_incident_at = Column(DateTime, default=datetime.utcnow)
    
    # Relevance
    relevance_score = Column(Integer, nullable=True)  # 0-100
    is_primary = Column(Boolean, default=False)  # Primary evidence for incident
    
    # Relationship
    incident = relationship("IncidentTicket", back_populates="evidences")
    
    __table_args__ = (
        Index("idx_evidence_incident_type", "incident_id", "evidence_type"),
    )

    def __repr__(self):
        return f"<IncidentEvidence {self.evidence_type}: {self.title}>"


class SLAPolicy(Base):
    """SLA policies by risk tier."""

    __tablename__ = "sla_policies"

    id = Column(UUID, primary_key=True, default=uuid4, index=True)
    risk_tier = Column(SQLEnum(RiskTier), unique=True, nullable=False, index=True)
    
    # Response times in hours
    response_time_hours = Column(Integer, nullable=False)  # Time to first response
    resolution_time_hours = Column(Integer, nullable=False)  # Time to resolution
    escalation_time_hours = Column(Integer, nullable=False)  # Time to escalate if not progressing
    
    # Escalation rules
    default_priority = Column(Integer, nullable=False)  # 1-5
    approvals_required = Column(Integer, default=1)
    
    # Notifications
    notify_on_breach = Column(Boolean, default=True)
    slack_channel = Column(String(255), nullable=True)
    
    created_at = Column(DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<SLAPolicy {self.risk_tier.value}: {self.resolution_time_hours}h>"


# Utility functions for common queries

def get_sla_hours_for_tier(risk_tier: RiskTier) -> int:
    """Get SLA hours for a risk tier (for default SLA assignment)."""
    sla_map = {
        RiskTier.LOW: 24,
        RiskTier.MEDIUM: 8,
        RiskTier.HIGH: 4,
        RiskTier.CRITICAL: 1,
    }
    return sla_map.get(risk_tier, 24)


def generate_incident_id(session) -> str:
    """Generate unique incident ID (INC-YYYY-NNNNN).

    Uses a SELECT ... FOR UPDATE on a per-year count to prevent duplicate IDs
    when multiple sessions insert concurrently.
    """
    from datetime import datetime
    from sqlalchemy import text

    today = datetime.utcnow().strftime("%Y")

    # Atomically claim the next sequence number for this year using an advisory lock
    # so concurrent inserts don't race to the same count.
    row = session.execute(
        text(
            "SELECT COUNT(*) FROM incidents "
            "WHERE incident_id LIKE :prefix"
        ),
        {"prefix": f"INC-{today}-%"},
    ).scalar()

    seq = int(row or 0) + 1
    candidate = f"INC-{today}-{seq:05d}"

    # Verify uniqueness; if taken, keep incrementing
    while True:
        exists = session.execute(
            text("SELECT 1 FROM incidents WHERE incident_id = :iid"),
            {"iid": candidate},
        ).scalar()
        if not exists:
            return candidate
        seq += 1
        candidate = f"INC-{today}-{seq:05d}"


# ── Approval Models ────────────────────────────────────────────────────────────


class ApprovalStatus(str, Enum):
    """Approval request lifecycle states."""
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class ApprovalRequest(Base):
    """Persisted HITL approval request from Phase 3 workflows.

    Created when a Phase 3 workflow reaches an approval gate for a
    medium/high/critical risk action.  Analysts approve or reject
    via the Phase 4 web UI; Phase 4 then resumes the Phase 3 workflow.
    """
    __tablename__ = "approval_requests"

    id = Column(UUID, primary_key=True, default=uuid4)
    approval_id = Column(String(32), unique=True, nullable=False, index=True)  # APR-2026-00001

    # Linkage
    incident_id = Column(String(32), nullable=True, index=True)         # Phase 4 INC-YYYY-NNNNN (may be null)
    phase3_incident_id = Column(String(128), nullable=False, index=True) # Phase 3 incident ID

    # Approval metadata
    workflow_type = Column(String(64), default="phase3_action", nullable=False)
    risk_tier = Column(SQLEnum(RiskTier), nullable=False)
    approvals_needed = Column(Integer, nullable=False, default=1)
    approvals_received = Column(Integer, nullable=False, default=0)
    status = Column(SQLEnum(ApprovalStatus), default=ApprovalStatus.PENDING, nullable=False, index=True)

    # Action payload (JSON blobs)
    proposed_action = Column(JSON, nullable=True)   # tool, args, verify, rollback, etc.
    workflow_summary = Column(Text, nullable=True)  # human-readable triage summary

    # Request context
    requested_by = Column(String(255), nullable=True)
    phase3_resume_url = Column(String(512), nullable=True)  # URL to POST resume decision to Phase 3

    # Timing
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    decided_at = Column(DateTime, nullable=True)

    notification_sent = Column(Boolean, default=False, nullable=False)

    # Completion data: filled in after Phase 3 resumes and finishes
    completion_report = Column(JSON, nullable=True)  # full RunPhase3Response from Phase 3 resume
    completion_status = Column(String(64), nullable=True)  # e.g. completed_actioned, completed_rejected

    decisions = relationship(
        "ApprovalDecision",
        back_populates="approval_request",
        cascade="all, delete-orphan",
        order_by="ApprovalDecision.decided_at",
    )

    __table_args__ = (
        Index("idx_approval_status_created", "status", "created_at"),
    )

    def __repr__(self) -> str:
        return f"<ApprovalRequest {self.approval_id}: {self.status}>"

    def to_dict(self) -> dict:
        return {
            "approval_id": self.approval_id,
            "incident_id": self.incident_id,
            "phase3_incident_id": self.phase3_incident_id,
            "workflow_type": self.workflow_type,
            "risk_tier": self.risk_tier.value if isinstance(self.risk_tier, Enum) else self.risk_tier,
            "approvals_needed": self.approvals_needed,
            "approvals_received": self.approvals_received,
            "status": self.status.value if isinstance(self.status, Enum) else self.status,
            "proposed_action": self.proposed_action,
            "workflow_summary": self.workflow_summary,
            "requested_by": self.requested_by,
            "phase3_resume_url": self.phase3_resume_url,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
            "notification_sent": self.notification_sent,
            "completion_report": self.completion_report,
            "completion_status": self.completion_status,
            "decisions": [d.to_dict() for d in self.decisions] if self.decisions else [],
        }


class ApprovalDecision(Base):
    """A single analyst decision on an approval request."""
    __tablename__ = "approval_decisions"

    id = Column(UUID, primary_key=True, default=uuid4)
    approval_id = Column(UUID, ForeignKey("approval_requests.id"), nullable=False, index=True)

    actor = Column(String(255), nullable=False)
    decision = Column(String(32), nullable=False)   # "approved" or "rejected"
    comment = Column(String(2048), nullable=True)
    decided_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    approval_request = relationship("ApprovalRequest", back_populates="decisions")

    def __repr__(self) -> str:
        return f"<ApprovalDecision {self.decision} by {self.actor}>"

    def to_dict(self) -> dict:
        return {
            "actor": self.actor,
            "decision": self.decision,
            "comment": self.comment,
            "decided_at": self.decided_at.isoformat() if self.decided_at else None,
        }


def generate_approval_id(session) -> str:
    """Generate unique approval ID (APR-YYYY-NNNNN)."""
    from sqlalchemy import func
    year = datetime.utcnow().strftime("%Y")
    count = session.query(func.count(ApprovalRequest.id)).scalar()
    return f"APR-{year}-{count + 1:05d}"
