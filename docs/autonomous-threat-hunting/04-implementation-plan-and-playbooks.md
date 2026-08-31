# Implementation Plan and Hunt Playbooks

← [Back to index](../AUTONOMOUS_THREAT_HUNTING_LOCAL_LLM.md)

---

## 8. Implementation Plan (Phased)

### Phase A: Read-only autonomous hunts

- Add a dedicated LangGraph hunt workflow in `phase3-langgraph`
- Restrict to read-only MCP tools
- Generate structured hunt reports only

### Phase B: Analyst-in-the-loop escalation

- Add explicit approval checkpoints
- Support queueing high-confidence findings for analyst action

### Phase C: Controlled auto-response (optional)

- Enable automated containment only for policy-approved scenarios
- Keep rollback verification and post-action checks mandatory

### Phase D: Automated quarantining for active breach

- Enable host isolation and related containment actions only when breach
  confidence, scope, and policy thresholds are satisfied.
- Require machine-verifiable evidence thresholds before quarantine execution.
- Keep mandatory post-action verification and rollback path per action.

## 9. Suggested Initial Hunt Playbooks

Start with high-value, low-risk use cases:

1. Credential abuse / brute-force chaining
2. Beaconing and C2 behavior hunt
3. Lateral movement indicators
4. Data exfiltration pattern hunt

Each playbook should define:

- Required signals
- Required minimum confidence
- Tool query plan
- Escalation policy

### 9.1 Database and Storage Threat Hunting Coverage

The autonomous hunt design should explicitly include project database and
storage security as first-class hunt domains.

Covered asset classes:

- relational databases used by application or platform services
- search/index stores and document stores
- object storage, artifact storage, and backup targets
- attached file shares and persistent volumes used by platform components

Primary database hunt goals:

- detect suspicious administrative access and privilege escalation
- detect anomalous query behavior and bulk data access
- detect schema tampering, unauthorized DDL, or configuration drift
- detect suspicious backup, export, or replication activity

Primary storage hunt goals:

- detect bulk read, mass delete, overwrite, or encryption-like activity
- detect unusual snapshot, retention, or bucket policy changes
- detect suspicious cross-boundary data movement and exfiltration patterns
- detect access from unexpected principals, services, or networks

Recommended first database playbooks:

1. Database privilege misuse hunt
2. Bulk query / export anomaly hunt
3. Schema and configuration tampering hunt
4. Backup and replication abuse hunt

Recommended first storage playbooks:

1. Mass object access / exfiltration hunt
2. Snapshot and retention tampering hunt
3. Backup repository integrity hunt
4. Ransomware-like delete/encrypt pattern hunt

Required signals for database hunts:

- database audit logs for auth, grants, DDL, and export activity
- slow query / high-volume query telemetry
- service-account and admin credential usage logs
- network flow evidence for database access paths
- infrastructure or secret-management changes affecting DB connectivity

Required signals for storage hunts:

- object access logs and bucket/container policy changes
- snapshot lifecycle events and backup job history
- large egress volume or repeated archive/download patterns
- file integrity or ransomware-like rename/delete bursts on mounted volumes
- IAM or service-account changes affecting storage permissions

Recommended scoring enrichments:

- baseline-aware comparison by user, service, host, time window, and data size
- higher weight for destructive actions against backups or retention controls
- higher weight for admin actions from new source locations or unusual runtimes
- separate confidence fields for exposure risk, integrity risk, and recovery risk

Containment rules for DB/storage scope:

- default to read-only hunting and analyst escalation
- do not auto-quarantine database or storage infrastructure by default
- prefer credential disablement, network restriction, or temporary access-token
  revocation over destructive storage actions
- require explicit rollback plan before any automated DB/storage containment

Example structured outputs for DB/storage hunts should add these fields:

- `asset_domain`: `database` | `storage`
- `data_risk`: `low` | `medium` | `high` | `critical`
- `integrity_risk`: `low` | `medium` | `high` | `critical`
- `recovery_impact`: `low` | `medium` | `high` | `critical`
- `suspected_actions[]`: export, grant, ddl_change, snapshot_delete, bucket_policy_change

Suggested future tool additions for this scope:

- `query_database_audit_events`
- `query_storage_access_events`
- `inspect_backup_integrity`
- `detect_mass_delete_or_encrypt_pattern`
- `check_bucket_or_snapshot_policy_drift`

This scope is not fully implemented in the current repository. It is a planned
extension of the autonomous hunt model and should be introduced first in
read-only mode with dedicated baselines and analyst review.

