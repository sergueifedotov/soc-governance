"""Sprint 4 / Phase C: RBAC, policy lifecycle, signed bundles, audit integrity."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

try:
    import jwt
except Exception:  # pragma: no cover
    jwt = None  # type: ignore


ROLE_PERMISSIONS: Dict[str, frozenset] = {
    "admin": frozenset(
        {
            "policy:read",
            "policy:write",
            "policy:approve",
            "policy:rollback",
            "bundle:apply",
            "bundle:sign",
            "audit:read",
            "audit:purge",
            "usage:read",
            "governance:read",
            "config:write",
        }
    ),
    "operator": frozenset(
        {
            "policy:read",
            "policy:write",
            "bundle:apply",
            "audit:read",
            "usage:read",
            "governance:read",
        }
    ),
    "auditor": frozenset(
        {
            "policy:read",
            "audit:read",
            "usage:read",
            "governance:read",
        }
    ),
}

VALID_ROLES = frozenset(ROLE_PERMISSIONS.keys())


@dataclass(frozen=True)
class AuthContext:
    subject: str
    role: str
    auth_method: str


def parse_governance_profile(raw: Any) -> Dict[str, Any]:
    config = raw if isinstance(raw, dict) else {}
    rbac_raw = config.get("rbac") if isinstance(config.get("rbac"), dict) else {}
    lifecycle_raw = config.get("policy_lifecycle") if isinstance(config.get("policy_lifecycle"), dict) else {}
    signing_raw = config.get("signing") if isinstance(config.get("signing"), dict) else {}
    audit_raw = config.get("audit_chain") if isinstance(config.get("audit_chain"), dict) else {}
    oidc_raw = config.get("oidc") if isinstance(config.get("oidc"), dict) else {}

    tokens: List[Dict[str, str]] = []
    for entry in rbac_raw.get("api_tokens") or []:
        if not isinstance(entry, dict):
            continue
        token = str(entry.get("token", "")).strip()
        role = str(entry.get("role", "")).strip().lower()
        subject = str(entry.get("subject", role or "token")).strip() or role
        if token and role in VALID_ROLES:
            tokens.append({"token": token, "role": role, "subject": subject})

    signing_key = os.getenv("MCP_PROXY_POLICY_SIGNING_KEY", "").strip() or str(
        signing_raw.get("signing_key", "")
    ).strip()

    return {
        "enabled": bool(config.get("enabled", False)),
        "rbac": {
            "enabled": bool(rbac_raw.get("enabled", True)),
            "api_tokens": tokens,
        },
        "policy_lifecycle": {
            "enabled": bool(lifecycle_raw.get("enabled", True)),
            "require_approval_for_writes": bool(lifecycle_raw.get("require_approval_for_writes", False)),
            "max_versions": max(1, int(lifecycle_raw.get("max_versions", 50))),
            "auto_version_on_write": bool(lifecycle_raw.get("auto_version_on_write", True)),
        },
        "signing": {
            "enabled": bool(signing_raw.get("enabled", False)),
            "require_signature_on_apply": bool(signing_raw.get("require_signature_on_apply", False)),
            "signing_key": signing_key,
            "algorithm": str(signing_raw.get("algorithm", "hmac-sha256")).strip().lower(),
        },
        "audit_chain": {
            "enabled": bool(audit_raw.get("enabled", False)),
        },
        "oidc": {
            "enabled": bool(oidc_raw.get("enabled", False)),
            "issuer": str(oidc_raw.get("issuer", "")).strip(),
            "audience": str(oidc_raw.get("audience", "mcp-security-proxy")).strip(),
            "jwt_secret": os.getenv("MCP_PROXY_OIDC_JWT_SECRET", "").strip()
            or str(oidc_raw.get("jwt_secret", "")).strip(),
            "role_claim": str(oidc_raw.get("role_claim", "role")).strip(),
            "subject_claim": str(oidc_raw.get("subject_claim", "sub")).strip(),
        },
    }


def governance_profile_from_policy(policy: Any) -> Dict[str, Any]:
    raw = getattr(policy, "governance", None)
    return raw if isinstance(raw, dict) else parse_governance_profile({})


def _decode_oidc_jwt(token: str, oidc: Dict[str, Any]) -> Optional[AuthContext]:
    if not oidc.get("enabled") or not jwt:
        return None
    secret = str(oidc.get("jwt_secret", "")).strip()
    if not secret:
        return None
    try:
        claims = jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            audience=str(oidc.get("audience", "")).strip() or None,
            options={"verify_aud": bool(oidc.get("audience"))},
        )
    except Exception:
        return None
    if not isinstance(claims, dict):
        return None
    role = str(claims.get(oidc.get("role_claim", "role"), "")).strip().lower()
    if role not in VALID_ROLES:
        role = "auditor"
    subject = str(claims.get(oidc.get("subject_claim", "sub"), "oidc-user")).strip() or "oidc-user"
    return AuthContext(subject=subject, role=role, auth_method="oidc_jwt")


def resolve_auth(
    authorization: Optional[str],
    *,
    proxy_api_key: str,
    governance: Dict[str, Any],
) -> Optional[AuthContext]:
    if not authorization or not authorization.startswith("Bearer "):
        return None
    token = authorization.split(" ", 1)[1].strip()
    if not token:
        return None

    if not proxy_api_key and not governance.get("enabled"):
        return AuthContext(subject="anonymous", role="admin", auth_method="open")

    oidc = governance.get("oidc") if isinstance(governance.get("oidc"), dict) else {}
    oidc_ctx = _decode_oidc_jwt(token, oidc)
    if oidc_ctx is not None:
        return oidc_ctx

    if proxy_api_key and token == proxy_api_key:
        return AuthContext(subject="proxy-api-key", role="admin", auth_method="api_key")

    if governance.get("enabled"):
        rbac = governance.get("rbac") if isinstance(governance.get("rbac"), dict) else {}
        if rbac.get("enabled", True):
            for entry in rbac.get("api_tokens") or []:
                if isinstance(entry, dict) and token == str(entry.get("token", "")).strip():
                    role = str(entry.get("role", "")).strip().lower()
                    if role in VALID_ROLES:
                        return AuthContext(
                            subject=str(entry.get("subject", role)).strip() or role,
                            role=role,
                            auth_method="rbac_token",
                        )
        return None

    if not proxy_api_key:
        return AuthContext(subject="anonymous", role="admin", auth_method="open")
    return None


def has_permission(role: str, permission: str) -> bool:
    perms = ROLE_PERMISSIONS.get(role, frozenset())
    return permission in perms


def public_governance_status(governance: Dict[str, Any]) -> Dict[str, Any]:
    oidc = governance.get("oidc") if isinstance(governance.get("oidc"), dict) else {}
    signing = governance.get("signing") if isinstance(governance.get("signing"), dict) else {}
    lifecycle = governance.get("policy_lifecycle") if isinstance(governance.get("policy_lifecycle"), dict) else {}
    rbac = governance.get("rbac") if isinstance(governance.get("rbac"), dict) else {}
    audit = governance.get("audit_chain") if isinstance(governance.get("audit_chain"), dict) else {}
    return {
        "enabled": bool(governance.get("enabled")),
        "rbac_enabled": bool(rbac.get("enabled", True)) if governance.get("enabled") else False,
        "rbac_token_count": len(rbac.get("api_tokens") or []) if governance.get("enabled") else 0,
        "policy_lifecycle_enabled": bool(lifecycle.get("enabled", True)) if governance.get("enabled") else False,
        "require_approval_for_writes": bool(lifecycle.get("require_approval_for_writes", False)),
        "signed_bundles_enabled": bool(signing.get("enabled", False)),
        "require_signature_on_apply": bool(signing.get("require_signature_on_apply", False)),
        "signing_key_configured": bool(str(signing.get("signing_key", "")).strip()),
        "audit_chain_enabled": bool(audit.get("enabled", False)),
        "oidc_enabled": bool(oidc.get("enabled", False)),
        "oidc_issuer": str(oidc.get("issuer", "")).strip() if oidc.get("enabled") else "",
        "roles": sorted(VALID_ROLES),
    }


def public_oidc_config(governance: Dict[str, Any]) -> Dict[str, Any]:
    oidc = governance.get("oidc") if isinstance(governance.get("oidc"), dict) else {}
    return {
        "enabled": bool(oidc.get("enabled", False)),
        "issuer": str(oidc.get("issuer", "")).strip(),
        "audience": str(oidc.get("audience", "mcp-security-proxy")).strip(),
        "role_claim": str(oidc.get("role_claim", "role")).strip(),
        "subject_claim": str(oidc.get("subject_claim", "sub")).strip(),
        "note": "Local HS256 validation when jwt_secret is configured; wire IdP in production.",
    }


def _governance_data_dir() -> Path:
    default = Path(__file__).resolve().parent.parent / "data" / "governance"
    return Path(os.getenv("MCP_PROXY_GOVERNANCE_DATA_DIR", str(default)))


def _policy_versions_dir() -> Path:
    return _governance_data_dir() / "policy_versions"


def _policy_versions_index_path() -> Path:
    return _policy_versions_dir() / "index.json"


def _proposals_path() -> Path:
    return _governance_data_dir() / "policy_proposals.json"


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=True)
        f.write("\n")
    tmp.replace(path)


def _read_json_file(path: Path, default: Any) -> Any:
    if not path.exists():
        return default
    try:
        with path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def policy_content_hash(policy: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json_bytes(policy)).hexdigest()


def sign_policy_bundle(bundle: Dict[str, Any], signing_key: str) -> Dict[str, Any]:
    if not signing_key:
        raise ValueError("signing_key not configured")
    signature = hmac.new(signing_key.encode("utf-8"), canonical_json_bytes(bundle), hashlib.sha256).hexdigest()
    return {
        "policy_bundle": bundle,
        "signature": signature,
        "algorithm": "hmac-sha256",
        "signed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def verify_signed_bundle_envelope(envelope: Dict[str, Any], signing_key: str) -> Tuple[bool, str]:
    if not isinstance(envelope, dict):
        return False, "invalid_envelope"
    bundle = envelope.get("policy_bundle")
    signature = str(envelope.get("signature", "")).strip()
    if not isinstance(bundle, dict):
        return False, "missing_policy_bundle"
    if not signature:
        return False, "missing_signature"
    if not signing_key:
        return False, "signing_key_not_configured"
    expected = hmac.new(signing_key.encode("utf-8"), canonical_json_bytes(bundle), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "signature_mismatch"
    return True, "ok"


def compute_audit_chain_hash(prev_hash: str, event: Dict[str, Any]) -> str:
    material = f"{prev_hash}|{canonical_json_bytes(event).decode('utf-8')}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


_CHAIN_METADATA_FIELDS = frozenset({"chain_prev", "chain_hash", "chain_seq"})


def _audit_chain_event_payload(event: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in event.items() if k not in _CHAIN_METADATA_FIELDS}


def _resolve_audit_chain_tip(
    chained: List[Dict[str, Any]],
    chain_head: Optional[str] = None,
) -> Optional[str]:
    tip = str(chain_head or "").strip()
    if tip and tip != "genesis":
        return tip

    with_seq = [e for e in chained if e.get("chain_seq") is not None]
    if with_seq:
        latest = max(with_seq, key=lambda e: int(e.get("chain_seq", 0)))
        latest_hash = str(latest.get("chain_hash") or "").strip()
        return latest_hash or None

    referenced_prev = {
        str(e.get("chain_prev"))
        for e in chained
        if isinstance(e.get("chain_prev"), str) and str(e.get("chain_prev")).strip()
    }
    tips = [
        e
        for e in chained
        if str(e.get("chain_hash") or "").strip()
        and str(e.get("chain_hash")) not in referenced_prev
    ]
    if len(tips) == 1:
        return str(tips[0].get("chain_hash"))
    return None


def verify_audit_chain(
    events: List[Dict[str, Any]],
    *,
    chain_head: Optional[str] = None,
) -> Dict[str, Any]:
    """Verify the active audit chain by walking backward from the chain head.

    Forward scans sorted by ``chain_seq`` fail when legacy events omit ``chain_seq``
    (all default to zero) or when the ring buffer drops predecessors. Backward
    verification from the live head matches how events are appended at runtime.
    """
    chained = [e for e in events if isinstance(e, dict) and e.get("chain_hash")]
    total = len(chained)
    if not chained:
        return {
            "valid": True,
            "verified_events": 0,
            "total_events": 0,
            "broken_at_index": None,
            "chain_head": chain_head or "genesis",
            "partial": False,
        }

    by_hash = {str(e.get("chain_hash")): e for e in chained if e.get("chain_hash")}
    tip = _resolve_audit_chain_tip(chained, chain_head=chain_head)
    if not tip or tip == "genesis":
        return {
            "valid": True,
            "verified_events": 0,
            "total_events": total,
            "broken_at_index": None,
            "chain_head": "genesis",
            "partial": False,
        }
    if tip not in by_hash:
        return {
            "valid": False,
            "verified_events": 0,
            "total_events": total,
            "broken_at_index": None,
            "chain_head": None,
            "partial": False,
            "reason": "chain_head_not_found",
        }

    verified = 0
    current: Optional[Dict[str, Any]] = by_hash[tip]
    visited: set[str] = set()
    partial = False
    reason: Optional[str] = None
    while current:
        current_hash = str(current.get("chain_hash") or "")
        if not current_hash or current_hash in visited:
            return {
                "valid": False,
                "verified_events": verified,
                "total_events": total,
                "broken_at_index": verified,
                "chain_head": None,
                "partial": partial,
                "reason": "cycle_detected" if current_hash in visited else "missing_chain_hash",
            }
        visited.add(current_hash)

        prev = str(current.get("chain_prev", "genesis"))
        payload = _audit_chain_event_payload(current)
        if compute_audit_chain_hash(prev, payload) != current_hash:
            return {
                "valid": False,
                "verified_events": verified,
                "total_events": total,
                "broken_at_index": verified,
                "chain_head": None,
                "partial": partial,
                "reason": "hash_mismatch",
            }
        verified += 1
        if prev == "genesis":
            return {
                "valid": True,
                "verified_events": verified,
                "total_events": total,
                "broken_at_index": None,
                "chain_head": tip,
                "partial": False,
            }
        current = by_hash.get(prev)
        if current is None:
            partial = True
            reason = "predecessor_not_in_buffer"
            break

    return {
        "valid": True,
        "verified_events": verified,
        "total_events": total,
        "broken_at_index": None,
        "chain_head": tip,
        "partial": partial,
        "reason": reason,
    }


def list_policy_versions() -> List[Dict[str, Any]]:
    index = _read_json_file(_policy_versions_index_path(), {"versions": []})
    versions = index.get("versions") if isinstance(index, dict) else []
    return [v for v in versions if isinstance(v, dict)]


def get_policy_version(version_id: str) -> Optional[Dict[str, Any]]:
    path = _policy_versions_dir() / f"{version_id}.json"
    payload = _read_json_file(path, None)
    return payload if isinstance(payload, dict) else None


def save_policy_version(
    policy: Dict[str, Any],
    *,
    created_by: str,
    reason: str,
    max_versions: int,
) -> Dict[str, Any]:
    version_id = f"v-{time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())}-{uuid.uuid4().hex[:8]}"
    record = {
        "version_id": version_id,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "created_by": created_by,
        "reason": reason,
        "content_hash": policy_content_hash(policy),
        "summary": {
            "denied_tool_count": len(policy.get("denied_tools") or []),
            "discovery_rule_count": len([r for r in (policy.get("discovery_rules") or []) if isinstance(r, dict)]),
        },
        "policy": policy,
    }
    _policy_versions_dir().mkdir(parents=True, exist_ok=True)
    _atomic_write_json(_policy_versions_dir() / f"{version_id}.json", record)

    index = _read_json_file(_policy_versions_index_path(), {"versions": []})
    versions = index.get("versions") if isinstance(index, dict) else []
    if not isinstance(versions, list):
        versions = []
    versions.insert(
        0,
        {
            "version_id": version_id,
            "created_at": record["created_at"],
            "created_by": created_by,
            "reason": reason,
            "content_hash": record["content_hash"],
            "summary": record["summary"],
        },
    )
    trimmed = versions[: max(1, max_versions)]
    _atomic_write_json(_policy_versions_index_path(), {"versions": trimmed, "updated_at": record["created_at"]})
    return record


def list_policy_proposals() -> List[Dict[str, Any]]:
    payload = _read_json_file(_proposals_path(), {"proposals": []})
    proposals = payload.get("proposals") if isinstance(payload, dict) else []
    return [p for p in proposals if isinstance(p, dict)]


def _save_proposals(proposals: List[Dict[str, Any]]) -> None:
    _atomic_write_json(
        _proposals_path(),
        {"proposals": proposals, "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
    )


def create_policy_proposal(
    raw_policy: Dict[str, Any],
    *,
    proposed_by: str,
    note: str,
) -> Dict[str, Any]:
    proposal_id = f"prop-{uuid.uuid4().hex[:12]}"
    record = {
        "proposal_id": proposal_id,
        "status": "pending",
        "proposed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "proposed_by": proposed_by,
        "note": note,
        "content_hash": policy_content_hash(raw_policy),
        "raw_policy": raw_policy,
    }
    proposals = list_policy_proposals()
    proposals.insert(0, record)
    _save_proposals(proposals)
    return record


def update_proposal_status(
    proposal_id: str,
    *,
    new_status: str,
    actor: str,
    rejection_reason: str = "",
) -> Optional[Dict[str, Any]]:
    proposals = list_policy_proposals()
    updated: Optional[Dict[str, Any]] = None
    for idx, proposal in enumerate(proposals):
        if proposal.get("proposal_id") != proposal_id:
            continue
        proposal = dict(proposal)
        proposal["status"] = new_status
        proposal["resolved_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        proposal["resolved_by"] = actor
        if rejection_reason:
            proposal["rejection_reason"] = rejection_reason
        proposals[idx] = proposal
        updated = proposal
        break
    if updated is None:
        return None
    _save_proposals(proposals)
    return updated


def diff_policy_versions(left: Dict[str, Any], right: Dict[str, Any]) -> Dict[str, Any]:
    left_keys = set(left.keys())
    right_keys = set(right.keys())
    changed_keys = sorted(left_keys | right_keys)
    changes: List[Dict[str, Any]] = []
    for key in changed_keys:
        lv = left.get(key)
        rv = right.get(key)
        if lv != rv:
            changes.append({"key": key, "before": lv, "after": rv})
    return {
        "changed_key_count": len(changes),
        "changes": changes[:50],
        "truncated": len(changes) > 50,
    }
