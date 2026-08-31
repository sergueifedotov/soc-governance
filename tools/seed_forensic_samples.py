#!/usr/bin/env python3
"""seed_forensic_samples.py — Populate Neo4j with a realistic APT forensic timeline.

Scenario: APT intrusion — C2 beacon → lateral movement → data exfiltration
--------------------------------------------------------------------------
  INC-FORENSIC-001  Initial compromise of WEBSERVER-01 via SSH brute-force.
                    Attacker establishes C2 beacon to malware-c2.badactor.ru.

  INC-FORENSIC-002  Lateral movement: attacker pivots from WEBSERVER-01 to
                    JUMPBOX-02 using stolen credentials (alice).  Privilege
                    escalation attempted.  Second C2 beacon observed.

  INC-FORENSIC-003  Data exfiltration: alice pivots from JUMPBOX-02 to DBSERVER-03.
                    mysqldump executed; 4 GB transferred to exfil.badactor.ru.

Usage:
    python tools/seed_forensic_samples.py [BASE_URL]

    BASE_URL defaults to http://localhost:8082

All data is entirely fictional (RFC 5737 / RFC 2606 addresses and domains).
"""
from __future__ import annotations

import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


# ---------------------------------------------------------------------------
# HTTP helpers (no external deps)
# ---------------------------------------------------------------------------

_arg = sys.argv[1] if len(sys.argv) > 1 else ""
BASE_URL = (_arg if _arg.startswith(("http://", "https://")) else "http://localhost:8082").rstrip("/")


def _request(method: str, path: str, body: Optional[Dict] = None) -> Any:
    url = BASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        resp_body = exc.read().decode(errors="replace")
        print(f"  ✗ HTTP {exc.code} {method} {path}: {resp_body[:200]}")
        return None


def post(path: str, body: Dict) -> Any:
    return _request("POST", path, body)


def get(path: str) -> Any:
    return _request("GET", path)


def ok(label: str, result: Any) -> None:
    if result is not None:
        print(f"  ✓ {label}")
    # Errors already printed by _request


# ---------------------------------------------------------------------------
# Step 0: Health check
# ---------------------------------------------------------------------------

def check_health() -> bool:
    print("\n── Health check ────────────────────────────────────────────")
    h = get("/cases/health")
    if h is None:
        print("  ✗ Cannot reach the API — is phase4-api running?")
        return False
    print(f"  Neo4j: available={h['neo4j']['available']}, connected={h['neo4j']['connected']}")
    print(f"  MinIO: available={h['minio']['available']}, connected={h['minio']['connected']}")
    if not h["neo4j"]["connected"]:
        print("  ✗ Neo4j not connected — start phase4-neo4j first")
        return False
    return True


# ---------------------------------------------------------------------------
# Step 1: Ingest alert nodes (also auto-creates IP + USER nodes)
# ---------------------------------------------------------------------------

ALERTS = [
    # INC-FORENSIC-001 ───────────────────────────────────────────────────────
    {
        "alert_id":   "alert-001-F1",
        "incident_id":"INC-FORENSIC-001",
        "rule_id":    5763,
        "rule_name":  "SSH authentication failure (brute force)",
        "severity":   7,
        "timestamp":  "2026-04-18T02:15:00Z",
        "src_ip":     "198.51.100.77",
        "dest_ip":    "10.0.1.10",
        "full_log":   "Apr 18 02:15:00 webserver-01 sshd[1234]: Failed password for root from 198.51.100.77 port 49821 ssh2",
    },
    {
        "alert_id":   "alert-002-F1",
        "incident_id":"INC-FORENSIC-001",
        "rule_id":    5501,
        "rule_name":  "SSH login successful",
        "severity":   8,
        "timestamp":  "2026-04-18T02:47:00Z",
        "src_ip":     "198.51.100.77",
        "dest_ip":    "10.0.1.10",
        "username":   "www-data",
        "full_log":   "Apr 18 02:47:00 webserver-01 sshd[1234]: Accepted password for www-data from 198.51.100.77 port 50114 ssh2",
    },
    {
        "alert_id":   "alert-003-F1",
        "incident_id":"INC-FORENSIC-001",
        "rule_id":    533,
        "rule_name":  "Suspicious process executed from /tmp",
        "severity":   12,
        "timestamp":  "2026-04-18T03:05:00Z",
        "src_ip":     "10.0.1.10",
        "username":   "www-data",
        "full_log":   "Apr 18 03:05:00 webserver-01 kernel: [1234.5678] SYSCALL /tmp/.x execve args=-c http://malware-c2.badactor.ru/beacon",
    },
    {
        "alert_id":   "alert-004-F1",
        "incident_id":"INC-FORENSIC-001",
        "rule_id":    82730,
        "rule_name":  "DNS query to known malicious domain",
        "severity":   14,
        "timestamp":  "2026-04-18T03:22:00Z",
        "src_ip":     "10.0.1.10",
        "dest_ip":    "198.51.100.77",
        "username":   "www-data",
        "full_log":   "Apr 18 03:22:00 webserver-01 named: malware-c2.badactor.ru -> 198.51.100.77 (NXDOMAIN bypass)",
    },
    # INC-FORENSIC-002 ───────────────────────────────────────────────────────
    {
        "alert_id":   "alert-005-F2",
        "incident_id":"INC-FORENSIC-002",
        "rule_id":    5501,
        "rule_name":  "SSH login successful from internal host",
        "severity":   7,
        "timestamp":  "2026-04-18T04:02:00Z",
        "src_ip":     "10.0.1.10",
        "dest_ip":    "10.0.1.20",
        "username":   "alice",
        "full_log":   "Apr 18 04:02:00 jumpbox-02 sshd[5678]: Accepted publickey for alice from 10.0.1.10 port 54321 ssh2",
    },
    {
        "alert_id":   "alert-006-F2",
        "incident_id":"INC-FORENSIC-002",
        "rule_id":    5501,
        "rule_name":  "SSH login from new source host",
        "severity":   8,
        "timestamp":  "2026-04-18T04:05:00Z",
        "src_ip":     "10.0.1.10",
        "dest_ip":    "10.0.1.20",
        "username":   "alice",
        "full_log":   "Apr 18 04:05:00 jumpbox-02 sshd[5679]: First login for alice from 10.0.1.10",
    },
    {
        "alert_id":   "alert-007-F2",
        "incident_id":"INC-FORENSIC-002",
        "rule_id":    5500,
        "rule_name":  "Privilege escalation attempt (sudo)",
        "severity":   10,
        "timestamp":  "2026-04-18T05:31:00Z",
        "src_ip":     "10.0.1.20",
        "username":   "alice",
        "full_log":   "Apr 18 05:31:00 jumpbox-02 sudo: alice : command not allowed ; TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash",
    },
    {
        "alert_id":   "alert-008-F2",
        "incident_id":"INC-FORENSIC-002",
        "rule_id":    82730,
        "rule_name":  "DNS query to known malicious domain",
        "severity":   14,
        "timestamp":  "2026-04-18T05:45:00Z",
        "src_ip":     "10.0.1.20",
        "dest_ip":    "198.51.100.77",
        "username":   "alice",
        "full_log":   "Apr 18 05:45:00 jumpbox-02 named: malware-c2.badactor.ru -> 198.51.100.77",
    },
    {
        "alert_id":   "alert-009-F2",
        "incident_id":"INC-FORENSIC-002",
        "rule_id":    554,
        "rule_name":  "File created in suspicious location",
        "severity":   8,
        "timestamp":  "2026-04-18T05:58:00Z",
        "src_ip":     "10.0.1.20",
        "username":   "alice",
        "full_log":   "Apr 18 05:58:00 jumpbox-02 syscheck: File /tmp/.pivot created by alice",
    },
    # INC-FORENSIC-003 ───────────────────────────────────────────────────────
    {
        "alert_id":   "alert-010-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    5501,
        "rule_name":  "SSH login to database server",
        "severity":   9,
        "timestamp":  "2026-04-18T06:01:00Z",
        "src_ip":     "10.0.1.20",
        "dest_ip":    "10.0.1.30",
        "username":   "alice",
        "full_log":   "Apr 18 06:01:00 dbserver-03 sshd[9012]: Accepted publickey for alice from 10.0.1.20 port 60001 ssh2",
    },
    {
        "alert_id":   "alert-011-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    533,
        "rule_name":  "Suspicious database dump process detected",
        "severity":   12,
        "timestamp":  "2026-04-18T06:15:00Z",
        "src_ip":     "10.0.1.30",
        "username":   "dbadmin",
        "full_log":   "Apr 18 06:15:00 dbserver-03 syscheck: Process mysqldump --all-databases -u root -p started by dbadmin",
    },
    {
        "alert_id":   "alert-012-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    100100,
        "rule_name":  "Abnormally large outbound data transfer",
        "severity":   15,
        "timestamp":  "2026-04-18T06:47:00Z",
        "src_ip":     "10.0.1.30",
        "dest_ip":    "198.51.100.78",
        "full_log":   "Apr 18 06:47:00 dbserver-03 netflow: 10.0.1.30->198.51.100.78 4.3GB transferred (TCP/443)",
    },
    {
        "alert_id":   "alert-013-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    82730,
        "rule_name":  "DNS query to known exfil domain",
        "severity":   14,
        "timestamp":  "2026-04-18T06:48:00Z",
        "src_ip":     "10.0.1.30",
        "dest_ip":    "198.51.100.78",
        "full_log":   "Apr 18 06:48:00 dbserver-03 named: exfil.badactor.ru -> 198.51.100.78",
    },
    {
        "alert_id":   "alert-014-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    5501,
        "rule_name":  "Database admin login at unusual hour",
        "severity":   9,
        "timestamp":  "2026-04-18T06:52:00Z",
        "src_ip":     "10.0.1.20",
        "dest_ip":    "10.0.1.30",
        "username":   "dbadmin",
        "full_log":   "Apr 18 06:52:00 dbserver-03 sshd[9100]: Accepted password for dbadmin from 10.0.1.20 port 60042 ssh2",
    },
    {
        "alert_id":   "alert-015-F3",
        "incident_id":"INC-FORENSIC-003",
        "rule_id":    5501,
        "rule_name":  "Privileged user SSH login from pivot host",
        "severity":   10,
        "timestamp":  "2026-04-18T07:00:00Z",
        "src_ip":     "10.0.1.20",
        "dest_ip":    "10.0.1.30",
        "username":   "alice",
        "full_log":   "Apr 18 07:00:00 dbserver-03 sshd[9200]: Accepted publickey for alice from 10.0.1.20 port 60043 ssh2",
    },
]


# ---------------------------------------------------------------------------
# Step 2: Additional entity nodes (domain, workstation, process, file)
# ---------------------------------------------------------------------------

ENTITIES = [
    # C2 / exfil domains
    {"node_type": "DOMAIN", "name": "malware-c2.badactor.ru",
     "category": "c2", "threat_score": 95},
    {"node_type": "DOMAIN", "name": "exfil.badactor.ru",
     "category": "exfil", "threat_score": 98},

    # Internal workstations (pivot hosts)
    {"node_type": "WORKSTATION", "hostname": "webserver-01",
     "os": "Ubuntu 22.04", "role": "web", "ip": "10.0.1.10"},
    {"node_type": "WORKSTATION", "hostname": "jumpbox-02",
     "os": "Ubuntu 22.04", "role": "bastion", "ip": "10.0.1.20"},
    {"node_type": "WORKSTATION", "hostname": "dbserver-03",
     "os": "Ubuntu 22.04", "role": "database", "ip": "10.0.1.30"},

    # Malicious processes
    {"node_type": "PROCESS",
     "pid_host":  "1234@webserver-01",
     "name":      "/tmp/.x",
     "cmdline":   "/tmp/.x -c http://malware-c2.badactor.ru/beacon -d 300"},
    {"node_type": "PROCESS",
     "pid_host":  "5678@jumpbox-02",
     "name":      "ssh",
     "cmdline":   "ssh -i /tmp/.key alice@10.0.1.30 -p 22"},
    {"node_type": "PROCESS",
     "pid_host":  "9012@dbserver-03",
     "name":      "mysqldump",
     "cmdline":   "mysqldump --all-databases -u root -p --single-transaction"},

    # Suspicious files
    {"node_type": "FILE", "path": "/tmp/.x",
     "hash_sha256": "e3b0c44298fc1c149afbf4c8996fb924deadbeef",
     "size_bytes": 204800},
    {"node_type": "FILE", "path": "/tmp/.pivot",
     "hash_sha256": "d41d8cd98f00b204e9800998ecf8427edeadbeef",
     "size_bytes": 4096},
    {"node_type": "FILE", "path": "/var/lib/mysql/dump.sql",
     "hash_sha256": "abc123def456789012345678901234567890abcd",
     "size_bytes": 4587520000},
]


# ---------------------------------------------------------------------------
# Step 3: Relationships
# ---------------------------------------------------------------------------

RELATIONSHIPS = [
    # C2 IP → RESOLVES_TO → C2 domain
    {"from_label": "IP_ADDRESS", "from_key": "ip",   "from_value": "198.51.100.77",
     "to_label":   "DOMAIN",     "to_key":   "name", "to_value":   "malware-c2.badactor.ru",
     "rel_type":   "RESOLVES_TO", "props": {"first_seen": "2026-04-18T03:22:00Z"}},
    {"from_label": "IP_ADDRESS", "from_key": "ip",   "from_value": "198.51.100.78",
     "to_label":   "DOMAIN",     "to_key":   "name", "to_value":   "malware-c2.badactor.ru",
     "rel_type":   "RESOLVES_TO", "props": {"first_seen": "2026-04-18T05:45:00Z"}},
    {"from_label": "IP_ADDRESS", "from_key": "ip",   "from_value": "198.51.100.78",
     "to_label":   "DOMAIN",     "to_key":   "name", "to_value":   "exfil.badactor.ru",
     "rel_type":   "RESOLVES_TO", "props": {"first_seen": "2026-04-18T06:48:00Z"}},

    # USER → LOGGED_IN_TO → WORKSTATION (lateral movement chain)
    {"from_label": "USER",        "from_key": "username", "from_value": "www-data",
     "to_label":   "WORKSTATION", "to_key":   "hostname", "to_value":   "webserver-01",
     "rel_type":   "LOGGED_IN_TO", "props": {"first_seen": "2026-04-18T02:47:00Z"}},
    {"from_label": "USER",        "from_key": "username", "from_value": "alice",
     "to_label":   "WORKSTATION", "to_key":   "hostname", "to_value":   "webserver-01",
     "rel_type":   "LOGGED_IN_TO", "props": {"first_seen": "2026-04-18T03:00:00Z"}},
    {"from_label": "USER",        "from_key": "username", "from_value": "alice",
     "to_label":   "WORKSTATION", "to_key":   "hostname", "to_value":   "jumpbox-02",
     "rel_type":   "LOGGED_IN_TO", "props": {"first_seen": "2026-04-18T04:02:00Z"}},
    {"from_label": "USER",        "from_key": "username", "from_value": "alice",
     "to_label":   "WORKSTATION", "to_key":   "hostname", "to_value":   "dbserver-03",
     "rel_type":   "LOGGED_IN_TO", "props": {"first_seen": "2026-04-18T06:01:00Z"}},
    {"from_label": "USER",        "from_key": "username", "from_value": "dbadmin",
     "to_label":   "WORKSTATION", "to_key":   "hostname", "to_value":   "dbserver-03",
     "rel_type":   "LOGGED_IN_TO", "props": {"first_seen": "2026-04-18T06:52:00Z"}},

    # ALERT → DETECTED → FILE (alert-003 → suspicious binary)
    {"from_label": "ALERT",  "from_key": "alert_id", "from_value": "alert-003-F1",
     "to_label":   "FILE",   "to_key":   "path",     "to_value":   "/tmp/.x",
     "rel_type":   "DETECTED"},
    {"from_label": "ALERT",  "from_key": "alert_id", "from_value": "alert-009-F2",
     "to_label":   "FILE",   "to_key":   "path",     "to_value":   "/tmp/.pivot",
     "rel_type":   "DETECTED"},
    {"from_label": "ALERT",  "from_key": "alert_id", "from_value": "alert-011-F3",
     "to_label":   "FILE",   "to_key":   "path",     "to_value":   "/var/lib/mysql/dump.sql",
     "rel_type":   "DETECTED"},

    # FILE → MODIFIED_BY → PROCESS
    {"from_label": "FILE",    "from_key": "path",     "from_value": "/tmp/.x",
     "to_label":   "PROCESS", "to_key":   "pid_host", "to_value":   "1234@webserver-01",
     "rel_type":   "MODIFIED_BY"},
    {"from_label": "FILE",    "from_key": "path",     "from_value": "/tmp/.pivot",
     "to_label":   "PROCESS", "to_key":   "pid_host", "to_value":   "5678@jumpbox-02",
     "rel_type":   "MODIFIED_BY"},
    {"from_label": "FILE",    "from_key": "path",     "from_value": "/var/lib/mysql/dump.sql",
     "to_label":   "PROCESS", "to_key":   "pid_host", "to_value":   "9012@dbserver-03",
     "rel_type":   "MODIFIED_BY"},

    # PROCESS → CONNECTS_TO → IP (C2 / exfil outbound)
    {"from_label": "PROCESS",    "from_key": "pid_host", "from_value": "1234@webserver-01",
     "to_label":   "IP_ADDRESS", "to_key":   "ip",       "to_value":   "198.51.100.77",
     "rel_type":   "CONNECTS_TO", "props": {"port": 443, "protocol": "HTTPS"}},
    {"from_label": "PROCESS",    "from_key": "pid_host", "from_value": "5678@jumpbox-02",
     "to_label":   "IP_ADDRESS", "to_key":   "ip",       "to_value":   "10.0.1.30",
     "rel_type":   "CONNECTS_TO", "props": {"port": 22, "protocol": "SSH"}},
    {"from_label": "PROCESS",    "from_key": "pid_host", "from_value": "9012@dbserver-03",
     "to_label":   "IP_ADDRESS", "to_key":   "ip",       "to_value":   "198.51.100.78",
     "rel_type":   "CONNECTS_TO", "props": {"port": 443, "protocol": "HTTPS", "bytes": 4587520000}},
]


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:  # noqa: C901
    print("=" * 64)
    print("  Wazuh Layer 2 — Forensic Sample Data Seeder")
    print(f"  Target: {BASE_URL}")
    print("=" * 64)

    if not check_health():
        sys.exit(1)

    # ── Step 1: Ingest alerts ──────────────────────────────────────────────
    print(f"\n── Step 1: Ingesting {len(ALERTS)} alert nodes ─────────────────────")
    for alert in ALERTS:
        result = post("/cases/alerts", alert)
        ok(f"alert {alert['alert_id']}  (incident: {alert['incident_id']})", result)

    # ── Step 2: Create additional entities ────────────────────────────────
    print(f"\n── Step 2: Creating {len(ENTITIES)} additional entity nodes ──────────")
    for entity in ENTITIES:
        result = post("/cases/entities", entity)
        label = entity.get("name") or entity.get("hostname") or entity.get("pid_host") or entity.get("path", "?")
        ok(f"{entity['node_type']:12s}  {label}", result)

    # ── Step 3: Create relationships ──────────────────────────────────────
    print(f"\n── Step 3: Creating {len(RELATIONSHIPS)} relationships ──────────────────────")
    for rel in RELATIONSHIPS:
        result = post("/cases/relationships", rel)
        ok(
            f"{rel['from_value']:30s} --[{rel['rel_type']}]--> {rel['to_value']}",
            result,
        )

    # ── Summary ───────────────────────────────────────────────────────────
    print("\n── Verification queries ─────────────────────────────────────────────")

    r = get("/cases/query/by-domain/malware-c2.badactor.ru")
    if r:
        print(f"  C2 domain malware-c2.badactor.ru: {r['count']} incident(s): {r['incident_ids']}")

    r = get("/cases/query/by-domain/exfil.badactor.ru")
    if r:
        print(f"  Exfil domain exfil.badactor.ru:   {r['count']} incident(s): {r['incident_ids']}")

    r = get("/cases/query/by-ip/198.51.100.77")
    if r:
        print(f"  IP 198.51.100.77:                 {r['count']} incident(s): {r['incident_ids']}")

    r = get("/cases/query/by-user/alice")
    if r:
        print(f"  User alice:                       {r['count']} incident(s): {r['incident_ids']}")

    r = get("/cases/query/lateral-movement?min_workstations=2")
    if r:
        for c in r.get("candidates", []):
            hosts = ", ".join(c["workstations"])
            print(f"  Lateral movement candidate:       {c['user']} → {c['login_count']} hosts ({hosts})")

    r = get("/cases/query/attack-chain/198.51.100.77")
    if r:
        print(f"  Attack chain from 198.51.100.77:  {r['path_count']} path(s)")

    print("\n══ Seeding complete ══════════════════════════════════════════════════")
    print("  Open http://localhost:8082/cases/ui to explore in the browser")
    print("  Incident IDs: INC-FORENSIC-001  INC-FORENSIC-002  INC-FORENSIC-003")
    print("═" * 64)


if __name__ == "__main__":
    main()
