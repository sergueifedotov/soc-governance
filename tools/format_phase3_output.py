#!/usr/bin/env python3

import json
import re
import sys
import textwrap
from typing import Any


# ── helpers ──────────────────────────────────────────────────────────────────

def _div(char: str = "─", width: int = 72) -> str:
    return char * width


def _section(title: str) -> None:
    print(f"\n{_div()}")
    print(f"  {title}")
    print(_div())


def _subsection(title: str) -> None:
    print(f"\n── {title} {'─' * max(0, 68 - len(title))}")


def _kv(label: str, value: Any, width: int = 18) -> None:
    print(f"  {label:<{width}} {value}")


def _bullet(text: str, indent: int = 4) -> None:
    prefix = " " * indent + "• "
    wrapped = textwrap.fill(
        text, width=72,
        initial_indent=prefix,
        subsequent_indent=" " * (indent + 2),
    )
    print(wrapped)


def _extract_mcp_data(obj: dict[str, Any]) -> dict[str, Any] | None:
    """Return the parsed data dict from an MCP result envelope, or None."""
    text = ((obj.get("result", {}).get("content") or [{}])[0].get("text", ""))
    if not text:
        return None
    _, sep, body = text.partition("\n")
    if sep and body.lstrip().startswith("{"):
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                return parsed.get("data") or parsed
        except json.JSONDecodeError:
            pass
    return None


def _strip_markdown(text: str) -> str:
    """Remove bold markers and normalise bullets for terminal output."""
    text = re.sub(r"\*\*(.+?)\*\*", r"\1", text)
    text = re.sub(r"\*\*", "", text)          # remove unclosed bold markers
    text = re.sub(r"^\s*\*\s+", "• ", text, flags=re.MULTILINE)
    return text.strip()


def _analysis_lines(data: dict[str, Any]) -> list[str]:
    raw = data.get("analysis") or (data.get("orchestration") or {}).get("summary") or ""
    return _strip_markdown(raw).splitlines() if raw else []


# ── section printers ──────────────────────────────────────────────────────────

def _print_summary(obj: dict[str, Any]) -> None:
    incident_id = obj.get("incident_id", "—")
    risk_tier   = obj.get("risk_tier", "—")
    status      = obj.get("workflow_status", "—")
    steps       = obj.get("steps", [])
    approval    = obj.get("approval") or {}

    _section(f"Phase 3 Run — {incident_id}  ({risk_tier} / {obj.get('proposed_action', {}).get('use_case', '—')})")

    _kv("Status:", status)
    _kv("Step trace:", " → ".join(steps))

    actor    = approval.get("actor", "—")
    needed   = approval.get("approvals_needed", "—")
    decision = approval.get("decision", "—")
    _kv("Approval:", f"{actor} · {needed} approver(s) required · decision: {decision}")


def _print_triage(data: dict[str, Any]) -> None:
    _subsection("Triage")
    lines = _analysis_lines(data)
    if lines:
        for line in lines:
            if line.strip():
                print(textwrap.fill(line, width=72, initial_indent="  ",
                                    subsequent_indent="    "))
    else:
        total = data.get("total_alerts", 0)
        print(f"  Total alerts in window: {total}")


def _print_enrichment(data: dict[str, Any]) -> None:
    _subsection("Enrichment")

    sc = data.get("supporting_context") or {}
    threats = (sc.get("top_threats") or {}).get("threats") or []

    if threats:
        col = [6, 44, 5, 6, 30]
        hdr = f"  {'Rule':<{col[0]}}  {'Description':<{col[1]}}  {'Lvl':<{col[2]}}  {'Count':<{col[3]}}  {'Source IPs'}"
        print(hdr)
        print("  " + "─" * 68)
        for t in threats:
            rule  = str(t.get("rule_id", ""))
            desc  = (t.get("description") or "")[:col[1]]
            lvl   = str(t.get("level", ""))
            count = str(t.get("count", ""))
            ips   = ", ".join(t.get("source_ips") or []) or "—"
            print(f"  {rule:<{col[0]}}  {desc:<{col[1]}}  {lvl:<{col[2]}}  {count:<{col[3]}}  {ips}")

    lines = _analysis_lines(data)
    if lines:
        print()
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("•"):
                _bullet(stripped[1:].strip())
            else:
                print(textwrap.fill(line, width=72, initial_indent="  ",
                                    subsequent_indent="    "))


def _print_execution(value: Any) -> None:
    _subsection("Execution")
    if value is None:
        print("  (skipped)")
        return
    if isinstance(value, dict):
        _kv("Tool:",   value.get("tool", "—"))
        args = value.get("args") or {}
        _kv("Args:",   "  ".join(f"{k}={v}" for k, v in args.items()) if args else "—")
        _kv("Status:", value.get("status", "—"))
        err = value.get("error")
        if err:
            _kv("Error:", err)
    else:
        print(f"  {value}")


def _print_verify_or_rollback(label: str, value: Any) -> None:
    _subsection(label)
    if value is None:
        print("  (skipped — not reached)")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _kv(f"{k}:", v)
    else:
        print(f"  {value}")


def _print_handoff(data: dict[str, Any]) -> None:
    _subsection("SOC Handoff")

    sections = data.get("sections") or {}

    # Active agents
    agents_data = (sections.get("running_agents") or {}).get("data") or {}
    agents = agents_data.get("affected_items") or []
    non_mgr = [a for a in agents if a.get("id") != "000"]
    mgr     = next((a for a in agents if a.get("id") == "000"), None)
    agent_parts = []
    if mgr:
        agent_parts.append(f"{mgr.get('name')} (000, {mgr.get('os', {}).get('name', '')})")
    for a in non_mgr:
        os_name = a.get("os", {}).get("name", "")
        os_ver  = a.get("os", {}).get("version", "")
        label   = f"{os_name} {os_ver}".strip()
        agent_parts.append(f"{a.get('name')} ({a.get('id')}, {label})")
    _kv("Environment:",
        f"{len(agents)} active agent(s) — " + ", ".join(agent_parts) if agent_parts else f"{len(agents)} active agent(s)")

    # Alert volume
    alert_data = (sections.get("alert_summary") or {}).get("data") or {}
    total = alert_data.get("total_alerts", 0)
    groups = alert_data.get("groups") or {}
    group_str = "  ".join(f"level {k}: {v}" for k, v in sorted(groups.items(), key=lambda x: int(x[0])))
    _kv("Alerts:", f"{total} total — {group_str}" if group_str else str(total))

    # Top threats table
    threats = ((sections.get("top_threats") or {}).get("data") or {}).get("threats") or []
    if threats:
        print()
        print(f"  {'Rule':<8}  {'Description':<44}  {'Lvl':<4}  {'Count':<6}  Score")
        print("  " + "─" * 68)
        for t in threats:
            print(
                f"  {str(t.get('rule_id', '')):<8}  "
                f"{(t.get('description') or '')[:44]:<44}  "
                f"{str(t.get('level', '')):<4}  "
                f"{str(t.get('count', '')):<6}  "
                f"{t.get('threat_score', '')}"
            )

    # Critical CVEs
    cve_items = ((sections.get("critical_vulnerabilities") or {}).get("data") or {}).get("affected_items") or []
    if cve_items:
        print()
        print(f"  {'CVE':<20}  {'Package':<32}  Summary")
        print("  " + "─" * 68)
        seen: set[tuple[str, str]] = set()
        for c in cve_items:
            cve_id  = c.get("cve") or c.get("id") or "—"
            pkg     = f"{(c.get('package') or {}).get('name', '?')}  {(c.get('package') or {}).get('version', '')}".strip()
            desc    = (c.get("description") or "")[:120]
            # one-line summary: first sentence
            summary = re.split(r"(?<=[.!?])\s", desc)[0][:50]
            key = (cve_id, (c.get("package") or {}).get("name", ""))
            if key in seen:
                continue
            seen.add(key)
            print(f"  {cve_id:<20}  {pkg:<32}  {summary}")

    # Manager errors summary
    err_data = (sections.get("manager_errors") or {}).get("data") or {}
    total_errs = err_data.get("total_affected_items", 0)
    if total_errs:
        print()
        print(f"  Manager log errors: {total_errs} entries (see raw output for details)")

    # LangChain analysis
    lines = _analysis_lines(data)
    if lines:
        print()
        for line in lines:
            stripped = line.strip()
            if not stripped:
                continue
            if stripped.startswith("•"):
                _bullet(stripped[1:].strip())
            else:
                print(textwrap.fill(line, width=72, initial_indent="  ",
                                    subsequent_indent="    "))


def _print_audit(obj: dict[str, Any]) -> None:
    proposed = obj.get("proposed_action") or {}
    approval = obj.get("approval") or {}
    outputs  = obj.get("outputs") or {}
    verify   = outputs.get("verify") or {}
    rollback = outputs.get("rollback") or {}

    fields = [
        ("incident_id",      [obj]),
        ("use_case",         [proposed]),
        ("approvals_needed", [proposed, approval]),
        ("decision",         [approval]),
        ("actor",            [approval]),
        ("status",           [verify, rollback]),
        ("forced",           [verify, rollback]),
    ]

    _subsection("Audit")
    for field, sources in fields:
        for src in sources:
            if isinstance(src, dict) and field in src:
                _kv(f"{field}:", src[field])
                break


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    try:
        obj = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"Invalid JSON input: {error}", file=sys.stderr)
        return 1

    _print_summary(obj)

    outputs = obj.get("outputs") or {}

    # triage
    triage_raw = outputs.get("triage")
    if triage_raw is not None:
        data = _extract_mcp_data(triage_raw) if isinstance(triage_raw, dict) else None
        _print_triage(data or {})

    # enrichment
    enrich_raw = outputs.get("enrichment")
    if enrich_raw is not None:
        data = _extract_mcp_data(enrich_raw) if isinstance(enrich_raw, dict) else None
        _print_enrichment(data or {})

    # execution
    _print_execution(outputs.get("execution"))

    # verify / rollback
    if "verify" in outputs:
        _print_verify_or_rollback("Verify", outputs["verify"])
    if "rollback" in outputs:
        _print_verify_or_rollback("Rollback", outputs["rollback"])

    # handoff
    handoff_raw = outputs.get("handoff")
    if handoff_raw is not None:
        data = _extract_mcp_data(handoff_raw) if isinstance(handoff_raw, dict) else None
        _print_handoff(data or {})

    _print_audit(obj)

    print(f"\n{_div()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
