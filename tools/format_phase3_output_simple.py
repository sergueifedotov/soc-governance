#!/usr/bin/env python3
"""
Simple Phase 3 output formatter — JSON structure with description/analysis/summary
fields rendered as plain human-readable text inline within their parent context.
MCP result text envelopes are transparently unwrapped and rendered the same way.
"""

import json
import sys

# These string fields are always rendered as plain readable text, not JSON strings
_TEXT_FIELDS = {"description", "analysis", "summary"}


def _fmt(value, key="", depth=0):
    """
    Recursively format *value* into a pretty-printed string.
    - dicts/lists: JSON-like indented structure
    - strings whose key is in _TEXT_FIELDS: plain text block (no quotes)
    - the "text" key inside MCP result content items: parsed if it contains
      an embedded JSON body, then rendered recursively so inner text fields
      are also shown as plain text
    - everything else: standard JSON representation
    """
    pad = "  " * depth
    child_pad = "  " * (depth + 1)

    if isinstance(value, dict):
        if not value:
            return "{}"
        lines = ["{"]
        items = list(value.items())
        for i, (k, v) in enumerate(items):
            comma = "," if i < len(items) - 1 else ""

            # MCP "text" field: try to unwrap header + JSON body transparently
            if k == "text" and isinstance(v, str):
                header, sep, body = v.partition("\n")
                if sep and body.lstrip().startswith("{"):
                    try:
                        payload = json.loads(body)
                        note = f"  // {header.strip()}" if header.strip() else ""
                        lines.append(f"{child_pad}{json.dumps(k)}: [MCP text envelope]{note}")
                        inner = _fmt(payload, k, depth + 1)
                        lines.append(f"{child_pad}{inner}{comma}")
                        continue
                    except json.JSONDecodeError:
                        pass
                # Plain (non-JSON) text field — print as-is
                note = f"  // {header.strip()}" if header.strip() else ""
                lines.append(f"{child_pad}{json.dumps(k)}: [plain text]{note}")
                for line in v.splitlines():
                    lines.append(f"{child_pad}  {line}")
                lines.append(f"{child_pad}{comma}")
                continue

            formatted = _fmt(v, k, depth + 1)
            lines.append(f"{child_pad}{json.dumps(k)}: {formatted}{comma}")

        lines.append(f"{pad}}}")
        return "\n".join(lines)

    elif isinstance(value, list):
        if not value:
            return "[]"
        lines = ["["]
        for i, item in enumerate(value):
            comma = "," if i < len(value) - 1 else ""
            formatted = _fmt(item, key, depth + 1)
            lines.append(f"{child_pad}{formatted}{comma}")
        lines.append(f"{pad}]")
        return "\n".join(lines)

    elif isinstance(value, str) and key in _TEXT_FIELDS and value.strip():
        # Render as an unquoted, indented plain-text block
        text_lines = value.splitlines()
        if not text_lines:
            return '""'
        if len(text_lines) == 1:
            return f"(text) {text_lines[0]}"
        block = [f"(text)"]
        for line in text_lines:
            block.append(f"{child_pad}{line}")
        return "\n".join(block)

    else:
        return json.dumps(value, ensure_ascii=False)


def main() -> int:
    try:
        obj = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"Invalid JSON input: {error}", file=sys.stderr)
        return 1

    # ── Header summary ────────────────────────────────────────────────────────
    incident_id     = obj.get("incident_id", "—")
    risk_tier       = obj.get("risk_tier", "—")
    workflow_status = obj.get("workflow_status", "—")
    steps           = obj.get("steps", [])
    approval        = obj.get("approval") or {}

    print(f"=== Phase 3 Run: {incident_id} ===")
    print(f"Risk tier:       {risk_tier}")
    print(f"Workflow status: {workflow_status}")
    if steps:
        print(f"Steps:           {' → '.join(steps)}")
    if approval:
        print(f"Approval:        decision={approval.get('decision', '—')}  "
              f"actor={approval.get('actor', '—')}  "
              f"approvals_needed={approval.get('approvals_needed', '—')}")

    # ── Full output with inline plain-text rendering ──────────────────────────
    print()
    print(_fmt(obj))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

