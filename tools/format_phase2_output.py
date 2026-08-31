#!/usr/bin/env python3

import json
import sys


def main() -> int:
    try:
        obj = json.load(sys.stdin)
    except json.JSONDecodeError as error:
        print(f"Invalid JSON input: {error}", file=sys.stderr)
        return 1

    text = ((obj.get("result", {}).get("content") or [{}])[0].get("text", ""))
    header, sep, body = text.partition("\n")

    print(header if header else "MCP Text Output")

    if not sep:
        if text:
            print(text)
        return 0

    payload = None
    if body.lstrip().startswith("{"):
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            payload = None

    if payload is None:
        print(body)
        return 0

    print(json.dumps(payload, indent=2, ensure_ascii=False))

    data = payload.get("data", {})
    analysis = data.get("analysis")
    summary = data.get("orchestration", {}).get("summary")

    if analysis:
        print("\nAnalysis:\n")
        print(analysis)

    if summary:
        print("\nSummary:\n")
        print(summary)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())