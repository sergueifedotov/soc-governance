#!/usr/bin/env python3

import json
import os
import sqlite3
from pathlib import Path


DB_PATH = Path("/data/webui.db")


def load_tool_server_connections() -> list[dict]:
    raw_value = os.environ.get("TOOL_SERVER_CONNECTIONS", "[]")
    try:
        value = json.loads(raw_value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"Invalid TOOL_SERVER_CONNECTIONS JSON: {exc}")

    if not isinstance(value, list):
        raise SystemExit("TOOL_SERVER_CONNECTIONS must be a JSON array")

    normalized: list[dict] = []
    for item in value:
        if not isinstance(item, dict):
            continue

        candidate = dict(item)
        candidate.setdefault("path", "")
        normalized.append(candidate)

    return normalized


def load_existing_config(cursor: sqlite3.Cursor) -> tuple[int | None, dict]:
    cursor.execute("SELECT id, data FROM config ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    if row is None:
        return None, {"version": 0, "ui": {}}

    config_id, raw_data = row
    if isinstance(raw_data, str):
        data = json.loads(raw_data)
    else:
        data = raw_data

    if not isinstance(data, dict):
        data = {"version": 0, "ui": {}}

    return config_id, data


def main() -> int:
    tool_server_connections = load_tool_server_connections()

    if not DB_PATH.exists():
        print("Open WebUI database not found yet; skipping persistent config patch.")
        return 0

    connection = sqlite3.connect(DB_PATH)
    try:
        cursor = connection.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='config'")
        if cursor.fetchone() is None:
            print("Open WebUI config table not found yet; skipping persistent config patch.")
            return 0

        config_id, config_data = load_existing_config(cursor)
        config_data.setdefault("tool_server", {})["connections"] = tool_server_connections

        serialized = json.dumps(config_data, separators=(",", ":"))

        if config_id is None:
            cursor.execute(
                "INSERT INTO config (data, version, created_at, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
                (serialized, int(config_data.get("version", 0))),
            )
            print("Created Open WebUI config row with Wazuh MCP server connection.")
        else:
            cursor.execute(
                "UPDATE config SET data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (serialized, config_id),
            )
            print("Updated Open WebUI config with Wazuh MCP server connection.")

        connection.commit()
        return 0
    finally:
        connection.close()


if __name__ == "__main__":
    raise SystemExit(main())