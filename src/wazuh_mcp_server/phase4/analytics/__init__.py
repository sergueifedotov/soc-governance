"""Layer 5: Analytics & Business Intelligence (DuckDB + Grafana)

Real-time dashboards and reporting for SOC KPIs.
"""

import logging
import os
from datetime import datetime, timedelta
from typing import Dict, List, Any
import duckdb
from sqlalchemy import create_engine, text

logger = logging.getLogger(__name__)


class SOCAnalytics:
    """Analytics engine for SOC KPIs."""

    def __init__(self, db_path: str = ":memory:"):
        """Initialize DuckDB analytics engine."""
        self.conn = duckdb.connect(db_path)
        self.pg_engine = None

        db_url = os.getenv("DATABASE_URL")
        if db_url:
            try:
                self.pg_engine = create_engine(db_url, pool_pre_ping=True)
            except Exception as exc:  # pragma: no cover
                logger.warning("Failed to initialize PostgreSQL analytics fallback: %s", exc)

    def _pg_all(self, query: str, params: Dict[str, Any] | None = None) -> List[tuple]:
        """Execute a PostgreSQL fallback query and return row tuples."""
        if self.pg_engine is None:
            return []

        with self.pg_engine.connect() as conn:
            result = conn.execute(text(query), params or {})
            return [tuple(row) for row in result.fetchall()]

    @staticmethod
    def _safe_number(value: Any, default: float = 0.0) -> float:
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default

    def get_sla_metrics(self) -> Dict[str, float]:
        """Get SLA compliance metrics for last 30 days."""
        query = """
        SELECT
            COUNT(*) as total_incidents,
            SUM(CASE WHEN sla_breach THEN 1 ELSE 0 END) as breached_count,
            100.0 * SUM(CASE WHEN sla_breach THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) as breach_rate,
            AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0) as avg_resolution_hours
        FROM incidents
        WHERE created_at >= NOW() - INTERVAL '30 days'
        """
        try:
            result = self.conn.execute(query).fetchall()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB SLA query failed, falling back to PostgreSQL: %s", exc)
            result = self._pg_all(query)

        if not result:
            return {
                "total_incidents": 0,
                "breached_count": 0,
                "breach_rate": 0.0,
                "avg_resolution_hours": 0.0,
            }

        r = result[0]
        return {
            "total_incidents": int(self._safe_number(r[0], 0.0)),
            "breached_count": int(self._safe_number(r[1], 0.0)),
            "breach_rate": self._safe_number(r[2], 0.0),
            "avg_resolution_hours": self._safe_number(r[3], 0.0),
        }

    def get_risk_tier_distribution(self) -> Dict[str, int]:
        """Get incident distribution by risk tier."""
        query = """
        SELECT risk_tier, COUNT(*) as count
        FROM incidents
        WHERE created_at >= NOW() - INTERVAL '30 days'
        GROUP BY risk_tier
        ORDER BY risk_tier
        """
        try:
            results = self.conn.execute(query).fetchall()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB risk distribution query failed, falling back to PostgreSQL: %s", exc)
            results = self._pg_all(query)
        return {r[0]: r[1] for r in results}

    def get_analyst_workload(self) -> List[Dict[str, Any]]:
        """Get current workload per analyst."""
        query = """
        SELECT 
            assigned_to,
            COUNT(*) as open_incidents,
            status,
            risk_tier
        FROM incidents
        WHERE status IN ('ASSIGNED', 'INVESTIGATING')
        GROUP BY assigned_to, status, risk_tier
        ORDER BY open_incidents DESC
        """
        try:
            results = self.conn.execute(query).fetchall()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB analyst workload query failed, falling back to PostgreSQL: %s", exc)
            results = self._pg_all(query)
        return [
            {
                "analyst": r[0],
                "open_incidents": r[1],
                "status": r[2],
                "risk_tier": r[3],
            }
            for r in results
        ]

    def get_mean_time_to_detect(self) -> float:
        """Get MTTD (Mean Time To Detect) in minutes."""
        # Current incident schema does not include alert_timestamp. Keep stable 0.0 until
        # alert ingest time is persisted in incidents.
        return 0.0

    def get_mean_time_to_resolve(self) -> float:
        """Get MTTR (Mean Time To Resolve) in hours."""
        query = """
        SELECT AVG(EXTRACT(EPOCH FROM (resolved_at - created_at)) / 3600.0) as mttr_hours
        FROM incidents
        WHERE resolved_at IS NOT NULL
          AND created_at >= NOW() - INTERVAL '30 days'
        """
        try:
            result = self.conn.execute(query).fetchone()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB MTTR query failed, falling back to PostgreSQL: %s", exc)
            rows = self._pg_all(query)
            result = rows[0] if rows else None
        return self._safe_number(result[0], 0.0) if result else 0.0

    def get_alert_trends(self, days: int = 30) -> List[Dict[str, Any]]:
        """Get daily alert alert generation trends."""
        days = max(1, min(int(days), 365))
        query = f"""
        SELECT 
            DATE(created_at) as date,
            COUNT(*) as incident_count,
            SUM(alert_count) as total_alerts,
            COUNT(CASE WHEN sla_breach THEN 1 END) as sla_breaches
        FROM incidents
        WHERE created_at >= NOW() - INTERVAL '{days} days'
        GROUP BY DATE(created_at)
        ORDER BY date DESC
        """
        try:
            results = self.conn.execute(query).fetchall()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB alert trends query failed, falling back to PostgreSQL: %s", exc)
            results = self._pg_all(query)
        return [
            {
                "date": r[0],
                "incidents": r[1],
                "alerts": r[2],
                "sla_breaches": r[3],
            }
            for r in results
        ]

    def get_top_rules(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top triggering rules."""
        # Phase 4 incidents schema does not include rule_id/rule_name. Approximate with title.
        limit = max(1, min(int(limit), 100))
        query = """
        SELECT title as rule_name, COUNT(*) as count
        FROM incidents
        WHERE created_at >= NOW() - INTERVAL '7 days'
        GROUP BY title
        ORDER BY count DESC
        LIMIT :limit
        """
        try:
            results = self.conn.execute(query.replace(":limit", str(limit))).fetchall()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB top rules query failed, falling back to PostgreSQL: %s", exc)
            results = self._pg_all(query, {"limit": limit})
        return [
            {
                "rule_id": "n/a",
                "rule_name": r[0],
                "count": r[1],
            }
            for r in results
        ]

    def get_false_positive_rate(self) -> float:
        """Get false positive rate from ML predictions."""
        query = """
        SELECT 
            100.0 * SUM(CASE WHEN ml_false_positive_prob > 80 THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0)
        FROM incidents
        WHERE ml_false_positive_prob IS NOT NULL
          AND created_at >= NOW() - INTERVAL '7 days'
        """
        try:
            result = self.conn.execute(query).fetchone()
        except Exception as exc:  # pragma: no cover
            logger.warning("DuckDB false-positive-rate query failed, falling back to PostgreSQL: %s", exc)
            rows = self._pg_all(query)
            result = rows[0] if rows else None
        return self._safe_number(result[0], 0.0) if result else 0.0

    def generate_executive_report(self, start_date: datetime, end_date: datetime) -> Dict[str, Any]:
        """Generate executive summary report."""
        return {
            "period": f"{start_date.date()} to {end_date.date()}",
            "sla_metrics": self.get_sla_metrics(),
            "risk_distribution": self.get_risk_tier_distribution(),
            "mean_time_to_resolve": self.get_mean_time_to_resolve(),
            "false_positive_rate": self.get_false_positive_rate(),
            "top_rules": self.get_top_rules(5),
        }
