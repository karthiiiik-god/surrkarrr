from __future__ import annotations

import re
import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from .models import Asset, Remediation, ReportSnapshot, ScanJob, Vulnerability


VULNERABILITY_COLUMNS = {
    "vuln_id": "TEXT PRIMARY KEY",
    "host": "TEXT NOT NULL",
    "port": "INTEGER NOT NULL",
    "service": "TEXT NOT NULL",
    "vulnerability_name": "TEXT NOT NULL",
    "description": "TEXT NOT NULL",
    "cve_id": "TEXT",
    "cvss_score": "REAL NOT NULL DEFAULT 0.0",
    "severity": "TEXT NOT NULL DEFAULT 'Low'",
    "network_exposed": "INTEGER NOT NULL DEFAULT 0",
    "authentication_required": "INTEGER NOT NULL DEFAULT 0",
    "exploit_available": "INTEGER NOT NULL DEFAULT 0",
    "source_tool": "TEXT NOT NULL DEFAULT 'unknown'",
    "timestamp": "TEXT NOT NULL",
    "epss_score": "REAL NOT NULL DEFAULT 0.0",
    "nvd_description": "TEXT NOT NULL DEFAULT ''",
    "risk_score": "REAL NOT NULL DEFAULT 0.0",
    "exploit_prob": "REAL NOT NULL DEFAULT 0.0",
    "risk_path": "TEXT NOT NULL DEFAULT ''",
    "reference_links": "TEXT NOT NULL DEFAULT ''",
    "remediation": "TEXT NOT NULL DEFAULT ''",
    "asset_id": "TEXT",
}


USER_COLUMNS = {
    "username": "TEXT PRIMARY KEY",
    "password_hash": "TEXT NOT NULL",
    "role": "TEXT NOT NULL DEFAULT 'analyst'",
    "full_name": "TEXT NOT NULL DEFAULT ''",
    "is_active": "INTEGER NOT NULL DEFAULT 1",
    "created_at": "TEXT NOT NULL DEFAULT ''",
}


SCAN_JOB_COLUMNS = {
    "id": "TEXT PRIMARY KEY",
    "scanner": "TEXT NOT NULL",
    "mode": "TEXT NOT NULL",
    "target": "TEXT NOT NULL",
    "profile": "TEXT NOT NULL",
    "status": "TEXT NOT NULL",
    "command": "TEXT NOT NULL DEFAULT ''",
    "artifact_path": "TEXT NOT NULL DEFAULT ''",
    "findings_count": "INTEGER NOT NULL DEFAULT 0",
    "started_at": "TEXT NOT NULL",
    "finished_at": "TEXT NOT NULL DEFAULT ''",
    "error_message": "TEXT NOT NULL DEFAULT ''",
    "asset_id": "TEXT",
    "created_by": "TEXT NOT NULL DEFAULT ''",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Database:
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._table_column_cache: dict[str, set[str]] = {}
        self._initialize()

    def _initialize(self) -> None:
        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                vulnerability_name TEXT NOT NULL,
                description TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL NOT NULL DEFAULT 0.0,
                severity TEXT NOT NULL DEFAULT 'Low',
                network_exposed INTEGER NOT NULL DEFAULT 0,
                authentication_required INTEGER NOT NULL DEFAULT 0,
                exploit_available INTEGER NOT NULL DEFAULT 0,
                source_tool TEXT NOT NULL DEFAULT 'unknown',
                timestamp TEXT NOT NULL,
                epss_score REAL NOT NULL DEFAULT 0.0,
                nvd_description TEXT NOT NULL DEFAULT '',
                risk_score REAL NOT NULL DEFAULT 0.0,
                exploit_prob REAL NOT NULL DEFAULT 0.0,
                risk_path TEXT NOT NULL DEFAULT '',
                reference_links TEXT NOT NULL DEFAULT '',
                remediation TEXT NOT NULL DEFAULT '',
                asset_id TEXT
            )
            """
        )
        self._migrate_table_columns("vulnerabilities", VULNERABILITY_COLUMNS)
        self._backfill_vulnerability_compatibility_columns()

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'analyst',
                full_name TEXT NOT NULL DEFAULT '',
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._migrate_table_columns("users", USER_COLUMNS)

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS assets (
                asset_id TEXT PRIMARY KEY,
                target TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                owner_username TEXT NOT NULL DEFAULT '',
                environment TEXT NOT NULL DEFAULT 'production',
                criticality TEXT NOT NULL DEFAULT 'Medium',
                tags TEXT NOT NULL DEFAULT '',
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                vuln_id TEXT NOT NULL,
                assigned_to TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'Open',
                priority TEXT NOT NULL DEFAULT 'High',
                due_date TEXT,
                notes TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (vuln_id)
            )
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_jobs (
                id TEXT PRIMARY KEY,
                scanner TEXT NOT NULL,
                mode TEXT NOT NULL,
                target TEXT NOT NULL,
                profile TEXT NOT NULL,
                status TEXT NOT NULL,
                command TEXT NOT NULL DEFAULT '',
                artifact_path TEXT NOT NULL DEFAULT '',
                findings_count INTEGER NOT NULL DEFAULT 0,
                started_at TEXT NOT NULL,
                finished_at TEXT NOT NULL DEFAULT '',
                error_message TEXT NOT NULL DEFAULT '',
                asset_id TEXT,
                created_by TEXT NOT NULL DEFAULT ''
            )
            """
        )
        self._migrate_table_columns("scan_jobs", SCAN_JOB_COLUMNS)

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS report_snapshots (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                format_type TEXT NOT NULL,
                content TEXT NOT NULL,
                created_by TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            )
            """
        )

        self.conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        self.conn.commit()

    def _migrate_table_columns(self, table_name: str, column_map: dict[str, str]) -> None:
        existing = {
            row["name"]: row
            for row in self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        }
        for column, column_sql in column_map.items():
            if column not in existing:
                # SQLite does not allow adding a PRIMARY KEY column via ALTER TABLE.
                # Strip PRIMARY KEY so the column can be added; for new tables
                # the CREATE TABLE statement already enforces the primary key.
                migration_sql = re.sub(r"\s*PRIMARY\s+KEY\s*", " ", column_sql, flags=re.IGNORECASE).strip()
                self.conn.execute(
                    f"ALTER TABLE {table_name} ADD COLUMN {column} {migration_sql}"
                )
        self._table_column_cache.pop(table_name, None)
        self.conn.commit()

    def _table_columns(self, table_name: str) -> set[str]:
        if table_name not in self._table_column_cache:
            rows = self.conn.execute(f"PRAGMA table_info({table_name})").fetchall()
            self._table_column_cache[table_name] = {row["name"] for row in rows}
        return self._table_column_cache[table_name]

    def _backfill_vulnerability_compatibility_columns(self) -> None:
        columns = self._table_columns("vulnerabilities")
        if "risk_path" in columns and "attack_path" in columns:
            self.conn.execute(
                """
                UPDATE vulnerabilities
                SET risk_path = CASE
                    WHEN COALESCE(risk_path, '') = '' THEN COALESCE(attack_path, '')
                    ELSE risk_path
                END
                """
            )
            self.conn.commit()

    def log_action(self, username: str, action: str, target: str) -> None:
        self.conn.execute(
            "INSERT INTO audit_logs (username, action, target) VALUES (?, ?, ?)",
            (username, action, target),
        )
        self.conn.commit()

    def count_users(self) -> int:
        row = self.conn.execute("SELECT COUNT(*) AS count FROM users").fetchone()
        return int(row["count"])

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str = "analyst",
        *,
        full_name: str = "",
        is_active: bool = True,
    ) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO users (username, password_hash, role, full_name, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, COALESCE((SELECT created_at FROM users WHERE username = ?), ?))
            """,
            (username, password_hash, role, full_name, int(is_active), username, _now_iso()),
        )
        self.conn.commit()

    def get_user(self, username: str) -> Optional[dict[str, Any]]:
        row = self.conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,),
        ).fetchone()
        return dict(row) if row else None

    def list_users(self) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT username, role, full_name, is_active, created_at FROM users ORDER BY username"
        ).fetchall()
        return [dict(row) for row in rows]

    def update_user_role(self, username: str, role: str) -> None:
        self.conn.execute("UPDATE users SET role = ? WHERE username = ?", (role, username))
        self.conn.commit()

    def update_user_password(self, username: str, password_hash: str) -> None:
        self.conn.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (password_hash, username),
        )
        self.conn.commit()

    def set_user_active(self, username: str, is_active: bool) -> None:
        self.conn.execute(
            "UPDATE users SET is_active = ? WHERE username = ?",
            (int(is_active), username),
        )
        self.conn.commit()

    def upsert_asset(self, asset: Asset) -> Asset:
        asset.updated_at = _now_iso()
        self.conn.execute(
            """
            INSERT OR REPLACE INTO assets (
                asset_id, target, display_name, owner_username, environment,
                criticality, tags, notes, created_at, updated_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?,
                COALESCE((SELECT created_at FROM assets WHERE target = ?), ?), ?
            )
            """,
            (
                asset.asset_id,
                asset.target,
                asset.display_name,
                asset.owner_username,
                asset.environment,
                asset.criticality,
                asset.tags,
                asset.notes,
                asset.target,
                asset.created_at or _now_iso(),
                asset.updated_at,
            ),
        )
        self.conn.commit()
        return self.get_asset_by_target(asset.target) or asset

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        row = self.conn.execute(
            "SELECT * FROM assets WHERE asset_id = ?",
            (asset_id,),
        ).fetchone()
        return Asset.from_row(row) if row else None

    def get_asset_by_target(self, target: str) -> Optional[Asset]:
        row = self.conn.execute(
            "SELECT * FROM assets WHERE target = ?",
            (target,),
        ).fetchone()
        return Asset.from_row(row) if row else None

    def ensure_asset(
        self,
        target: str,
        *,
        owner_username: str = "",
        tags: str = "",
        display_name: str | None = None,
        environment: str = "production",
        criticality: str = "Medium",
        notes: str = "",
    ) -> Asset:
        asset = self.get_asset_by_target(target)
        if asset:
            updates = False
            if owner_username and not asset.owner_username:
                asset.owner_username = owner_username
                updates = True
            if tags:
                merged = self._merge_tags(asset.tags, tags)
                if merged != asset.tags:
                    asset.tags = merged
                    updates = True
            if notes and not asset.notes:
                asset.notes = notes
                updates = True
            if updates:
                asset.updated_at = _now_iso()
                self.upsert_asset(asset)
            return asset

        asset = Asset.new(
            target=target,
            display_name=display_name or target,
            owner_username=owner_username,
            environment=environment,
            criticality=criticality,
            tags=tags or "discovered",
            notes=notes,
        )
        return self.upsert_asset(asset)

    def list_assets(self, username: str | None = None, role: str | None = None) -> list[Asset]:
        rows = self.conn.execute("SELECT * FROM assets ORDER BY target").fetchall()
        assets = [Asset.from_row(row) for row in rows]
        return self._filter_assets_for_scope(assets, username=username, role=role)

    def delete_asset(self, asset_id: str) -> None:
        self.conn.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
        self.conn.commit()

    def insert_vulnerability(self, vuln: Vulnerability) -> None:
        asset = self.ensure_asset(vuln.host)
        vuln.asset_id = asset.asset_id
        column_values: dict[str, Any] = {
            "vuln_id": vuln.vuln_id,
            "host": vuln.host,
            "port": int(vuln.port),
            "service": vuln.service,
            "vulnerability_name": vuln.vulnerability_name,
            "description": vuln.description,
            "cve_id": vuln.cve_id,
            "cvss_score": float(vuln.cvss_score),
            "severity": vuln.severity,
            "network_exposed": int(vuln.network_exposed),
            "authentication_required": int(vuln.authentication_required),
            "exploit_available": int(vuln.exploit_available),
            "source_tool": vuln.source_tool,
            "source_tools": vuln.source_tool,
            "timestamp": vuln.timestamp,
            "epss_score": float(vuln.epss_score),
            "nvd_description": vuln.nvd_description,
            "risk_score": float(vuln.risk_score),
            "exploit_prob": float(vuln.exploit_prob),
            "risk_path": vuln.risk_path,
            "attack_path": vuln.risk_path,
            "reference_links": vuln.references,
            "remediation": vuln.remediation,
            "asset_id": vuln.asset_id,
        }
        available_columns = self._table_columns("vulnerabilities")
        insert_columns = [column for column in column_values if column in available_columns]
        placeholders = ", ".join("?" for _ in insert_columns)
        column_sql = ", ".join(insert_columns)
        values = [column_values[column] for column in insert_columns]
        self.conn.execute(
            f"INSERT OR REPLACE INTO vulnerabilities ({column_sql}) VALUES ({placeholders})",
            values,
        )
        self.conn.commit()

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        row = self.conn.execute(
            "SELECT * FROM vulnerabilities WHERE vuln_id = ?",
            (vuln_id,),
        ).fetchone()
        return Vulnerability.from_row(row) if row else None

    def get_all_vulnerabilities(
        self,
        username: str | None = None,
        role: str | None = None,
    ) -> list[Vulnerability]:
        rows = self.conn.execute(
            "SELECT * FROM vulnerabilities ORDER BY timestamp DESC, cvss_score DESC"
        ).fetchall()
        vulns = [Vulnerability.from_row(row) for row in rows]
        return self._filter_vulnerabilities_for_scope(vulns, username=username, role=role)

    def clear_vulnerabilities(self) -> None:
        self.conn.execute("DELETE FROM vulnerabilities")
        self.conn.commit()

    def update_vulnerability(self, vuln: Vulnerability) -> None:
        self.insert_vulnerability(vuln)

    def delete_vulnerability(self, vuln_id: str) -> None:
        self.conn.execute("DELETE FROM vulnerabilities WHERE vuln_id = ?", (vuln_id,))
        self.conn.commit()

    def create_remediation(self, remediation: Remediation) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO remediations (
                id, vuln_id, assigned_to, status, priority, due_date, notes, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                remediation.id,
                remediation.vuln_id,
                remediation.assigned_to,
                remediation.status,
                remediation.priority,
                remediation.due_date,
                remediation.notes,
                remediation.created_at,
            ),
        )
        self.conn.commit()

    def list_remediations(
        self,
        status: Optional[str] = None,
        *,
        username: str | None = None,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        if status:
            rows = self.conn.execute(
                """
                SELECT r.*, v.host, v.port, v.vulnerability_name, v.severity, v.asset_id
                FROM remediations r
                LEFT JOIN vulnerabilities v ON v.vuln_id = r.vuln_id
                WHERE r.status = ?
                ORDER BY r.priority DESC, r.due_date
                """,
                (status,),
            ).fetchall()
        else:
            rows = self.conn.execute(
                """
                SELECT r.*, v.host, v.port, v.vulnerability_name, v.severity, v.asset_id
                FROM remediations r
                LEFT JOIN vulnerabilities v ON v.vuln_id = r.vuln_id
                ORDER BY r.status, r.priority DESC, r.due_date
                """
            ).fetchall()
        remediations = [dict(row) for row in rows]
        if role == "admin" or not username:
            return remediations
        allowed_assets = {asset.asset_id for asset in self.list_assets(username, role)}
        return [item for item in remediations if not item.get("asset_id") or item["asset_id"] in allowed_assets]

    def update_remediation_status(self, remediation_id: str, status: str) -> None:
        self.conn.execute(
            "UPDATE remediations SET status = ? WHERE id = ?",
            (status, remediation_id),
        )
        self.conn.commit()

    def create_scan_job(self, scan_job: ScanJob) -> None:
        if not scan_job.asset_id and scan_job.target:
            asset = self.get_asset_by_target(scan_job.target)
            if asset:
                scan_job.asset_id = asset.asset_id
        self.conn.execute(
            """
            INSERT OR REPLACE INTO scan_jobs (
                id, scanner, mode, target, profile, status, command, artifact_path,
                findings_count, started_at, finished_at, error_message, asset_id, created_by
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_job.id,
                scan_job.scanner,
                scan_job.mode,
                scan_job.target,
                scan_job.profile,
                scan_job.status,
                scan_job.command,
                scan_job.artifact_path,
                scan_job.findings_count,
                scan_job.started_at,
                scan_job.finished_at,
                scan_job.error_message,
                scan_job.asset_id,
                scan_job.created_by,
            ),
        )
        self.conn.commit()

    def update_scan_job(
        self,
        scan_job_id: str,
        *,
        status: Optional[str] = None,
        command: Optional[str] = None,
        artifact_path: Optional[str] = None,
        findings_count: Optional[int] = None,
        finished_at: Optional[str] = None,
        error_message: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> None:
        updates: list[str] = []
        values: list[Any] = []
        if status is not None:
            updates.append("status = ?")
            values.append(status)
        if command is not None:
            updates.append("command = ?")
            values.append(command)
        if artifact_path is not None:
            updates.append("artifact_path = ?")
            values.append(artifact_path)
        if findings_count is not None:
            updates.append("findings_count = ?")
            values.append(findings_count)
        if finished_at is not None:
            updates.append("finished_at = ?")
            values.append(finished_at)
        if error_message is not None:
            updates.append("error_message = ?")
            values.append(error_message)
        if asset_id is not None:
            updates.append("asset_id = ?")
            values.append(asset_id)

        if not updates:
            return

        values.append(scan_job_id)
        self.conn.execute(
            f"UPDATE scan_jobs SET {', '.join(updates)} WHERE id = ?",
            values,
        )
        self.conn.commit()

    def list_scan_jobs(
        self,
        limit: int = 25,
        *,
        username: str | None = None,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT *
            FROM scan_jobs
            ORDER BY started_at DESC, scanner
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        jobs = [dict(row) for row in rows]
        if role == "admin" or not username:
            return jobs
        allowed_assets = {asset.asset_id for asset in self.list_assets(username, role)}
        return [
            job
            for job in jobs
            if job.get("created_by") == username or not job.get("asset_id") or job["asset_id"] in allowed_assets
        ]

    def save_report_snapshot(self, snapshot: ReportSnapshot) -> None:
        self.conn.execute(
            """
            INSERT OR REPLACE INTO report_snapshots (
                id, title, format_type, content, created_by, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                snapshot.id,
                snapshot.title,
                snapshot.format_type,
                snapshot.content,
                snapshot.created_by,
                snapshot.created_at,
            ),
        )
        self.conn.commit()

    def list_report_snapshots(
        self,
        limit: int = 20,
        *,
        username: str | None = None,
        role: str | None = None,
    ) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            """
            SELECT *
            FROM report_snapshots
            ORDER BY created_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        snapshots = [dict(row) for row in rows]
        if role == "admin" or not username:
            return snapshots
        return [
            snapshot for snapshot in snapshots
            if not snapshot.get("created_by") or snapshot["created_by"] == username
        ]

    def get_summary(
        self,
        username: str | None = None,
        role: str | None = None,
    ) -> dict[str, Any]:
        vulns = self.get_all_vulnerabilities(username=username, role=role)
        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
        top_hosts: dict[str, int] = {}
        for vuln in vulns:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
            top_hosts[vuln.host] = top_hosts.get(vuln.host, 0) + 1
        scan_jobs = self.list_scan_jobs(limit=100, username=username, role=role)
        return {
            "total": len(vulns),
            "severity_counts": severity_counts,
            "top_hosts": sorted(top_hosts.items(), key=lambda item: item[1], reverse=True)[:5],
            "open_remediations": len(
                [
                    item
                    for item in self.list_remediations(username=username, role=role)
                    if item["status"] != "Closed"
                ]
            ),
            "scan_count": len(scan_jobs),
            "latest_scan_at": scan_jobs[0]["started_at"] if scan_jobs else "",
            "unique_assets": len(self.list_assets(username, role)),
            "report_count": len(self.list_report_snapshots(limit=100, username=username, role=role)),
        }

    def _filter_assets_for_scope(
        self,
        assets: list[Asset],
        *,
        username: str | None = None,
        role: str | None = None,
    ) -> list[Asset]:
        if role == "admin" or not username:
            return assets
        return [
            asset
            for asset in assets
            if not asset.owner_username or asset.owner_username == username
        ]

    def _filter_vulnerabilities_for_scope(
        self,
        vulns: list[Vulnerability],
        *,
        username: str | None = None,
        role: str | None = None,
    ) -> list[Vulnerability]:
        if role == "admin" or not username:
            return vulns
        allowed_assets = {asset.asset_id for asset in self.list_assets(username, role)}
        return [
            vuln
            for vuln in vulns
            if not vuln.asset_id or vuln.asset_id in allowed_assets
        ]

    @staticmethod
    def _merge_tags(existing_tags: str, incoming_tags: str) -> str:
        existing = {item.strip() for item in existing_tags.split(",") if item.strip()}
        incoming = {item.strip() for item in incoming_tags.split(",") if item.strip()}
        return ", ".join(sorted(existing | incoming))

    def close(self) -> None:
        self.conn.close()
