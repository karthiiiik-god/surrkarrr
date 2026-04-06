import sqlite3
from typing import List, Optional
from .models import Vulnerability

class Database:
    def __init__(self, db_path: str = "vulnerabilities.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path)
        self._create_table()

    def _create_table(self):
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                vuln_id TEXT PRIMARY KEY,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                service TEXT NOT NULL,
                vulnerability_name TEXT NOT NULL,
                description TEXT NOT NULL,
                cve_id TEXT,
                cvss_score REAL NOT NULL,
                severity TEXT NOT NULL,
                network_exposed INTEGER NOT NULL,
                authentication_required INTEGER NOT NULL,
                exploit_available INTEGER NOT NULL,
                source_tool TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                epss_score REAL DEFAULT 0.0,
                nvd_description TEXT
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                vuln_id TEXT,
                assigned_to TEXT,
                status TEXT DEFAULT 'Open',
                priority TEXT DEFAULT 'High',
                due_date TEXT,
                notes TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (vuln_id) REFERENCES vulnerabilities (vuln_id)
            )
        """)
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT,
                target TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()

    def create_user(self, username: str, password_hash: str, role: str):
        self.conn.execute("INSERT OR REPLACE INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                         (username, password_hash, role))
        self.conn.commit()

    def get_user(self, username: str) -> Optional[dict]:
        cursor = self.conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if row:
            return {'username': row[0], 'password_hash': row[1], 'role': row[2]}
        return None

    def insert_vulnerability(self, vuln: Vulnerability):
        self.conn.execute("""
            INSERT OR REPLACE INTO vulnerabilities
            (vuln_id, host, port, service, vulnerability_name, description, cve_id, cvss_score, severity, network_exposed, authentication_required, exploit_available, source_tool, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (vuln.vuln_id, vuln.host, vuln.port, vuln.service, vuln.vulnerability_name, vuln.description,
              vuln.cve_id, vuln.cvss_score, vuln.severity, int(vuln.network_exposed), int(vuln.authentication_required), int(vuln.exploit_available), str(vuln.get('source_tool', 'unknown')), vuln.timestamp))
        self.conn.commit()

    def get_vulnerability(self, vuln_id: str) -> Optional[Vulnerability]:
        cursor = self.conn.execute("SELECT * FROM vulnerabilities WHERE vuln_id = ?", (vuln_id,))
        row = cursor.fetchone()
        if row:
            return Vulnerability(
                vuln_id=row[0], host=row[1], port=row[2], service=row[3], vulnerability_name=row[4],
                description=row[5], cve_id=row[6], cvss_score=row[7], severity=row[8],
                network_exposed=bool(row[9]), authentication_required=bool(row[10]), exploit_available=bool(row[11]), source_tool=row[12], timestamp=row[13]
            )
        return None

    def get_all_vulnerabilities(self) -> List[Vulnerability]:
        vulnerabilities = []
        cursor = self.conn.execute("SELECT * FROM vulnerabilities")
        for row in cursor:
            vulnerabilities.append(Vulnerability(
                vuln_id=row[0], host=row[1], port=row[2], service=row[3], vulnerability_name=row[4],
                description=row[5], cve_id=row[6], cvss_score=row[7], severity=row[8],
                network_exposed=bool(row[9]), authentication_required=bool(row[10]), exploit_available=bool(row[11]), source_tool=row[12], timestamp=row[13]
            ))
        return vulnerabilities

    def update_vulnerability(self, vuln: Vulnerability):
        self.insert_vulnerability(vuln)

    def delete_vulnerability(self, vuln_id: str):
        self.conn.execute("DELETE FROM vulnerabilities WHERE vuln_id = ?", (vuln_id,))
        self.conn.commit()

    def close(self):
        self.conn.close()
