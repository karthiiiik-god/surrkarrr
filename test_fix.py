import os
import tempfile
import unittest

from core.storage.database import Database
from core.storage.models import Vulnerability


class LegacySchemaCompatibilityTests(unittest.TestCase):
    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db = Database(self.temp_db.name)

    def tearDown(self):
        self.db.close()
        os.unlink(self.temp_db.name)

    def test_insert_vulnerability_supports_legacy_source_tools_column(self):
        self.db.conn.execute("ALTER TABLE vulnerabilities ADD COLUMN source_tools TEXT NOT NULL DEFAULT ''")
        self.db.conn.commit()
        self.db._table_column_cache.pop("vulnerabilities", None)

        vuln = Vulnerability.new(
            host="test-host",
            port=80,
            service="http",
            vulnerability_name="Test Vuln",
            description="Test description",
            cvss_score=5.0,
            severity="Medium",
            source_tool="nmap",
            risk_path="test risk path",
        )

        self.db.insert_vulnerability(vuln)
        stored = self.db.get_vulnerability(vuln.vuln_id)

        self.assertIsNotNone(stored)
        self.assertEqual(stored.risk_path, "test risk path")


if __name__ == "__main__":
    unittest.main()
