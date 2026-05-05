import os
import tempfile
import unittest
from hashlib import sha256

from core.ai_query.query_executor import QueryExecutor
from core.normalization.normalizer import normalize_vulnerabilities
from core.reporting.report_generator import generate_report
from core.scanner.adapters import get_scanner_adapter, list_live_adapters, list_upload_adapters
from core.scanner.live_scanner import build_scan_command, preview_scan_command, validate_target
from core.scanner_ingestion.nessus_parser import parse_nessus
from core.scanner_ingestion.nikto_parser import parse_nikto
from core.scanner_ingestion.nmap_parser import parse_nmap
from core.scanner_ingestion.nuclei_parser import parse_nuclei
from core.scanner_ingestion.openvas_parser import parse_openvas
from core.storage.database import Database
from core.storage.models import Asset, ReportSnapshot, ScanJob


class BackendSmokeTests(unittest.TestCase):
    @staticmethod
    def _read(path):
        with open(path, encoding="utf-8") as handle:
            return handle.read()

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.temp_db.close()
        self.db = Database(self.temp_db.name)
        self.db.create_user("admin", sha256("admin123".encode("utf-8")).hexdigest(), "admin", full_name="Admin User")

    def tearDown(self):
        self.db.close()
        os.unlink(self.temp_db.name)

    def test_database_crud(self):
        vuln = normalize_vulnerabilities(parse_nmap(self._read("sample_nmap.xml")))[0]
        self.db.insert_vulnerability(vuln)

        fetched = self.db.get_vulnerability(vuln.vuln_id)
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched.vuln_id, vuln.vuln_id)
        self.assertIsNotNone(fetched.asset_id)
        self.assertTrue(fetched.risk_path)
        self.assertEqual(fetched.attack_path, fetched.risk_path)

        fetched.severity = "Critical"
        self.db.update_vulnerability(fetched)
        self.assertEqual(self.db.get_vulnerability(vuln.vuln_id).severity, "Critical")

        self.db.delete_vulnerability(vuln.vuln_id)
        self.assertIsNone(self.db.get_vulnerability(vuln.vuln_id))

    def test_parsers(self):
        nmap_vulns = parse_nmap(self._read("sample_nmap.xml"))
        nessus_vulns = parse_nessus(self._read("sample_nessus.nessus"))
        openvas_vulns = parse_openvas(
            """<?xml version="1.0"?>
            <report><results><result><host>192.168.1.10</host><port>443/tcp</port>
            <nvt><name>Sample OpenVAS</name><cvss_base>7.5</cvss_base><cve>CVE-2023-0001</cve>
            <description>Sample description</description></nvt></result></results></report>"""
        )
        nikto_vulns = parse_nikto(
            '[{"host": "192.168.1.20", "port": 80, "msg": "Nikto finding", "cve": "CVE-2023-0002", "cvss": 5.0}]'
        )
        nuclei_vulns = parse_nuclei(
            '{"template-id":"test-template","matched-at":"https://example.com/login","info":{"severity":"high","description":"Test nuclei finding","reference":["https://example.com/advisory"]}}'
        )

        self.assertGreaterEqual(len(nmap_vulns), 1)
        self.assertGreaterEqual(len(nessus_vulns), 1)
        self.assertEqual(len(openvas_vulns), 1)
        self.assertEqual(len(nikto_vulns), 1)
        self.assertEqual(len(nuclei_vulns), 1)

    def test_assets_and_reports(self):
        asset = Asset.new(
            target="example.com",
            display_name="Example External",
            owner_username="admin",
            environment="production",
            criticality="High",
            tags="internet-facing, critical",
        )
        saved_asset = self.db.upsert_asset(asset)
        self.assertEqual(self.db.get_asset(saved_asset.asset_id).target, "example.com")

        snapshot = ReportSnapshot.new(
            title="Weekly Summary",
            format_type="markdown",
            content="# Weekly Summary\nEverything looks good.",
            created_by="admin",
        )
        self.db.save_report_snapshot(snapshot)
        self.assertEqual(len(self.db.list_report_snapshots(username="admin", role="admin")), 1)

    def test_normalization_reporting_and_summary(self):
        normalized = normalize_vulnerabilities(parse_nmap(self._read("sample_nmap.xml")))
        for vuln in normalized:
            self.db.insert_vulnerability(vuln)
        self.assertGreaterEqual(len(normalized), 1)
        self.assertTrue(all(vuln.risk_score >= vuln.cvss_score for vuln in normalized))

        report = generate_report(normalized, "markdown")
        self.assertIn("SurrKarr Vulnerability Report", report)

        pdf_report = generate_report(normalized, "pdf")
        self.assertIsInstance(pdf_report, bytes)

        summary = self.db.get_summary("admin", "admin")
        self.assertGreaterEqual(summary["unique_assets"], 1)

    def test_query_executor(self):
        normalized = normalize_vulnerabilities(parse_nmap(self._read("sample_nmap.xml")))
        for vuln in normalized:
            self.db.insert_vulnerability(vuln)
        self.db.save_report_snapshot(
            ReportSnapshot.new(
                title="Log4j Report",
                format_type="markdown",
                content="This report references CVE-2021-44228 and web exposure.",
                created_by="admin",
            )
        )

        executor = QueryExecutor(self.db, "admin", "admin")
        filtered = executor.execute_query("Critical vulnerabilities")
        top_hosts = executor.execute_query("Top risky hosts")
        risk_paths = executor.execute_query("Risk path for ssh")
        report_lookup = executor.execute_query("report summary log4j")

        self.assertEqual(filtered["mode"], "vulnerabilities")
        self.assertEqual(top_hosts["mode"], "hosts")
        self.assertEqual(risk_paths["mode"], "paths")
        self.assertEqual(report_lookup["mode"], "documents")
        self.assertIn("response", filtered)
        self.assertIn("summary", filtered["response"])
        self.assertTrue(any(citation["source_type"] == "threat-intel" for citation in report_lookup["citations"] + filtered["citations"]))

    def test_scan_job_and_command_helpers(self):
        asset = self.db.ensure_asset("example.com", owner_username="admin", tags="lab")
        job = ScanJob.new(
            scanner="nmap",
            mode="live",
            target="example.com",
            profile="Quick Discovery",
            status="Running",
            asset_id=asset.asset_id,
            created_by="admin",
        )
        self.db.create_scan_job(job)
        self.db.update_scan_job(job.id, status="Completed", findings_count=3, finished_at="done")
        jobs = self.db.list_scan_jobs(limit=5, username="admin", role="admin")

        self.assertEqual(len(jobs), 1)
        self.assertEqual(jobs[0]["status"], "Completed")

        self.assertEqual(validate_target("example.com"), "example.com")
        preview = preview_scan_command("nmap", "example.com", "Quick Discovery")
        command = build_scan_command(
            "nikto",
            "example.com",
            "Baseline Web Audit",
            output_path="scan.txt",
            extra_args=[],
        )

        self.assertIn("nmap", preview)
        self.assertEqual(command[0], "nikto")

    def test_scanner_adapter_registry(self):
        upload_names = {adapter.display_name for adapter in list_upload_adapters()}
        live_names = {adapter.display_name for adapter in list_live_adapters()}

        self.assertIn("Nmap", upload_names)
        self.assertIn("Nessus", upload_names)
        self.assertIn("Nmap", live_names)
        self.assertEqual(get_scanner_adapter("Nmap").key, "nmap")


if __name__ == "__main__":
    unittest.main()
