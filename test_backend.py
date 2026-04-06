import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from core.storage.models import Vulnerability
from core.storage.database import Database
from core.scanner_ingestion import nmap_parser, nessus_parser, openvas_parser, nikto_parser
from core.normalization import cve_mapper, deduplicator, schema
from core.risk_engine import cvss_calculator, severity_ranker, false_positive_filter
from core.ai_query import nlp_parser, intent_classifier, query_executor
from core.reporting.report_generator import generate_report
import uuid
import datetime

def test_database():
    print("Testing Database CRUD...")
    db = Database(":memory:")  # Use in-memory for testing
    vuln = Vulnerability(
        id=str(uuid.uuid4()),
        host="192.168.1.1",
        port=80,
        service="http",
        vulnerability_name="Test Vuln",
        description="Test description",
        cve_id="CVE-2023-1234",
        cvss_score=7.5,
        severity="High",
        source_tools=["nmap"],
        timestamp=datetime.datetime.now().isoformat()
    )
    db.insert_vulnerability(vuln)
    retrieved = db.get_vulnerability(vuln.id)
    assert retrieved is not None and retrieved.id == vuln.id
    vuln.cvss_score = 8.0
    db.update_vulnerability(vuln)
    updated = db.get_vulnerability(vuln.id)
    assert updated.cvss_score == 8.0
    db.delete_vulnerability(vuln.id)
    assert db.get_vulnerability(vuln.id) is None
    print("Database CRUD tests passed.")

def test_parsers():
    print("Testing Parsers...")
    # Nmap sample
    nmap_xml = '''<?xml version="1.0"?>
<nmaprun>
<host><address addr="192.168.1.1"/><ports><port portid="80"><service name="http"/><script id="vuln"><output>CVE-2023-1234 7.5 Vulnerability found</output></script></port></ports></host>
</nmaprun>'''
    nmap_vulns = nmap_parser.parse_nmap(nmap_xml)
    assert len(nmap_vulns) > 0
    assert nmap_vulns[0].cve_id == "CVE-2023-1234"

    # Nessus sample (simplified)
    nessus_xml = '''<?xml version="1.0"?>
<NessusClientData_v2><Report><ReportHost name="192.168.1.1"><ReportItem port="80" svc_name="http" pluginName="Test Plugin" severity="3"><cvss_base_score>7.5</cvss_base_score><cve>CVE-2023-1234</cve><description>Test desc</description></ReportItem></ReportHost></Report></NessusClientData_v2>'''
    nessus_vulns = nessus_parser.parse_nessus(nessus_xml)
    assert len(nessus_vulns) > 0

    # OpenVAS sample
    openvas_xml = '''<?xml version="1.0"?>
<report><results><result><host>192.168.1.1</host><port>80/tcp</port><nvt><name>Test NVT</name><cvss_base>7.5</cvss_base><cve>CVE-2023-1234</cve><description>Test desc</description></nvt><threat>High</threat></result></results></report>'''
    openvas_vulns = openvas_parser.parse_openvas(openvas_xml)
    assert len(openvas_vulns) > 0

    # Nikto JSON sample
    nikto_json = '''[{"host": "192.168.1.1", "port": 80, "msg": "Test finding", "cve": "CVE-2023-1234", "cvss": 7.5}]'''
    nikto_vulns = nikto_parser.parse_nikto(nikto_json)
    assert len(nikto_vulns) > 0

    print("Parser tests passed.")

def test_normalization():
    print("Testing Normalization...")
    vuln1 = Vulnerability(id="1", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id="cve-2023-1234", cvss_score=7.5, severity="High", source_tools=["nmap"], timestamp="t")
    vuln2 = cve_mapper.map_cve(vuln1)
    assert vuln2.cve_id == "CVE-2023-1234"

    vuln3 = Vulnerability(id="2", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id="CVE-2023-1234", cvss_score=8.0, severity="High", source_tools=["nessus"], timestamp="t")
    deduped = deduplicator.deduplicate_vulnerabilities([vuln1, vuln3])
    assert len(deduped) == 1
    assert deduped[0].cvss_score == 8.0  # Higher score
    assert "nmap" in deduped[0].source_tools and "nessus" in deduped[0].source_tools

    assert schema.validate_vulnerability(vuln1)
    print("Normalization tests passed.")

def test_risk_engine():
    print("Testing Risk Engine...")
    vuln = Vulnerability(id="1", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id=None, cvss_score=0.0, severity="Low", source_tools=["nmap"], timestamp="t")
    cvss = cvss_calculator.calculate_cvss_fallback(vuln)
    assert cvss == 2.0  # Low severity fallback

    severity = severity_ranker.classify_severity(7.5)
    assert severity == "High"

    vulns = [
        Vulnerability(id="1", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id=None, cvss_score=9.0, severity="Critical", source_tools=["nmap"], timestamp="t"),
        Vulnerability(id="2", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id=None, cvss_score=7.0, severity="High", source_tools=["nmap"], timestamp="t")
    ]
    ranked = severity_ranker.rank_vulnerabilities(vulns)
    assert ranked[0].cvss_score == 9.0

    filtered = false_positive_filter.filter_false_positives(vulns)
    assert len(filtered) == 2  # No false positives here
    print("Risk Engine tests passed.")

def test_ai_query():
    print("Testing AI Query...")
    filters = nlp_parser.parse_query("Critical vulnerabilities on port 22")
    assert filters.get("severity") == "Critical"
    assert filters.get("port") == 22

    intent = intent_classifier.classify_intent("Top risky hosts")
    assert intent == "top_hosts"

    # Mock db for query_executor
    class MockDB:
        def get_all_vulnerabilities(self):
            return [
                Vulnerability(id="1", host="192.168.1.1", port=22, service="ssh", vulnerability_name="SSH Vuln", description="d", cve_id=None, cvss_score=9.0, severity="Critical", source_tools=["nmap"], timestamp="t")
            ]

    db = MockDB()
    result = query_executor.execute_query("Critical vulnerabilities", db)
    assert result["intent"] == "list_vulnerabilities"
    assert len(result["results"]) == 1
    print("AI Query tests passed.")

def test_reporting():
    print("Testing Reporting...")
    vulns = [
        Vulnerability(id="1", host="h", port=80, service="s", vulnerability_name="v", description="d", cve_id=None, cvss_score=9.0, severity="Critical", source_tools=["nmap"], timestamp="t")
    ]
    md_report = generate_report(vulns, "markdown")
    assert "Total Vulnerabilities: 1" in md_report
    assert "Critical: 1" in md_report

    pdf_report = generate_report(vulns, "pdf")
    assert isinstance(pdf_report, bytes)
    print("Reporting tests passed.")

if __name__ == "__main__":
    test_database()
    test_parsers()
    test_normalization()
    test_risk_engine()
    test_ai_query()
    test_reporting()
    print("All backend tests passed!")
