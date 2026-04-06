from typing import List, Dict, Any
from ..storage.database import Database
from ..storage.models import Vulnerability
from .intent_parser import parse_intent
from ..risk_engine.attack_path_generator import generate_attack_paths

class QueryExecutor:
    def __init__(self, db: Database):
        self.db = db

    def execute_query(self, query: str) -> Dict[str, Any]:
        """
        Execute natural language query and return results with explanation.
        """
        filters = parse_intent(query)
        intent = filters.pop("intent", None)

        if intent == "top_risky_hosts":
            return self._get_top_risky_hosts()
        elif intent == "attack_path":
            service = filters.get("service", "ssh")
            return self._get_attack_path(service)
        else:
            # Standard filter query
            vulns = self._filter_vulnerabilities(filters)
            explanation = f"Found {len(vulns)} vulnerabilities matching filters: {filters}"
            return {"results": vulns, "explanation": explanation}

    def _filter_vulnerabilities(self, filters: Dict[str, Any]) -> List[Vulnerability]:
        all_vulns = self.db.get_all_vulnerabilities()
        filtered = []
        for vuln in all_vulns:
            match = True
            if "severity" in filters and vuln.severity != filters["severity"]:
                match = False
            if "port" in filters and vuln.port != filters["port"]:
                match = False
            if "cvss_min" in filters and vuln.cvss_score < filters["cvss_min"]:
                match = False
            if "cvss_max" in filters and vuln.cvss_score > filters["cvss_max"]:
                match = False
            if "host" in filters and vuln.host != filters["host"]:
                match = False
            if "cve_id" in filters and vuln.cve_id != filters["cve_id"]:
                match = False
            if "service" in filters and vuln.service != filters["service"]:
                match = False
            if match:
                filtered.append(vuln)
        return filtered

    def _get_top_risky_hosts(self) -> Dict[str, Any]:
        all_vulns = self.db.get_all_vulnerabilities()
        host_risks = {}
        for vuln in all_vulns:
            risk = vuln.cvss_score + (1 if vuln.network_exposed else 0) + (1 if vuln.exploit_available else 0)
            if vuln.host not in host_risks:
                host_risks[vuln.host] = 0
            host_risks[vuln.host] += risk
        top_hosts = sorted(host_risks.items(), key=lambda x: x[1], reverse=True)[:5]
        explanation = "Top risky hosts based on aggregated vulnerability risk scores."
        return {"results": top_hosts, "explanation": explanation}

    def _get_attack_path(self, service: str) -> Dict[str, Any]:
        all_vulns = self.db.get_all_vulnerabilities()
        service_vulns = [v for v in all_vulns if v.service == service]
        paths = generate_attack_paths(service_vulns)
        explanation = f"Generated attack paths for {service} service."
        return {"results": paths, "explanation": explanation}
