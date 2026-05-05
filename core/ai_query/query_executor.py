from __future__ import annotations

import re
from typing import Any

from .intent_parser import parse_intent
from ..risk_engine.attack_path_generator import generate_attack_paths
from ..storage.database import Database
from ..storage.models import Vulnerability


class QueryExecutor:
    def __init__(self, db: Database, username: str = "", role: str = "viewer"):
        self.db = db
        self.username = username
        self.role = role

    def execute_query(self, query: str) -> dict[str, Any]:
        filters = parse_intent(query)
        intent = filters.pop("intent", "semantic_search")

        if intent == "top_risky_hosts":
            return self._get_top_risky_hosts()
        if intent == "attack_path":
            return self._get_risk_paths(filters.get("service"))
        if intent == "asset_lookup":
            return self._lookup_assets(filters)
        if intent == "report_lookup":
            return self._lookup_reports(query)

        structured = self._filter_vulnerabilities(filters)
        if structured and any(key in filters for key in ("severity", "port", "cvss_min", "cvss_max", "host", "cve_id", "service")):
            citations = [self._citation_for_vulnerability(vuln) for vuln in structured[:5]]
            return {
                "mode": "vulnerabilities",
                "results": structured,
                "answer": f"Matched {len(structured)} findings in the current access scope.",
                "explanation": "These results were filtered directly from normalized vulnerability records.",
                "citations": citations,
            }

        return self._semantic_search(query)

    def _accessible_vulnerabilities(self) -> list[Vulnerability]:
        return self.db.get_all_vulnerabilities(self.username, self.role)

    def _accessible_assets(self):
        return self.db.list_assets(self.username, self.role)

    def _accessible_reports(self):
        return self.db.list_report_snapshots(limit=50, username=self.username, role=self.role)

    def _accessible_scan_jobs(self):
        return self.db.list_scan_jobs(limit=50, username=self.username, role=self.role)

    def _filter_vulnerabilities(self, filters: dict[str, Any]) -> list[Vulnerability]:
        filtered: list[Vulnerability] = []
        for vuln in self._accessible_vulnerabilities():
            if "severity" in filters and vuln.severity != filters["severity"]:
                continue
            if "port" in filters and vuln.port != filters["port"]:
                continue
            if "cvss_min" in filters and vuln.cvss_score < filters["cvss_min"]:
                continue
            if "cvss_max" in filters and vuln.cvss_score > filters["cvss_max"]:
                continue
            if "host" in filters and filters["host"].lower() not in vuln.host.lower():
                continue
            if "cve_id" in filters and vuln.cve_id != filters["cve_id"]:
                continue
            if "service" in filters and vuln.service.lower() != filters["service"].lower():
                continue
            filtered.append(vuln)
        return filtered

    def _get_top_risky_hosts(self) -> dict[str, Any]:
        host_scores: dict[str, float] = {}
        for vuln in self._accessible_vulnerabilities():
            host_scores[vuln.host] = host_scores.get(vuln.host, 0.0) + vuln.risk_score
        top_hosts = sorted(host_scores.items(), key=lambda item: item[1], reverse=True)[:5]
        citations = [
            {"label": f"{host}", "source_type": "asset-summary", "reference": f"host:{host}"}
            for host, _ in top_hosts
        ]
        return {
            "mode": "hosts",
            "results": top_hosts,
            "answer": "These hosts have the highest aggregated normalized risk in your accessible scope.",
            "explanation": "Host ranking is calculated from stored vulnerability risk scores.",
            "citations": citations,
        }

    def _get_risk_paths(self, service: str | None = None) -> dict[str, Any]:
        vulns = self._accessible_vulnerabilities()
        if service:
            vulns = [vuln for vuln in vulns if vuln.service.lower() == service.lower()]
        paths = generate_attack_paths(vulns)
        citations = [
            {"label": path["description"], "source_type": "risk-path", "reference": f"path:{index}"}
            for index, path in enumerate(paths[:5], start=1)
        ]
        return {
            "mode": "paths",
            "results": paths,
            "answer": "These defensive risk paths summarize how exposed findings may combine into broader risk.",
            "explanation": "Paths are derived from local findings, exposure, and service context.",
            "citations": citations,
        }

    def _lookup_assets(self, filters: dict[str, Any]) -> dict[str, Any]:
        assets = self._accessible_assets()
        filtered = []
        for asset in assets:
            if "host" in filters and filters["host"].lower() not in asset.target.lower() and filters["host"].lower() not in asset.display_name.lower():
                continue
            if "owner" in filters and filters["owner"].lower() not in (asset.owner_username or "").lower():
                continue
            if "tag" in filters and filters["tag"].lower() not in (asset.tags or "").lower():
                continue
            filtered.append(asset)

        results = [
            {
                "title": asset.display_name,
                "source_type": "asset",
                "snippet": f"Target: {asset.target} | Owner: {asset.owner_username or 'Unassigned'} | Tags: {asset.tags or 'None'} | Criticality: {asset.criticality}",
                "reference": f"asset:{asset.asset_id}",
            }
            for asset in filtered[:10]
        ]
        return {
            "mode": "documents",
            "results": results,
            "answer": f"Found {len(filtered)} asset records matching your query.",
            "explanation": "Asset retrieval is grounded in the local inventory table.",
            "citations": results,
        }

    def _lookup_reports(self, query: str) -> dict[str, Any]:
        docs = self._semantic_documents(query, include_reports_only=True)
        return {
            "mode": "documents",
            "results": docs,
            "answer": f"Retrieved {len(docs)} report snapshots or summaries related to your query.",
            "explanation": "Results come from saved report snapshots in the local database.",
            "citations": docs,
        }

    def _semantic_search(self, query: str) -> dict[str, Any]:
        docs = self._semantic_documents(query, include_reports_only=False)
        if not docs:
            return {
                "mode": "documents",
                "results": [],
                "answer": "No strongly grounded matches were found in assets, findings, scans, or saved reports.",
                "explanation": "Try naming a host, CVE, owner, tag, or service to narrow the search.",
                "citations": [],
            }

        top_sources = ", ".join(sorted({doc["source_type"] for doc in docs[:3]}))
        answer = (
            f"I found {len(docs)} grounded matches across {top_sources}. "
            f"The highest-ranked item is {docs[0]['title']}."
        )
        return {
            "mode": "documents",
            "results": docs,
            "answer": answer,
            "explanation": "Matches are ranked by token overlap against local findings, assets, scan jobs, and saved reports.",
            "citations": docs,
        }

    def _semantic_documents(self, query: str, *, include_reports_only: bool) -> list[dict[str, Any]]:
        tokens = self._tokenize(query)
        documents: list[dict[str, Any]] = []

        if not include_reports_only:
            asset_map = {asset.asset_id: asset for asset in self._accessible_assets()}
            for vuln in self._accessible_vulnerabilities():
                asset = asset_map.get(vuln.asset_id)
                title = f"{vuln.vulnerability_name} on {vuln.host}:{vuln.port}"
                text = " ".join(
                    filter(
                        None,
                        [
                            vuln.host,
                            vuln.service,
                            vuln.vulnerability_name,
                            vuln.description,
                            vuln.cve_id or "",
                            vuln.severity,
                            vuln.remediation,
                            asset.display_name if asset else "",
                            asset.tags if asset else "",
                            asset.owner_username if asset else "",
                        ],
                    )
                )
                documents.append(
                    {
                        "title": title,
                        "source_type": "finding",
                        "snippet": vuln.description[:220],
                        "reference": f"vuln:{vuln.vuln_id}",
                        "score": self._score_text(tokens, text) + 2,
                    }
                )

            for asset in self._accessible_assets():
                text = " ".join([asset.target, asset.display_name, asset.owner_username, asset.tags, asset.notes, asset.environment, asset.criticality])
                documents.append(
                    {
                        "title": asset.display_name,
                        "source_type": "asset",
                        "snippet": f"Target: {asset.target} | Owner: {asset.owner_username or 'Unassigned'} | Tags: {asset.tags or 'None'}",
                        "reference": f"asset:{asset.asset_id}",
                        "score": self._score_text(tokens, text) + 1,
                    }
                )

            for job in self._accessible_scan_jobs():
                text = " ".join([job.get("scanner", ""), job.get("target", ""), job.get("profile", ""), job.get("status", ""), job.get("command", "")])
                documents.append(
                    {
                        "title": f"{job.get('scanner', '').upper()} scan on {job.get('target', '')}",
                        "source_type": "scan-job",
                        "snippet": f"Profile: {job.get('profile', '')} | Status: {job.get('status', '')} | Findings: {job.get('findings_count', 0)}",
                        "reference": f"scan:{job.get('id', '')}",
                        "score": self._score_text(tokens, text),
                    }
                )

        for snapshot in self._accessible_reports():
            text = " ".join([snapshot.get("title", ""), snapshot.get("content", "")[:4000]])
            documents.append(
                {
                    "title": snapshot.get("title", "Saved Report"),
                    "source_type": "report",
                    "snippet": snapshot.get("content", "")[:220],
                    "reference": f"report:{snapshot.get('id', '')}",
                    "score": self._score_text(tokens, text) + 1,
                }
            )

        ranked = [doc for doc in documents if doc["score"] > 0]
        ranked.sort(key=lambda item: item["score"], reverse=True)
        for doc in ranked:
            doc.pop("score", None)
        return ranked[:8]

    @staticmethod
    def _tokenize(query: str) -> set[str]:
        return {token for token in re.findall(r"[a-zA-Z0-9_.-]+", query.lower()) if len(token) > 2}

    @staticmethod
    def _score_text(tokens: set[str], text: str) -> int:
        lowered = text.lower()
        return sum(2 if token in lowered.split() else 1 for token in tokens if token in lowered)

    @staticmethod
    def _citation_for_vulnerability(vuln: Vulnerability) -> dict[str, str]:
        return {
            "label": f"{vuln.vulnerability_name} on {vuln.host}:{vuln.port}",
            "source_type": "finding",
            "reference": f"vuln:{vuln.vuln_id}",
        }
