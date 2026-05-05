import re
from typing import Any


def parse_intent(query: str) -> dict[str, Any]:
    filters: dict[str, Any] = {}
    query_lower = query.lower()

    if "critical" in query_lower:
        filters["severity"] = "Critical"
    elif "high" in query_lower:
        filters["severity"] = "High"
    elif "medium" in query_lower:
        filters["severity"] = "Medium"
    elif "low" in query_lower:
        filters["severity"] = "Low"

    port_match = re.search(r"port (\d+)", query_lower)
    if port_match:
        filters["port"] = int(port_match.group(1))

    cvss_match = re.search(r"cvss (\d+(?:\.\d+)?)", query_lower)
    if cvss_match:
        cvss_value = float(cvss_match.group(1))
        if "above" in query_lower or "greater" in query_lower:
            filters["cvss_min"] = cvss_value
        elif "below" in query_lower or "less" in query_lower:
            filters["cvss_max"] = cvss_value
        else:
            filters["cvss_min"] = cvss_value

    host_match = re.search(r"(?:host|asset|target) (\S+)", query_lower)
    if host_match:
        filters["host"] = host_match.group(1)

    cve_match = re.search(r"cve[- ](\d{4}[-]\d{4,})", query_lower)
    if cve_match:
        filters["cve_id"] = f"CVE-{cve_match.group(1)}"

    service_match = re.search(r"service (\w+)", query_lower)
    if service_match:
        filters["service"] = service_match.group(1)

    owner_match = re.search(r"owner (\w+)", query_lower)
    if owner_match:
        filters["owner"] = owner_match.group(1)

    tag_match = re.search(r"tag (\w+)", query_lower)
    if tag_match:
        filters["tag"] = tag_match.group(1)

    if "top risky hosts" in query_lower or "top risky assets" in query_lower:
        filters["intent"] = "top_risky_hosts"
    elif "risk path" in query_lower or "attack path" in query_lower:
        service_match = re.search(r"(?:risk|attack) path for (\w+)", query_lower)
        filters["intent"] = "risk_path"
        if service_match:
            filters["service"] = service_match.group(1)
    elif "asset" in query_lower and ("owner" in query_lower or "tag" in query_lower or "inventory" in query_lower):
        filters["intent"] = "asset_lookup"
    elif "report" in query_lower or "summary" in query_lower or "snapshot" in query_lower:
        filters["intent"] = "report_lookup"
    else:
        filters["intent"] = "semantic_search"

    return filters
