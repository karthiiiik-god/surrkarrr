import re
from typing import Dict, Any

def parse_intent(query: str) -> Dict[str, Any]:
    """
    Parse natural language query into intent and filters using rule-based approach.
    Supported queries:
    - “Critical vulnerabilities”
    - “Vulnerabilities on port 22”
    - “CVEs above CVSS 8”
    - “Top risky hosts”
    - “Attack path for SSH”
    """
    filters = {}
    query_lower = query.lower()

    # Severity filters
    if "critical" in query_lower:
        filters["severity"] = "Critical"
    elif "high" in query_lower:
        filters["severity"] = "High"
    elif "medium" in query_lower:
        filters["severity"] = "Medium"
    elif "low" in query_lower:
        filters["severity"] = "Low"

    # Port filter
    port_match = re.search(r'port (\d+)', query_lower)
    if port_match:
        filters["port"] = int(port_match.group(1))

    # CVSS score filter
    cvss_match = re.search(r'cvss (\d+(?:\.\d+)?)', query_lower)
    if cvss_match:
        cvss_value = float(cvss_match.group(1))
        if "above" in query_lower or "greater" in query_lower:
            filters["cvss_min"] = cvss_value
        elif "below" in query_lower or "less" in query_lower:
            filters["cvss_max"] = cvss_value
        else:
            filters["cvss_min"] = cvss_value

    # Host filter
    host_match = re.search(r'host (\S+)', query_lower)
    if host_match:
        filters["host"] = host_match.group(1)

    # CVE filter
    cve_match = re.search(r'cve[- ](\d{4}[-]\d{4,})', query_lower)
    if cve_match:
        filters["cve_id"] = f"CVE-{cve_match.group(1)}"

    # Service filter
    service_match = re.search(r'service (\w+)', query_lower)
    if service_match:
        filters["service"] = service_match.group(1)

    # Special intents
    if "top risky hosts" in query_lower:
        filters["intent"] = "top_risky_hosts"
    elif "attack path" in query_lower:
        service_match = re.search(r'attack path for (\w+)', query_lower)
        if service_match:
            filters["intent"] = "attack_path"
            filters["service"] = service_match.group(1)

    return filters
