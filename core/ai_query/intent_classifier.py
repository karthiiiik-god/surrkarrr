from typing import Dict, Any

def classify_intent(query: str) -> str:
    """
    Classify the intent of the query using rule-based approach.
    Possible intents: 'list_vulnerabilities', 'top_hosts', 'summary', 'unknown'
    """
    query_lower = query.lower()
    
    if "top" in query_lower and "host" in query_lower:
        return "top_hosts"
    elif "summary" in query_lower or "overview" in query_lower:
        return "summary"
    elif any(word in query_lower for word in ["vulnerability", "vulnerabilities", "cve", "cvss", "severity", "port", "service"]):
        return "list_vulnerabilities"
    else:
        return "unknown"
