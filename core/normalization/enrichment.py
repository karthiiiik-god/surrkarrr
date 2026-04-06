from ..storage.models import Vulnerability

# Static offline CVE data (simulated NVD-style)
STATIC_CVE_DATA = {
    "CVE-2021-44228": {
        "description": "Apache Log4j2 remote code execution vulnerability",
        "exploit_available": True,
        "network_exposed": True,
        "authentication_required": False,
        "attack_complexity": "Low"
    },
    "CVE-2017-0144": {
        "description": "EternalBlue SMB vulnerability",
        "exploit_available": True,
        "network_exposed": True,
        "authentication_required": False,
        "attack_complexity": "Low"
    },
    # Add more as needed
}

async def enrich_vulnerability(vuln: Vulnerability) -> Vulnerability:
    """
    Enrich vulnerability with NVD/EPSS API data.
    """
    nvd_fetcher = NVDFetcher()
    
    if vuln.cve_id:
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                vuln = await nvd_fetcher.enrich_vuln(vuln)
        except:
            # Fallback
            vuln.exploit_likelihood = 0.05
    
    # Rule-based
    vuln.network_exposed = vuln.port in [80, 443, 22, 3389]
    
    return vuln

