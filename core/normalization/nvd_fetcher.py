import asyncio
import aiohttp
from typing import Optional, Dict, Any
import time

class NVDFetcher:
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    async def fetch_cve(self, cve_id: str, session: aiohttp.ClientSession) -> Optional[Dict[str, Any]]:
        url = f"{self.BASE_URL}?cveId={cve_id}"
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data.get('vulnerabilities', [{}])[0].get('cve', {})
                return None
        except Exception as e:
            print(f"NVD fetch error {cve_id}: {e}")
            return None

    async def fetch_epss(self, cve_id: str, session: aiohttp.ClientSession) -> Optional[float]:
        url = f"https://api.first.org/data/v1/epss?cve={cve_id}"
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    data = await response.json()
                    return data[0].get('epss', 0.0) if data else 0.0
                return 0.0
        except Exception as e:
            print(f"EPSS fetch error {cve_id}: {e}")
            return 0.0

    async def enrich_vuln(self, vuln) -> dict:
        async with aiohttp.ClientSession() as session:
            cve_data = await self.fetch_cve(vuln.get('cve_id', ''), session)
            epss = await self.fetch_epss(vuln.get('cve_id', ''), session)
            
            if cve_data:
                vuln['nvd_description'] = cve_data.get('descriptions', [{}])[0].get('value', '')
                vuln['published'] = cve_data.get('published', '')
            
            vuln['epss_score'] = epss
            vuln['epss_percentile'] = epss * 100
            
            return vuln
