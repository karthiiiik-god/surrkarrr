# Scanner Upload Fix Plan - Progress Tracker

**Status: Active**

## 1. [x] Update core/storage/models.py ✅
- Add missing fields to Vulnerability dataclass: network_exposed:bool, authentication_required:bool, exploit_available:bool, epss_score:float, nvd_description:str
- Add def to_dict(self) -> dict: return {c.name: getattr(self, c.name) for c in dataclasses.fields(self)}
- Fix inconsistencies (vuln_id not id, source_tool)

## 2. [x] app/pages/upload_scans.py - Add debugging/logging ✅
- Wrap parse/normalize/ML/DB in try/except
- st.info(f"Parsed {len(vulns)} vulns" ) at each step
- Handle dataclass -> dict if needed
- Add test sample upload button
- Import traceback for error details

## 3. [x] Robustify parsers ✅
- nmap_parser.py: Added support for 'vulners' script (common nmap vuln script)
- More .get() fallbacks added

## 4. [x] ML graceful fail ✅
- model_loader.py: try/except load/train, default predict=0.0

## 5. [x] Test ✅
- Test sample nmap parses 2 vulns (CVE-2018-15473, CVE-2021-44228)
- Full flow: parse/normalize/ML/DB/dashboard
- Added CVE regex fallback for zero-detection scans
- Run test_backend.py 
- Upload sample_nmap.xml, check DB
- sqlite3 "SELECT COUNT(*) from vulnerabilities.db"
- Verify dashboard shows data

## 6. [ ] Cleanup
- Update this TODO with [x] completes

