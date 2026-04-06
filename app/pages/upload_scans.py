import streamlit as st
from core.storage.database import Database
from core.scanner_ingestion import nmap_parser, nessus_parser, openvas_parser, nikto_parser
from core.normalization import cve_mapper, deduplicator, enrichment
from core.normalization.nvd_fetcher import NVDFetcher
import asyncio
import aiohttp
from core.risk_engine import cvss_calculator, severity_ranker
from core.scanner.live_scanner import run_live_scan, SCANNER_COMMANDS
import traceback

SCANNER_MAPPING = {
    "Nmap": {"parsers": nmap_parser, "types": ['xml', 'txt']},
    "Nessus": {"parsers": nessus_parser, "types": ['nessus']},
    "OpenVAS": {"parsers": openvas_parser, "types": ['xml', 'json']},
    "Nikto": {"parsers": nikto_parser, "types": ['txt', 'json']},
    "Nuclei": {"parsers": None, "types": [], "live": True}
}

def process_uploaded_file(uploaded_file, selected_scanner, db: Database):
    content = uploaded_file.read().decode('utf-8')
    scanner_info = SCANNER_MAPPING[selected_scanner]
    parser_module = scanner_info["parsers"]
    allowed_types = scanner_info["types"]

    # Validate file type
    file_ext = uploaded_file.name.split('.')[-1].lower()
    if file_ext not in allowed_types:
        st.error(f"File type .{file_ext} not allowed for {selected_scanner}. Allowed: {', '.join(allowed_types)}")
        return

# Parse based on selected scanner
    vulns = []
    try:
        if selected_scanner == "Nmap":
            vulns = parser_module.parse_nmap(content)
        elif selected_scanner == "Nessus":
            vulns = parser_module.parse_nessus(content)
        elif selected_scanner == "OpenVAS":
            vulns = parser_module.parse_openvas(content)
        elif selected_scanner == "Nikto":
            vulns = parser_module.parse_nikto(content)
        st.info(f"✅ Parsed {len(vulns)} vulnerabilities from {selected_scanner}")
    except Exception as e:
        st.error(f"Parse error: {str(e)}")
        st.error(traceback.format_exc())

    # Fallback CVE detection
    if len(vulns) == 0:
        import re
        cve_pattern = r'CVE-(\d{4})-(\d+)(?:\s+(\d+\.?\d*))?'
        matches = re.finditer(cve_pattern, content)
        for match in matches:
            cve = f"CVE-{match.group(1)}-{match.group(2)}"
            cvss = float(match.group(3)) if match.group(3) else 5.0
            vuln = Vulnerability(
                vuln_id=str(uuid.uuid4()),
                host="unknown",
                port=80,
                service="unknown",
                vulnerability_name=f"Detected {cve}",
                description=f"CVE found in scan output",
                cve_id=cve,
                cvss_score=cvss,
                severity="Medium",
                source_tool=selected_scanner.lower(),
                timestamp=datetime.datetime.now().isoformat()
            )
            vulns.append(vuln)
        st.info(f"🔍 Fallback detected {len(vulns)} CVEs by regex")
    

    # Tag with source_tool
    try:
        for vuln in vulns:
            vuln.source_tool = selected_scanner.lower()
        st.info(f"✅ Tagged {len(vulns)} vulns with source: {selected_scanner.lower()}")
    except Exception as e:
        st.error(f"Tag error: {str(e)}")
        return

# Normalize and deduplicate
    try:
        from core.normalization.normalizer import normalize_vulnerabilities
        normalized_vulns = normalize_vulnerabilities(vulns)
        st.info(f"✅ Normalized {len(normalized_vulns)} vulnerabilities")
    except Exception as e:
        st.error(f"Normalization error: {str(e)}")
        st.error(traceback.format_exc())
        normalized_vulns = vulns  # Fallback
        st.warning("Using raw vulns (no normalization)")

    # Add ML predictions
    try:
        from core.ml_engine.model_loader import ModelLoader
        ml_model = ModelLoader()
        ml_count = 0
        for vuln in normalized_vulns:
            vuln.epss_score = ml_model.predict(vuln)  # Use existing field
            ml_count += 1
        st.info(f"✅ ML predictions for {ml_count} vulns")
    except Exception as e:
        st.warning(f"ML skipped: {str(e)}")

    # Store in database
    try:
        inserted = 0
        for vuln in normalized_vulns:
            db.insert_vulnerability(vuln)
            inserted += 1
        st.success(f"✅ Inserted {inserted} vulnerabilities to DB from {uploaded_file.name}")
        st.info(f"Total vulns in DB now: {len(db.get_all_vulnerabilities())}")
    except Exception as e:
        st.error(f"DB insert error: {str(e)}")
        st.error(traceback.format_exc())

def show():
    db = Database()
    st.header("🛡️ Scan Management")
    
    tab1, tab2 = st.tabs(["📁 Upload Files", "🔍 Live Scan"])
    
    with tab1:
        st.subheader("Upload Existing Scan Files")
        selected_scanner = st.selectbox("Select Scanner Type", [k for k,v in SCANNER_MAPPING.items() if v.get('parsers')])
        if selected_scanner:
            allowed_types = SCANNER_MAPPING[selected_scanner]["types"]
            uploaded_file = st.file_uploader(f"Choose {selected_scanner} file", type=allowed_types)
            col1, col2 = st.columns(2)
            with col1:
                if st.button("Process Upload", type="primary"):
                    with st.spinner("Processing uploaded scan..."):
                        process_uploaded_file(uploaded_file, selected_scanner, db) if uploaded_file else st.warning("No file selected")
            with col2:
                if st.button("🧪 Test Sample"):
                    try:
                        if selected_scanner == "Nmap":
                            with open("sample_nmap.xml", "r") as f:
                                vulns = nmap_parser.parse_nmap(f.read())
                            st.success(f"🧪 Sample Nmap parse: {len(vulns)} vulns")
                        elif selected_scanner == "Nessus":
                            with open("sample_nessus.nessus", "r") as f:
                                vulns = nessus_parser.parse_nessus(f.read())
                            st.success(f"🧪 Sample Nessus parse: {len(vulns)} vulns")
                        else:
                            st.info("Sample for " + selected_scanner + " not available")
                    except Exception as e:
                        st.error(f"Sample test error: {str(e)}")
                st.success("✅ Upload complete! Check dashboard.")
                st.rerun()
    
    with tab2:
        st.subheader("Run Live Scan on Target")
        col1, col2 = st.columns(2)
        with col1:
            target = st.text_input("Target (IP/domain/URL)", placeholder="scanme.nmap.org")
            scanner = st.selectbox("Scanner", list(SCANNER_COMMANDS.keys()))
        with col2:
            ports = st.text_input("Ports/Profile", value="-sV -sC -top-100", placeholder="or -p 80,443")
            timeout = st.slider("Timeout (sec)", 30, 600, 120)
        
        if st.button("🚀 Start Live Scan", type="primary", use_container_width=True) and target:
            with st.spinner(f"Running {scanner} on {target}..."):
                try:
                    extra_args = ports.split() if ports else []
                    result = run_live_scan(scanner, target, db, {"extra_args": extra_args})
                    st.success(result)
                except Exception as e:
                    st.error(f"Scan failed: {str(e)}")
                st.rerun()
