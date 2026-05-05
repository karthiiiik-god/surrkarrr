from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import streamlit as st

from app.pages.login import current_user, require_roles
from app.ui import info_cards, page_hero
from core.ml_engine.model_loader import ModelLoader
from core.normalization.normalizer import normalize_vulnerabilities
from core.scanner.adapters import get_scanner_adapter, list_live_adapters, list_upload_adapters
from core.scanner.live_scanner import (
    get_scan_profiles,
    get_scanner_inventory,
    preview_scan_command,
    run_live_scan,
    scanner_available,
    validate_target,
)
from core.storage.database import Database
from core.storage.models import ScanJob


UPLOAD_ADAPTERS = {adapter.display_name: adapter for adapter in list_upload_adapters()}
LIVE_ADAPTERS = list_live_adapters()


def _complete_scan_job(db: Database, scan_job: ScanJob, findings_count: int, error_message: str = "") -> None:
    db.update_scan_job(
        scan_job.id,
        status="Completed" if not error_message else "Failed",
        findings_count=findings_count,
        finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        error_message=error_message,
    )


def _ingest_content(
    *,
    content: str,
    parser,
    db: Database,
    source_name: str,
    target_label: str,
    profile: str,
    command: str,
    asset_owner: str = "",
    asset_tags: str = "",
) -> int:
    scan_job = ScanJob.new(
        scanner=source_name.lower(),
        mode="upload",
        target=target_label,
        profile=profile,
        status="Running",
        command=command,
        created_by=current_user().get("username", ""),
    )
    db.create_scan_job(scan_job)

    try:
        parsed = parser(content)
        normalized = normalize_vulnerabilities(parsed)
        model = ModelLoader()

        for vuln in normalized:
            db.ensure_asset(
                vuln.host,
                owner_username=asset_owner,
                tags=asset_tags,
                display_name=vuln.host,
            )
            vuln.source_tool = source_name.lower()
            vuln.exploit_prob = model.predict(vuln)
            db.insert_vulnerability(vuln)

        _complete_scan_job(db, scan_job, len(normalized))
        return len(normalized)
    except Exception as exc:
        _complete_scan_job(db, scan_job, 0, str(exc))
        raise


def _load_sample(sample_name: str) -> str:
    return Path(sample_name).read_text(encoding="utf-8", errors="ignore")


def _inventory_frame() -> pd.DataFrame:
    return pd.DataFrame(get_scanner_inventory()).rename(
        columns={
            "scanner": "Scanner",
            "available": "Available",
            "binary": "Binary",
            "profiles": "Profiles",
        }
    )


def show(db: Database) -> None:
    user = current_user()
    page_hero(
        "Scan Operations",
        "Bring in external scanner artifacts or run approved live scans against authorized targets.",
        kicker="Collection Pipeline",
        pills=["Authorized use only", "Unified normalization", "Scan-job tracking"],
    )

    if not require_roles("admin", "analyst"):
        return

    inventory_col, readiness_col = st.columns([1.5, 1])
    with inventory_col:
        st.subheader("Scanner Inventory")
        st.dataframe(_inventory_frame(), use_container_width=True, hide_index=True)
    with readiness_col:
        info_cards(
            [
                ("Artifact Import", "Upload-based ingestion works even when local scanner binaries are unavailable."),
                ("Live Execution", "Live scans require the corresponding scanner binary on PATH and explicit authorization confirmation."),
                ("Auditability", "Every import or scan generates a persisted scan-job record for history and reporting."),
            ]
        )

    upload_tab, sample_tab, live_tab, history_tab = st.tabs(
        ["Upload File", "Load Sample", "Live Scan", "Scan History"]
    )

    with upload_tab:
        scanner_name = st.selectbox("Scanner type", list(UPLOAD_ADAPTERS), key="upload_scanner")
        selected_upload_adapter = UPLOAD_ADAPTERS[scanner_name]
        target_label = st.text_input("Target label", placeholder="example.com or 192.168.1.10")
        import_tags = st.text_input("Import tags", value="artifact-import")
        uploaded_file = st.file_uploader(
            "Choose a scan artifact",
            type=list(selected_upload_adapter.upload_extensions),
        )
        if st.button("Import Uploaded Scan", type="primary", disabled=uploaded_file is None):
            try:
                content = uploaded_file.read().decode("utf-8", errors="ignore")
                count = _ingest_content(
                    content=content,
                    parser=selected_upload_adapter.parser,
                    db=db,
                    source_name=selected_upload_adapter.display_name,
                    target_label=target_label.strip() or uploaded_file.name,
                    profile="Artifact Import",
                    command=f"artifact import: {uploaded_file.name}",
                    asset_owner=user["username"],
                    asset_tags=import_tags,
                )
                if target_label.strip():
                    db.ensure_asset(
                        target_label.strip(),
                        owner_username=user["username"],
                        tags=import_tags,
                        display_name=target_label.strip(),
                    )
                db.log_action(user["username"], "artifact-import", uploaded_file.name)
                st.success(f"Imported {count} normalized findings from {uploaded_file.name}.")
            except Exception as exc:
                st.error(f"Import failed: {exc}")

    with sample_tab:
        col1, col2, col3 = st.columns(3)
        if col1.button("Load Sample Nmap", use_container_width=True):
            count = _ingest_content(
                content=_load_sample("sample_nmap.xml"),
                parser=UPLOAD_ADAPTERS["Nmap"].parser,
                db=db,
                source_name="Nmap",
                target_label="sample_nmap.xml",
                profile="Sample Import",
                command="sample import: sample_nmap.xml",
                asset_owner=user["username"],
                asset_tags="sample-import",
            )
            st.success(f"Imported {count} findings from sample_nmap.xml.")
        if col2.button("Load Sample Nessus", use_container_width=True):
            count = _ingest_content(
                content=_load_sample("sample_nessus.nessus"),
                parser=UPLOAD_ADAPTERS["Nessus"].parser,
                db=db,
                source_name="Nessus",
                target_label="sample_nessus.nessus",
                profile="Sample Import",
                command="sample import: sample_nessus.nessus",
                asset_owner=user["username"],
                asset_tags="sample-import",
            )
            st.success(f"Imported {count} findings from sample_nessus.nessus.")
        if col3.button("Clear Stored Findings", use_container_width=True):
            db.clear_vulnerabilities()
            st.success("All stored findings were cleared.")

    with live_tab:
        scanner = st.selectbox(
            "Live scanner",
            [adapter.display_name for adapter in LIVE_ADAPTERS],
            key="live_scanner",
        )
        selected_live_adapter = get_scanner_adapter(scanner)
        available = scanner_available(scanner)
        profiles = get_scan_profiles(scanner)
        profile_name = st.selectbox("Scan profile", list(profiles), key="live_profile")
        target = st.text_input("Target host or domain", placeholder="scanme.nmap.org", key="live_target")
        asset_tags = st.text_input("Asset tags", value="live-scan", key="live_tags")
        extra_args = st.text_input("Extra arguments", value="", key="live_args")
        timeout = st.slider("Timeout (seconds)", 60, 1800, 600, step=30)
        authorized = st.checkbox("I confirm this target is authorized for defensive scanning.")

        st.info(profiles[profile_name]["description"])

        if target.strip():
            try:
                normalized_target = validate_target(target)
                preview = preview_scan_command(
                    scanner,
                    normalized_target,
                    profile_name,
                    [arg for arg in extra_args.split() if arg],
                )
                st.caption("Command preview")
                st.code(preview)
            except ValueError as exc:
                st.warning(str(exc))

        if not available:
            st.warning(f"{selected_live_adapter.display_name} is not currently available on PATH on this machine.")

        if st.button("Run Live Scan", type="primary", disabled=not available or not target.strip()):
            if not authorized:
                st.error("Authorization confirmation is required before running a live scan.")
            else:
                try:
                    result = run_live_scan(
                        scanner,
                        target.strip(),
                        db,
                        {
                            "profile": profile_name,
                            "extra_args": [arg for arg in extra_args.split() if arg],
                            "timeout": timeout,
                            "created_by": user["username"],
                            "asset_owner": user["username"],
                            "asset_tags": asset_tags,
                        },
                    )
                    db.log_action(user["username"], "live-scan", target.strip())
                    st.success(
                        f"Completed {result['scanner']} scan for {result['target']} with {result['findings_count']} findings."
                    )
                    st.write(f"Profile: {result['profile']}")
                    st.write(f"Artifact: {result['artifact_path']}")
                    st.code(str(result["command"]))
                except Exception as exc:
                    st.error(f"Live scan failed: {exc}")

    with history_tab:
        history = db.list_scan_jobs(limit=100, username=user["username"], role=user["role"])
        if not history:
            st.info("No scan jobs recorded yet.")
        else:
            df = pd.DataFrame(history).rename(
                columns={
                    "started_at": "Started",
                    "finished_at": "Finished",
                    "findings_count": "Findings",
                    "error_message": "Error",
                    "artifact_path": "Artifact",
                    "command": "Command",
                }
            )
            st.dataframe(df, use_container_width=True, hide_index=True)
