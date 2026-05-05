from __future__ import annotations

import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from subprocess import list2cmdline

from core.ml_engine.model_loader import ModelLoader
from core.normalization.normalizer import normalize_vulnerabilities
from core.scanner_ingestion import nikto_parser, nmap_parser, nuclei_parser
from core.storage.database import Database
from core.storage.models import ScanJob


SAFE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9:/._,-]+$")


def _nmap_command(target: str, output_path: str, profile_args: list[str], extra_args: list[str]) -> list[str]:
    return ["nmap", *profile_args, *extra_args, "-oX", output_path, target]


def _nikto_command(target: str, output_path: str, profile_args: list[str], extra_args: list[str]) -> list[str]:
    return ["nikto", "-h", target, *profile_args, *extra_args, "-Format", "txt", "-output", output_path]


def _nuclei_command(target: str, output_path: str, profile_args: list[str], extra_args: list[str]) -> list[str]:
    return ["nuclei", "-u", target, *profile_args, *extra_args, "-jsonl", "-o", output_path]


SCANNER_COMMANDS = {
    "nmap": {
        "binary": "nmap",
        "file_ext": ".xml",
        "parser": nmap_parser.parse_nmap,
        "command_builder": _nmap_command,
        "profiles": {
            "Quick Discovery": {
                "description": "Top 100 TCP ports with version detection for fast triage.",
                "args": ["-Pn", "-T4", "--top-ports", "100", "-sV"],
            },
            "Web Surface": {
                "description": "Common web ports plus basic HTTP and TLS metadata checks.",
                "args": ["-Pn", "-T4", "-p", "80,443,8080,8443", "-sV", "--script", "http-title,http-headers,ssl-cert"],
            },
            "Vulnerability Audit": {
                "description": "Service detection with Nmap vuln NSE scripts for authorized assessments.",
                "args": ["-Pn", "-T4", "--top-ports", "100", "-sV", "--script", "vuln"],
            },
        },
    },
    "nikto": {
        "binary": "nikto",
        "file_ext": ".txt",
        "parser": nikto_parser.parse_nikto,
        "command_builder": _nikto_command,
        "profiles": {
            "Baseline Web Audit": {
                "description": "General-purpose Nikto checks for common web misconfigurations.",
                "args": [],
            },
            "TLS Web Audit": {
                "description": "HTTPS-focused Nikto scan for SSL/TLS-enabled web targets.",
                "args": ["-ssl"],
            },
        },
    },
    "nuclei": {
        "binary": "nuclei",
        "file_ext": ".jsonl",
        "parser": nuclei_parser.parse_nuclei,
        "command_builder": _nuclei_command,
        "profiles": {
            "Web Quick Templates": {
                "description": "Medium-to-critical templates with moderate rate limiting.",
                "args": ["-severity", "medium,high,critical", "-rate-limit", "50"],
            },
            "Critical Focus": {
                "description": "High and critical template sweep for quicker validation.",
                "args": ["-severity", "high,critical", "-rate-limit", "25"],
            },
        },
    },
}


def validate_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("Target is required.")
    if not SAFE_TARGET_PATTERN.match(normalized):
        raise ValueError("Target contains unsupported characters.")
    return normalized


def scanner_available(scanner: str) -> bool:
    config = SCANNER_COMMANDS.get(scanner)
    return bool(config and shutil.which(config["binary"]))


def get_scan_profiles(scanner: str) -> dict[str, dict[str, str | list[str]]]:
    if scanner not in SCANNER_COMMANDS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    return SCANNER_COMMANDS[scanner]["profiles"]


def get_scanner_inventory() -> list[dict[str, str | bool | int]]:
    inventory = []
    for scanner, config in SCANNER_COMMANDS.items():
        inventory.append(
            {
                "scanner": scanner,
                "available": scanner_available(scanner),
                "binary": config["binary"],
                "profiles": len(config["profiles"]),
            }
        )
    return inventory


def build_scan_command(
    scanner: str,
    target: str,
    profile: str,
    *,
    output_path: str,
    extra_args: list[str] | None = None,
) -> list[str]:
    if scanner not in SCANNER_COMMANDS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    normalized_target = validate_target(target)
    profiles = SCANNER_COMMANDS[scanner]["profiles"]
    if profile not in profiles:
        raise ValueError(f"Unsupported profile '{profile}' for {scanner}")
    builder = SCANNER_COMMANDS[scanner]["command_builder"]
    return builder(
        normalized_target,
        output_path,
        profiles[profile]["args"],
        extra_args or [],
    )


def preview_scan_command(scanner: str, target: str, profile: str, extra_args: list[str] | None = None) -> str:
    preview_path = "scan-output"
    if scanner in SCANNER_COMMANDS:
        preview_path += SCANNER_COMMANDS[scanner]["file_ext"]
    return list2cmdline(
        build_scan_command(scanner, target, profile, output_path=preview_path, extra_args=extra_args)
    )


def run_live_scan(
    scanner: str,
    target: str,
    db: Database,
    options: dict | None = None,
) -> dict[str, str | int]:
    if scanner not in SCANNER_COMMANDS:
        raise ValueError(f"Unsupported scanner: {scanner}")
    if not scanner_available(scanner):
        raise RuntimeError(f"{scanner} is not installed or not available on PATH.")

    options = options or {}
    target = validate_target(target)
    profile = options.get("profile") or next(iter(SCANNER_COMMANDS[scanner]["profiles"]))
    extra_args = options.get("extra_args", [])
    timeout = int(options.get("timeout", 600))
    created_by = options.get("created_by", "")
    asset_owner = options.get("asset_owner", "")
    asset_tags = options.get("asset_tags", "")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_dir = Path("scan_artifacts") / scanner
    artifact_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = artifact_dir / f"{timestamp}_{target.replace(':', '_').replace('/', '_')}{SCANNER_COMMANDS[scanner]['file_ext']}"

    command = build_scan_command(
        scanner,
        target,
        profile,
        output_path=str(artifact_path),
        extra_args=extra_args,
    )
    command_preview = list2cmdline(command)
    asset = db.ensure_asset(
        target,
        owner_username=asset_owner,
        tags=asset_tags,
        display_name=target,
    )

    scan_job = ScanJob.new(
        scanner=scanner,
        mode="live",
        target=target,
        profile=profile,
        status="Running",
        command=command_preview,
        artifact_path=str(artifact_path.resolve()),
        asset_id=asset.asset_id,
        created_by=created_by,
    )
    db.create_scan_job(scan_job)

    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if completed.returncode != 0:
            error_message = completed.stderr.strip() or completed.stdout.strip() or "scanner returned a non-zero exit code"
            db.update_scan_job(
                scan_job.id,
                status="Failed",
                finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                error_message=error_message,
                asset_id=asset.asset_id,
            )
            raise RuntimeError(error_message)

        content = artifact_path.read_text(encoding="utf-8", errors="ignore")
        parsed_vulns = SCANNER_COMMANDS[scanner]["parser"](content)
        normalized = normalize_vulnerabilities(parsed_vulns)

        model = ModelLoader()
        for vuln in normalized:
            vuln.exploit_prob = model.predict(vuln)
            db.insert_vulnerability(vuln)

        db.update_scan_job(
            scan_job.id,
            status="Completed",
            findings_count=len(normalized),
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            asset_id=asset.asset_id,
        )

        return {
            "job_id": scan_job.id,
            "scanner": scanner,
            "profile": profile,
            "target": target,
            "command": command_preview,
            "artifact_path": str(artifact_path.resolve()),
            "findings_count": len(normalized),
            "asset_id": asset.asset_id,
        }
    except subprocess.TimeoutExpired as exc:
        error_message = f"Scan timed out after {timeout} seconds."
        db.update_scan_job(
            scan_job.id,
            status="Timed Out",
            finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            error_message=error_message,
            asset_id=asset.asset_id,
        )
        raise RuntimeError(error_message) from exc
