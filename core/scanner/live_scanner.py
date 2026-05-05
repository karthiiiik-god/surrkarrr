from __future__ import annotations

import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from subprocess import list2cmdline

from core.ml_engine.model_loader import ModelLoader
from core.normalization.normalizer import normalize_vulnerabilities
from core.storage.database import Database
from core.storage.models import ScanJob

from .adapters import get_scanner_adapter, list_live_adapters


SAFE_TARGET_PATTERN = re.compile(r"^[A-Za-z0-9:/._,-]+$")


SCANNER_COMMANDS = {
    adapter.key: {
        "binary": adapter.binary,
        "file_ext": adapter.file_ext,
        "parser": adapter.parser,
        "command_builder": adapter.command_builder,
        "profiles": adapter.profile_map(),
    }
    for adapter in list_live_adapters()
}


def validate_target(target: str) -> str:
    normalized = target.strip()
    if not normalized:
        raise ValueError("Target is required.")
    if not SAFE_TARGET_PATTERN.match(normalized):
        raise ValueError("Target contains unsupported characters.")
    return normalized


def scanner_available(scanner: str) -> bool:
    return get_scanner_adapter(scanner).is_available()


def get_scan_profiles(scanner: str) -> dict[str, dict[str, str | list[str]]]:
    adapter = get_scanner_adapter(scanner)
    return adapter.profile_map()


def get_scanner_inventory() -> list[dict[str, str | bool | int]]:
    inventory = []
    for adapter in list_live_adapters():
        inventory.append(
            {
                "scanner": adapter.display_name,
                "available": adapter.is_available(),
                "binary": adapter.binary or "",
                "profiles": len(adapter.profiles),
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
    adapter = get_scanner_adapter(scanner)
    normalized_target = validate_target(target)
    return adapter.build_command(normalized_target, output_path, profile, extra_args)


def preview_scan_command(scanner: str, target: str, profile: str, extra_args: list[str] | None = None) -> str:
    adapter = get_scanner_adapter(scanner)
    normalized_target = validate_target(target)
    return list2cmdline(
        adapter.build_command(normalized_target, f"scan-output{adapter.file_ext}", profile, extra_args)
    )


def run_live_scan(
    scanner: str,
    target: str,
    db: Database,
    options: dict | None = None,
) -> dict[str, str | int]:
    adapter = get_scanner_adapter(scanner)
    if not adapter.supports_live():
        raise ValueError(f"{adapter.display_name} does not support live execution.")
    if not adapter.is_available():
        raise RuntimeError(f"{adapter.display_name} is not installed or not available on PATH.")

    options = options or {}
    target = validate_target(target)
    profile = options.get("profile") or next(iter(adapter.profiles))
    extra_args = options.get("extra_args", [])
    timeout = int(options.get("timeout", 600))
    created_by = options.get("created_by", "")
    asset_owner = options.get("asset_owner", "")
    asset_tags = options.get("asset_tags", "")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    artifact_dir = Path("scan_artifacts") / adapter.key
    artifact_dir.mkdir(parents=True, exist_ok=True)
    safe_target = target.replace(":", "_").replace("/", "_")
    artifact_path = artifact_dir / f"{timestamp}_{safe_target}{adapter.file_ext}"

    command = adapter.build_command(
        target,
        str(artifact_path),
        profile,
        extra_args,
    )
    command_preview = list2cmdline(command)
    asset = db.ensure_asset(
        target,
        owner_username=asset_owner,
        tags=asset_tags,
        display_name=target,
    )

    scan_job = ScanJob.new(
        scanner=adapter.key,
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
            error_message = (
                completed.stderr.strip()
                or completed.stdout.strip()
                or "scanner returned a non-zero exit code"
            )
            db.update_scan_job(
                scan_job.id,
                status="Failed",
                finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                error_message=error_message,
                asset_id=asset.asset_id,
            )
            raise RuntimeError(error_message)

        content = artifact_path.read_text(encoding="utf-8", errors="ignore")
        parsed_vulns = adapter.parser(content)
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
            "scanner": adapter.display_name,
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
