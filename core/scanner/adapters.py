from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from subprocess import list2cmdline
from typing import Callable

from core.scanner_ingestion import nessus_parser, nikto_parser, nmap_parser, nuclei_parser, openvas_parser
from core.storage.models import Vulnerability


Parser = Callable[[str], list[Vulnerability]]
CommandBuilder = Callable[[str, str, tuple[str, ...], list[str]], list[str]]


def _nmap_command(target: str, output_path: str, profile_args: tuple[str, ...], extra_args: list[str]) -> list[str]:
    return ["nmap", *profile_args, *extra_args, "-oX", output_path, target]


def _nikto_command(target: str, output_path: str, profile_args: tuple[str, ...], extra_args: list[str]) -> list[str]:
    return ["nikto", "-h", target, *profile_args, *extra_args, "-Format", "txt", "-output", output_path]


def _nuclei_command(target: str, output_path: str, profile_args: tuple[str, ...], extra_args: list[str]) -> list[str]:
    return ["nuclei", "-u", target, *profile_args, *extra_args, "-jsonl", "-o", output_path]


@dataclass(frozen=True)
class ScanProfile:
    description: str
    args: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScannerAdapter:
    key: str
    display_name: str
    parser: Parser
    upload_extensions: tuple[str, ...]
    file_ext: str
    binary: str | None = None
    command_builder: CommandBuilder | None = None
    profiles: dict[str, ScanProfile] = field(default_factory=dict)

    def supports_live(self) -> bool:
        return bool(self.binary and self.command_builder and self.profiles)

    def is_available(self) -> bool:
        return self.supports_live() and bool(shutil.which(self.binary or ""))

    def profile_map(self) -> dict[str, dict[str, str | list[str]]]:
        return {
            name: {"description": profile.description, "args": list(profile.args)}
            for name, profile in self.profiles.items()
        }

    def build_command(self, target: str, output_path: str, profile: str, extra_args: list[str] | None = None) -> list[str]:
        if not self.supports_live() or self.command_builder is None:
            raise ValueError(f"{self.display_name} does not support live execution.")
        if profile not in self.profiles:
            raise ValueError(f"Unsupported profile '{profile}' for {self.display_name}")
        return self.command_builder(
            target,
            output_path,
            self.profiles[profile].args,
            extra_args or [],
        )

    def preview_command(self, target: str, profile: str, extra_args: list[str] | None = None) -> str:
        return list2cmdline(self.build_command(target, f"scan-output{self.file_ext}", profile, extra_args))


SCANNER_ADAPTERS: dict[str, ScannerAdapter] = {
    "nmap": ScannerAdapter(
        key="nmap",
        display_name="Nmap",
        parser=nmap_parser.parse_nmap,
        upload_extensions=("xml",),
        file_ext=".xml",
        binary="nmap",
        command_builder=_nmap_command,
        profiles={
            "Quick Discovery": ScanProfile(
                description="Top 100 TCP ports with version detection for fast triage.",
                args=("-Pn", "-T4", "--top-ports", "100", "-sV"),
            ),
            "Web Surface": ScanProfile(
                description="Common web ports plus basic HTTP and TLS metadata checks.",
                args=("-Pn", "-T4", "-p", "80,443,8080,8443", "-sV", "--script", "http-title,http-headers,ssl-cert"),
            ),
            "Vulnerability Audit": ScanProfile(
                description="Service detection with Nmap vuln NSE scripts for authorized assessments.",
                args=("-Pn", "-T4", "--top-ports", "100", "-sV", "--script", "vuln"),
            ),
        },
    ),
    "nessus": ScannerAdapter(
        key="nessus",
        display_name="Nessus",
        parser=nessus_parser.parse_nessus,
        upload_extensions=("nessus", "xml"),
        file_ext=".nessus",
    ),
    "openvas": ScannerAdapter(
        key="openvas",
        display_name="OpenVAS",
        parser=openvas_parser.parse_openvas,
        upload_extensions=("xml",),
        file_ext=".xml",
    ),
    "nikto": ScannerAdapter(
        key="nikto",
        display_name="Nikto",
        parser=nikto_parser.parse_nikto,
        upload_extensions=("txt", "json"),
        file_ext=".txt",
        binary="nikto",
        command_builder=_nikto_command,
        profiles={
            "Baseline Web Audit": ScanProfile(
                description="General-purpose Nikto checks for common web misconfigurations.",
            ),
            "TLS Web Audit": ScanProfile(
                description="HTTPS-focused Nikto scan for SSL/TLS-enabled web targets.",
                args=("-ssl",),
            ),
        },
    ),
    "nuclei": ScannerAdapter(
        key="nuclei",
        display_name="Nuclei",
        parser=nuclei_parser.parse_nuclei,
        upload_extensions=("json", "jsonl", "txt"),
        file_ext=".jsonl",
        binary="nuclei",
        command_builder=_nuclei_command,
        profiles={
            "Web Quick Templates": ScanProfile(
                description="Medium-to-critical templates with moderate rate limiting.",
                args=("-severity", "medium,high,critical", "-rate-limit", "50"),
            ),
            "Critical Focus": ScanProfile(
                description="High and critical template sweep for quicker validation.",
                args=("-severity", "high,critical", "-rate-limit", "25"),
            ),
        },
    ),
}


def get_scanner_adapter(scanner: str) -> ScannerAdapter:
    normalized = scanner.strip().lower()
    if normalized in SCANNER_ADAPTERS:
        return SCANNER_ADAPTERS[normalized]

    for adapter in SCANNER_ADAPTERS.values():
        if adapter.display_name.lower() == normalized:
            return adapter

    raise ValueError(f"Unsupported scanner: {scanner}")


def list_upload_adapters() -> list[ScannerAdapter]:
    return list(SCANNER_ADAPTERS.values())


def list_live_adapters() -> list[ScannerAdapter]:
    return [adapter for adapter in SCANNER_ADAPTERS.values() if adapter.supports_live()]
