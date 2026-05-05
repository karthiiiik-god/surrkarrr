from __future__ import annotations

from .risk_path_analyzer import generate_risk_paths, summarize_risk_path


def generate_attack_paths(vulns):
    """
    Backward-compatible wrapper around the remediation-focused risk-path
    analyzer. New code should import `generate_risk_paths` instead.
    """
    return generate_risk_paths(vulns)


__all__ = ["generate_attack_paths", "generate_risk_paths", "summarize_risk_path"]
