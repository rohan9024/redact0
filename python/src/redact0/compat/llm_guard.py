"""
Drop-in zero-dependency compatibility layer for archived `llm-guard` (Protect AI).
Replaces Anonymize / Deanonymize / Sensitive / Vault / scan_prompt / scan_output
without PyTorch, spaCy, or presidio-anonymizer.
"""
from __future__ import annotations

from typing import Any

from ..vault import Vault as CoreVault


class Vault(CoreVault):
    """Drop-in replacement for `llm_guard.vault.Vault`."""


class Anonymize:
    def __init__(self, vault: CoreVault | None = None, preset: str = "default", **kwargs: Any) -> None:
        self.vault = vault if vault is not None else CoreVault(preset=preset, **kwargs)

    def scan(self, prompt: str) -> tuple[str, bool, float]:
        res = self.vault.redact_text(prompt)
        is_valid = res.count == 0
        risk_score = 0.0 if is_valid else 1.0
        return res.value, is_valid, risk_score


class Deanonymize:
    def __init__(self, vault: CoreVault) -> None:
        self.vault = vault

    def scan(self, _prompt: str, output: str) -> tuple[str, bool, float]:
        restored = self.vault.restore(output)
        return restored, True, 0.0


class Sensitive:
    def __init__(self, preset: str = "strict", **kwargs: Any) -> None:
        self.vault = CoreVault(preset=preset, **kwargs)

    def scan(self, _prompt: str, output: str) -> tuple[str, bool, float]:
        res = self.vault.redact_text(output)
        is_valid = res.count == 0
        return res.value, is_valid, 0.0 if is_valid else 1.0


def scan_prompt(scanners: list[Any], prompt: str) -> tuple[str, dict[str, bool], dict[str, float]]:
    current = prompt
    results_valid: dict[str, bool] = {}
    results_score: dict[str, float] = {}
    for scanner in scanners:
        name = type(scanner).__name__
        current, is_valid, score = scanner.scan(current)
        results_valid[name] = is_valid
        results_score[name] = score
    return current, results_valid, results_score


def scan_output(
    scanners: list[Any], prompt: str, output: str
) -> tuple[str, dict[str, bool], dict[str, float]]:
    current = output
    results_valid: dict[str, bool] = {}
    results_score: dict[str, float] = {}
    for scanner in scanners:
        name = type(scanner).__name__
        current, is_valid, score = scanner.scan(prompt, current)
        results_valid[name] = is_valid
        results_score[name] = score
    return current, results_valid, results_score
