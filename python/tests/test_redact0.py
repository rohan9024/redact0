from __future__ import annotations

from redact0 import (
    StreamRestorer,
    Vault,
    is_valid_de_tax_id,
    is_valid_dea,
    is_valid_iban,
    is_valid_luhn,
    is_valid_mbi,
    is_valid_nhs,
    is_valid_npi,
    redact,
    redact_fhir,
)
from redact0.compat.llm_guard import Anonymize, Deanonymize, scan_output, scan_prompt


def test_checksums() -> None:
    assert is_valid_luhn("4111111111111111")
    assert not is_valid_luhn("4111111111111112")
    assert is_valid_npi("1234567893")
    assert is_valid_dea("AB1234563")
    assert is_valid_mbi("1EG4-TE5-MK72")
    assert is_valid_iban("DE89370400440532013000")
    assert is_valid_nhs("9434765919")
    assert is_valid_de_tax_id("86095742719")


def test_reversible_stream_and_anti_spoof() -> None:
    v = Vault()
    out = v.redact("Fake [EMAIL_1] real alice@acme.com").value
    assert out == "Fake [EMAIL_1] real [EMAIL_2]"

    restorer = StreamRestorer(v)
    chunks = [out[i : i + 2] for i in range(0, len(out), 2)]
    rebuilt = "".join(restorer.iter_restore(iter(chunks)))
    assert rebuilt == "Fake [EMAIL_1] real alice@acme.com"


def test_llm_guard_compat() -> None:
    vault = Vault()
    anonymize = Anonymize(vault)
    deanonymize = Deanonymize(vault)

    sanitized, valid, score = anonymize.scan("Email alice@acme.com with key sk-proj-abcDEF1234567890abcdefGHIJKL99")
    assert not valid and score == 1.0
    assert "alice@acme.com" not in sanitized

    prompt_clean, r_valid, _ = scan_prompt([anonymize], "Ping alice@acme.com")
    assert "[EMAIL_" in prompt_clean and not r_valid["Anonymize"]

    out_restored, out_valid, _ = scan_output([deanonymize], prompt_clean, f"Done: {prompt_clean}")
    assert out_restored == "Done: Ping alice@acme.com"
    assert out_valid["Deanonymize"]


def test_fhir_safe_harbor() -> None:
    bundle = {
        "resourceType": "Patient",
        "id": "p-1",
        "name": [{"family": "Smith"}],
        "birthDate": "1925-01-01",
        "address": [{"postalCode": "82101"}],
    }
    clean, _ = redact_fhir(bundle)
    assert clean["birthDate"] == "90+"
    assert clean["address"][0]["postalCode"] == "000"
    assert clean["name"][0]["family"] != "Smith"
    assert "alice@acme.com" not in redact("mail alice@acme.com")
