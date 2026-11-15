from __future__ import annotations

import argparse
import json
import sys

from .vault import redact_detailed, scan


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="redact0", description="0-dep reversible PII & secret redactor")
    parser.add_argument("--preset", default="default", choices=["default", "secrets", "hipaa", "gdpr", "strict"])
    parser.add_argument("--scan", action="store_true", help="Output findings metadata as JSON without raw values")
    args = parser.parse_args(argv)

    text = sys.stdin.read()
    if args.scan:
        findings = [f.__dict__ for f in scan(text, preset=args.preset)]
        print(json.dumps(findings, indent=2))
        return 1 if findings else 0

    res = redact_detailed(text, preset=args.preset)
    sys.stdout.write(res.value)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
