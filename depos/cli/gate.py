"""``depos-intel gate`` — fail CI on CONFIRMED high/critical findings."""
from __future__ import annotations

import json
import sys
from argparse import Namespace
from pathlib import Path


def run_gate(args: Namespace) -> int:
    from depos.output.gate import evaluate_gate, load_allowlist, load_violations_path

    path = Path(args.violations)
    if not path.is_file():
        print(f"violations file not found: {path}", file=sys.stderr)
        return 2
    doc = load_violations_path(path)
    findings = list(doc.get("findings") or [])
    allow = load_allowlist(args.allowlist)
    if args.allow_finding_id:
        print(
            "warning: --allow-finding-id is deprecated; prefer .depOS/allowlist.json",
            file=sys.stderr,
        )
        allow.update(str(x) for x in args.allow_finding_id if x)
    fail, blocking = evaluate_gate(findings, allowlist=allow)
    summary = {
        "gate": "failed" if fail else "passed",
        "blocking_count": len(blocking),
        "blocking_finding_ids": [b.get("finding_id") for b in blocking],
    }
    print(json.dumps(summary, indent=2))
    return 1 if fail else 0


__all__ = ["run_gate"]
