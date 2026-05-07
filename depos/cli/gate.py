"""``depos-intel gate`` — fail CI on CONFIRMED high/critical findings."""
from __future__ import annotations

import json
import sys
from argparse import Namespace
from pathlib import Path


def run_gate(args: Namespace) -> int:
    from depos.output.gate import evaluate_gate, load_allowlist, load_auto_suppress, load_violations_path
    from depos.output.gate_result import build_gate_result

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
    auto = load_auto_suppress(args.auto_suppress) if getattr(args, "auto_suppress", None) else set()
    fail, blocking = evaluate_gate(findings, allowlist=allow, auto_suppress=auto or None)
    prod_block: bool | None = None
    prod_ids: list[str] = []
    summary_path = path.parent / "product_summary.json"
    if summary_path.is_file():
        try:
            pdata = json.loads(summary_path.read_text(encoding="utf-8"))
            dec = pdata.get("ci_decision") if isinstance(pdata, dict) else None
            if isinstance(dec, dict):
                pb = dec.get("should_block")
                if isinstance(pb, bool):
                    prod_block = pb
                bi = dec.get("blocking_finding_ids") or []
                if isinstance(bi, list):
                    prod_ids = [str(x) for x in bi]
        except (json.JSONDecodeError, OSError):
            pass
    gate_doc = build_gate_result(
        doc,
        allowlist=allow,
        product_should_block=prod_block,
        product_blocking_ids=prod_ids,
    )
    gate_out = path.parent / "gate_result.json"
    gate_out.write_text(json.dumps(gate_doc, indent=2, default=str), encoding="utf-8")

    summary = {
        "gate": "failed" if fail else "passed",
        "blocking_count": len(blocking),
        "blocking_finding_ids": [b.get("finding_id") for b in blocking],
        "gate_result_path": str(gate_out),
        "gate_outcome": gate_doc.get("outcome"),
    }
    print(json.dumps(summary, indent=2))
    return 1 if fail else 0


__all__ = ["run_gate"]
