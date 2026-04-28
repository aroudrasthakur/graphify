"""CLI for ``depos-intel intent-context``."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from depos.analysis.config import load_config_from_env
from depos.intent_context.build import run_intent_context_build
from depos.intent_graph.run import run_graphical_intent_compare


def run_intent_context_cli(args: argparse.Namespace) -> int:
    cmd = getattr(args, "intent_command", None)
    if cmd == "build":
        cfg = load_config_from_env()
        return run_intent_context_build(
            Path(args.repo_root),
            Path(args.output_dir),
            cfg,
            intent_llm_override=args.intent_llm,
        )
    if cmd == "graph-compare":
        intent_dir = Path(getattr(args, "intent_dir", "intent-out"))
        if not (intent_dir / "intent_manifest.json").exists():
            print(
                f"error: intent_manifest.json not found in {intent_dir!s} (run intent-context build first).",
                file=sys.stderr,
            )
            return 2
        _, code = run_graphical_intent_compare(
            Path(args.repo_root),
            intent_dir,
            args.graph_json,
            output_dir=getattr(args, "output_dir", None) or None,
            strict=getattr(args, "strict", False),
            require_same_commit=getattr(args, "require_same_commit", False),
        )
        return code
    return 2
