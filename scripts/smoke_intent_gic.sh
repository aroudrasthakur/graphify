#!/usr/bin/env bash
# Local smoke test: intent-context build → graph-compare → print artifact paths.
# Uses DEPOS_INTEL_INTENT_LLM=rules (no OpenAI). Graph step runs graphify on the repo (can be slow on large trees).
#
# Usage:
#   ./scripts/smoke_intent_gic.sh
#
# Prerequisites: repo root; `depos-intel` on PATH (e.g. `pip install -e .` from graphify root).

set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT"

echo "== pytest (intent_graph + intent_context) =="
python -m pytest tests/intent_graph tests/intent_context -q --tb=line

WORK="$(mktemp -d)"
INTENT="$WORK/intent"
GIC="$WORK/gic"
mkdir -p "$INTENT" "$GIC"

export DEPOS_INTEL_INTENT_LLM=rules

echo ""
echo "== intent-context build (rules-only, no network) → $INTENT =="
depos-intel intent-context build --repo-root "$ROOT" --output-dir "$INTENT" --intent-llm rules

echo ""
echo "== graph-compare → $GIC =="
echo "    (this may take a while: full graphify extract+snapshot)"
depos-intel intent-context graph-compare \
  --repo-root "$ROOT" \
  --intent-dir "$INTENT" \
  --output-dir "$GIC"

JSON="$GIC/intent_graph_report.json"
MD="$GIC/intent_graph_report.md"
test -f "$JSON" && test -f "$MD"

echo ""
echo "OK — artifacts:"
echo "  $JSON"
echo "  $MD"

if command -v jq >/dev/null 2>&1; then
  echo ""
  echo "Quick peek (scores / alignment):"
  jq '{gic_alignment_score: .composite.gic_alignment_score, commit_alignment, intent_repo_sha, current_head_sha, units: (.units|length)}' "$JSON"
fi

echo ""
echo "First ~40 lines of markdown report:"
sed -n '1,40p' "$MD" | sed 's/^/  /' || true

echo ""
echo "Scratch dir (inspect, then remove when done): $WORK"
echo "  rm -rf \"$WORK\""
