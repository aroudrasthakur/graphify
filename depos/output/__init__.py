"""Structured output for depOS: JSON, SARIF, PR Markdown, and CI gate helpers.

Import submodules explicitly, e.g. ``from depos.output.sarif import render_sarif``.
"""
from __future__ import annotations

from . import canonical, gate, json, pr_comment, sarif

__all__ = ["canonical", "gate", "json", "pr_comment", "sarif"]
