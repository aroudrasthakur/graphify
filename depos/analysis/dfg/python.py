"""Python def-use DFG (stdlib :mod:`ast`).

Re-exports from :mod:`depos.analysis.dfg.python_dfg` for the plan path
``depos/analysis/dfg/python.py``.
"""
from __future__ import annotations

from depos.analysis.dfg.python_dfg import DfgResult, build_python_dfg

__all__ = ["DfgResult", "build_python_dfg"]
