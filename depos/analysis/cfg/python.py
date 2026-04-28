"""Python intra-procedural CFG (stdlib :mod:`ast`).

Re-exports the implementation from :mod:`depos.analysis.cfg.python_cfg` for the
depOS plan module path ``depos/analysis/cfg/python.py``.
"""
from __future__ import annotations

from depos.analysis.cfg.python_cfg import CfgResult, build_python_function_cfg

__all__ = ["CfgResult", "build_python_function_cfg"]
