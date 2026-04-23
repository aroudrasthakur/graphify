"""Group C: DFG/taint-gated detectors (master plan inventory)."""
from __future__ import annotations

import re
from pathlib import Path

import networkx as nx

from depos.analysis.detectors import register
from depos.analysis.detectors.builtin.common import make_candidate, simple_spec
from depos.analysis.detectors.policy import iter_eligible_scopes
from depos.analysis.schemas import SeedType, TaintEdge, Universe


def _read(repo_root: Path | None, rel: str) -> str | None:
    if not repo_root or not rel:
        return None
    p = (repo_root / rel).resolve()
    if not p.is_file():
        return None
    return p.read_text(encoding="utf-8", errors="replace")


RE_SQL = re.compile(r"execute\(|raw\(|`select\s|INSERT\s+INTO", re.I)
RE_CMD = re.compile(r"os\.system|subprocess|child_process|exec\(", re.I)
RE_SUDO = re.compile(r"\bsudo\b|setuid|seteuid|chmod\s+4755", re.I)
RE_UAF = re.compile(r"free\s*\(|delete\s+\w+[\s;]", re.M)
RE_OVERFLOW = re.compile(r"<<\s*\d+|0x[0-9a-f]+\s*\*\s*|Math\.imul", re.I)
RE_AW_RACE = re.compile(r"async\s+function|async\s*\(", re.M)
RE_AW_MUT = re.compile(r"\+=|-=|\+\+|--|\.push\(", re.M)


def _make(
    name: str,
    scope: str,
    mode,
    config,
    extra: dict,
    ps: float,
    *,
    req_dfg: bool = False,
    req_taint: bool = False,
):
    e = {**extra, "group": "C", "detector": name}
    return make_candidate(
        scope_id=f"sem:{name}:{scope}",
        seed_type=SeedType.graph_anomaly,
        detector_confidence=ps,
        analysis_mode=mode,
        config=config,
        diff_anchors=[str(scope)],
        extra=e,
        requires_dfg=req_dfg,
        # taint is encoded as "requires" via semantic layer + payload
    )


def _taint_edges(graph: nx.DiGraph) -> list[TaintEdge]:
    return list(graph.graph.get("taint_edges", []) or [])


def _run_sql_injection(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.taint_edges_available.values()):
        return []
    spec = ctx["detector"]
    el = set(iter_eligible_scopes(graph, rctx, spec))
    out = []
    for te in _taint_edges(graph):
        if str(te.scope or "") not in el:
            continue
        sp = str(te.sink_pattern or "")
        if not sp or not RE_SQL.search(sp + str(te.source_chain or "")):
            continue
        out.append(
            _make(
                "sql-injection-approx",
                str(te.scope or "unknown"),
                mode,
                config,
                {"taint": te.model_dump(mode="json"), "kind": "sql"},
                0.9,
                req_dfg=True,
            )
        )
    return out


def _run_cmd_injection(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.taint_edges_available.values()):
        return []
    spec = ctx["detector"]
    el = set(iter_eligible_scopes(graph, rctx, spec))
    out = []
    for te in _taint_edges(graph):
        if str(te.scope or "") not in el:
            continue
        blob = f"{te.sink_pattern or ''} {te.source_chain or ''}"
        if not RE_CMD.search(blob):
            continue
        out.append(
            _make(
                "command-injection-approx",
                str(te.scope or "unknown"),
                mode,
                config,
                {"taint": te.model_dump(mode="json"), "kind": "cmd"},
                0.92,
                req_dfg=True,
            )
        )
    return out


def _run_uninit(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.dfg_available.values()):
        return []
    spec = ctx["detector"]
    el = set(iter_eligible_scopes(graph, rctx, spec))
    for u, v, d in graph.edges(data=True):
        su, sv = str(u), str(v)
        if su not in el and sv not in el:
            continue
        if d.get("type") == "dfg" and d.get("var") and not str(u).startswith("dfgdef:param"):
            return [
                _make(
                    "uninit-variable-approx",
                    "dfg:snapshot",
                    mode,
                    config,
                    {"edge": f"{u}->{v}", "var": d.get("var"), "note": "dfg_path_sample"},
                    0.55,
                    req_dfg=True,
                )
            ]
    return []


def _run_auth_bypass(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.dfg_available.values()):
        return []
    spec = ctx["detector"]
    out = []
    root = rctx.repo_root
    for n in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(n) or {}
        rel = str(a.get("source_file") or "")
        src = _read(root, rel)
        if not src or "middleware" not in rel and "auth" not in rel.lower():
            continue
        if re.search(r"if\s*\(\s*true\s*\)\s*return|if\s*True:\s*return", src):
            out.append(
                _make("auth-bypass-approx", str(n), mode, config, {"file": rel}, 0.75, req_dfg=True)
            )
    return out


def _run_priv(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.taint_edges_available.values()):
        return []
    spec = ctx["detector"]
    el = set(iter_eligible_scopes(graph, rctx, spec))
    out = []
    for te in _taint_edges(graph):
        if str(te.scope or "") not in el:
            continue
        if RE_SUDO.search(str(te.source_chain or "") + str(te.sink_pattern or "")):
            out.append(
                _make(
                    "privilege-escalation-approx",
                    str(te.scope or "n"),
                    mode,
                    config,
                    te.model_dump(mode="json"),
                    0.85,
                    req_dfg=True,
                )
            )
    root = rctx.repo_root
    for n in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(n) or {}
        s = _read(root, str(a.get("source_file") or ""))
        if s and RE_SUDO.search(s):
            out.append(
                _make("privilege-escalation-approx", str(n), mode, config, {"file": a.get("source_file")}, 0.78, req_dfg=True)
            )
    return out


def _run_uaf(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.dfg_available.values()):
        return []
    spec = ctx["detector"]
    out = []
    root = rctx.repo_root
    for n in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(n) or {}
        s = _read(root, str(a.get("source_file") or ""))
        if s and RE_UAF.search(s) and "delete" in s:
            out.append(
                _make("use-after-free-approx", str(n), mode, config, {"pattern": "delete_or_free"}, 0.63, req_dfg=True)
            )
    return out


def _run_overflow(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.dfg_available.values()):
        return []
    spec = ctx["detector"]
    out = []
    root = rctx.repo_root
    for n in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(n) or {}
        s = _read(root, str(a.get("source_file") or ""))
        if s and RE_OVERFLOW.search(s):
            out.append(
                _make("integer-overflow-approx", str(n), mode, config, {"pattern": "bitshift_or_mul"}, 0.57, req_dfg=True)
            )
    return out


def _run_race(graph, manifest, mode, config, ctx) -> list:
    rctx = ctx.get("run_context")
    if rctx is None or not any(rctx.dfg_available.values()):
        return []
    spec = ctx["detector"]
    out = []
    root = rctx.repo_root
    await_suspensions = [
        (u, v)
        for u, v, d in graph.edges(data=True)
        if str(d.get("type") or "") in ("AWAIT_SUSPENSION", "await_suspension")
    ]
    for n in iter_eligible_scopes(graph, rctx, spec):
        a = graph.nodes.get(n) or {}
        s = _read(root, str(a.get("source_file") or ""))
        if not s:
            continue
        if RE_AW_RACE.search(s) and RE_AW_MUT.search(s):
            ex = {"pattern": "async_mutation", "await_suspension_edge_count": len(await_suspensions)}
            out.append(_make("race-condition-approx", str(n), mode, config, ex, 0.58, req_dfg=True))
    return out


def _spec(
    name: str, checks: list[str], severity: str, sem: str
):
    return simple_spec(
        name=name,
        universe=Universe.code,
        verifier_checks=checks,
        requires_reasoner=severity in ("high", "critical"),
        severity=severity,  # type: ignore[arg-type]
        semantic_requirement=sem,  # type: ignore[arg-type]
    )


S1 = _spec("sql-injection-approx", ["taint_sinks_sql", "dfg_witness"], "high", "taint")
S2 = _spec("command-injection-approx", ["taint_sinks_subprocess", "dfg_witness"], "critical", "taint")
S3 = _spec("uninit-variable-approx", ["dfg_def_before_use", "source_snippet"], "medium", "dfg")
S4 = _spec("auth-bypass-approx", ["static_pattern", "router_context"], "high", "dfg")
S5 = _spec("privilege-escalation-approx", ["sudo_pattern", "graph_context"], "critical", "taint")
S6 = _spec("use-after-free-approx", ["free_delete_pattern", "dfg_witness"], "high", "dfg")
S7 = _spec("integer-overflow-approx", ["bitshift_pattern", "arithmetic_witness"], "medium", "dfg")
S8 = _spec("race-condition-approx", ["async_await", "shared_mutation", "dfg_witness"], "medium", "dfg")

register(S1, _run_sql_injection)
register(S2, _run_cmd_injection)
register(S3, _run_uninit)
register(S4, _run_auth_bypass)
register(S5, _run_priv)
register(S6, _run_uaf)
register(S7, _run_overflow)
register(S8, _run_race)
