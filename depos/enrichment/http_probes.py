"""HTTP probes: lift FastAPI route decorators and TypeScript fetch / axios
URL literals onto the graph.

Graphify does not extract:
- FastAPI ``@router.get(...)``/``@app.post(...)`` decorator arguments.
- Literal URL strings passed to ``fetch(...)`` or ``axios.<method>(...)``.

These probes re-read the Python / TS source files referenced by existing
nodes and annotate those nodes with ``route_pattern``, ``http_method``,
``decorator``, ``url_literal``, ``url_template_tokens``, and
``is_dynamic_url``. We do NOT edit ``graphify/extract.py`` \u2014 all new
logic lives under ``depos/enrichment/`` so the vendored library stays
upstream-clean.

The probes are regex-based for portability (no extra tree-sitter wiring
needed in PR 2). They operate per-file and only on files already
referenced by graph nodes, so they do not blow up on gigantic repos.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import networkx as nx

from depos.analysis.fragments import GraphFragment, NodeAttrUpdate, make_fragment

# ---------------------------------------------------------------------------
# FastAPI route decorator lifter (Python)
# ---------------------------------------------------------------------------

# Matches @router.get("/repos"), @app.post("/x", status_code=201), etc.
_FASTAPI_DECORATOR = re.compile(
    r"@(?P<obj>[A-Za-z_][A-Za-z0-9_]*)\.(?P<method>get|post|put|patch|delete|options|head)"
    r"\s*\(\s*(?P<quote>[\"'])(?P<path>[^\"']+)(?P=quote)",
)

# Matches `def handler_name(` on a line that immediately follows one or more
# decorators. We look at the raw source below each decorator for a function
# definition.
_FUNCDEF = re.compile(r"^\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)


def _python_hash_comment_before(source: str, pos: int) -> bool:
    """True if ``pos`` lies in a Python ``# ...`` comment (whole-line or inline).

    The FastAPI decorator regex runs over raw source; examples in comments
    (e.g. ``# Matches @router.get("/x")``) must not pair with the next ``def``.
    """
    line_start = source.rfind("\n", 0, pos) + 1
    line_end = source.find("\n", pos)
    if line_end == -1:
        line_end = len(source)
    line = source[line_start:line_end]
    if line.strip().startswith("#"):
        return True
    before = source[line_start:pos]
    # Inline comment: first '#' outside a string starts the comment.
    in_single = in_double = False
    i = 0
    while i < len(before):
        c = before[i]
        if in_single:
            if c == "\\" and i + 1 < len(before):
                i += 2
                continue
            if c == "'":
                in_single = False
            i += 1
            continue
        if in_double:
            if c == "\\" and i + 1 < len(before):
                i += 2
                continue
            if c == '"':
                in_double = False
            i += 1
            continue
        if c == "'":
            in_single = True
        elif c == '"':
            in_double = True
        elif c == "#":
            return True
        i += 1
    return False


@dataclass
class RouteDecoration:
    file: str
    handler_name: str
    http_method: str  # uppercase
    route_pattern: str
    decorator_object: str
    line: int


def scan_fastapi_routes(source: str, *, file: str) -> list[RouteDecoration]:
    """Return all FastAPI route decorations discovered in ``source``.

    Each decoration is paired with the *next* function definition in the file.
    """
    out: list[RouteDecoration] = []
    for m in _FASTAPI_DECORATOR.finditer(source):
        start = m.start()
        if _python_hash_comment_before(source, start):
            continue
        line_no = source[:start].count("\n") + 1
        # Walk forward to find the next function definition.
        rest = source[m.end():]
        fm = _FUNCDEF.search(rest)
        handler = fm.group("name") if fm else ""
        out.append(
            RouteDecoration(
                file=file,
                handler_name=handler,
                http_method=m.group("method").upper(),
                route_pattern=m.group("path"),
                decorator_object=m.group("obj"),
                line=line_no,
            )
        )
    return out


# ---------------------------------------------------------------------------
# TypeScript fetch / axios call lifter
# ---------------------------------------------------------------------------

# fetch("/api/...") with optional `{ method: 'GET' }` second arg.
_TS_FETCH = re.compile(
    r"""fetch\s*\(\s*
        (?P<quote>[`'"])(?P<url>[^`'"]+)(?P=quote)       # url literal or template
        (?:\s*,\s*\{(?P<options>[^}]*)\})?              # optional options
    """,
    re.VERBOSE,
)

# axios.get("/api/..."), axios.post("/api/...", body), axios("/...", {...})
_TS_AXIOS = re.compile(
    r"""axios
        (?:\.(?P<method>get|post|put|patch|delete|options|head))?
        \s*\(\s*
        (?P<quote>[`'"])(?P<url>[^`'"]+)(?P=quote)
        (?:\s*,\s*\{(?P<config>[^}]*)\})?              # optional config object
    """,
    re.VERBOSE,
)

# ${ } inside a template literal -> dynamic URL
_TEMPLATE_EXPR = re.compile(r"\$\{([^}]+)\}")


def _detect_method(options_blob: Optional[str]) -> Optional[str]:
    """Extract HTTP method from fetch/axios options object.
    
    Supports single quotes, double quotes, and backticks around method value.
    Examples:
        method: 'POST'
        method: "PUT"
        method: `DELETE`
    """
    if not options_blob:
        return None
    # Match method with single quotes, double quotes, or backticks
    m = re.search(r"method\s*:\s*['\"`]([A-Za-z]+)['\"`]", options_blob)
    return m.group(1).upper() if m else None


@dataclass
class HTTPCallSite:
    file: str
    line: int
    url_literal: str
    url_template_tokens: list[str] = field(default_factory=list)
    is_dynamic_url: bool = False
    http_method: Optional[str] = None
    method_inferred: bool = False
    kind: str = "fetch"  # "fetch" | "axios"


def scan_ts_http_calls(source: str, *, file: str) -> list[HTTPCallSite]:
    out: list[HTTPCallSite] = []
    for m in _TS_FETCH.finditer(source):
        url = m.group("url")
        line = source[: m.start()].count("\n") + 1
        options = m.group("options")
        method = _detect_method(options)
        tokens = [t.strip() for t in _TEMPLATE_EXPR.findall(url)]
        dynamic = "${" in url
        out.append(
            HTTPCallSite(
                file=file,
                line=line,
                url_literal=url,
                url_template_tokens=tokens,
                is_dynamic_url=dynamic,
                http_method=method or ("GET" if not options else None),
                method_inferred=method is None,
                kind="fetch",
            )
        )
    for m in _TS_AXIOS.finditer(source):
        url = m.group("url")
        line = source[: m.start()].count("\n") + 1
        # Try to get method from function name (axios.get, axios.post, etc.)
        method_from_name = m.group("method")
        # If no method in function name, try to extract from config object
        config = m.group("config")
        method_from_config = _detect_method(config) if config else None
        # Prefer method from function name, fall back to config, default to GET
        method = (method_from_name or method_from_config or "get").upper()
        method_inferred = method_from_name is None and method_from_config is None
        tokens = [t.strip() for t in _TEMPLATE_EXPR.findall(url)]
        dynamic = "${" in url
        out.append(
            HTTPCallSite(
                file=file,
                line=line,
                url_literal=url,
                url_template_tokens=tokens,
                is_dynamic_url=dynamic,
                http_method=method,
                method_inferred=method_inferred,
                kind="axios",
            )
        )
    return out


# ---------------------------------------------------------------------------
# Graph annotation
# ---------------------------------------------------------------------------

_PY_EXTS = {".py"}
_TS_EXTS = {".ts", ".tsx", ".js", ".jsx", ".mjs"}


def _unique_source_files(graph: nx.DiGraph, suffixes: set[str]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for _, attrs in graph.nodes(data=True):
        sf = attrs.get("source_file")
        if not sf or sf in seen:
            continue
        p = Path(sf)
        if p.suffix.lower() in suffixes:
            seen.add(sf)
            out.append(p)
    return out


def _node_for_file_and_name(
    graph: nx.DiGraph,
    *,
    source_file: str,
    name_hint: str,
) -> Optional[str]:
    sf_norm = Path(source_file).as_posix()
    name_suffix = f"{name_hint}()"
    for nid, attrs in graph.nodes(data=True):
        sf = attrs.get("source_file")
        if not sf:
            continue
        if Path(sf).as_posix() != sf_norm:
            continue
        label = attrs.get("label", "")
        if label == name_suffix or label == name_hint:
            return nid
    return None


def _nodes_for_file(graph: nx.DiGraph, source_file: str) -> list[str]:
    sf_norm = Path(source_file).as_posix()
    return [
        nid
        for nid, attrs in graph.nodes(data=True)
        if attrs.get("source_file") and Path(attrs["source_file"]).as_posix() == sf_norm
    ]


def _read_text_safely(path: Path) -> Optional[str]:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def annotate_fastapi_routes(graph: nx.DiGraph, repo_root: Optional[Path] = None) -> GraphFragment:
    """Walk every distinct Python source file referenced by nodes, parse
    route decorations, and return a GraphFragment with NodeAttrUpdates for
    ``route_pattern`` / ``http_method`` / ``decorator`` / ``is_fastapi_route``.
    """
    updates: list[NodeAttrUpdate] = []
    for p in _unique_source_files(graph, _PY_EXTS):
        full = p if p.is_absolute() else ((repo_root / p) if repo_root else p)
        text = _read_text_safely(full)
        if text is None:
            continue
        for dec in scan_fastapi_routes(text, file=p.as_posix()):
            nid = _node_for_file_and_name(graph, source_file=p.as_posix(), name_hint=dec.handler_name)
            if nid is None:
                continue
            updates.append(NodeAttrUpdate(node_id=nid, key="route_pattern", value=dec.route_pattern))
            updates.append(NodeAttrUpdate(node_id=nid, key="http_method", value=dec.http_method))
            updates.append(NodeAttrUpdate(
                node_id=nid,
                key="decorator",
                value=f"@{dec.decorator_object}.{dec.http_method.lower()}",
            ))
            updates.append(NodeAttrUpdate(node_id=nid, key="is_fastapi_route", value=True))
    return make_fragment("enrich_annotate_fastapi", node_attr_updates=updates)


def annotate_ts_http_calls(graph: nx.DiGraph, repo_root: Optional[Path] = None) -> GraphFragment:
    """Walk TS source files, find fetch/axios call sites, and return a
    GraphFragment with a NodeAttrUpdate setting ``http_call_sites`` on one
    representative node per file.
    """
    updates: list[NodeAttrUpdate] = []
    for p in _unique_source_files(graph, _TS_EXTS):
        full = p if p.is_absolute() else ((repo_root / p) if repo_root else p)
        text = _read_text_safely(full)
        if text is None:
            continue
        sites = scan_ts_http_calls(text, file=p.as_posix())
        if not sites:
            continue
        file_nodes = _nodes_for_file(graph, p.as_posix())
        if not file_nodes:
            continue
        call_site_dicts = [
            {
                "file": s.file,
                "line": s.line,
                "url_literal": s.url_literal,
                "url_template_tokens": s.url_template_tokens,
                "is_dynamic_url": s.is_dynamic_url,
                "http_method": s.http_method,
                "method_inferred": s.method_inferred,
                "kind": s.kind,
                "node_id": file_nodes[0],
            }
            for s in sites
        ]
        updates.append(
            NodeAttrUpdate(node_id=file_nodes[0], key="http_call_sites", value=call_site_dicts)
        )
    return make_fragment("enrich_annotate_ts", node_attr_updates=updates)


def iter_fastapi_route_nodes(graph: nx.DiGraph) -> Iterable[tuple[str, dict]]:
    for nid, attrs in graph.nodes(data=True):
        if attrs.get("is_fastapi_route"):
            yield nid, attrs
