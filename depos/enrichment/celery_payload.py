"""Module 1: Celery / task-queue payload matcher.

Graphify already surfaces Celery ``@task``-decorated functions; this pass
adds:

- ``TASK_ENQUEUES`` edges from producers (call sites using ``.delay()`` or
  ``.apply_async()``) to the task function.
- ``PRODUCES_PAYLOAD`` / ``CONSUMES_PAYLOAD`` edges whose metadata
  enumerates overlap / missing / extra keyword-argument field names so
  the verifier can check payload drift without re-reading source.

Inference is regex-based (same posture as the HTTP probes): works well
for typical codebases, reports ``inferred=True`` when the call site's
kwargs cannot be statically determined.

Note on edge merging: DiGraph allows one edge per (u, v) pair. For each
caller→task pair we emit PRODUCES_PAYLOAD (the surviving relation after
the prior overwrite behaviour). For the task self-loop we emit TASK_CONSUMES
merged with CONSUMES_PAYLOAD attrs.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

import networkx as nx

from depos.analysis.fragments import FragmentEdge, FragmentNode, GraphFragment, make_fragment
from depos.graph_relations import CONSUMES_PAYLOAD
from depos.graph_relations import PRODUCES_PAYLOAD
from depos.graph_relations import TASK_CONSUMES
from depos.graph_relations import TASK_ENQUEUES
from depos.analysis.schemas import ContractKind, SemanticEdgeMetadata


_ENQUEUE = re.compile(
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\.(?P<method>delay|apply_async)\s*\(",
)
_KW_RE = re.compile(r"(?P<kw>[A-Za-z_][A-Za-z0-9_]*)\s*=")
_TASK_DEF_RE = re.compile(
    r"@(?:celery_app\.|app\.|shared_)?task[^\n]*\n\s*(?:async\s+)?def\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*\((?P<args>[^)]*)\)",
    re.MULTILINE,
)


@dataclass
class _TaskDef:
    node_id: str
    source_file: str
    name: str
    expected_kwargs: list[str]


def _extract_kwargs(signature: str) -> list[str]:
    kwargs: list[str] = []
    for chunk in signature.split(","):
        chunk = chunk.strip()
        if not chunk or chunk.startswith("*"):
            continue
        name = chunk.split(":", 1)[0].split("=", 1)[0].strip()
        if name:
            kwargs.append(name)
    return kwargs


def _find_task_defs(
    graph: nx.DiGraph, repo_root: Path | None = None
) -> tuple[dict[str, _TaskDef], list[FragmentNode]]:
    """Find Celery task definitions. Returns the task map and any synthetic
    FragmentNodes needed for tasks not already in the graph."""
    out: dict[str, _TaskDef] = {}
    synthetic_nodes: list[FragmentNode] = []
    seen_files: set[str] = set()
    for nid, attrs in graph.nodes(data=True):
        sf = attrs.get("source_file")
        if not sf or sf in seen_files or not sf.endswith(".py"):
            continue
        seen_files.add(sf)
        try:
            path = Path(sf)
            if not path.is_absolute() and repo_root is not None:
                path = repo_root / path
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _TASK_DEF_RE.finditer(text):
            name = m.group("name")
            kw = _extract_kwargs(m.group("args"))
            node_id = None
            suffix = f"{name}()"
            for cand_id, cand_attrs in graph.nodes(data=True):
                if (
                    cand_attrs.get("source_file") == sf
                    and cand_attrs.get("label") in {suffix, name}
                ):
                    node_id = cand_id
                    break
            if node_id is None:
                node_id = f"py:task:{sf}:{name}"
                synthetic_nodes.append(FragmentNode(
                    node_id=node_id,
                    attrs={
                        "label": suffix,
                        "file_type": "code",
                        "source_file": sf,
                        "synthetic": True,
                    },
                ))
            out[name] = _TaskDef(node_id=node_id, source_file=sf, name=name, expected_kwargs=kw)
    return out, synthetic_nodes


def _find_enqueue_sites(
    graph: nx.DiGraph, tasks: dict[str, _TaskDef], repo_root: Path | None = None
) -> list[tuple[str, str, list[str]]]:
    """Return (caller_node_id, task_name, provided_kwargs)."""
    sites: list[tuple[str, str, list[str]]] = []
    seen_files: set[str] = set()
    for nid, attrs in graph.nodes(data=True):
        sf = attrs.get("source_file")
        if not sf or sf in seen_files or not sf.endswith(".py"):
            continue
        seen_files.add(sf)
        try:
            path = Path(sf)
            if not path.is_absolute() and repo_root is not None:
                path = repo_root / path
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _ENQUEUE.finditer(text):
            name = m.group("name")
            if name not in tasks:
                continue
            start = m.end()
            depth = 1
            i = start
            while i < len(text) and depth > 0:
                if text[i] == "(":
                    depth += 1
                elif text[i] == ")":
                    depth -= 1
                i += 1
            call_args = text[start : i - 1]
            kw_names = [km.group("kw") for km in _KW_RE.finditer(call_args)]
            caller_id = nid
            for cand_id, cand_attrs in graph.nodes(data=True):
                if cand_id == tasks[name].node_id:
                    continue
                if cand_attrs.get("source_file") == sf:
                    caller_id = cand_id
                    break
            sites.append((caller_id, name, kw_names))
    return sites


def emit_celery_payload_edges(graph: nx.DiGraph, *, repo_root: Path | None = None) -> GraphFragment:
    tasks, synthetic_nodes = _find_task_defs(graph, repo_root=repo_root)
    if not tasks:
        return make_fragment("enrich_celery")
    sites = _find_enqueue_sites(graph, tasks, repo_root=repo_root)
    edges: list[FragmentEdge] = []
    seen_caller_task: set[tuple[str, str]] = set()
    for caller_id, task_name, provided_kwargs in sites:
        task = tasks[task_name]
        expected = set(task.expected_kwargs)
        provided = set(provided_kwargs)
        overlap = sorted(expected & provided)
        missing = sorted(expected - provided)
        extra = sorted(provided - expected)

        metadata = SemanticEdgeMetadata(
            confidence=0.8 if missing or extra else 1.0,
            inferred=False,
            source_system="python",
            target_system="celery",
            contract_kind=ContractKind.queue,
            task_name=task_name,
            payload_fields=overlap,
        )
        dumped = metadata.model_dump(mode="json")
        dumped["payload_missing_fields"] = missing
        dumped["payload_extra_fields"] = extra

        # Emit PRODUCES_PAYLOAD for caller→task (matches effective DiGraph overwrite behaviour).
        caller_pair = (caller_id, task.node_id)
        if caller_pair not in seen_caller_task:
            seen_caller_task.add(caller_pair)
            edges.append(FragmentEdge(
                u=caller_id,
                v=task.node_id,
                key=f"producer:{task_name}",
                attrs={"relation": PRODUCES_PAYLOAD, **dumped},
            ))

        # Emit TASK_CONSUMES self-loop merged with CONSUMES_PAYLOAD attrs.
        self_loop = (task.node_id, task.node_id)
        if self_loop not in seen_caller_task:
            seen_caller_task.add(self_loop)
            edges.append(FragmentEdge(
                u=task.node_id,
                v=task.node_id,
                key=f"task_consumes:{task_name}",
                attrs={
                    "relation": TASK_CONSUMES,
                    "task_name": task_name,
                    "payload_fields": sorted(expected),
                    "inferred": False,
                    "source_system": "celery",
                    "target_system": "python",
                    "contract_kind": ContractKind.queue.value,
                },
            ))

    return make_fragment("enrich_celery", nodes=synthetic_nodes, edges=edges)


__all__ = ["emit_celery_payload_edges"]
