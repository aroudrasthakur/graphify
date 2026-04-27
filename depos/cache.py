"""depOS fragment cache primitives.

This is an additive cache layer for depOS graph fragments and semantic
enrichment products. It does not replace ``graphify/cache.py``.
"""
from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import logging
from pathlib import Path
import shutil
from typing import Any

from depos._jsonio import dumps as _json_dumps
from depos._jsonio import loads as _json_loads

logger = logging.getLogger(__name__)


CACHE_SCHEMA_VERSION = "depos-cache-v1"
SEMANTIC_FUNCTION_CACHE_VERSION = "semantic-function-v1"

# Keep this list explicit. These are the configuration inputs that can change
# extractor node/edge shape and therefore must invalidate per-file cache hits.
EXTRACTOR_CONFIG_HASH_FIELDS: tuple[str, ...] = (
    "ignore",
    "language_allowlist",
    "max_file_size",
    "tree_sitter_parser_version",
    "include_private_symbols",
    "include_import_edges",
    "include_call_edges",
    "include_type_edges",
    "schema_version",
)

_XXHASH_FALLBACK_LOGGED = False

try:
    from importlib.metadata import PackageNotFoundError, version
except ImportError:  # pragma: no cover - Python <3.8 compatibility guard
    PackageNotFoundError = Exception  # type: ignore[assignment]
    version = None  # type: ignore[assignment]


try:
    import xxhash as _xxhash
except ImportError:  # pragma: no cover - exercised when perf extra absent
    _xxhash = None


try:
    import diskcache as _diskcache
except ImportError:  # pragma: no cover - exercised when perf extra absent
    _diskcache = None


def _depos_version() -> str:
    if version is None:
        return "0.0.0"
    try:
        return version("graphifyy")
    except PackageNotFoundError:
        return "0.0.0"


DEPOS_VERSION = _depos_version()


@dataclass(frozen=True, slots=True)
class CacheKey:
    """Structured cache key with a byte-stable digest representation."""

    stage: str
    parts: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"stage": self.stage, "parts": dict(self.parts)}

    def digest(self) -> str:
        return stable_hash(self.as_dict())

    def __str__(self) -> str:
        return f"{self.stage}:{self.digest()}"


def hash_bytes(data: bytes) -> str:
    """Fast content hash: xxhash64 when installed, blake2b otherwise."""
    global _XXHASH_FALLBACK_LOGGED
    if _xxhash is not None:
        return _xxhash.xxh64_hexdigest(data)
    if not _XXHASH_FALLBACK_LOGGED:
        logger.info("xxhash is not installed; depOS cache uses hashlib.blake2b fallback.")
        _XXHASH_FALLBACK_LOGGED = True
    return hashlib.blake2b(data, digest_size=16).hexdigest()


def stable_hash(value: Any) -> str:
    """Hash a JSON-serializable value with stable key ordering."""
    return hash_bytes(_json_dumps(value, sort_keys=True))


def file_content_hash(path: Path | str) -> str:
    """Hash file bytes for cache invalidation."""
    return hash_bytes(Path(path).read_bytes())


def extractor_config_hash(values: Mapping[str, Any] | None = None) -> str:
    """Hash only the declared extractor config fields."""
    raw = values or {}
    selected = {field: raw.get(field) for field in EXTRACTOR_CONFIG_HASH_FIELDS}
    return stable_hash(selected)


def build_extraction_cache_key(
    *,
    stage: str,
    source_file: str,
    file_hash: str,
    language: str,
    parser_version: str,
    extractor_config_hash_value: str,
    depos_version: str = DEPOS_VERSION,
    schema_version: str = CACHE_SCHEMA_VERSION,
) -> CacheKey:
    return CacheKey(
        stage=stage,
        parts={
            "source_file": source_file,
            "file_hash": file_hash,
            "language": language,
            "depos_version": depos_version,
            "schema_version": schema_version,
            "parser_version": parser_version,
            "extractor_config_hash": extractor_config_hash_value,
        },
    )


def build_enrichment_fragment_cache_key(
    *,
    stage: str,
    source_file: str,
    file_hash: str,
    language: str,
    enricher_logic_version: str,
    depos_version: str = DEPOS_VERSION,
    schema_version: str = CACHE_SCHEMA_VERSION,
) -> CacheKey:
    return CacheKey(
        stage=stage,
        parts={
            "source_file": source_file,
            "file_hash": file_hash,
            "language": language,
            "depos_version": depos_version,
            "schema_version": schema_version,
            "enricher_logic_version": enricher_logic_version,
        },
    )


def build_semantic_function_cache_key(
    *,
    function_id: str,
    source_file: str,
    function_source_hash: str,
    language: str,
    version_tuple: Sequence[str],
    semantic_version: str = SEMANTIC_FUNCTION_CACHE_VERSION,
) -> CacheKey:
    return CacheKey(
        stage="semantic-function",
        parts={
            "function_id": function_id,
            "source_file": source_file,
            "function_source_hash": function_source_hash,
            "language": language,
            "semantic_version": semantic_version,
            "version_tuple": tuple(version_tuple),
        },
    )


def resolve_cache_root(config: Any) -> Path:
    """Resolve ``<DEPOS_DATA>/cache`` unless config.cache.cache_dir overrides it."""
    cache_cfg = getattr(config, "cache", None)
    cache_dir = getattr(cache_cfg, "cache_dir", None)
    if cache_dir:
        return Path(cache_dir)
    return Path(getattr(config, "data_dir", "depos-data")) / "cache"


def _has_merge_errors(merge_report: Any | None) -> bool:
    if merge_report is None:
        return False
    ok = getattr(merge_report, "ok", None)
    if ok is not None and not bool(ok):
        return True
    hard_collisions = getattr(merge_report, "hard_collisions", None)
    return bool(hard_collisions)


def cache_allowed(
    *,
    merge_report: Any | None = None,
    errors: Iterable[Any] | None = None,
) -> bool:
    """Return false when enrichment or fragment merge diagnostics are not clean."""
    if _has_merge_errors(merge_report):
        return False
    if errors is None:
        return True
    return not any(True for _ in errors)


def _taint_sortable(row: Any) -> dict[str, Any]:
    if hasattr(row, "model_dump"):
        return row.model_dump(mode="json")
    if isinstance(row, Mapping):
        return dict(row)
    return {"value": repr(row)}


def taint_edge_sort_key(row: Any) -> tuple[str, str, str, str, str]:
    payload = _taint_sortable(row)
    return (
        str(payload.get("scope") or ""),
        str(payload.get("source_node") or payload.get("source") or ""),
        str(payload.get("sink_node") or payload.get("sink") or ""),
        str(payload.get("line") or payload.get("taint_line") or ""),
        stable_hash(payload),
    )


def sort_taint_edges(rows: Iterable[Any]) -> list[Any]:
    """Sort typed or dict taint rows deterministically."""
    return sorted(list(rows), key=taint_edge_sort_key)


class OrjsonDisk:
    """Small diskcache adapter that stores values as compact JSON bytes."""

    def __init__(self, root: Path | str, *, namespace: str = "fragments") -> None:
        if _diskcache is None:
            raise RuntimeError(
                "diskcache is required for depOS cache; install graphifyy[perf] "
                "or pass --no-cache."
            )
        self.root = Path(root)
        self.namespace = namespace
        self.root.mkdir(parents=True, exist_ok=True)
        self._cache = _diskcache.Cache(str(self.root / namespace))

    def get(self, key: CacheKey | str, default: Any = None) -> Any:
        raw = self._cache.get(str(key), default=None)
        if raw is None:
            return default
        return _json_loads(raw)

    def set(self, key: CacheKey | str, value: Any) -> None:
        self._cache.set(str(key), _json_dumps(value, sort_keys=True))

    def delete(self, key: CacheKey | str) -> None:
        self._cache.delete(str(key))

    def clear(self) -> None:
        self._cache.clear()

    def close(self) -> None:
        self._cache.close()


class FragmentCache:
    """Fragment-cache facade with explicit no-op mode."""

    def __init__(
        self,
        root: Path | str,
        *,
        enabled: bool = True,
        namespace: str = "fragments",
    ) -> None:
        self.root = Path(root)
        self.enabled = enabled
        self.namespace = namespace
        self._disk: OrjsonDisk | None = None
        if enabled:
            self._disk = OrjsonDisk(self.root, namespace=namespace)

    def get(self, key: CacheKey | str, default: Any = None) -> Any:
        if not self.enabled or self._disk is None:
            return default
        return self._disk.get(key, default)

    def put(
        self,
        key: CacheKey | str,
        value: Any,
        *,
        merge_report: Any | None = None,
        errors: Iterable[Any] | None = None,
    ) -> bool:
        if not self.enabled or self._disk is None:
            return False
        if not cache_allowed(merge_report=merge_report, errors=errors):
            return False
        self._disk.set(key, value)
        return True

    def put_taint_edges(
        self,
        key: CacheKey | str,
        rows: Iterable[Any],
        *,
        merge_report: Any | None = None,
        errors: Iterable[Any] | None = None,
    ) -> bool:
        sorted_rows = [_taint_sortable(row) for row in sort_taint_edges(rows)]
        return self.put(
            key,
            sorted_rows,
            merge_report=merge_report,
            errors=errors,
        )

    def clear(self) -> None:
        if not self.enabled:
            return
        if self._disk is not None:
            self._disk.clear()
            self._disk.close()
            self._disk = None
        if self.root.exists():
            shutil.rmtree(self.root)
        self.root.mkdir(parents=True, exist_ok=True)
        self._disk = OrjsonDisk(self.root, namespace=self.namespace)

    def close(self) -> None:
        if self._disk is not None:
            self._disk.close()


__all__ = [
    "CACHE_SCHEMA_VERSION",
    "DEPOS_VERSION",
    "EXTRACTOR_CONFIG_HASH_FIELDS",
    "SEMANTIC_FUNCTION_CACHE_VERSION",
    "CacheKey",
    "FragmentCache",
    "OrjsonDisk",
    "build_enrichment_fragment_cache_key",
    "build_extraction_cache_key",
    "build_semantic_function_cache_key",
    "cache_allowed",
    "extractor_config_hash",
    "file_content_hash",
    "hash_bytes",
    "resolve_cache_root",
    "sort_taint_edges",
    "stable_hash",
    "taint_edge_sort_key",
]
