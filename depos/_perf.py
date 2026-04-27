"""Optional perf instrumentation — zero-cost when pyinstrument is not installed.

Phase 1 of the pipeline acceleration plan. Import lazily; the rest of the
codebase should not import this at module level.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

try:
    from pyinstrument import Profiler as _Profiler

    _PYINSTRUMENT = True
except ImportError:
    _Profiler = None  # type: ignore[assignment,misc]
    _PYINSTRUMENT = False


@contextmanager
def pyinstrument_session(output_path: Path | str | None = None) -> Iterator[None]:
    """Profile the body and write an HTML report.

    Falls back to a no-op when pyinstrument is not installed.
    If *output_path* is None the report is printed to stdout instead.
    """
    if not _PYINSTRUMENT or _Profiler is None:
        yield
        return
    profiler = _Profiler()
    profiler.start()
    try:
        yield
    finally:
        profiler.stop()
        if output_path is not None:
            path = Path(output_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(profiler.output_html(), encoding="utf-8")
        else:
            profiler.print()


class Stage:
    """Lightweight wall-clock timer for sub-stage breakdowns.

    Compatible with :func:`depos.analysis.observability.timed_stage` — use
    that for structured logging; use this for finer-grained measurements
    within a single pipeline stage. Call ``as_dict()`` to merge into an
    observability payload.

        with Stage("fragment_merge") as s:
            merge_fragments(graph, fragments)
        payload.update(s.as_dict())
    """

    def __init__(self, name: str) -> None:
        self.name = name
        self._start: float | None = None
        self.elapsed_ms: float = 0.0

    def __enter__(self) -> "Stage":
        self._start = time.perf_counter()
        return self

    def __exit__(self, *_: Any) -> None:
        if self._start is not None:
            self.elapsed_ms = round((time.perf_counter() - self._start) * 1000.0, 3)

    def as_dict(self) -> dict[str, Any]:
        return {"stage": self.name, "elapsed_ms": self.elapsed_ms}


__all__ = ["pyinstrument_session", "Stage"]
