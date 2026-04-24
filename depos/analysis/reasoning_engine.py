"""Module 4 — reasoning engine.

Responsibilities:

- Provider abstraction: Gemma (HTTP), OpenAI (HTTP), Ollama (HTTP), plus
  an always-available :class:`StubProvider` used by tests and when no
  external service is configured.
- Three prompt modes (A/B/C) with strict JSON outputs validated against
  :class:`ModeAOutput` / :class:`ModeBOutput` / :class:`ModeCOutput`.
- Typed exception dispatch so every failure mode (transport, empty
  response, not JSON, JSON-but-invalid-schema) is recorded in
  :class:`ReasonerCallStats` and on the corresponding
  :class:`ReasonerQueueRow`.
- JSON repair pass before strict validation that strips ```` ```json ````
  fences/trailing commas and lifts a single-finding dict into the
  expected ``{"findings": [<dict>]}`` envelope. Each repair attempt is
  recorded in ``validation_errors`` so the change is auditable.
- Replay queue entries are JSONL rows under
  ``<DEPOS_DATA>/intelligence/<run_id>/reasoner_queue.jsonl`` matching
  :class:`ReasonerQueueRow`. The full prompt body is cached once per
  unique hash under ``<run_dir>/prompts/<sha>.json`` so
  :func:`replay_one` can re-issue without re-running upstream stages.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional, Tuple

from pydantic import ValidationError

from depos.analysis.bundle_prompter import render_bundle_prompt
from depos.analysis.config import IntelligenceConfig
from depos.analysis.observability import emit_event
from depos.analysis.schemas import (
    Candidate,
    ContextBundle,
    ModeAOutput,
    ModeBOutput,
    ModeCOutput,
    ReasonerCallStats,
    ReasonerMode,
    ReasonerQueueRow,
)


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Ollama startup checks
# ---------------------------------------------------------------------------


def resolve_ollama_base_url(base_url: Optional[str]) -> str:
    import os

    return (base_url or os.environ.get("OLLAMA_HOST") or "http://localhost:11434").rstrip("/")


def _validate_ollama_model(base_url: str, model: str) -> None:
    """Check that the configured Ollama tag is actually available."""

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - dev safety
        raise RuntimeError(f"httpx unavailable: {exc}") from exc

    base_url = resolve_ollama_base_url(base_url)
    try:
        response = httpx.get(f"{base_url}/api/tags", timeout=10.0)
        response.raise_for_status()
        payload = response.json()
    except httpx.ConnectError:
        raise RuntimeError(f"Cannot reach Ollama at {base_url}. Is it running?") from None
    except httpx.ReadTimeout:
        raise RuntimeError(
            f"Ollama at {base_url} did not respond to /api/tags within 10.0s. Is it running?"
        ) from None
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama returned HTTP {exc.response.status_code} while listing models at {base_url}."
        ) from None
    except ValueError:
        raise RuntimeError(f"Ollama at {base_url} returned invalid JSON from /api/tags.") from None

    available = [
        str(entry.get("name"))
        for entry in payload.get("models", [])
        if isinstance(entry, dict) and entry.get("name")
    ]
    if model in available:
        return

    model_prefix = model.split(":", 1)[0]
    close = [name for name in available if model_prefix and model_prefix in name]
    suggestion = f" Did you mean one of: {close}?" if close else ""
    raise RuntimeError(
        f"Ollama model '{model}' is not pulled.{suggestion} "
        f"Available: {available}. "
        f"Run: ollama pull {model}"
    )


def _preflight_ollama(base_url: str, model: str, timeout: float = 30.0) -> None:
    """Fire a tiny Ollama probe before sending full bundle prompts."""

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - dev safety
        raise RuntimeError(f"httpx unavailable: {exc}") from exc

    base_url = resolve_ollama_base_url(base_url)
    probe = {
        "model": model,
        "prompt": '{"ok":true}',
        "stream": False,
        "num_predict": 5,
        "options": {"num_predict": 5},
    }
    try:
        response = httpx.post(f"{base_url}/api/generate", json=probe, timeout=timeout)
        response.raise_for_status()
    except httpx.ReadTimeout:
        raise RuntimeError(
            f"Ollama model '{model}' did not respond within {timeout}s. "
            f"Run: ollama list - confirm the tag exists. "
            f"Run: ollama pull {model} - if it is missing. "
            f"Or set DEPOS_INTEL_PROVIDER=stub to skip LLM reasoning."
        ) from None
    except httpx.ConnectError:
        raise RuntimeError(f"Cannot reach Ollama at {base_url}. Is it running?") from None
    except httpx.HTTPStatusError as exc:
        raise RuntimeError(
            f"Ollama returned HTTP {exc.response.status_code} for model '{model}'. "
            f"Check: ollama list"
        ) from None


# ---------------------------------------------------------------------------
# Provider abstraction
# ---------------------------------------------------------------------------


class ProviderError(Exception):
    """Wrap provider transport/decoding failures with a typed reason."""

    def __init__(
        self,
        reason: str,
        message: str,
        *,
        http_status: Optional[int] = None,
        raw_excerpt: str = "",
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.http_status = http_status
        self.raw_excerpt = raw_excerpt


class ReasoningProvider:
    """Minimal interface. Implementations must return a raw string.

    Implementations should raise :class:`ProviderError` so the caller can
    record a typed ``failure_reason``.
    """

    name: str = "base"

    def complete(self, prompt: str, *, max_tokens: int) -> Tuple[str, dict[str, Any]]:
        """Return ``(text, meta)``.

        ``meta`` must include ``model`` and may include
        ``response_path_used`` to help operators tune
        ``ReasonerProviderConfig`` after the fact.
        """
        raise NotImplementedError


class StubProvider(ReasoningProvider):
    """Returns a minimal, valid JSON doc for each mode. Used in tests and
    when no external service is reachable. Keeps the pipeline runnable
    out of the box without network access."""

    name = "stub"

    def __init__(self, mode: ReasonerMode):
        self.mode = mode

    def complete(self, prompt: str, *, max_tokens: int) -> Tuple[str, dict[str, Any]]:
        if self.mode == ReasonerMode.A:
            text = json.dumps({"mode": "A", "findings": []})
        elif self.mode == ReasonerMode.B:
            text = json.dumps({"mode": "B", "findings": []})
        else:
            text = json.dumps({"mode": "C", "findings": []})
        return text, {"model": "stub", "response_path_used": "literal"}


class ReasonerSession:
    """Tracks per-run reasoner call state such as Ollama warmup timeouts."""

    def __init__(self, config: IntelligenceConfig):
        self.config = config
        self.provider = (config.llm.provider or "stub").lower()
        self.call_index = 0
        self.last_timeout_seconds: float | None = None

    def _get_timeout(self, call_index: int) -> float:
        if self.provider != "ollama":
            return self.config.llm.read_timeout_seconds
        return (
            self.config.llm.ollama_first_call_timeout
            if call_index == 0
            else self.config.llm.ollama_subsequent_timeout
        )

    def get_provider(self, mode: ReasonerMode) -> ReasoningProvider:
        read_timeout = self._get_timeout(self.call_index)
        self.last_timeout_seconds = read_timeout
        self.call_index += 1
        if read_timeout == self.config.llm.read_timeout_seconds:
            return get_provider(self.config, mode)
        provider_config = self.config.model_copy(deep=True)
        provider_config.llm.read_timeout_seconds = read_timeout
        return get_provider(provider_config, mode)


# ---------------------------------------------------------------------------
# Response path extraction
# ---------------------------------------------------------------------------


_PATH_TOKEN = re.compile(r"([^.\[\]]+)|\[(\d+)\]")


def _extract_by_path(data: Any, path: str) -> Any:
    """Walk a dotted/bracketed path. Returns ``None`` on miss.

    Accepts ``"choices[0].message.content"``-style expressions. We do not
    eval, only walk dict keys and list indices.
    """
    if not path:
        return None
    cursor: Any = data
    for raw_key, raw_idx in _PATH_TOKEN.findall(path):
        try:
            if raw_idx:
                cursor = cursor[int(raw_idx)]
            elif isinstance(cursor, dict):
                cursor = cursor.get(raw_key)
            else:
                return None
        except (KeyError, IndexError, TypeError):
            return None
        if cursor is None:
            return None
    return cursor


def _extract_text(data: Any, paths: list[str]) -> Tuple[str, Optional[str]]:
    """Try each path in order; return ``(text, path_used)``.

    Returns ``("", None)`` if every path misses or yields a non-string.
    """
    for path in paths:
        if not path:
            continue
        value = _extract_by_path(data, path)
        if isinstance(value, str) and value.strip():
            return value, path
        if isinstance(value, (dict, list)):
            # Some providers nest the JSON object directly.
            return json.dumps(value), path
    return "", None


class _HTTPProvider(ReasoningProvider):
    """Shared helper that POSTs JSON to a URL and parses a single string field."""

    name = "http"

    def __init__(
        self,
        url: Optional[str],
        *,
        header_key: Optional[str] = None,
        header_value: Optional[str] = None,
        response_paths: list[str],
        model: str,
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
    ):
        self.url = url
        self.headers = {"Content-Type": "application/json"}
        if header_key and header_value:
            self.headers[header_key] = header_value
        self.response_paths = response_paths
        self.model = model
        self.connect_timeout = max(0.1, float(connect_timeout))
        self.read_timeout = max(0.1, float(read_timeout))

    def complete(self, prompt: str, *, max_tokens: int) -> Tuple[str, dict[str, Any]]:
        if not self.url:
            raise ProviderError("transport", f"{self.name}: no URL configured")
        try:
            import httpx  # lazy import so tests without httpx still work
        except ImportError as exc:  # pragma: no cover - dev safety
            raise ProviderError("transport", f"httpx unavailable: {exc}") from exc

        body = self._build_body(prompt, max_tokens=max_tokens)
        timeout = httpx.Timeout(
            connect=self.connect_timeout,
            read=self.read_timeout,
            write=self.connect_timeout,
            pool=self.connect_timeout,
        )
        try:
            with httpx.Client(timeout=timeout) as client:
                resp = client.post(self.url, json=body, headers=self.headers)
        except httpx.ConnectTimeout as exc:
            raise ProviderError(
                "transport",
                f"{self.name} connect timeout after {self.connect_timeout:.1f}s to {self.url}",
            ) from exc
        except httpx.ReadTimeout as exc:
            raise ProviderError(
                "transport",
                f"{self.name} read timeout after {self.read_timeout:.1f}s from {self.url}",
            ) from exc
        except httpx.RequestError as exc:
            raise ProviderError("transport", f"{self.name} request failed: {exc}") from exc

        if resp.status_code >= 400:
            raise ProviderError(
                "transport",
                f"{self.name} HTTP {resp.status_code}",
                http_status=resp.status_code,
                raw_excerpt=_clip(resp.text, 2048),
            )

        try:
            data = resp.json()
        except ValueError as exc:
            raise ProviderError(
                "not_json",
                f"{self.name} returned non-JSON body: {exc}",
                http_status=resp.status_code,
                raw_excerpt=_clip(resp.text, 2048),
            ) from exc

        text, path_used = _extract_text(data, self.response_paths)
        if not text:
            raise ProviderError(
                "empty_response",
                f"{self.name} produced no extractable text",
                http_status=resp.status_code,
                raw_excerpt=_clip(json.dumps(data), 2048),
            )
        return text, {"model": self.model, "response_path_used": path_used or ""}

    def _build_body(self, prompt: str, *, max_tokens: int) -> dict[str, Any]:
        return {"prompt": prompt, "max_tokens": max_tokens}


def _clip(text: str, limit: int) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def _retry_backoff_seconds(attempt_idx: int) -> float:
    return min(0.25 * (2 ** max(0, attempt_idx - 1)), 2.0)


# Common Gemma response shapes — tried in order if the configured path
# misses. Keeps deployments without code changes for known servers.
_GEMMA_FALLBACK_PATHS: list[str] = [
    "response",
    "text",
    "candidates[0].content.parts[0].text",
    "candidates[0].text",
    "output[0].generated_text",
    "outputs[0].text",
]

_OPENAI_FALLBACK_PATHS: list[str] = [
    "choices[0].message.content",
    "choices[0].text",
]

_OLLAMA_FALLBACK_PATHS: list[str] = ["response", "message.content"]


class GemmaProvider(_HTTPProvider):
    name = "gemma"

    def __init__(
        self,
        url: Optional[str],
        *,
        model: str = "gemma-4",
        response_path: str = "response",
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
    ):
        paths = [response_path] + [p for p in _GEMMA_FALLBACK_PATHS if p != response_path]
        super().__init__(
            url,
            response_paths=paths,
            model=model,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

    def _build_body(self, prompt: str, *, max_tokens: int) -> dict[str, Any]:
        return {
            "model": self.model,
            "prompt": prompt,
            "max_tokens": max_tokens,
            "format": "json",
        }


class OpenAIProvider(_HTTPProvider):
    name = "openai"

    def __init__(
        self,
        api_key: Optional[str],
        *,
        model: str = "gpt-4o-mini",
        response_path: str = "choices[0].message.content",
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
    ):
        paths = [response_path] + [p for p in _OPENAI_FALLBACK_PATHS if p != response_path]
        super().__init__(
            "https://api.openai.com/v1/chat/completions",
            header_key="Authorization",
            header_value=f"Bearer {api_key}" if api_key else None,
            response_paths=paths,
            model=model,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

    def _build_body(self, prompt: str, *, max_tokens: int) -> dict[str, Any]:
        return {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": max_tokens,
            "response_format": {"type": "json_object"},
        }


class OllamaProvider(_HTTPProvider):
    name = "ollama"

    def __init__(
        self,
        host: Optional[str],
        *,
        model: str = "gemma:2b",
        response_path: str = "response",
        connect_timeout: float = 5.0,
        read_timeout: float = 60.0,
    ):
        base = resolve_ollama_base_url(host)
        paths = [response_path] + [p for p in _OLLAMA_FALLBACK_PATHS if p != response_path]
        super().__init__(
            f"{base.rstrip('/')}/api/generate",
            response_paths=paths,
            model=model,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )

    def _build_body(self, prompt: str, *, max_tokens: int) -> dict[str, Any]:
        return {
            "model": self.model,
            "prompt": prompt,
            "format": "json",
            "stream": False,
            "options": {"num_predict": max_tokens},
        }


def get_provider(config: IntelligenceConfig, mode: ReasonerMode) -> ReasoningProvider:
    name = (config.llm.provider or "stub").lower()
    connect_timeout = config.llm.connect_timeout_seconds
    read_timeout = config.llm.read_timeout_seconds
    if name == "openai":
        return OpenAIProvider(
            config.llm.openai_api_key,
            model=config.llm.openai_model,
            response_path=config.llm.openai_response_path,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
    if name == "gemma":
        if config.llm.gemma_api_url:
            return GemmaProvider(
                config.llm.gemma_api_url,
                model=config.llm.gemma_model,
                response_path=config.llm.gemma_response_path,
                connect_timeout=connect_timeout,
                read_timeout=read_timeout,
            )
        return StubProvider(mode)
    if name == "ollama":
        return OllamaProvider(
            config.llm.ollama_host,
            model=config.llm.ollama_model,
            response_path=config.llm.ollama_response_path,
            connect_timeout=connect_timeout,
            read_timeout=read_timeout,
        )
    return StubProvider(mode)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------


def _render_prompt(
    mode: ReasonerMode,
    bundle: ContextBundle,
    *,
    config: IntelligenceConfig,
    rank_metadata: Optional[dict[str, Any]] = None,
) -> str:
    return render_bundle_prompt(mode, bundle, rank_metadata=rank_metadata, config=config)


# ---------------------------------------------------------------------------
# Parsing + JSON repair
# ---------------------------------------------------------------------------

_MODE_SCHEMA = {
    ReasonerMode.A: ModeAOutput,
    ReasonerMode.B: ModeBOutput,
    ReasonerMode.C: ModeCOutput,
}

_FENCE_OPEN = re.compile(r"^\s*```(?:json|JSON)?\s*", re.MULTILINE)
_FENCE_CLOSE = re.compile(r"\s*```\s*$", re.MULTILINE)
_TRAILING_COMMA = re.compile(r",(\s*[}\]])")


def _strip_fences_and_trailing_commas(raw: str) -> str:
    no_open = _FENCE_OPEN.sub("", raw)
    no_close = _FENCE_CLOSE.sub("", no_open)
    return _TRAILING_COMMA.sub(r"\1", no_close).strip()


def _coerce_envelope(mode: ReasonerMode, data: Any) -> tuple[dict[str, Any], list[str]]:
    """Try to coerce arbitrary JSON into the expected mode envelope.

    Returns the (possibly rewritten) dict plus a list of repair tags.
    """
    repairs: list[str] = []
    if isinstance(data, list):
        repairs.append("wrap_list_into_findings")
        data = {"mode": mode.value, "findings": data}
    if not isinstance(data, dict):
        return {"mode": mode.value, "findings": []}, repairs + ["non_object_replaced_with_empty"]
    if "findings" not in data:
        # If it looks like a single finding, lift it.
        if any(key in data for key in ("bug_type", "violation_type", "flow_bug_type")):
            repairs.append("lift_single_finding")
            data = {"mode": mode.value, "findings": [data]}
        else:
            repairs.append("inject_empty_findings")
            data = {**data, "findings": data.get("findings", [])}
    if "mode" not in data:
        repairs.append("inject_mode")
        data = {**data, "mode": mode.value}
    return data, repairs


def _coerce_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    if isinstance(value, str):
        return value
    return str(value)


def _coerce_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [_coerce_str(item) for item in value if _coerce_str(item)]
    if isinstance(value, tuple):
        return [_coerce_str(item) for item in value if _coerce_str(item)]
    text = _coerce_str(value)
    return [text] if text else []


def _first_present(mapping: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        if key in mapping and mapping[key] not in (None, ""):
            return mapping[key]
    return None


def _normalize_graph_anchor_nodes(finding: dict[str, Any]) -> list[str]:
    return _coerce_str_list(
        _first_present(
            finding,
            "graph_anchor_nodes",
            "affected_path",
            "violating_path",
            "affected_components",
        )
    )


def _normalize_mode_specific_fields(
    mode: ReasonerMode,
    data: dict[str, Any],
) -> tuple[dict[str, Any], list[str]]:
    findings = data.get("findings")
    if not isinstance(findings, list):
        return data, []

    repairs: list[str] = []
    normalized_findings: list[Any] = []
    for finding in findings:
        if not isinstance(finding, dict):
            normalized_findings.append(finding)
            continue
        normalized = dict(finding)
        anchor_nodes = _normalize_graph_anchor_nodes(normalized)
        if mode == ReasonerMode.A:
            if "bug_type" not in normalized:
                bug_type = _first_present(
                    normalized, "violation_type", "flow_bug_type", "type", "category"
                )
                if bug_type is not None:
                    normalized["bug_type"] = _coerce_str(bug_type)
            if "description" not in normalized:
                description = _first_present(normalized, "disagreement", "summary")
                if description is not None:
                    normalized["description"] = _coerce_str(description)
            if "affected_path" not in normalized and anchor_nodes:
                normalized["affected_path"] = anchor_nodes
            if "graph_anchor_nodes" not in normalized and anchor_nodes:
                normalized["graph_anchor_nodes"] = anchor_nodes
        elif mode == ReasonerMode.B:
            if "violation_type" not in normalized:
                violation_type = _first_present(
                    normalized, "bug_type", "flow_bug_type", "type", "category"
                )
                normalized["violation_type"] = _coerce_str(
                    violation_type, default="semantic_mismatch"
                )
            components = _coerce_str_list(
                _first_present(normalized, "affected_components", "graph_anchor_nodes")
            )
            if "component_a" not in normalized:
                normalized["component_a"] = (
                    components[0] if len(components) >= 1 else _coerce_str(normalized.get("source"), "unknown")
                )
            if "component_b" not in normalized:
                normalized["component_b"] = (
                    components[1] if len(components) >= 2 else _coerce_str(normalized.get("target"), "unknown")
                )
            if "disagreement" not in normalized:
                disagreement = _first_present(
                    normalized,
                    "description",
                    "trigger_condition",
                    "remediation_suggestion",
                )
                normalized["disagreement"] = _coerce_str(
                    disagreement,
                    default="semantic contract mismatch",
                )
            if "description" not in normalized:
                normalized["description"] = normalized["disagreement"]
            if "graph_anchor_nodes" not in normalized and anchor_nodes:
                normalized["graph_anchor_nodes"] = anchor_nodes
        elif mode == ReasonerMode.C:
            if "flow_bug_type" not in normalized:
                flow_bug_type = _first_present(
                    normalized, "bug_type", "violation_type", "type", "category"
                )
                normalized["flow_bug_type"] = _coerce_str(
                    flow_bug_type, default="control_flow_bug"
                )
            if "operation" not in normalized:
                operation = _first_present(
                    normalized,
                    "component_a",
                    "source",
                    "scope",
                )
                normalized["operation"] = _coerce_str(operation, default="unknown")
            if "violating_path" not in normalized and anchor_nodes:
                normalized["violating_path"] = anchor_nodes
            if "missing_guard" not in normalized:
                missing_guard = _first_present(
                    normalized,
                    "trigger_condition",
                    "remediation_suggestion",
                )
                if missing_guard is not None:
                    normalized["missing_guard"] = _coerce_str(missing_guard)
            if "description" not in normalized:
                description = _first_present(normalized, "disagreement", "summary")
                if description is not None:
                    normalized["description"] = _coerce_str(description)
            if "graph_anchor_nodes" not in normalized and anchor_nodes:
                normalized["graph_anchor_nodes"] = anchor_nodes

        if normalized != finding:
            repairs.append("normalize_mode_specific_fields")
        normalized_findings.append(normalized)

    if repairs:
        data = {**data, "findings": normalized_findings}
    return data, repairs


def _parse(mode: ReasonerMode, raw: str) -> tuple[Any, list[str]]:
    """Strict-validate ``raw`` into the mode schema.

    Returns ``(parsed_obj, repair_tags)``. Raises ``json.JSONDecodeError``
    if no JSON can be recovered, or ``pydantic.ValidationError`` if the
    JSON does not match the mode schema.
    """
    schema = _MODE_SCHEMA[mode]
    cleaned = _strip_fences_and_trailing_commas(raw)
    repairs: list[str] = []
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        first = cleaned.find("{")
        last = cleaned.rfind("}")
        if first == -1 or last == -1 or last <= first:
            # Try a list outermost as a last resort.
            list_first = cleaned.find("[")
            list_last = cleaned.rfind("]")
            if list_first == -1 or list_last == -1 or list_last <= list_first:
                raise
            repairs.append("substring_recover_list")
            data = json.loads(cleaned[list_first : list_last + 1])
        else:
            repairs.append("substring_recover_object")
            data = json.loads(cleaned[first : last + 1])

    coerced, coercion_repairs = _coerce_envelope(mode, data)
    repairs.extend(coercion_repairs)
    coerced, mode_repairs = _normalize_mode_specific_fields(mode, coerced)
    repairs.extend(mode_repairs)
    return schema.model_validate(coerced), repairs


# ---------------------------------------------------------------------------
# Queue + prompt cache
# ---------------------------------------------------------------------------


def _queue_path(config: IntelligenceConfig, run_id: str) -> Path:
    out = config.data_dir / config.run_output_subdir / run_id
    out.mkdir(parents=True, exist_ok=True)
    return out / "reasoner_queue.jsonl"


def _attempts_path(config: IntelligenceConfig, run_id: str) -> Path:
    out = config.data_dir / config.run_output_subdir / run_id
    out.mkdir(parents=True, exist_ok=True)
    return out / "reasoner_attempts.jsonl"


def _prompts_dir(config: IntelligenceConfig, run_id: str) -> Path:
    out = config.data_dir / config.run_output_subdir / run_id / "prompts"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _cache_prompt(config: IntelligenceConfig, run_id: str, prompt: str, mode: ReasonerMode) -> str:
    sha = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    target = _prompts_dir(config, run_id) / f"{sha}.json"
    if not target.exists():
        target.write_text(
            json.dumps({"mode": mode.value, "prompt": prompt}, indent=2),
            encoding="utf-8",
        )
    return sha


def _enqueue(
    config: IntelligenceConfig,
    run_id: str,
    bundle: ContextBundle,
    mode: ReasonerMode,
    ranking_phase: int,
    *,
    failure_reason: str,
    http_status: Optional[int],
    attempt_count: int,
    validation_errors: list[dict[str, Any]],
    raw_response_excerpt: str,
    provider_name: str,
    model: str,
    prompt_hash: str,
    prompt_token_estimate: int,
    response_path_used: Optional[str],
    score_composite: float = 0.0,
    extra: Optional[dict[str, Any]] = None,
) -> None:
    row = ReasonerQueueRow(
        bundle_id=bundle.bundle_id,
        candidate_id=bundle.candidate_id,
        mode=mode,
        evidence_pack={"data_reads": bundle.data_reads, "data_writes": bundle.data_writes},
        pack_manifest=bundle.pack_manifest,
        score_composite=score_composite,
        ranking_phase=ranking_phase,
        queued_at=datetime.now(tz=timezone.utc),
        failure_reason=failure_reason,  # type: ignore[arg-type]
        http_status=http_status,
        attempt_count=attempt_count,
        validation_errors=validation_errors,
        raw_response_excerpt=raw_response_excerpt,
        provider_name=provider_name,
        model=model,
        request_payload_sha256=prompt_hash,
        prompt_token_estimate=prompt_token_estimate,
        response_path_used=response_path_used,
        extra=extra or {},
    )
    with _queue_path(config, run_id).open("a", encoding="utf-8") as fp:
        fp.write(row.model_dump_json() + "\n")


_ATTEMPT_KEYS = (
    "event_type",
    "run_id",
    "candidate_id",
    "detector_name",
    "mode",
    "provider",
    "model",
    "attempt_idx",
    "max_retries",
    "timeout_seconds",
    "prompt_chars",
    "prompt_bytes",
    "max_prompt_tokens",
    "requested_output_tokens",
    "elapsed_ms",
    "success",
    "failure_type",
    "failure_message",
    "recovered_by_retry",
)


def _attempt_record(
    *,
    run_id: str | None,
    bundle: ContextBundle,
    detector_name: str | None,
    mode: ReasonerMode,
    provider_name: str | None,
    model: str | None,
    attempt_idx: int | None,
    max_retries: int | None,
    timeout_seconds: float | None,
    prompt: str | None,
    max_prompt_tokens: int | None,
    requested_output_tokens: int | None,
    elapsed_ms: float | None,
    success: bool,
    failure_type: str | None,
    failure_message: str | None,
    recovered_by_retry: bool = False,
) -> dict[str, Any]:
    record = {
        "event_type": "reasoner_attempt",
        "run_id": run_id,
        "candidate_id": bundle.candidate_id if bundle is not None else None,
        "detector_name": detector_name,
        "mode": mode.value if mode is not None else None,
        "provider": provider_name,
        "model": model,
        "attempt_idx": attempt_idx,
        "max_retries": max_retries,
        "timeout_seconds": timeout_seconds,
        "prompt_chars": len(prompt) if prompt is not None else None,
        "prompt_bytes": len(prompt.encode("utf-8")) if prompt is not None else None,
        "max_prompt_tokens": max_prompt_tokens,
        "requested_output_tokens": requested_output_tokens,
        "elapsed_ms": elapsed_ms,
        "success": success,
        "failure_type": failure_type,
        "failure_message": _clip(failure_message or "", 500) if failure_message else None,
        "recovered_by_retry": recovered_by_retry,
    }
    return {key: record.get(key) for key in _ATTEMPT_KEYS}


def _flush_attempt_records(
    config: IntelligenceConfig,
    run_id: str,
    records: list[dict[str, Any]],
) -> None:
    if not records:
        return
    path = _attempts_path(config, run_id)
    with path.open("a", encoding="utf-8") as fp:
        for record in records:
            fp.write(json.dumps(record, default=str) + "\n")
            observability_payload = dict(record)
            observability_payload.pop("run_id", None)
            emit_event(config, run_id, "reasoner_attempt", **observability_payload)


def _empty_attempt_summary() -> dict[str, Any]:
    return {
        "provider": None,
        "model": None,
        "total_attempts": 0,
        "successful_attempts": 0,
        "failed_attempts": 0,
        "recovered_failures": 0,
        "total_elapsed_ms": 0,
        "avg_attempt_ms": None,
        "p50_attempt_ms": None,
        "p75_attempt_ms": None,
        "p90_attempt_ms": None,
        "p95_attempt_ms": None,
        "timeouts": 0,
        "by_detector": {},
    }


def _percentile(values: list[float], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return round(ordered[0], 3)
    rank = (len(ordered) - 1) * percentile
    lower = int(rank)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = rank - lower
    value = ordered[lower] + (ordered[upper] - ordered[lower]) * fraction
    return round(value, 3)


def _unique_or_mixed(values: list[Any]) -> str | None:
    normalized = {str(value) for value in values if value not in (None, "")}
    if not normalized:
        return None
    if len(normalized) == 1:
        return next(iter(normalized))
    return "mixed"


def _is_timeout_record(record: dict[str, Any]) -> bool:
    text = f"{record.get('failure_type') or ''} {record.get('failure_message') or ''}".lower()
    return "timeout" in text or "timed out" in text


def summarize_reasoner_attempts(attempts_path: Path) -> dict[str, Any]:
    summary = _empty_attempt_summary()
    if not attempts_path.exists():
        return summary

    records: list[dict[str, Any]] = []
    for line in attempts_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            records.append(row)
    if not records:
        return summary

    elapsed_values = [
        float(row["elapsed_ms"])
        for row in records
        if isinstance(row.get("elapsed_ms"), (int, float))
    ]
    total_elapsed = round(sum(elapsed_values), 3)
    total_attempts = len(records)
    summary.update(
        {
            "provider": _unique_or_mixed([row.get("provider") for row in records]),
            "model": _unique_or_mixed([row.get("model") for row in records]),
            "total_attempts": total_attempts,
            "successful_attempts": sum(1 for row in records if row.get("success") is True),
            "failed_attempts": sum(1 for row in records if row.get("success") is not True),
            "recovered_failures": sum(1 for row in records if row.get("recovered_by_retry") is True),
            "total_elapsed_ms": total_elapsed,
            "avg_attempt_ms": round(total_elapsed / len(elapsed_values), 3) if elapsed_values else None,
            "p50_attempt_ms": _percentile(elapsed_values, 0.50),
            "p75_attempt_ms": _percentile(elapsed_values, 0.75),
            "p90_attempt_ms": _percentile(elapsed_values, 0.90),
            "p95_attempt_ms": _percentile(elapsed_values, 0.95),
            "timeouts": sum(1 for row in records if row.get("success") is not True and _is_timeout_record(row)),
        }
    )

    detectors: dict[str, dict[str, Any]] = {}
    detector_candidates: dict[str, set[str]] = {}
    detector_elapsed: dict[str, list[float]] = {}
    for row in records:
        detector = str(row.get("detector_name") or "unknown")
        bucket = detectors.setdefault(
            detector,
            {
                "candidates": 0,
                "attempts": 0,
                "successes": 0,
                "failures": 0,
                "recovered_failures": 0,
                "total_elapsed_ms": 0,
                "avg_attempt_ms": None,
                "p90_attempt_ms": None,
            },
        )
        detector_candidates.setdefault(detector, set())
        detector_elapsed.setdefault(detector, [])
        candidate_id = row.get("candidate_id")
        if candidate_id:
            detector_candidates[detector].add(str(candidate_id))
        bucket["attempts"] += 1
        if row.get("success") is True:
            bucket["successes"] += 1
        else:
            bucket["failures"] += 1
        if row.get("recovered_by_retry") is True:
            bucket["recovered_failures"] += 1
        if isinstance(row.get("elapsed_ms"), (int, float)):
            elapsed = float(row["elapsed_ms"])
            bucket["total_elapsed_ms"] = round(float(bucket["total_elapsed_ms"]) + elapsed, 3)
            detector_elapsed[detector].append(elapsed)

    for detector, bucket in detectors.items():
        values = detector_elapsed.get(detector, [])
        bucket["candidates"] = len(detector_candidates.get(detector, set()))
        bucket["avg_attempt_ms"] = (
            round(float(bucket["total_elapsed_ms"]) / len(values), 3) if values else None
        )
        bucket["p90_attempt_ms"] = _percentile(values, 0.90)
    summary["by_detector"] = detectors
    return summary


# ---------------------------------------------------------------------------
# Reasoner runners
# ---------------------------------------------------------------------------


def run_reasoner(
    bundle: ContextBundle,
    *,
    mode: ReasonerMode,
    config: IntelligenceConfig,
    run_id: str,
    ranking_phase: int = 0,
    rank_metadata: Optional[dict[str, Any]] = None,
    stats: Optional[ReasonerCallStats] = None,
    session: Optional[ReasonerSession] = None,
    detector_name: str | None = None,
) -> Optional[ModeAOutput | ModeBOutput | ModeCOutput]:
    session = session or ReasonerSession(config)
    provider = session.get_provider(mode)
    prompt = _render_prompt(mode, bundle, config=config, rank_metadata=rank_metadata)
    prompt_hash = _cache_prompt(config, run_id, prompt, mode)
    prompt_token_estimate = max(1, len(prompt) // 4)
    attempts = max(1, config.llm.max_retries + 1)

    last_failure_reason = "other"
    last_http_status: Optional[int] = None
    last_validation_errors: list[dict[str, Any]] = []
    last_raw_excerpt = ""
    last_response_path: Optional[str] = None
    last_attempt = 0
    last_repairs: list[str] = []
    provider_model = ""
    provider_name = getattr(provider, "name", provider.__class__.__name__)
    current_raw_excerpt = ""
    attempt_records: list[dict[str, Any]] = []

    for attempt_idx in range(1, attempts + 1):
        last_attempt = attempt_idx
        attempt_started = time.perf_counter()
        attempt_elapsed_ms: float | None = None
        attempt_model = provider_model or str(getattr(provider, "model", "") or "") or None
        try:
            raw, meta = provider.complete(prompt, max_tokens=config.llm.default_max_tokens)
            attempt_elapsed_ms = round((time.perf_counter() - attempt_started) * 1000.0, 3)
            current_raw_excerpt = _clip(raw, 2048)
            provider_model = str(meta.get("model", ""))
            attempt_model = provider_model or attempt_model
            last_response_path = meta.get("response_path_used") or last_response_path
            parsed, repairs = _parse(mode, raw)
            last_repairs = repairs
            if stats is not None:
                stats.record_success(mode.value)
            for record in attempt_records:
                if not record["success"]:
                    record["recovered_by_retry"] = True
            attempt_records.append(
                _attempt_record(
                    run_id=run_id,
                    bundle=bundle,
                    detector_name=detector_name,
                    mode=mode,
                    provider_name=provider_name,
                    model=attempt_model,
                    attempt_idx=attempt_idx,
                    max_retries=config.llm.max_retries,
                    timeout_seconds=session.last_timeout_seconds,
                    prompt=prompt,
                    max_prompt_tokens=config.bundles.max_prompt_tokens,
                    requested_output_tokens=config.llm.default_max_tokens,
                    elapsed_ms=attempt_elapsed_ms,
                    success=True,
                    failure_type=None,
                    failure_message=None,
                )
            )
            _flush_attempt_records(config, run_id, attempt_records)
            if repairs:
                logger.info(
                    "reasoner_call_repaired",
                    extra={
                        "mode": mode.value,
                        "provider": provider_name,
                        "repairs": repairs,
                        "candidate_id": bundle.candidate_id,
                    },
                )
            return parsed
        except ProviderError as exc:
            attempt_elapsed_ms = round((time.perf_counter() - attempt_started) * 1000.0, 3)
            last_failure_reason = exc.reason
            last_http_status = exc.http_status
            last_raw_excerpt = exc.raw_excerpt or str(exc)
            if stats is not None:
                stats.record_failure(mode.value, last_failure_reason)
            logger.warning(
                "reasoner_call_failed mode=%s provider=%s reason=%s http_status=%s attempt=%d/%d candidate=%s detail=%s",
                mode.value,
                provider_name,
                exc.reason,
                exc.http_status,
                attempt_idx,
                attempts,
                bundle.candidate_id,
                _clip(str(exc), 240),
                extra={
                    "mode": mode.value,
                    "provider": provider_name,
                    "reason": exc.reason,
                    "http_status": exc.http_status,
                    "attempt": attempt_idx,
                    "candidate_id": bundle.candidate_id,
                },
            )
            attempt_records.append(
                _attempt_record(
                    run_id=run_id,
                    bundle=bundle,
                    detector_name=detector_name,
                    mode=mode,
                    provider_name=provider_name,
                    model=attempt_model,
                    attempt_idx=attempt_idx,
                    max_retries=config.llm.max_retries,
                    timeout_seconds=session.last_timeout_seconds,
                    prompt=prompt,
                    max_prompt_tokens=config.bundles.max_prompt_tokens,
                    requested_output_tokens=config.llm.default_max_tokens,
                    elapsed_ms=attempt_elapsed_ms,
                    success=False,
                    failure_type=exc.reason,
                    failure_message=str(exc),
                )
            )
        except json.JSONDecodeError as exc:
            if attempt_elapsed_ms is None:
                attempt_elapsed_ms = round((time.perf_counter() - attempt_started) * 1000.0, 3)
            last_failure_reason = "not_json"
            last_raw_excerpt = _clip(getattr(exc, "doc", "") or str(exc), 2048)
            if stats is not None:
                stats.record_failure(mode.value, last_failure_reason)
            logger.warning(
                "reasoner_call_failed mode=%s provider=%s reason=not_json attempt=%d/%d candidate=%s detail=%s",
                mode.value,
                provider_name,
                attempt_idx,
                attempts,
                bundle.candidate_id,
                _clip(str(exc), 240),
                extra={
                    "mode": mode.value,
                    "provider": provider_name,
                    "reason": "not_json",
                    "attempt": attempt_idx,
                    "candidate_id": bundle.candidate_id,
                },
            )
            attempt_records.append(
                _attempt_record(
                    run_id=run_id,
                    bundle=bundle,
                    detector_name=detector_name,
                    mode=mode,
                    provider_name=provider_name,
                    model=attempt_model,
                    attempt_idx=attempt_idx,
                    max_retries=config.llm.max_retries,
                    timeout_seconds=session.last_timeout_seconds,
                    prompt=prompt,
                    max_prompt_tokens=config.bundles.max_prompt_tokens,
                    requested_output_tokens=config.llm.default_max_tokens,
                    elapsed_ms=attempt_elapsed_ms,
                    success=False,
                    failure_type="not_json",
                    failure_message=str(exc),
                )
            )
        except ValidationError as exc:
            if attempt_elapsed_ms is None:
                attempt_elapsed_ms = round((time.perf_counter() - attempt_started) * 1000.0, 3)
            last_failure_reason = "json_but_invalid_schema"
            last_raw_excerpt = current_raw_excerpt or last_raw_excerpt
            last_validation_errors = [
                {k: _stringify(v) for k, v in err.items()} for err in exc.errors()
            ]
            if stats is not None:
                stats.record_failure(mode.value, last_failure_reason)
            logger.warning(
                "reasoner_call_failed mode=%s provider=%s reason=json_but_invalid_schema errors=%d attempt=%d/%d candidate=%s",
                mode.value,
                provider_name,
                len(last_validation_errors),
                attempt_idx,
                attempts,
                bundle.candidate_id,
                extra={
                    "mode": mode.value,
                    "provider": provider_name,
                    "reason": "json_but_invalid_schema",
                    "errors": len(last_validation_errors),
                    "attempt": attempt_idx,
                    "candidate_id": bundle.candidate_id,
                },
            )
            attempt_records.append(
                _attempt_record(
                    run_id=run_id,
                    bundle=bundle,
                    detector_name=detector_name,
                    mode=mode,
                    provider_name=provider_name,
                    model=attempt_model,
                    attempt_idx=attempt_idx,
                    max_retries=config.llm.max_retries,
                    timeout_seconds=session.last_timeout_seconds,
                    prompt=prompt,
                    max_prompt_tokens=config.bundles.max_prompt_tokens,
                    requested_output_tokens=config.llm.default_max_tokens,
                    elapsed_ms=attempt_elapsed_ms,
                    success=False,
                    failure_type="json_but_invalid_schema",
                    failure_message=str(exc),
                )
            )
        except Exception as exc:  # noqa: BLE001
            attempt_elapsed_ms = round((time.perf_counter() - attempt_started) * 1000.0, 3)
            last_failure_reason = "other"
            last_raw_excerpt = _clip(str(exc), 2048)
            if stats is not None:
                stats.record_failure(mode.value, last_failure_reason)
            logger.warning(
                "reasoner_call_failed mode=%s provider=%s reason=other attempt=%d/%d candidate=%s detail=%s",
                mode.value,
                provider_name,
                attempt_idx,
                attempts,
                bundle.candidate_id,
                _clip(str(exc), 240),
                extra={
                    "mode": mode.value,
                    "provider": provider_name,
                    "reason": "other",
                    "attempt": attempt_idx,
                    "candidate_id": bundle.candidate_id,
                },
            )
            attempt_records.append(
                _attempt_record(
                    run_id=run_id,
                    bundle=bundle,
                    detector_name=detector_name,
                    mode=mode,
                    provider_name=provider_name,
                    model=attempt_model,
                    attempt_idx=attempt_idx,
                    max_retries=config.llm.max_retries,
                    timeout_seconds=session.last_timeout_seconds,
                    prompt=prompt,
                    max_prompt_tokens=config.bundles.max_prompt_tokens,
                    requested_output_tokens=config.llm.default_max_tokens,
                    elapsed_ms=attempt_elapsed_ms,
                    success=False,
                    failure_type="other",
                    failure_message=str(exc),
                )
            )
        if attempt_idx < attempts:
            time.sleep(_retry_backoff_seconds(attempt_idx))

    logger.error(
        "reasoner_call_exhausted mode=%s provider=%s reason=%s http_status=%s attempts=%d candidate=%s",
        mode.value,
        provider_name,
        last_failure_reason,
        last_http_status,
        last_attempt,
        bundle.candidate_id,
    )
    extra_meta: dict[str, Any] = {}
    if last_repairs:
        extra_meta["repairs"] = last_repairs
    _flush_attempt_records(config, run_id, attempt_records)
    _enqueue(
        config,
        run_id,
        bundle,
        mode,
        ranking_phase,
        failure_reason=last_failure_reason,
        http_status=last_http_status,
        attempt_count=last_attempt,
        validation_errors=last_validation_errors,
        raw_response_excerpt=last_raw_excerpt,
        provider_name=provider_name,
        model=provider_model,
        prompt_hash=prompt_hash,
        prompt_token_estimate=prompt_token_estimate,
        response_path_used=last_response_path,
        score_composite=float(bundle.score_composite),
        extra=extra_meta,
    )
    return None


def _stringify(value: Any) -> Any:
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_stringify(v) for v in value]
    if isinstance(value, dict):
        return {str(k): _stringify(v) for k, v in value.items()}
    return str(value)


def run_all_modes(
    bundle: ContextBundle,
    *,
    config: IntelligenceConfig,
    run_id: str,
    ranking_phase: int = 0,
    rank_metadata: Optional[dict[str, Any]] = None,
    stats: Optional[ReasonerCallStats] = None,
    session: Optional[ReasonerSession] = None,
    modes: Optional[Iterable[ReasonerMode]] = None,
    detector_name: str | None = None,
) -> dict[ReasonerMode, Any]:
    out: dict[ReasonerMode, Any] = {}
    session = session or ReasonerSession(config)
    selected_modes = tuple(dict.fromkeys(modes)) if modes is not None else (
        ReasonerMode.A,
        ReasonerMode.B,
        ReasonerMode.C,
    )
    for mode in selected_modes:
        result = run_reasoner(
            bundle,
            mode=mode,
            config=config,
            run_id=run_id,
            ranking_phase=ranking_phase,
            rank_metadata=rank_metadata,
            stats=stats,
            session=session,
            detector_name=detector_name,
        )
        if result is not None:
            out[mode] = result
    return out


# ---------------------------------------------------------------------------
# Replay
# ---------------------------------------------------------------------------


def replay_one(
    row: dict[str, Any],
    *,
    config: IntelligenceConfig,
    run_id: str | None = None,
) -> Iterable[Any]:
    """Re-issue a single queued reasoner call.

    Reads the prompt body from ``<DEPOS_DATA>/intelligence/<run_id>/prompts/<sha>.json``
    if available; otherwise yields nothing. On success returns the parsed
    mode output. On failure, appends a fresh queue row with
    ``attempt_count`` incremented.

    ``run_id`` may be provided explicitly when the caller knows it (e.g., from
    the queue-file path). Otherwise it falls back to the row's own ``run_id``.
    """
    sha = str(row.get("request_payload_sha256") or "")
    mode_raw = str(row.get("mode") or "")
    try:
        mode = ReasonerMode(mode_raw)
    except ValueError:
        return []

    resolved_run_id = run_id or _infer_run_id(row)
    if not resolved_run_id or not sha:
        return []
    run_id = resolved_run_id

    prompt_path = config.data_dir / config.run_output_subdir / run_id / "prompts" / f"{sha}.json"
    if not prompt_path.exists():
        return []
    try:
        cached = json.loads(prompt_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    prompt = str(cached.get("prompt") or "")
    if not prompt:
        return []

    provider = ReasonerSession(config).get_provider(mode)
    prior_attempts = int(row.get("attempt_count") or 0)
    try:
        raw, meta = provider.complete(prompt, max_tokens=config.llm.default_max_tokens)
        parsed, _ = _parse(mode, raw)
        return [parsed]
    except (ProviderError, json.JSONDecodeError, ValidationError) as exc:
        failure_reason = (
            exc.reason if isinstance(exc, ProviderError)
            else "not_json" if isinstance(exc, json.JSONDecodeError)
            else "json_but_invalid_schema"
        )
        # Append a fresh queue row reflecting the replay attempt.
        queue_path = (
            config.data_dir / config.run_output_subdir / run_id / "reasoner_queue.jsonl"
        )
        queue_path.parent.mkdir(parents=True, exist_ok=True)
        new_row = {
            **row,
            "failure_reason": failure_reason,
            "attempt_count": prior_attempts + 1,
            "queued_at": datetime.now(tz=timezone.utc).isoformat(),
            "raw_response_excerpt": _clip(
                getattr(exc, "raw_excerpt", "") or str(exc), 2048
            ),
        }
        with queue_path.open("a", encoding="utf-8") as fp:
            fp.write(json.dumps(new_row) + "\n")
        return []


def _infer_run_id(row: dict[str, Any]) -> str:
    # Best-effort: the row itself may not include run_id; the canonical
    # location is the parent directory of the queue file. If the caller
    # passes a row with explicit ``run_id``, honor it.
    if row.get("run_id"):
        return str(row["run_id"])
    queued_at = row.get("queued_at")
    if not queued_at:
        return ""
    return ""


__all__ = [
    "ReasoningProvider",
    "StubProvider",
    "ReasonerSession",
    "GemmaProvider",
    "OpenAIProvider",
    "OllamaProvider",
    "ProviderError",
    "resolve_ollama_base_url",
    "get_provider",
    "run_reasoner",
    "run_all_modes",
    "summarize_reasoner_attempts",
    "replay_one",
]
