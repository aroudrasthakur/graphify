"""Runtime configuration for the intelligence layer.

Lives separately from Supabase/Auth env vars — those are read only by
``depos.db``, ``depos.auth``, ``depos.supabase_client``, and the Next.js
``lib/supabase/*`` modules. Do NOT read ``SUPABASE_*`` / ``DATABASE_URL``
from here.
"""
from __future__ import annotations

import os
import logging
from pathlib import Path
from typing import Literal, Optional

import warnings

from pydantic import AliasChoices, BaseModel, Field

logger = logging.getLogger(__name__)


class IntentContextConfig(BaseModel):
    """Intent Context Layer: doc discovery, chunking, rules + optional OpenAI."""

    llm_mode: str = "auto"  # auto | rules | llm
    max_tokens_per_call: int = 4096
    max_input_bytes_per_repo: int = 5_000_000
    max_chunks_per_run: int = 500
    max_bytes_per_file: int = 512_000
    chunk_max_chars: int = 8000
    chunk_overlap_chars: int = 400
    intent_openai_model: Optional[str] = Field(
        default=None,
        description="If set, overrides OPENAI_MODEL for intent extraction and summaries only.",
    )
    fenced_code_policy: str = "strip"  # strip | annotate
    enable_tag_scan: bool = True
    tag_scan_globs: list[str] = Field(
        default_factory=lambda: [
            "**/*.py",
            "**/*.go",
            "**/*.rs",
            "**/*.java",
            "**/*.ts",
            "**/*.tsx",
            "**/*.js",
            "**/*.jsx",
            "**/*.c",
            "**/*.h",
            "**/*.cpp",
            "**/*.cs",
            "**/*.sql",
            "**/*.sh",
        ],
    )
    #: When enabled, populate ``IntentManifestFile.doc_signals`` from ``git log -1``.
    enable_doc_git_signals: bool = True
    #: When set (``P0``/``P1``/``P2``), overrides YAML ``default_tier`` without editing the file.
    default_intent_tier: Optional[str] = Field(default=None)



class VerifierPolicy(BaseModel):
    min_edge_confidence_for_confirmed: float = 0.8
    min_edge_confidence_for_partially_confirmed: float = 0.6
    phantom_anchor_short_circuit: bool = True
    full_repo_scan_confidence_delta: float = 0.1
    #: When True, ``finding_id`` is a stable hash of scope, anchors, seams, detector, mode; legacy id in ``finding_id_legacy``.
    stable_finding_ids: bool = False


class CandidateBudget(BaseModel):
    max_seeds: int = 80
    max_seeds_per_diff: int = 80
    max_paths_per_seed: int = 10
    max_hop_count: int = 6
    high_churn_file_threshold: int = 50
    high_churn_file_sample: int = 20
    #: Cap for :mod:`lexical_keyword_seed` candidates (separate from ``max_seeds`` global ranking).
    max_lexical_seeds: int = 24


class BundleBudget(BaseModel):
    token_budget_default: int = 8000
    token_estimator: str = "chars4"  # pinned default; tiktoken if installed & enabled
    allow_tiktoken: bool = True
    extra_source_roots: list[str] = Field(default_factory=list)
    path_aliases: dict[str, str] = Field(default_factory=dict)
    min_snippet_chars: int = 80
    max_caller_texts: int = 3
    max_callee_texts: int = 3
    max_seam_neighbor_texts: int = 3
    max_snippet_chars: int = 400
    max_prompt_tokens: int = 2048
    min_evidence_quality_for_reasoner: str = "embedded"  # full | embedded | label_only
    min_evidence_score_for_reasoner: float = 0.00


class ReasonerProviderConfig(BaseModel):
    provider: str = "gemma"  # gemma | openai | ollama | anthropic | stub
    max_retries: int = 2
    gemma_api_url: Optional[str] = None
    gemma_model: str = "gemma-4"
    openai_api_key: Optional[str] = None
    openai_model: str = "gpt-4o-mini"
    ollama_host: Optional[str] = None
    ollama_model: str = "gemma:2b"
    anthropic_api_key: Optional[str] = None
    anthropic_model: str = "claude-sonnet-4-6"
    default_max_tokens: int = 1000
    # JSON path expressions used to extract the model's text reply from the
    # provider response. Override per-deployment (e.g. Vertex AI Gemma vs
    # an Ollama-style server). The Gemma provider tries the configured path
    # first, then falls back through a known list of common shapes.
    gemma_response_path: str = "response"
    openai_response_path: str = "choices[0].message.content"
    ollama_response_path: str = "response"
    # HTTP timeouts (seconds). Keep connect small so unreachable providers
    # fail fast; read needs to cover first-token latency for local models
    # like Ollama loading weights on the first call.
    connect_timeout_seconds: float = 5.0
    read_timeout_seconds: float = 60.0
    # Preflight uses /api/generate with a tiny prompt; first call still loads
    # the full model locally, so defaults must exceed typical cold-start latency.
    ollama_preflight_timeout: float = 120.0
    ollama_first_call_timeout: float = 300.0
    ollama_subsequent_timeout: float = 120.0
    # Concurrency: how many modes (A/B/C) may run in parallel per candidate.
    max_concurrent_reasoner_modes: int = 3
    # Optional system prompt override; when set, replaces the built-in prompt
    # head so operators can tune instructions per-provider without a code change.
    reasoner_system_prompt: Optional[str] = None
    # Per-mode provider/model overrides — take precedence over `provider`.
    # Useful for routing lightweight Mode A to a cheaper model and Mode C to
    # a stronger one. Leave None to use the global `provider` for that mode.
    mode_a_provider: Optional[str] = None
    mode_b_provider: Optional[str] = None
    mode_c_provider: Optional[str] = None
    mode_a_model: Optional[str] = None
    mode_b_model: Optional[str] = None
    mode_c_model: Optional[str] = None


class ReasonerPolicyConfig(BaseModel):
    disabled_detectors: set[str] = Field(default_factory=set)
    min_evidence_by_detector: dict[str, float] = Field(default_factory=dict)
    max_candidates_by_detector: dict[str, int] = Field(default_factory=dict)


class GrayZoneConfig(BaseModel):
    enabled: bool = True
    # When None, Module 7 uses the same backend as ``IntelligenceConfig.llm.provider``
    # (so Ollama/OpenAI runs do not silently fall back to Gemma-without-URL → stub).
    model_a_provider: Optional[str] = None
    model_b_provider: Optional[str] = None
    model_c_provider: Optional[str] = None
    unconfirmed_confidence_threshold: float = 0.75


class RankerConfig(BaseModel):
    ranking_phase_override: Optional[int] = None  # force a phase for tests
    phase_0_weights: dict[str, float] = Field(
        default_factory=lambda: {
            "cross_language_seam_count": 0.25,
            "changed_node_density": 0.22,
            "unresolved_symbol_count": 0.18,
            "removed_entity_references": 0.12,
            "missing_guard_signals": 0.1,
            "candidate_score_composite": 0.13,
            "graphcodebert_score": 0.05,
        }
    )


class ScoringConfig(BaseModel):
    """Weights per analysis mode for :class:`CandidateScore` composite."""

    weights: dict[str, dict[str, float]] = Field(default_factory=dict)


class DetectorHeuristicsConfig(BaseModel):
    """Detector-specific allowlists and heuristics."""

    env_var_safe_names: list[str] = Field(default_factory=list)
    #: Minimum rolling precision (0..1) before ``detector_precision_rollup`` triggers a confidence dampen in ``_wrap_candidate``.
    confidence_floor_by_detector: dict[str, float] = Field(default_factory=dict)


class CacheConfig(BaseModel):
    enabled: bool = True
    cache_dir: Optional[Path] = None
    clear: bool = False


class PerfConfig(BaseModel):
    """Pipeline performance tuning (``DEPOS_PERF_*`` environment variables)."""

    taint_n_jobs: int = 1
    cfg_dfg_n_jobs: int = 1
    bundle_n_jobs: int = 1
    graph_metrics_expensive: bool = True
    metrics_backend: Literal["networkx", "rustworkx"] = "networkx"
    #: When the graph has at least this many nodes, expensive metrics are skipped unless already off.
    graph_metrics_expensive_max_nodes: int = 35_000


def load_perf_config_from_env() -> PerfConfig:
    """Load :class:`PerfConfig` from ``DEPOS_PERF_*`` when set."""
    p = PerfConfig()
    raw_taint = os.environ.get("DEPOS_PERF_TAINT_N_JOBS")
    if raw_taint:
        try:
            p.taint_n_jobs = max(1, int(raw_taint.strip()))
        except ValueError:
            logger.warning("Ignoring invalid DEPOS_PERF_TAINT_N_JOBS=%r", raw_taint)
    raw_bundle = os.environ.get("DEPOS_PERF_BUNDLE_N_JOBS")
    if raw_bundle:
        try:
            p.bundle_n_jobs = max(1, int(raw_bundle.strip()))
        except ValueError:
            logger.warning("Ignoring invalid DEPOS_PERF_BUNDLE_N_JOBS=%r", raw_bundle)
    raw_cfg_dfg = os.environ.get("DEPOS_PERF_CFG_DFG_N_JOBS")
    if raw_cfg_dfg:
        try:
            p.cfg_dfg_n_jobs = max(1, int(raw_cfg_dfg.strip()))
        except ValueError:
            logger.warning("Ignoring invalid DEPOS_PERF_CFG_DFG_N_JOBS=%r", raw_cfg_dfg)
    v = os.environ.get("DEPOS_PERF_GRAPH_METRICS_EXPENSIVE", "").strip().lower()
    if v in {"0", "false", "no", "off"}:
        p.graph_metrics_expensive = False
    elif v in {"1", "true", "yes", "on"}:
        p.graph_metrics_expensive = True
    mb = os.environ.get("DEPOS_PERF_METRICS_BACKEND", "").strip().lower()
    if mb == "rustworkx":
        p = p.model_copy(update={"metrics_backend": "rustworkx"})
    elif mb == "networkx":
        p = p.model_copy(update={"metrics_backend": "networkx"})
    raw_mx = os.environ.get("DEPOS_PERF_GRAPH_METRICS_AUTO_DOWNGRADE_AT")
    if raw_mx:
        try:
            p = p.model_copy(
                update={"graph_metrics_expensive_max_nodes": max(500, int(raw_mx.strip()))}
            )
        except ValueError:
            logger.warning(
                "Ignoring invalid DEPOS_PERF_GRAPH_METRICS_AUTO_DOWNGRADE_AT=%r", raw_mx
            )
    return p


class IntelligenceConfig(BaseModel):
    data_dir: Path = Field(default_factory=lambda: Path(os.environ.get("DEPOS_DATA", "depos-data")))
    run_output_subdir: str = "intelligence"

    # Module 1 defaults
    migration_glob: str = "supabase/migrations/*.sql"
    migration_timestamp_pattern: str = r"(\d{14})_.*\.sql"

    # Module 1 coverage threshold
    low_stitcher_coverage_threshold: float = 0.7

    # Replay
    replay_stale_threshold_days: int = 7

    prompt_globs: list[str] = Field(
        default_factory=lambda: [
            "**/prompts/**/*.{md,toml,json,prompt}",
            "**/.cursor/rules/*.md",
            "**/agents/**/*.{md,toml}",
        ]
    )
    openapi_globs: list[str] = Field(
        default_factory=lambda: [
            "**/openapi.yaml",
            "**/openapi.yml",
            "**/openapi.json",
        ]
    )

    # Module 2 optional expansion: lexical keyword seeds (reasoner triage hooks).
    enable_lexical_seeds: bool = False
    #: Deprecated alias for :attr:`enable_lexical_seeds` (kept for config/env back-compat).
    enable_ai_driven_seeds: bool = False
    #: Opt-in embedding-ranked seeds (stub provider until a model is wired).
    enable_embedding_seeds: bool = False
    #: Case-insensitive word-boundary matches against node labels, embedded text, and ``source_file`` path.
    lexical_seed_keywords: list[str] = Field(
        default_factory=lambda: [
            "auth",
            "token",
            "secret",
            "password",
            "credential",
            "bearer",
            "csrf",
            "session",
            "privilege",
            "openssl",
            "crypto",
        ]
    )

    # Branch ref for migration branch-state resolution. ``None`` means "HEAD".
    branch_ref: Optional[str] = None

    verifier: VerifierPolicy = Field(default_factory=VerifierPolicy)
    detectors: DetectorHeuristicsConfig = Field(default_factory=DetectorHeuristicsConfig)
    candidates: CandidateBudget = Field(default_factory=CandidateBudget)
    bundles: BundleBudget = Field(default_factory=BundleBudget)
    llm: ReasonerProviderConfig = Field(
        default_factory=ReasonerProviderConfig,
        validation_alias=AliasChoices("llm", "reasoner"),
    )
    reasoner_policy: ReasonerPolicyConfig = Field(default_factory=ReasonerPolicyConfig)
    gray_zone: GrayZoneConfig = Field(default_factory=GrayZoneConfig)
    ranker: RankerConfig = Field(default_factory=RankerConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    cache: CacheConfig = Field(default_factory=CacheConfig)
    intent_context: IntentContextConfig = Field(default_factory=IntentContextConfig)
    #: Rolling precision per detector (0..1), loaded from ``detector_precision_rollup.json`` under ``data_dir``.
    detector_precision_rollup: dict[str, float] = Field(default_factory=dict)

    @property
    def reasoner(self) -> ReasonerProviderConfig:  # noqa: ANN201 - public compat
        warnings.warn(
            "IntelligenceConfig.reasoner is deprecated; use .llm",
            DeprecationWarning,
            stacklevel=2,
        )
        return self.llm

    def resolved_llm_model_label(self) -> str:
        r = self.llm
        provider = (r.provider or "gemma").lower()
        model_map: dict[str, str] = {
            "openai": r.openai_model,
            "anthropic": r.anthropic_model,
            "ollama": r.ollama_model,
            "gemma": r.gemma_model,
        }
        model = model_map.get(provider, r.gemma_model) or provider
        return f"{provider}/{model}"


def load_config_from_env() -> IntelligenceConfig:
    """Build a config from DEPOS_INTEL_* env vars where present. Unknown
    vars are ignored; everything falls back to the defaults above."""
    cfg = IntelligenceConfig()
    cache_enabled = os.environ.get("DEPOS_CACHE_ENABLED")
    if cache_enabled is not None:
        cfg.cache.enabled = cache_enabled.strip().lower() not in {"0", "false", "no", "off"}
    if os.environ.get("DEPOS_NO_CACHE", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.cache.enabled = False
    cache_dir = os.environ.get("DEPOS_CACHE_DIR")
    if cache_dir:
        cfg.cache.cache_dir = Path(cache_dir)
    if os.environ.get("DEPOS_CACHE_CLEAR", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.cache.clear = True
    cfg.llm.provider = os.environ.get("DEPOS_INTEL_PROVIDER", cfg.llm.provider)
    if os.environ.get("DEPOS_GRAY_ZONE_ENABLED", "").strip().lower() in {"0", "false", "no", "off"}:
        cfg.gray_zone.enabled = False
    gz_a = os.environ.get("DEPOS_GRAY_ZONE_MODEL_A_PROVIDER", "").strip()
    if gz_a:
        cfg.gray_zone.model_a_provider = gz_a
    gz_b = os.environ.get("DEPOS_GRAY_ZONE_MODEL_B_PROVIDER", "").strip()
    if gz_b:
        cfg.gray_zone.model_b_provider = gz_b
    gz_c = os.environ.get("DEPOS_GRAY_ZONE_MODEL_C_PROVIDER", "").strip()
    if gz_c:
        cfg.gray_zone.model_c_provider = gz_c
    cfg.reasoner_policy.disabled_detectors = _parse_detector_set(
        os.environ.get("DEPOS_REASONER_DISABLED_DETECTORS", "")
    )
    cfg.reasoner_policy.min_evidence_by_detector = _parse_detector_float_map(
        os.environ.get("DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR", ""),
        env_name="DEPOS_REASONER_MIN_EVIDENCE_BY_DETECTOR",
        minimum=0.0,
        maximum=1.0,
    )
    cfg.reasoner_policy.max_candidates_by_detector = _parse_detector_int_map(
        os.environ.get("DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR", ""),
        env_name="DEPOS_REASONER_MAX_CANDIDATES_BY_DETECTOR",
        minimum=0,
    )
    cfg.llm.openai_api_key = os.environ.get("OPENAI_API_KEY", cfg.llm.openai_api_key)
    cfg.llm.openai_model = os.environ.get("OPENAI_MODEL", cfg.llm.openai_model)
    cfg.llm.anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY", cfg.llm.anthropic_api_key)
    cfg.llm.anthropic_model = os.environ.get("ANTHROPIC_MODEL", cfg.llm.anthropic_model)
    cfg.llm.gemma_api_url = os.environ.get("GEMMA_API_URL", cfg.llm.gemma_api_url)
    cfg.llm.gemma_model = os.environ.get("GEMMA_MODEL", cfg.llm.gemma_model)
    cfg.llm.gemma_response_path = os.environ.get(
        "GEMMA_RESPONSE_PATH", cfg.llm.gemma_response_path
    )
    cfg.llm.openai_response_path = os.environ.get(
        "OPENAI_RESPONSE_PATH", cfg.llm.openai_response_path
    )
    cfg.llm.ollama_response_path = os.environ.get(
        "OLLAMA_RESPONSE_PATH", cfg.llm.ollama_response_path
    )
    cfg.llm.ollama_host = os.environ.get("OLLAMA_HOST", cfg.llm.ollama_host)
    cfg.llm.ollama_model = os.environ.get("OLLAMA_MODEL", cfg.llm.ollama_model)
    try:
        cfg.bundles.token_budget_default = int(os.environ.get("DEPOS_INTEL_TOKEN_BUDGET", cfg.bundles.token_budget_default))
    except ValueError:
        pass
    try:
        cfg.llm.connect_timeout_seconds = float(
            os.environ.get("DEPOS_LLM_CONNECT_TIMEOUT", cfg.llm.connect_timeout_seconds)
        )
    except ValueError:
        pass
    try:
        cfg.llm.read_timeout_seconds = float(
            os.environ.get("DEPOS_LLM_READ_TIMEOUT", cfg.llm.read_timeout_seconds)
        )
    except ValueError:
        pass
    try:
        cfg.llm.ollama_preflight_timeout = float(
            os.environ.get(
                "DEPOS_LLM_OLLAMA_PREFLIGHT_TIMEOUT",
                cfg.llm.ollama_preflight_timeout,
            )
        )
    except ValueError:
        pass
    try:
        cfg.llm.ollama_first_call_timeout = float(
            os.environ.get(
                "DEPOS_OLLAMA_FIRST_CALL_TIMEOUT",
                os.environ.get(
                "DEPOS_LLM_OLLAMA_FIRST_CALL_TIMEOUT",
                cfg.llm.ollama_first_call_timeout,
                ),
            )
        )
    except ValueError:
        logger.warning("Ignoring invalid DEPOS_OLLAMA_FIRST_CALL_TIMEOUT / DEPOS_LLM_OLLAMA_FIRST_CALL_TIMEOUT")
    try:
        cfg.llm.ollama_subsequent_timeout = float(
            os.environ.get(
                "DEPOS_OLLAMA_SUBSEQUENT_TIMEOUT",
                os.environ.get(
                "DEPOS_LLM_OLLAMA_SUBSEQUENT_TIMEOUT",
                cfg.llm.ollama_subsequent_timeout,
                ),
            )
        )
    except ValueError:
        logger.warning("Ignoring invalid DEPOS_OLLAMA_SUBSEQUENT_TIMEOUT / DEPOS_LLM_OLLAMA_SUBSEQUENT_TIMEOUT")
    try:
        cfg.llm.max_retries = int(
            os.environ.get("DEPOS_REASONER_MAX_RETRIES", cfg.llm.max_retries)
        )
    except ValueError:
        logger.warning("Ignoring invalid DEPOS_REASONER_MAX_RETRIES")

    extra_roots = os.environ.get("DEPOS_INTEL_EXTRA_SOURCE_ROOTS")
    if extra_roots:
        cfg.bundles.extra_source_roots = [
            part for part in extra_roots.split(os.pathsep) if part.strip()
        ]
    try:
        cfg.bundles.max_caller_texts = int(
            os.environ.get("DEPOS_BUNDLE_MAX_CALLER_TEXTS", cfg.bundles.max_caller_texts)
        )
    except ValueError:
        pass
    try:
        cfg.bundles.max_callee_texts = int(
            os.environ.get("DEPOS_BUNDLE_MAX_CALLEE_TEXTS", cfg.bundles.max_callee_texts)
        )
    except ValueError:
        pass
    try:
        cfg.bundles.max_seam_neighbor_texts = int(
            os.environ.get(
                "DEPOS_BUNDLE_MAX_SEAM_NEIGHBOR_TEXTS",
                cfg.bundles.max_seam_neighbor_texts,
            )
        )
    except ValueError:
        pass
    try:
        cfg.bundles.max_snippet_chars = int(
            os.environ.get("DEPOS_BUNDLE_MAX_SNIPPET_CHARS", cfg.bundles.max_snippet_chars)
        )
    except ValueError:
        pass
    try:
        cfg.bundles.max_prompt_tokens = int(
            os.environ.get("DEPOS_BUNDLE_MAX_PROMPT_TOKENS", cfg.bundles.max_prompt_tokens)
        )
    except ValueError:
        pass
    aliases_json = os.environ.get("DEPOS_INTEL_PATH_ALIASES_JSON")
    if aliases_json:
        try:
            import json as _json

            parsed = _json.loads(aliases_json)
            if isinstance(parsed, dict):
                cfg.bundles.path_aliases = {str(k): str(v) for k, v in parsed.items()}
        except ValueError:
            pass
    min_evidence = os.environ.get("DEPOS_INTEL_MIN_EVIDENCE")
    if min_evidence in {"full", "embedded", "label_only"}:
        cfg.bundles.min_evidence_quality_for_reasoner = min_evidence
    try:
        cfg.bundles.min_evidence_score_for_reasoner = float(
            os.environ.get(
                "DEPOS_INTEL_MIN_EVIDENCE_SCORE",
                cfg.bundles.min_evidence_score_for_reasoner,
            )
        )
    except ValueError:
        pass
    intent_mode = os.environ.get("DEPOS_INTEL_INTENT_LLM", "").strip().lower()
    if intent_mode in {"auto", "rules", "llm"}:
        cfg.intent_context.llm_mode = intent_mode
    cfg.intent_context.intent_openai_model = os.environ.get(
        "DEPOS_INTEL_INTENT_MODEL", cfg.intent_context.intent_openai_model
    )
    for key, attr in (
        ("DEPOS_INTEL_INTENT_MAX_TOKENS", "max_tokens_per_call"),
        ("DEPOS_INTEL_INTENT_MAX_REPO_BYTES", "max_input_bytes_per_repo"),
        ("DEPOS_INTEL_INTENT_MAX_CHUNKS", "max_chunks_per_run"),
        ("DEPOS_INTEL_INTENT_MAX_FILE_BYTES", "max_bytes_per_file"),
        ("DEPOS_INTEL_INTENT_CHUNK_CHARS", "chunk_max_chars"),
        ("DEPOS_INTEL_INTENT_CHUNK_OVERLAP", "chunk_overlap_chars"),
    ):
        raw = os.environ.get(key)
        if raw:
            try:
                setattr(cfg.intent_context, attr, int(raw))
            except ValueError:
                pass
    fenced = os.environ.get("DEPOS_INTEL_INTENT_FENCED", "").strip().lower()
    if fenced in {"strip", "annotate"}:
        cfg.intent_context.fenced_code_policy = fenced
    cfg.intent_context.enable_tag_scan = os.environ.get(
        "DEPOS_INTEL_INTENT_TAG_SCAN", "1"
    ).strip().lower() not in {"0", "false", "off", "no"}
    cfg.intent_context.enable_doc_git_signals = os.environ.get(
        "DEPOS_INTEL_INTENT_GIT_SIGNALS", "1"
    ).strip().lower() not in {"0", "false", "off", "no"}
    tier_env = os.environ.get("DEPOS_INTEL_INTENT_DEFAULT_TIER", "").strip().upper()
    if tier_env in {"P0", "P1", "P2"}:
        cfg.intent_context.default_intent_tier = tier_env
    if os.environ.get("DEPOS_INTEL_STABLE_FINDING_IDS", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.verifier = cfg.verifier.model_copy(update={"stable_finding_ids": True})
    if os.environ.get("DEPOS_INTEL_ENABLE_LEXICAL_SEEDS", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.enable_lexical_seeds = True
    if os.environ.get("DEPOS_INTEL_ENABLE_AI_DRIVEN_SEEDS", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.enable_ai_driven_seeds = True
    if os.environ.get("DEPOS_INTEL_ENABLE_EMBEDDING_SEEDS", "").strip().lower() in {"1", "true", "yes", "on"}:
        cfg.enable_embedding_seeds = True
    kw = os.environ.get("DEPOS_INTEL_LEXICAL_SEED_KEYWORDS", "").strip()
    if kw:
        cfg.lexical_seed_keywords = [part.strip() for part in kw.split(",") if part.strip()]
    try:
        mx = int(os.environ.get("DEPOS_INTEL_MAX_LEXICAL_SEEDS", cfg.candidates.max_lexical_seeds))
        if mx >= 0:
            cfg.candidates = cfg.candidates.model_copy(update={"max_lexical_seeds": mx})
    except ValueError:
        logger.warning("Ignoring invalid DEPOS_INTEL_MAX_LEXICAL_SEEDS")
    return cfg


def _parse_detector_set(raw: str) -> set[str]:
    return {part.strip() for part in raw.split(",") if part.strip()}


def _parse_detector_float_map(
    raw: str,
    *,
    env_name: str,
    minimum: float,
    maximum: float,
) -> dict[str, float]:
    out: dict[str, float] = {}
    for item in (part.strip() for part in raw.split(",") if part.strip()):
        if ":" not in item:
            logger.warning("Ignoring malformed %s entry: %s", env_name, item)
            continue
        detector, value_raw = (part.strip() for part in item.split(":", 1))
        if not detector:
            logger.warning("Ignoring %s entry with empty detector: %s", env_name, item)
            continue
        try:
            value = float(value_raw)
        except ValueError:
            logger.warning("Ignoring non-numeric %s entry: %s", env_name, item)
            continue
        if value < minimum or value > maximum:
            logger.warning(
                "Ignoring out-of-range %s entry: %s (expected %.1f..%.1f)",
                env_name,
                item,
                minimum,
                maximum,
            )
            continue
        out[detector] = value
    return out


def _parse_detector_int_map(
    raw: str,
    *,
    env_name: str,
    minimum: int,
) -> dict[str, int]:
    out: dict[str, int] = {}
    for item in (part.strip() for part in raw.split(",") if part.strip()):
        if ":" not in item:
            logger.warning("Ignoring malformed %s entry: %s", env_name, item)
            continue
        detector, value_raw = (part.strip() for part in item.split(":", 1))
        if not detector:
            logger.warning("Ignoring %s entry with empty detector: %s", env_name, item)
            continue
        try:
            value = int(value_raw)
        except ValueError:
            logger.warning("Ignoring non-integer %s entry: %s", env_name, item)
            continue
        if value < minimum:
            logger.warning(
                "Ignoring out-of-range %s entry: %s (expected >= %d)",
                env_name,
                item,
                minimum,
            )
            continue
        out[detector] = value
    return out
