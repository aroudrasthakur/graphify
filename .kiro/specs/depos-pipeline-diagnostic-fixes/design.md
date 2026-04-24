# depOS Pipeline Diagnostic Fixes - Bugfix Design

## Overview

This design addresses five critical pipeline failures identified in diagnostic runs that systematically degrade the depOS intelligence pipeline. The fixes target Module 1 (stitcher route matching), Module 4 (Ollama timeout handling), Module 3 (prompt truncation), Module 2 (graph-anomaly noise suppression), and Module 4 (Group C taint evidence gating). Each fix is surgical, minimal, and designed to be applied sequentially with pytest validation after each change.

The root causes span incorrect route normalization logic, insufficient timeout configuration for local LLM hardware, missing prompt budget enforcement, detector emission without coverage checks, and missing taint evidence validation gates. The fixes restore pipeline health by improving route linking from 0/23 to X/23 (X > 0), eliminating Ollama transport failures, preventing prompt truncation errors, suppressing high-noise structural placeholders, and auto-gray-zoning hallucinated Group C findings.

## Glossary

- **Bug_Condition (C)**: The condition that triggers each of the 5 bugs - stitcher errors, ranker label corruption, Ollama timeouts, graph-anomaly noise, and Group C taint gating failures
- **Property (P)**: The desired behavior when each bug condition is met - successful route linking, preserved detector_name labels, appropriate timeouts, suppressed noise, and gated LLM reasoning
- **Preservation**: Existing behavior that must remain unchanged - adequate coverage graph-anomaly emission, non-Ollama provider timeouts, non-graph-anomaly detector_name preservation, within-budget prompt building, and Group A/B reasoner processing
- **emit_http_calls_route**: The function in `depos/enrichment/semantic_edges.py` that matches TypeScript HTTP clients to FastAPI route handlers
- **normalize_route**: The function in `depos/enrichment/url_normalize.py` that canonicalizes URL patterns for matching
- **score_match**: The function in `depos/enrichment/url_normalize.py` that computes match confidence between client and server routes
- **RankingMetadata**: A new schema field in `depos/analysis/schemas.py` that stores attack pattern labels separately from detector_name
- **detector_payload.detector_name**: The field in candidate payloads that identifies which detector emitted the candidate
- **ReasonerProviderConfig**: The config class in `depos/analysis/config.py` that controls LLM provider timeouts
- **ollama_preflight_timeout**: New config field for Ollama model availability probe timeout (default 30s)
- **ollama_first_call_timeout**: New config field for first Ollama call after weight loading (default 300s)
- **ollama_subsequent_timeout**: New config field for subsequent Ollama calls (default 120s)
- **BundleBudget**: The config class in `depos/analysis/config.py` that controls prompt token limits
- **max_prompt_tokens**: Existing config field that caps final prompt size (default 2048)
- **\_enforce_prompt_budget**: The function in `depos/analysis/bundle_prompter.py` that truncates prompts to fit token budgets
- **graph-anomaly detector**: The detector in `depos/analysis/detectors/policy.py` that emits structural placeholder candidates
- **low_stitcher_coverage**: Boolean flag in run_metadata indicating stitcher coverage below threshold (<20%)
- **taint_edges_available**: Boolean flag on bundles indicating pre-computed taint chains are present
- **\_needs_llm_reasoning**: The function in `depos/analysis/pipeline.py` that gates LLM reasoner calls based on evidence quality

## Bug Details

### Bug Condition

The bugs manifest across five distinct failure modes:

**Fix 1 - Stitcher Route Matching Errors:**
The stitcher reports "coverage 0/23 routes linked; errors=74" because `emit_http_calls_route` fails to match TypeScript HTTP clients to FastAPI route handlers. The `normalize_route` and `score_match` functions use incorrect pattern matching logic that rejects valid client-server pairs.

**Fix 2 - Ranker Label Corruption:**
The ranker overwrites `candidate.detector_payload.detector_name` with attack pattern labels like "command-injection-approx" instead of preserving "graph-anomaly". The matched_pattern metadata is stored in the wrong field, corrupting detector identity tracking.

**Fix 3 - Ollama Timeout and Prompt Truncation:**
Ollama reasoner calls timeout at 90 seconds on local hardware, causing transport failures. The first call after model loading requires 300+ seconds for weight loading latency. Additionally, `bundle_prompter` builds prompts with untruncated caller_texts and callee_texts that exceed max_prompt_tokens=2048.

**Fix 4 - Graph-Anomaly Noise Suppression:**
When stitcher coverage is low (<20%) in full_repo_scan mode, the graph-anomaly detector emits structural placeholders that flood the candidate budget with high-noise, zero-signal candidates.

**Fix 5 - Group C Taint Evidence Gating:**
Group C candidates with empty taint_edges lists are sent to the LLM reasoner, producing hallucinated findings. The pipeline lacks a gate to auto-gray-zone candidates without taint evidence before LLM invocation.

**Formal Specification:**

```
FUNCTION isBugCondition(input)
  INPUT: input of type PipelineState
  OUTPUT: boolean

  RETURN (
    // Fix 1: Stitcher errors
    (input.stitcher_coverage == 0 AND input.stitcher_errors > 0)
    OR
    // Fix 2: Ranker label corruption
    (input.candidate.detector_payload.detector_name != "graph-anomaly"
     AND input.candidate.seed_type == "graph_anomaly")
    OR
    // Fix 3: Ollama timeout
    (input.provider == "ollama" AND input.timeout <= 90)
    OR
    // Fix 3: Prompt truncation
    (input.prompt_tokens > input.max_prompt_tokens)
    OR
    // Fix 4: Graph-anomaly noise
    (input.low_stitcher_coverage AND input.detector_name == "graph-anomaly"
     AND input.mode == "full_repo_scan")
    OR
    // Fix 5: Group C taint gating
    (input.candidate.semantic_requirement == "taint"
     AND input.bundle.taint_edges.length == 0
     AND input.sent_to_llm == true)
  )
END FUNCTION
```

### Examples

- **Fix 1**: Client route `fetch("/api/repos")` fails to match server route `@router.get("/repos")` due to incorrect `/api` prefix handling → Expected: HTTP_CALLS_ROUTE edge created with confidence > 0.8
- **Fix 2**: graph-anomaly candidate with matched_pattern="command-injection-approx" has detector_name overwritten → Expected: detector_name="graph-anomaly", ranking_metadata.matched_pattern="command-injection-approx"
- **Fix 3**: First Ollama call with gemma:2b times out at 90s during weight loading → Expected: 300s timeout for first call, 120s for subsequent calls
- **Fix 3**: Prompt with 3000 estimated tokens exceeds max_prompt_tokens=2048 → Expected: Truncated to 2048 tokens via caller/callee/snippet reduction
- **Fix 4**: Full repo scan with 5% stitcher coverage emits 200 graph-anomaly candidates → Expected: 0 graph-anomaly candidates emitted when coverage < 20%
- **Fix 5**: Group C candidate with empty taint_edges sent to LLM produces hallucinated "SQL injection" finding → Expected: Auto-gray-zoned without LLM call

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**

- Stitcher coverage >= 20% must continue to emit graph-anomaly candidates normally
- Group A and Group B detectors must continue to process through reasoner without taint evidence requirements
- Non-Ollama providers (gemma, openai, stub) must continue to use existing timeout behavior (connect=5s, read=60s)
- Ranker processing of non-graph-anomaly candidates must continue to preserve their detector_name values unchanged
- Bundle prompter building prompts within token budget must continue to include full caller/callee texts without truncation
- FastAPI routes with valid HTTP_CALLS_ROUTE edges must continue to report as linked in coverage metrics
- Group C candidates with non-empty taint_edges must continue to send to LLM reasoner for analysis
- pytest tests/ -q must continue to pass all existing tests after each fix

**Scope:**
All inputs that do NOT involve the five bug conditions should be completely unaffected by these fixes. This includes:

- Routes that already match correctly via existing normalization logic
- Detectors other than graph-anomaly that emit candidates
- Non-Ollama LLM providers configured in production
- Prompts that fit within token budgets without truncation
- Full repo scans with adequate stitcher coverage (>= 20%)
- Group A/B candidates that do not require taint evidence
- Candidates with valid taint chains present in bundle.taint_edges

## Hypothesized Root Cause

Based on the bug descriptions and diagnostic run output, the most likely issues are:

1. **Incorrect Route Normalization (Fix 1)**: The `normalize_route` function strips `/api` prefixes inconsistently between client and server routes, causing match failures. The `score_match` function may also apply incorrect confidence penalties for valid dynamic URL patterns.

2. **Field Misuse in Ranker (Fix 2)**: The ranker Phase 1b logic writes matched_pattern metadata directly into `detector_payload.detector_name` instead of a separate `ranking_metadata` field, overwriting the detector identity.

3. **Insufficient Ollama Timeouts (Fix 3)**: The `ReasonerProviderConfig` uses a single `read_timeout_seconds=60.0` for all Ollama calls, insufficient for local hardware weight loading (first call) and inference latency (subsequent calls). The `bundle_prompter` also lacks enforcement of `max_prompt_tokens` budget, allowing oversized prompts.

4. **Missing Coverage Check (Fix 4)**: The graph-anomaly detector emits candidates without checking `run_metadata.low_stitcher_coverage`, flooding the pipeline with noise when Module 1 fails to link routes.

5. **Missing Taint Evidence Gate (Fix 5)**: The `_needs_llm_reasoning` function in `pipeline.py` does not check `bundle.taint_edges_available` for Group C candidates, allowing empty-taint candidates to reach the LLM and produce hallucinated findings.

## Correctness Properties

Property 1: Bug Condition - Stitcher Route Linking

_For any_ stitcher run where FastAPI routes exist in the graph and TypeScript HTTP clients reference those routes, the fixed emit_http_calls_route function SHALL create HTTP_CALLS_ROUTE edges with confidence > 0.0, increasing linked_routes count from 0 to X where X > 0.

**Validates: Requirements 2.1, 2.2**

Property 2: Bug Condition - Ranker Label Preservation

_For any_ graph-anomaly candidate processed by the ranker, the fixed ranker SHALL preserve candidate.detector_payload.detector_name as "graph-anomaly" and store attack pattern labels in a separate ranking_metadata.matched_pattern field.

**Validates: Requirements 2.3, 2.4**

Property 3: Bug Condition - Ollama Timeout Configuration

_For any_ Ollama reasoner call on local hardware, the fixed reasoning_engine SHALL use 300s timeout for the first call (weight loading) and 120s timeout for subsequent calls (inference), eliminating transport timeout failures.

**Validates: Requirements 2.5, 2.6**

Property 4: Bug Condition - Prompt Budget Enforcement

_For any_ bundle prompt that exceeds max_prompt_tokens=2048, the fixed bundle_prompter SHALL truncate caller_texts, callee_texts, and code_snippets to fit within the token budget, preventing prompt truncation errors.

**Validates: Requirements 2.7, 2.8**

Property 5: Bug Condition - Graph-Anomaly Noise Suppression

_For any_ full_repo_scan run where stitcher coverage is below 20%, the fixed graph-anomaly detector SHALL suppress candidate emission, reducing noise from 200+ candidates to 0.

**Validates: Requirements 2.9, 2.10**

Property 6: Bug Condition - Group C Taint Evidence Gating

_For any_ Group C candidate with empty taint_edges list, the fixed pipeline SHALL auto-gray-zone the candidate without LLM call, preventing hallucinated findings.

**Validates: Requirements 2.11, 2.12**

Property 7: Preservation - Non-Buggy Input Behavior

_For any_ input that does NOT match the bug conditions (adequate coverage, non-Ollama providers, non-graph-anomaly detectors, within-budget prompts, Group A/B candidates, non-empty taint chains), the fixed code SHALL produce exactly the same behavior as the original code, preserving all existing functionality.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7, 3.8**

## Fix Implementation

### Changes Required

Assuming our root cause analysis is correct:

**Fix 1: Stitcher Route Matching**

**File**: `depos/enrichment/semantic_edges.py`

**Function**: `emit_http_calls_route`

**Specific Changes**:

1. **Improve Route Normalization**: Update `normalize_route` calls to handle `/api` prefix stripping consistently for both client and server routes
2. **Adjust Match Scoring**: Review `score_match` confidence penalties for dynamic URLs to avoid rejecting valid template literal matches
3. **Add Debug Logging**: Emit structured logs showing (client_route, server_route, score, emit_decision) for each match attempt to diagnose remaining failures

**File**: `depos/enrichment/http_probes.py`

**Function**: `scan_ts_http_calls`

**Specific Changes**: 4. **Preserve Method Context**: Ensure `http_method` is correctly extracted from fetch options and axios method calls to improve match confidence

**Fix 2: Ranker Label Preservation**

**File**: `depos/analysis/schemas.py`

**Schema**: `Candidate`

**Specific Changes**:

1. **Add RankingMetadata Field**: Define new `RankingMetadata` Pydantic model with `matched_pattern: Optional[str]` field
2. **Add ranking_metadata Field**: Add `ranking_metadata: Optional[RankingMetadata]` to `Candidate` schema with default `None`

**File**: `depos/analysis/ranker.py`

**Function**: `rank` (Phase 1b logic - not currently in this file, likely in candidate_identifier.py)

**Specific Changes**: 3. **Stop Writing to detector_name**: Remove any code that writes matched_pattern to `candidate.detector_payload.detector_name` 4. **Write to ranking_metadata**: Store matched_pattern in `candidate.ranking_metadata.matched_pattern` instead

**Fix 3: Ollama Timeout and Prompt Truncation**

**File**: `depos/analysis/config.py`

**Class**: `ReasonerProviderConfig`

**Specific Changes**:

1. **Add Ollama Timeout Fields**: Add three new config fields:
   - `ollama_preflight_timeout: float = 30.0` (model availability probe)
   - `ollama_first_call_timeout: float = 300.0` (weight loading)
   - `ollama_subsequent_timeout: float = 120.0` (inference)
2. **Add Environment Variable Loading**: Update `load_config_from_env` to read `DEPOS_LLM_OLLAMA_PREFLIGHT_TIMEOUT`, `DEPOS_LLM_OLLAMA_FIRST_CALL_TIMEOUT`, `DEPOS_LLM_OLLAMA_SUBSEQUENT_TIMEOUT`

**File**: `depos/analysis/reasoning_engine.py`

**Class**: `ReasonerSession`

**Specific Changes**: 3. **Implement Timeout Selection Logic**: Update `_get_timeout` method to return `ollama_first_call_timeout` for `call_index == 0` and `ollama_subsequent_timeout` for `call_index > 0` when provider is "ollama" 4. **Add Preflight Probe**: Call `_preflight_ollama` with `ollama_preflight_timeout` before first bundle prompt to validate model availability or fail fast

**File**: `depos/analysis/bundle_prompter.py`

**Function**: `render_bundle_prompt`

**Specific Changes**: 5. **Enforce max_prompt_tokens Budget**: Ensure `_enforce_prompt_budget` is called with `max_prompt_tokens` from config and truncates in priority order: seam_neighbor_texts → callee_texts → caller_texts → code_snippets → call_chain_out → call_chain_in 6. **Add Truncation Logging**: Emit structured log when truncation occurs showing (original_tokens, final_tokens, truncation_order_applied)

**Fix 4: Graph-Anomaly Noise Suppression**

**File**: `depos/analysis/detectors/policy.py` (or wherever graph-anomaly detector logic lives)

**Function**: Graph-anomaly detector emission logic

**Specific Changes**:

1. **Add Coverage Check**: Before emitting graph-anomaly candidates, check `run_context.run_metadata.low_stitcher_coverage`
2. **Suppress Emission**: If `low_stitcher_coverage == True` AND `mode == AnalysisMode.full_repo_scan`, skip candidate emission and log suppression reason
3. **Preserve Diff-Aware Mode**: Continue to emit graph-anomaly candidates in `AnalysisMode.diff_aware` regardless of coverage

**Fix 5: Group C Taint Evidence Gating**

**File**: `depos/analysis/pipeline.py`

**Function**: `_needs_llm_reasoning`

**Specific Changes**:

1. **Add Taint Evidence Check**: For Group C candidates (semantic_requirement="taint"), check `bundle.taint_edges_available` and `len(bundle.taint_edges) > 0`
2. **Gate LLM Reasoning**: Return `False` if taint evidence is missing, causing candidate to skip LLM and proceed to verifier with deterministic_only=True
3. **Add Bundle Trace Entry**: Record skipped_reason="missing_taint_evidence" in bundle_trace for observability

**File**: `depos/analysis/pipeline.py`

**Function**: `run_modules_2_through_7` (per-candidate loop)

**Specific Changes**: 4. **Auto-Gray-Zone Logic**: When `needs_llm_reasoning == False` due to missing taint evidence, set `deterministic_only=True` and add bundle_trace entry with skipped_reason="missing_taint_evidence"

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate each bug on unfixed code, then verify each fix works correctly and preserves existing behavior. Each fix is applied sequentially with `pytest tests/ -q` validation after each change.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate each bug BEFORE implementing fixes. Confirm or refute the root cause analysis. If we refute, we will need to re-hypothesize.

**Test Plan**: Write tests that simulate each bug condition and assert the defective behavior occurs on UNFIXED code. Run these tests to observe failures and understand root causes.

**Test Cases**:

1. **Stitcher Route Matching Test**: Create graph with FastAPI route `@router.get("/repos")` and TS client `fetch("/api/repos")`, run `emit_http_calls_route`, assert 0 edges created (will fail on unfixed code)
2. **Ranker Label Corruption Test**: Create graph-anomaly candidate with matched_pattern="command-injection-approx", run ranker, assert detector_name != "graph-anomaly" (will fail on unfixed code)
3. **Ollama Timeout Test**: Mock Ollama provider with 120s response delay, run reasoner with 90s timeout, assert transport failure (will fail on unfixed code)
4. **Prompt Truncation Test**: Create bundle with 10 caller_texts of 500 chars each, render prompt, assert token count > 2048 (will fail on unfixed code)
5. **Graph-Anomaly Noise Test**: Create full_repo_scan run with 5% stitcher coverage, run graph-anomaly detector, assert > 0 candidates emitted (will fail on unfixed code)
6. **Group C Taint Gating Test**: Create Group C candidate with empty taint_edges, run pipeline, assert LLM call made (will fail on unfixed code)

**Expected Counterexamples**:

- Stitcher reports 0/23 routes linked with 74 errors
- Ranker overwrites detector_name with "command-injection-approx"
- Ollama calls timeout at 90s with "transport" failure_reason
- Prompts exceed 2048 tokens causing truncation errors
- Graph-anomaly emits 200+ candidates in low-coverage full_repo_scan
- Group C candidates with no taint produce hallucinated LLM findings

### Fix Checking

**Goal**: Verify that for all inputs where each bug condition holds, the fixed functions produce the expected behavior.

**Pseudocode:**

```
FOR ALL input WHERE isBugCondition(input) DO
  result := fixedFunction(input)
  ASSERT expectedBehavior(result)
END FOR
```

**Test Cases**:

1. **Fix 1 Verification**: Run stitcher on same graph, assert linked_routes > 0 and errors < 74
2. **Fix 2 Verification**: Run ranker on graph-anomaly candidate, assert detector_name == "graph-anomaly" AND ranking_metadata.matched_pattern == "command-injection-approx"
3. **Fix 3 Verification**: Run Ollama reasoner with 300s first-call timeout, assert no transport failures
4. **Fix 3 Verification**: Run bundle_prompter on oversized bundle, assert final prompt <= 2048 tokens
5. **Fix 4 Verification**: Run graph-anomaly detector in low-coverage full_repo_scan, assert 0 candidates emitted
6. **Fix 5 Verification**: Run pipeline on Group C candidate with empty taint_edges, assert skipped_reason="missing_taint_evidence" and no LLM call

### Preservation Checking

**Goal**: Verify that for all inputs where the bug conditions do NOT hold, the fixed functions produce the same result as the original functions.

**Pseudocode:**

```
FOR ALL input WHERE NOT isBugCondition(input) DO
  ASSERT originalFunction(input) = fixedFunction(input)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:

- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-buggy inputs

**Test Plan**: Observe behavior on UNFIXED code first for non-bug inputs, then write property-based tests capturing that behavior.

**Test Cases**:

1. **Stitcher Preservation**: Observe that routes with exact path matches continue to link correctly on unfixed code, then verify this continues after fix
2. **Ranker Preservation**: Observe that non-graph-anomaly detectors preserve their detector_name values on unfixed code, then verify this continues after fix
3. **Ollama Preservation**: Observe that non-Ollama providers use 60s read timeout on unfixed code, then verify this continues after fix
4. **Prompt Preservation**: Observe that prompts within budget include full caller/callee texts on unfixed code, then verify this continues after fix
5. **Graph-Anomaly Preservation**: Observe that adequate-coverage runs emit graph-anomaly candidates on unfixed code, then verify this continues after fix
6. **Group C Preservation**: Observe that Group C candidates with non-empty taint_edges reach LLM on unfixed code, then verify this continues after fix

### Unit Tests

- Test `normalize_route` with various client/server route patterns (exact match, /api prefix, dynamic segments)
- Test `score_match` confidence calculation for different match scenarios
- Test `RankingMetadata` schema serialization and deserialization
- Test `ReasonerSession._get_timeout` returns correct timeout for call_index 0, 1, 2+
- Test `_enforce_prompt_budget` truncation order and token estimation
- Test graph-anomaly detector coverage check logic
- Test `_needs_llm_reasoning` taint evidence gate for Group C candidates

### Property-Based Tests

- Generate random route patterns and verify stitcher matches valid client-server pairs
- Generate random candidate payloads and verify ranker preserves detector_name for all non-graph-anomaly detectors
- Generate random bundle sizes and verify prompt truncation always fits within max_prompt_tokens
- Generate random coverage ratios and verify graph-anomaly emission follows coverage threshold rules
- Generate random taint chain configurations and verify Group C gating logic

### Integration Tests

- Test full pipeline run with diagnostic dataset to verify all 5 fixes work together
- Test stitcher coverage report shows improved linked_routes count
- Test reasoner_call_stats shows reduced transport failures for Ollama
- Test bundle_trace shows correct skipped_reason values for gated candidates
- Test violations.json output contains no hallucinated Group C findings
