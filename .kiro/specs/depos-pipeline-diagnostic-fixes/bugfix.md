# Bugfix Requirements Document

## Introduction

Five critical issues in the depOS intelligence pipeline are causing systematic failures across Module 1 (stitcher), Module 4 (reasoner), Module 5 (ranker), and Module 2 (detectors). These issues were identified from a diagnostic run and affect route linking, label integrity, LLM timeout handling, noise reduction, and hallucination prevention. The fixes must be applied in priority order to restore pipeline health and ensure accurate vulnerability detection.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN the stitcher runs emit_http_calls_route THEN the system reports "coverage 0/23 routes linked; errors=74" with zero HTTP_CALLS_ROUTE edges created

1.2 WHEN FastAPI routes exist in the graph THEN the system leaves every route as an orphan node with no incoming HTTP_CALLS_ROUTE edges

1.3 WHEN the ranker processes graph-anomaly candidates in Phase 1b THEN the system overwrites candidate.detector_payload.detector_name with attack pattern labels like "command-injection-approx" instead of preserving "graph-anomaly"

1.4 WHEN the ranker writes matched_pattern metadata THEN the system stores it in detector_payload.detector_name instead of a separate ranking_metadata field

1.5 WHEN Ollama reasoner calls are made on local hardware THEN the system times out at 90 seconds causing transport failures

1.6 WHEN the first Ollama call is made after model loading THEN the system uses the same 90s timeout insufficient for weight loading latency

1.7 WHEN bundle_prompter builds prompts with untruncated caller_texts and callee_texts THEN the system exceeds token budgets causing prompt truncation errors

1.8 WHEN bundle_prompter includes full code snippets THEN the system creates prompts larger than max_prompt_tokens=2048

1.9 WHEN stitcher coverage is low (<20%) in full_repo_scan mode THEN the system emits graph-anomaly structural placeholders that flood the candidate budget

1.10 WHEN graph-anomaly detector runs with low stitcher coverage THEN the system produces high-noise candidates with no actionable signal

1.11 WHEN Group C candidates have no taint evidence (empty taint_edges list) THEN the system sends them to the LLM reasoner producing hallucinated findings

1.12 WHEN Group C detectors emit candidates without taint chains THEN the system wastes LLM time on candidates that cannot produce valid security findings

### Expected Behavior (Correct)

2.1 WHEN the stitcher runs emit_http_calls_route THEN the system SHALL successfully link X/23 routes where X > 0 with reduced error count

2.2 WHEN FastAPI routes exist in the graph THEN the system SHALL create HTTP_CALLS_ROUTE edges from TypeScript HTTP clients to route handlers

2.3 WHEN the ranker processes graph-anomaly candidates in Phase 1b THEN the system SHALL preserve candidate.detector_payload.detector_name as "graph-anomaly"

2.4 WHEN the ranker writes matched_pattern metadata THEN the system SHALL store attack patterns in a separate ranking_metadata.matched_pattern field

2.5 WHEN Ollama reasoner calls are made on local hardware THEN the system SHALL use 300s timeout for first call and 120s timeout for subsequent calls

2.6 WHEN the first Ollama call is made after model loading THEN the system SHALL run a preflight probe that validates model availability or fails fast with a clear message

2.7 WHEN bundle_prompter builds prompts THEN the system SHALL truncate to max_caller_texts=3, max_callee_texts=3, max_snippet_chars=400

2.8 WHEN bundle_prompter includes code snippets THEN the system SHALL respect max_prompt_tokens budget and truncate gracefully

2.9 WHEN stitcher coverage is low (<20%) in full_repo_scan mode THEN the system SHALL suppress graph-anomaly detector emission

2.10 WHEN graph-anomaly detector checks eligibility THEN the system SHALL skip candidate emission when config.low_stitcher_coverage_threshold is not met

2.11 WHEN Group C candidates have no taint evidence (empty taint_edges list) THEN the system SHALL auto-gray-zone them without LLM call

2.12 WHEN Group C detectors check taint_edges_available before emission THEN the system SHALL gate LLM reasoning on non-empty taint chain presence

### Unchanged Behavior (Regression Prevention)

3.1 WHEN stitcher coverage is adequate (>=20%) THEN the system SHALL CONTINUE TO emit graph-anomaly candidates normally

3.2 WHEN Group A and Group B detectors emit candidates THEN the system SHALL CONTINUE TO process them through the reasoner without taint evidence requirements

3.3 WHEN non-Ollama providers (gemma, openai, stub) are configured THEN the system SHALL CONTINUE TO use existing timeout behavior

3.4 WHEN ranker processes non-graph-anomaly candidates THEN the system SHALL CONTINUE TO preserve their detector_name values unchanged

3.5 WHEN bundle_prompter builds prompts within token budget THEN the system SHALL CONTINUE TO include full caller/callee texts without truncation

3.6 WHEN FastAPI routes have valid HTTP_CALLS_ROUTE edges THEN the system SHALL CONTINUE TO report them as linked in coverage metrics

3.7 WHEN Group C candidates have non-empty taint_edges THEN the system SHALL CONTINUE TO send them to the LLM reasoner for analysis

3.8 WHEN pytest tests/ -q runs after each fix THEN the system SHALL CONTINUE TO pass all existing tests

---

## Follow-up: Group C detector identity (supersedes portions of 1.3 / 1.4 / 2.3 / 2.4)

The ``graph-anomaly`` + ``ranking_metadata.matched_pattern`` workaround for Group C taint detectors is **removed** in favor of **``resolve_detector_spec``**: the verifier loads the emitting detector spec via ``DetectorPayload.category`` (always the spec name after wrap), so Group C ``verifier_checks`` (e.g. ``taint_sinks_sql``, ``dfg_witness``) run against the correct rule set. ``detector_payload.detector_name`` now matches the spec name end-to-end (e.g. ``command-injection-approx``). Requirements **2.3** and **2.4** in this document described the workaround; product behavior is now **native Group C names** on the payload.
