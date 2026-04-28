# Task 3: Bug Condition Exploration Test Results

## Test Status: COMPLETED ✓

The bug condition exploration test for Fix 3 (Ollama Timeout and Prompt Truncation) has been written, run, and documented.

## Test File

`tests/intelligence/test_bugfix_ollama_timeout_prompt_truncation.py`

## Counterexamples Found

### Counterexample 1: Ollama Subsequent Timeout Insufficient

**Bug Confirmed**: ✓ FAIL (Expected - confirms bug exists)

**Test**: `test_bug_condition_ollama_timeout_insufficient`

**Issue**: The `ollama_subsequent_timeout` configuration value is set to 90.0 seconds, but the requirements specify it should be 120.0 seconds for adequate inference latency on local hardware.

**Details**:

- **Expected**: `ollama_subsequent_timeout` = 120.0s (per Requirements 2.5)
- **Actual**: `ollama_subsequent_timeout` = 90.0s (current default in `depos/analysis/config.py`)
- **Impact**: Ollama calls timeout at 90s causing transport failures on local hardware during inference
- **Location**: `depos/analysis/config.py`, line 76: `ollama_subsequent_timeout: float = 90.0`

**Root Cause**: The default configuration value for `ollama_subsequent_timeout` is set to 90.0 instead of the required 120.0 seconds.

**Test Output**:

```
AssertionError: Subsequent call timeout should be >= 120s for inference, got 90.0s
assert 90.0 >= 120.0
```

### Counterexample 2: Prompt Budget Enforcement

**Bug Status**: ✓ PASS (Fix already in place)

**Test**: `test_bug_condition_prompt_exceeds_token_budget`

**Issue**: The prompt budget enforcement mechanism (`_enforce_prompt_budget`) is already implemented and working correctly in the codebase.

**Details**:

- **Expected**: Prompts should be truncated to fit within `max_prompt_tokens=2048`
- **Actual**: Prompts are correctly truncated to fit within the budget
- **Status**: The fix is already in place - `_enforce_prompt_budget` is called in `render_bundle_prompt`
- **Location**: `depos/analysis/bundle_prompter.py`, lines 297-300

**Observation**: The prompt truncation bug described in the requirements (1.7, 1.8) appears to have already been fixed. The `_enforce_prompt_budget` function is properly implemented and enforces the token budget by truncating in priority order:

1. seam_neighbor_texts
2. callee_texts
3. caller_texts
4. code_snippets
5. call_chain_out
6. call_chain_in

## Preservation Tests

### Test 1: Non-Ollama Providers Use Existing Timeouts

**Status**: ✓ PASS

Verified that gemma, openai, and stub providers continue to use `read_timeout_seconds` (60.0s) and are not affected by the Ollama-specific timeout configuration.

### Test 2: Within-Budget Prompts Include Full Texts

**Status**: ✓ PASS

Verified that prompts that fit within the token budget continue to include full caller/callee texts without unnecessary truncation.

## Summary

**Bug Confirmed**: The Ollama subsequent timeout is set to 90s instead of the required 120s.

**Counterexample**: `ollama_subsequent_timeout = 90.0s` (should be 120.0s)

**Fix Required**: Update `depos/analysis/config.py` line 76 from:

```python
ollama_subsequent_timeout: float = 90.0
```

to:

```python
ollama_subsequent_timeout: float = 120.0
```

**Prompt Truncation**: The prompt budget enforcement is already working correctly. No additional fix needed for this part.

## Next Steps

Per the task instructions:

1. ✓ Test written
2. ✓ Test run on UNFIXED code
3. ✓ Test FAILED (expected outcome - confirms bug exists)
4. ✓ Counterexamples documented
5. Task marked complete when test is written, run, and failure is documented

The test will PASS after the fix is implemented in Task 9 (Fix 3: Ollama Timeout and Prompt Truncation).
