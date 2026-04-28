"""Built-in pattern rule registry for detector integrations."""
from __future__ import annotations

from depos.analysis.detectors.pattern_types import PatternRule


_RULES: dict[str, PatternRule] = {}


def register_pattern_rule(rule: PatternRule) -> PatternRule:
    _RULES[rule.id] = rule
    return rule


def get_pattern_rule(rule_id: str) -> PatternRule:
    return _RULES[rule_id]


INFINITE_LOOP = register_pattern_rule(
    PatternRule(
        id="infinite-loop-source",
        detector_name="infinite-loop",
        risk_category="LOGIC_BUG",
        severity="high",
        scope="function",
        semantic_requirement="cfg",
        message="Loop condition is statically true and may not terminate.",
        formula={
            "source_regex": {
                "pattern": r"while\s*\(\s*true\s*\)\s*;|while\s*\(\s*true\s*\)|while\s+True\s*:",
                "flags": ["ignorecase"],
                "confidence": 0.8,
            }
        },
    )
)


TS_NON_NULL_ASSERTION = register_pattern_rule(
    PatternRule(
        id="ts-non-null-assertion",
        detector_name="null-dereference-approx",
        risk_category="NULL_DEREFERENCE",
        severity="high",
        scope="function",
        semantic_requirement="cfg",
        message="TypeScript non-null assertion before member access can hide a null path.",
        formula={
            "source_regex": {
                "pattern": r"\b\w+!\s*\.\s*\w+",
                "confidence": 0.66,
            }
        },
    )
)


ENV_VAR_REFERENCED_BUT_UNDEFINED = register_pattern_rule(
    PatternRule(
        id="env-var-referenced-but-undefined",
        detector_name="env-var-referenced-but-undefined",
        risk_category="CONFIG_RISK",
        severity="high",
        scope="env_var",
        semantic_requirement=None,
        message="Environment variable is read by code but has no known definition.",
        formula={
            "all_of": [
                {"env_var": {"defined": False, "name_regex": r"^[A-Z0-9_]+$"}},
                {"requires_edge": {"relation": "READS_ENV_VAR", "direction": "incoming"}},
            ]
        },
    )
)


__all__ = [
    "ENV_VAR_REFERENCED_BUT_UNDEFINED",
    "INFINITE_LOOP",
    "TS_NON_NULL_ASSERTION",
    "get_pattern_rule",
    "register_pattern_rule",
]
