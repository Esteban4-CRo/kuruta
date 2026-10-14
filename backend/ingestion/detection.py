"""Load simple, non-executable JSON rules and match normalized events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from backend.ingestion.schema import AlertDraft, EventRecord, Severity


class DetectionRule(BaseModel):
    """A constrained equality rule; rules cannot execute code or shell commands."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,63}$")
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(min_length=1, max_length=500)
    severity: Severity
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    platforms: list[Literal["windows", "linux"]] = Field(min_length=1)
    field: str = Field(min_length=1, max_length=64)
    equals: list[str] = Field(min_length=1, max_length=100)


class RuleEngine:
    """Evaluate platform-scoped exact-value rules against event data."""

    def __init__(self, rules: list[DetectionRule]) -> None:
        self._rules = rules

    @classmethod
    def from_directory(cls, rules_directory: Path) -> RuleEngine:
        """Load and validate every JSON rule file from platform subdirectories."""
        rule_files = sorted(rules_directory.glob("*/*.json"))
        if not rule_files:
            raise FileNotFoundError(f"No JSON detection rules found in {rules_directory}")

        rules: list[DetectionRule] = []
        seen_ids: set[str] = set()
        for rule_file in rule_files:
            raw_rule = json.loads(rule_file.read_text(encoding="utf-8"))
            try:
                rule = DetectionRule.model_validate(raw_rule)
            except ValidationError as error:
                raise ValueError(f"Invalid detection rule in {rule_file}: {error}") from error
            if rule.id in seen_ids:
                raise ValueError(f"Duplicate detection rule id {rule.id!r} in {rule_file}")
            seen_ids.add(rule.id)
            rules.append(rule)
        return cls(rules)

    def evaluate(self, event: EventRecord) -> list[AlertDraft]:
        """Return alerts for exact matches; unmatched events produce no alert."""
        matches: list[AlertDraft] = []
        for rule in self._rules:
            if event.event_type != rule.event_type:
                continue
            if event.host.platform not in rule.platforms:
                continue
            if event.data.get(rule.field) not in rule.equals:
                continue
            matches.append(
                AlertDraft(
                    rule_id=rule.id,
                    title=rule.name,
                    description=rule.description,
                    severity=rule.severity,
                )
            )
        return matches
