"""Versioned request and response models shared by Kuruta components."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

Platform = Literal["windows", "linux"]
Severity = Literal["info", "low", "medium", "high", "critical"]
Scalar = str | int | float | bool | None


class HostIdentity(BaseModel):
    """Stable host metadata attached to every event."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    hostname: str = Field(min_length=1, max_length=255)
    platform: Platform


class EventRecord(BaseModel):
    """Validated event envelope accepted by the ingestion API."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal[1]
    event_id: str = Field(min_length=1, max_length=128)
    timestamp: datetime
    host: HostIdentity
    source: Literal["host", "network"]
    event_type: str = Field(pattern=r"^[a-z][a-z0-9_.-]{1,63}$")
    severity: Severity
    data: dict[str, Scalar] = Field(max_length=32)

    @field_validator("timestamp")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        """Require timezone-aware timestamps and normalize them to UTC."""
        if value.utcoffset() is None:
            raise ValueError("timestamp must include a timezone")
        return value.astimezone(timezone.utc)


class AlertRecord(BaseModel):
    """Stored alert returned by the API."""

    alert_id: str
    event_id: str
    rule_id: str
    title: str
    description: str
    severity: Severity
    created_at: datetime


class HealthRecord(BaseModel):
    """Small health response that does not expose host details."""

    status: Literal["ok"]
    service: str


class AlertDraft(BaseModel):
    """Rule result before it is committed alongside its source event."""

    rule_id: str
    title: str
    description: str
    severity: Severity
