"""Stable report contract shared by checks and renderers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any


class Status(StrEnum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    SKIPPED = "SKIPPED"


class Severity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class Target:
    host: str
    port: int
    transport: str

    def __post_init__(self) -> None:
        if not self.host or any(ord(c) < 33 or ord(c) == 127 for c in self.host):
            raise ValueError("host must be nonempty and contain no whitespace/control characters")
        if not 1 <= self.port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if self.transport not in {"tcp", "tls"}:
            raise ValueError("transport must be tcp or tls")


@dataclass(frozen=True)
class Policy:
    anonymous_allowed: bool = False


@dataclass(frozen=True)
class Finding:
    check_id: str
    title: str
    status: Status
    severity: Severity
    evidence: str
    limitation: str
    recommendation: str


@dataclass(frozen=True)
class Report:
    schema_version: str
    scanner_version: str
    started_at: str
    finished_at: str
    target: Target
    policy: Policy
    findings: list[Finding]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")
