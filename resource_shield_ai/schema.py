from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


class Incident(BaseModel):
    incident_id: str
    observed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    server: str = "cwp7-demo"
    domain: str = "example.com"
    scope: Literal["ip", "subnet", "unknown"] = "unknown"
    subject: str
    reason: str
    requests: int = 0
    sensitive_requests: int = 0
    distinct_ips: int = 1
    action: str = "monitor"
    php_fpm_pressure: str = "unknown"
    server_load_1m: float | None = None
    server_load_5m: float | None = None
    memory_used_gb: float | None = None
    cloudflare_scope: str = "account_wide"
    context: dict[str, Any] = Field(default_factory=dict)


class Analysis(BaseModel):
    summary: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1)
    attack_pattern: str
    why_flagged: list[str]
    affected_assets: list[str]
    indicators: list[str]
    recommended_actions: list[str]
    operator_note: str
    customer_safe_report: str
    model: str
    provider: str = "Nebius Token Factory"
