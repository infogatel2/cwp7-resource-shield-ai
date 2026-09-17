from __future__ import annotations

import json
import os
from pathlib import Path
from uuid import uuid4

from .schema import Incident


ROOT = Path(__file__).resolve().parents[1]
DEMO_FILE = ROOT / "sample_data" / "coordinated_wordpress_attack.json"


def load_demo_incident() -> Incident:
    return Incident.model_validate_json(DEMO_FILE.read_text(encoding="utf-8"))


def incident_from_status(path: str) -> Incident:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    detections = data.get("recent_detections") or []
    if not detections:
        raise ValueError("No recent detections are available in Resource Shield status.json")

    d = detections[0]
    metrics = data.get("metrics") or {}
    cf = data.get("cloudflare") or {}
    return Incident(
        incident_id=f"rs-{uuid4().hex[:12]}",
        observed_at=d.get("ts") or data.get("updated_at") or "",
        server=(data.get("app") or "cwp7-resource-shield"),
        domain=d.get("domain") or "unknown",
        scope=d.get("scope") if d.get("scope") in {"ip", "subnet"} else "unknown",
        subject=d.get("subject") or "unknown",
        reason=d.get("reason") or "unknown",
        requests=int(d.get("requests") or 0),
        sensitive_requests=int(d.get("sensitive_requests") or 0),
        distinct_ips=int(d.get("distinct_ips") or 1),
        action=d.get("action") or "monitor",
        php_fpm_pressure="not directly reported",
        server_load_1m=_to_float(metrics.get("load_1m")),
        server_load_5m=_to_float(metrics.get("load_5m")),
        memory_used_gb=_to_float(metrics.get("memory_used_gb")),
        cloudflare_scope=cf.get("scope") or "unknown",
        context={
            "requests_seen_window": data.get("requests_seen_window"),
            "sensitive_requests_seen_window": data.get("sensitive_requests_seen_window"),
            "unique_ips_window": data.get("unique_ips_window"),
            "active_block_count": data.get("active_block_count"),
            "global_block_count": data.get("global_block_count"),
        },
    )


def get_default_incident() -> Incident:
    path = os.getenv("RESOURCE_SHIELD_STATUS_PATH", "").strip()
    if path and Path(path).exists():
        try:
            return incident_from_status(path)
        except Exception:
            pass
    return load_demo_incident()


def _to_float(value):
    try:
        return float(value) if value is not None else None
    except (TypeError, ValueError):
        return None
