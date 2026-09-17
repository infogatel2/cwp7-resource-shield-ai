from __future__ import annotations

import json
import os
import re
from typing import Literal

from .schema import Analysis, Incident

AnalysisMode = Literal["triage", "standard", "deep"]

SYSTEM_PROMPT = """You are Resource Shield AI Security Analyst, a defensive cybersecurity assistant for authorized CWP7 hosting operators.
You receive structured incident telemetry produced by a server-side detection engine. Your job is to explain the evidence, assess severity, and recommend safe defensive actions.

Rules:
- Treat telemetry as evidence, not certainty. Do not invent reputation data, CVEs, attribution, geolocation, ASN ownership, malware families, attacker identity, or compromise status.
- Do not describe activity as brute force, credential guessing, successful/failed login attempts, exploitation, compromise, or breach unless the telemetry explicitly contains authentication or integrity evidence supporting that statement.
- Never claim that no breach or compromise occurred unless the telemetry explicitly contains a completed verification establishing that. If compromise status is unknown, say that the supplied telemetry does not establish whether compromise occurred.
- Do not infer memory pressure, capacity exhaustion, or VM/server size from memory_used_gb alone. Only make a memory-pressure claim when the telemetry provides total memory, a utilization percentage, an explicit memory-pressure signal, or equivalent capacity context.
- Do not call an event sustained or long-running unless the telemetry contains a duration or observation-window value that supports that statement.
- Do not recommend offensive, retaliatory, destructive, persistence, credential theft, exploitation, or scanning actions.
- Prefer reversible defensive actions: edge blocks, rate limiting, log review, PHP-FPM tuning checks, WordPress hardening, Cgroups review, credential review, backups, and monitoring.
- Do not present URL hiding/renaming as a primary security control. Prefer authentication hardening, 2FA, rate limiting, WAF controls, least privilege, patching, and evidence review.
- Severity must reflect both traffic evidence and operational impact. A coordinated subnet event with at least 20 distinct IPs, at least 100 sensitive-path requests, and high/severe PHP-FPM pressure should normally be at least HIGH unless the telemetry contains a clear benign explanation. Reserve CRITICAL for stronger evidence such as severe sustained service impact or confirmed compromise.
- If the evidence is insufficient, say so explicitly.
- Return ONLY valid JSON matching this schema exactly:
{
  "summary": "string",
  "severity": "low|medium|high|critical",
  "confidence": 0.0,
  "attack_pattern": "string",
  "why_flagged": ["string"],
  "affected_assets": ["string"],
  "indicators": ["string"],
  "recommended_actions": ["string"],
  "operator_note": "string",
  "customer_safe_report": "string"
}
"""

MODE_HINTS = {
    "triage": "Give a fast, concise first-pass triage. Prioritize severity, confidence, and the three most important defensive actions.",
    "standard": "Provide a balanced operator-ready analysis with clear evidence reasoning and practical defensive next steps.",
    "deep": "Perform a deeper evidence-aware investigation. Carefully discuss uncertainty, competing benign explanations, escalation criteria, and prioritized defensive actions without inventing facts.",
}

MODEL_ENV_BY_MODE = {
    "triage": "NEBIUS_MODEL_TRIAGE",
    "standard": "NEBIUS_MODEL_STANDARD",
    "deep": "NEBIUS_MODEL_DEEP",
}

PREFERRED_MODEL_MATCH = {
    "triage": ["nano", "lightning", "super", "ultra"],
    "standard": ["super", "nano", "ultra", "lightning"],
    "deep": ["ultra", "super", "nano", "lightning"],
}


def analyze_incident(incident: Incident, mode: AnalysisMode = "standard") -> Analysis:
    key = os.getenv("NEBIUS_API_KEY", "").strip()
    base_url = os.getenv("NEBIUS_BASE_URL", "https://api.tokenfactory.nebius.com/v1/").strip()

    if mode not in MODE_HINTS:
        raise ValueError(f"Unsupported analysis mode: {mode}")

    model = _configured_model(mode)

    if not key:
        if os.getenv("DEMO_FALLBACK", "1") == "1":
            return demo_analysis(incident, model=f"demo-fallback:{mode}")
        raise RuntimeError("NEBIUS_API_KEY is not configured")

    from openai import OpenAI

    client = OpenAI(api_key=key, base_url=base_url)
    if not model:
        model = discover_nemotron_model(client, mode=mode)

    payload = incident.model_dump()
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Analysis mode: {mode}. {MODE_HINTS[mode]}\n\n"
                    "Analyze this Resource Shield incident telemetry:\n"
                    + json.dumps(payload, indent=2)
                ),
            },
        ],
        temperature=0.10 if mode == "deep" else 0.15,
        max_tokens=2200 if mode == "deep" else (1200 if mode == "triage" else 1700),
        extra_body={"chat_template_kwargs": {"enable_thinking": False}},
    )

    content = response.choices[0].message.content or ""
    if not content.strip():
        raise ValueError(
            "Nemotron returned an empty final answer. Retry once; if it repeats, use a larger max_tokens budget or another configured Nemotron mode."
        )
    obj = _extract_json(content)
    obj = _apply_evidence_guardrails(obj, incident)
    obj["model"] = model
    obj["provider"] = f"Nebius Token Factory • {mode.title()}"
    return Analysis.model_validate(obj)


def _configured_model(mode: AnalysisMode) -> str:
    global_override = os.getenv("NEBIUS_MODEL", "").strip()
    if global_override:
        return global_override
    return os.getenv(MODEL_ENV_BY_MODE[mode], "").strip()


def discover_nemotron_model(client, mode: AnalysisMode = "standard") -> str:
    models = client.models.list()
    ids = [getattr(m, "id", "") for m in getattr(models, "data", [])]
    nemotron = [m for m in ids if "nemotron" in m.lower()]
    if not nemotron:
        raise RuntimeError(
            "No NVIDIA Nemotron model was found in this Nebius Token Factory account. "
            "Set NEBIUS_MODEL explicitly after checking the available model list."
        )

    for needle in PREFERRED_MODEL_MATCH[mode]:
        matches = sorted(m for m in nemotron if needle in m.lower())
        if matches:
            return matches[0]
    return sorted(nemotron)[0]


def _extract_json(text: str) -> dict:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        match = re.search(r"\{.*\}", text, re.S)
        if not match:
            raise ValueError("Model response did not contain valid JSON")
        return json.loads(match.group(0))


def _apply_evidence_guardrails(obj: dict, incident: Incident) -> dict:
    """Apply deterministic safety/evidence rules after the model response.

    Detection remains deterministic and the LLM is advisory. This post-processing
    prevents unsupported reassurance and keeps severity aligned with measured impact.
    """
    guarded = dict(obj)
    context = {str(k).lower(): v for k, v in (incident.context or {}).items()}

    explicit_compromise_verification = any(
        key in context
        for key in {
            "breach_verified",
            "breach_status",
            "compromise_verified",
            "compromise_status",
            "integrity_check_result",
        }
    )

    if not explicit_compromise_verification:
        for field in ("summary", "operator_note", "customer_safe_report"):
            value = str(guarded.get(field, ""))
            value = re.sub(
                r"\bno evidence of (?:a )?(?:breach|compromise) (?:was|has been) found\.?",
                "The supplied telemetry does not establish whether compromise occurred.",
                value,
                flags=re.IGNORECASE,
            )
            value = re.sub(
                r"\b(?:no breach|no compromise) (?:was|has been) detected\.?",
                "The supplied telemetry does not establish whether compromise occurred.",
                value,
                flags=re.IGNORECASE,
            )
            guarded[field] = value

    memory_capacity_context = any(
        key in context
        for key in {
            "memory_total_gb",
            "memory_usage_percent",
            "memory_pressure",
            "ram_total_gb",
            "ram_usage_percent",
        }
    )
    if not memory_capacity_context:
        guarded["why_flagged"] = [
            item
            for item in guarded.get("why_flagged", [])
            if not (
                "memory" in str(item).lower()
                and any(
                    word in str(item).lower()
                    for word in ("pressure", "strain", "capacity", "exhaust", "high", "percent", "%")
                )
            )
        ]

    pressure = (incident.php_fpm_pressure or "").strip().lower()
    coordinated_high_impact = (
        incident.scope == "subnet"
        and incident.distinct_ips >= 20
        and incident.sensitive_requests >= 100
        and pressure in {"high", "critical", "severe"}
    )
    if coordinated_high_impact:
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        current = str(guarded.get("severity", "medium")).lower()
        if severity_order.get(current, 1) < severity_order["high"]:
            guarded["severity"] = "high"

    return guarded


def demo_analysis(incident: Incident, model: str = "demo-fallback") -> Analysis:
    ratio = (incident.sensitive_requests / incident.requests) if incident.requests else 0
    severity = "high" if incident.scope == "subnet" and incident.distinct_ips >= 12 else "medium"
    if incident.requests >= 1000 and incident.sensitive_requests >= 300:
        severity = "critical"

    why = [
        f"{incident.requests} requests were observed in the detection window.",
        f"{incident.sensitive_requests} requests targeted sensitive application paths.",
        f"Traffic involved {incident.distinct_ips} distinct IP addresses within {incident.subject}." if incident.scope == "subnet" else f"The source {incident.subject} crossed the configured detection threshold.",
    ]
    if ratio >= 0.25:
        why.append(f"Sensitive requests represented about {ratio:.0%} of the observed traffic.")

    return Analysis(
        summary=f"Resource Shield detected {incident.reason.replace('_', ' ')} affecting {incident.domain}.",
        severity=severity,
        confidence=0.91,
        attack_pattern="Distributed sensitive-path request flood" if incident.scope == "subnet" else "High-volume suspicious request pattern",
        why_flagged=why,
        affected_assets=[incident.domain, incident.server],
        indicators=[incident.subject, incident.reason],
        recommended_actions=[
            "Keep or apply the Cloudflare edge block if the detection has been confirmed by policy.",
            "Review web-server access logs for targeted paths and verify that legitimate administrators are not included.",
            "Check PHP-FPM saturation and CWP7 Cgroup limits for the affected hosting account.",
            "Review WordPress authentication, XML-RPC, cron, and plugin activity if those paths were targeted.",
            "Continue monitoring for recurrence from adjacent networks before broadening any block.",
        ],
        operator_note="This is a demonstration fallback. Configure NEBIUS_API_KEY to generate the contest-qualified Nemotron analysis at runtime.",
        customer_safe_report="A coordinated burst of suspicious traffic was detected and contained before it could continue consuming application resources. Monitoring remains active. The supplied telemetry does not establish whether compromise occurred.",
        model=model,
        provider="Local demo fallback",
    )