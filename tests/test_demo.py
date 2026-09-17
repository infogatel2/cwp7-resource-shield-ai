from resource_shield_ai.analyst import demo_analysis
from resource_shield_ai.telemetry import load_demo_incident


def test_demo_analysis_is_defensive_and_structured():
    incident = load_demo_incident()
    result = demo_analysis(incident)
    assert result.severity in {"low", "medium", "high", "critical"}
    assert result.confidence >= 0.0
    assert result.confidence <= 1.0
    assert incident.subject in result.indicators
    assert len(result.recommended_actions) >= 3
