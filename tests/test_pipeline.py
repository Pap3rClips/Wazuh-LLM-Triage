import json


def test_pipeline_produces_eight_results(results):
    assert len(results) == 8


def test_results_sorted_by_priority_descending(results):
    scores = [r.priority_score for r in results]
    assert scores == sorted(scores, reverse=True)


def test_all_alerts_accounted_for(results):
    assert sum(r.incident.size for r in results) == 70


def test_at_least_one_critical(results):
    from wazuh_triage.models import Severity
    assert any(r.severity == Severity.CRITICAL for r in results)


def test_injection_flagged_on_exactly_one_incident(results):
    flagged = [r for r in results if r.guardrails.injection_detected]
    assert len(flagged) == 1
    assert flagged[0].incident.agent == "ws-user-07"


def test_floor_never_below_model_severity(results):
    for r in results:
        assert r.severity >= r.assessment.model_severity


def test_results_are_json_serializable(results):
    payload = [r.as_dict() for r in results]
    # Ne doit pas lever.
    json.dumps(payload, ensure_ascii=False)
    assert payload[0]["severity"]
    assert "facts" in payload[0]
