from wazuh_triage.llm import assess, build_prompt
from wazuh_triage.models import Facts, Severity


def _facts(level=12, **kw):
    base = dict(
        incident_key="k", agent="dc-01", alert_count=5,
        time_start="2026-10-07T09:30:00Z", time_end="2026-10-07T09:32:00Z",
        duration_minutes=2.0, max_rule_level=level,
        tactics=["Credential Access"], techniques=["T1003"],
        rule_groups=["sysmon", "credential_dumping"], source_ips=[], dest_ips=[],
        users=[], files=[], highlights=["Accès à la mémoire LSASS"], indicators={},
    )
    base.update(kw)
    return Facts(**base)


def test_stub_runs_offline_and_is_structured():
    a = assess(_facts(), "- Isoler l'hôte\n- Rotation des identifiants",
               force_stub=True)
    assert a.source == "stub"
    assert a.summary
    assert a.recommended_actions
    assert isinstance(a.model_severity, Severity)


def test_stub_severity_tracks_rule_level():
    assert assess(_facts(level=14), "", force_stub=True).model_severity == Severity.HIGH
    assert assess(_facts(level=3), "", force_stub=True).model_severity == Severity.INFO


def test_stub_pulls_actions_from_playbooks():
    a = assess(_facts(), "- Première action\n- Deuxième action\ntexte ignoré",
               force_stub=True)
    assert "Première action" in a.recommended_actions


def test_prompt_marks_alert_data_as_untrusted():
    prompt = build_prompt(_facts(), "contexte playbook", injection_detected=True)
    assert "NON FIABLE" in prompt
    assert "GARDE-FOU" in prompt
