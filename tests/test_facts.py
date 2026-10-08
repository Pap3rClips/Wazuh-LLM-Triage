from wazuh_triage.correlate import correlate
from wazuh_triage.facts import establish_facts
from wazuh_triage.ingest import load_alerts


def _incident_on(incidents, agent, tactic):
    for inc in incidents:
        if inc.agent == agent and inc.tactic == tactic:
            return inc
    raise AssertionError(f"incident {agent}/{tactic} introuvable")


def test_lsass_incident_facts(sample_path):
    incidents = correlate(load_alerts(sample_path))
    inc = _incident_on(incidents, "dc-01", "Credential Access")
    f = establish_facts(inc)
    assert f.max_rule_level == 14
    assert f.indicators["lsass_access"] is True
    assert f.indicators["domain_controller"] is True
    assert "T1003" in f.techniques or "T1003.001" in f.techniques


def test_ssh_incident_detects_success_after_failures(sample_path):
    incidents = correlate(load_alerts(sample_path))
    inc = _incident_on(incidents, "bastion-01", "Credential Access")
    f = establish_facts(inc)
    assert f.indicators["success_after_failures"] is True
    assert "203.0.113.45" in f.source_ips


def test_facts_time_span_is_consistent(sample_path):
    incidents = correlate(load_alerts(sample_path))
    f = establish_facts(incidents[0])
    assert f.time_start <= f.time_end
    assert f.duration_minutes >= 0
    assert f.alert_count == incidents[0].size
