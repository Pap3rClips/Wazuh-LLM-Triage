from wazuh_triage.correlate import correlate
from wazuh_triage.ingest import load_alerts


def test_seventy_alerts_form_eight_incidents(sample_path):
    incidents = correlate(load_alerts(sample_path))
    assert len(incidents) == 8


def test_every_alert_is_covered_once(sample_path):
    alerts = load_alerts(sample_path)
    incidents = correlate(alerts)
    assert sum(inc.size for inc in incidents) == len(alerts)


def test_incident_contains_single_agent(sample_path):
    for inc in correlate(load_alerts(sample_path)):
        agents = {a["agent"]["id"] for a in inc.alerts}
        assert len(agents) == 1


def test_time_gap_splits_same_agent_into_sessions():
    # Même agent, deux rafales séparées de plus que la fenêtre → 2 incidents.
    def mk(ts):
        return {"timestamp": ts, "agent": {"id": "9", "name": "h9"},
                "rule": {"level": 5, "mitre": {"tactic": ["Execution"]}}}
    alerts = [mk("2026-10-07T09:00:00Z"), mk("2026-10-07T09:05:00Z"),
              mk("2026-10-07T11:00:00Z")]
    incidents = correlate(alerts, window_minutes=30)
    assert len(incidents) == 2
    assert [inc.size for inc in sorted(incidents, key=lambda i: i.alerts[0]["timestamp"])] == [2, 1]


def test_label_is_tactic_of_highest_level_alert():
    alerts = [
        {"timestamp": "2026-10-07T09:00:00Z", "agent": {"id": "1", "name": "h"},
         "rule": {"level": 3, "mitre": {"tactic": ["Execution"]}}},
        {"timestamp": "2026-10-07T09:01:00Z", "agent": {"id": "1", "name": "h"},
         "rule": {"level": 14, "mitre": {"tactic": ["Credential Access"]}}},
    ]
    (inc,) = correlate(alerts)
    assert inc.tactic == "Credential Access"
