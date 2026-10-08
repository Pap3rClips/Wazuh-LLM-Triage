import json

from wazuh_triage.ingest import load_alerts


def test_loads_seventy_alerts(sample_path):
    alerts = load_alerts(sample_path)
    assert len(alerts) == 70
    assert all(isinstance(a, dict) for a in alerts)


def test_accepts_json_array(tmp_path):
    p = tmp_path / "a.json"
    p.write_text(json.dumps([{"rule": {"level": 5}}, {"rule": {"level": 6}}]))
    assert len(load_alerts(p)) == 2


def test_skips_blank_and_malformed_lines(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"rule": {"level": 5}}\n\nnot-json\n{"rule": {"level": 7}}\n')
    assert len(load_alerts(p)) == 2


def test_empty_file(tmp_path):
    p = tmp_path / "empty.jsonl"
    p.write_text("")
    assert load_alerts(p) == []
