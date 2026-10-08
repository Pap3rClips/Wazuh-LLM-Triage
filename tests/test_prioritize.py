from wazuh_triage.models import Facts, Severity
from wazuh_triage.prioritize import priority_score, severity_floor

_NO_IND = {
    "credential_access": False, "lsass_access": False, "domain_controller": False,
    "success_after_failures": False, "webshell_exec": False, "malware_confirmed": False,
    "log_cleared": False, "defense_disabled": False, "exfiltration": False,
    "lateral_movement": False, "ransomware_note": False,
}


def _facts(level=5, **indicators):
    ind = dict(_NO_IND)
    ind.update(indicators)
    return Facts(
        incident_key="k", agent="h", alert_count=3,
        time_start="2026-10-07T09:00:00Z", time_end="2026-10-07T09:05:00Z",
        duration_minutes=5.0, max_rule_level=level, tactics=[], techniques=[],
        rule_groups=[], source_ips=[], dest_ips=[], users=[], files=[],
        highlights=[], indicators=ind,
    )


def test_floor_from_rule_level():
    assert severity_floor(_facts(level=2)) == Severity.INFO
    assert severity_floor(_facts(level=5)) == Severity.LOW
    assert severity_floor(_facts(level=9)) == Severity.MEDIUM
    assert severity_floor(_facts(level=12)) == Severity.HIGH
    assert severity_floor(_facts(level=14)) == Severity.CRITICAL


def test_lsass_forces_critical_even_on_low_level():
    # Niveau faible, mais accès LSASS → plancher critique quand même.
    assert severity_floor(_facts(level=3, lsass_access=True)) == Severity.CRITICAL


def test_log_cleared_never_lowers_and_raises_to_high():
    assert severity_floor(_facts(level=4, log_cleared=True)) == Severity.HIGH


def test_floor_is_monotonic_with_indicators():
    base = severity_floor(_facts(level=8))
    worse = severity_floor(_facts(level=8, exfiltration=True))
    assert worse >= base


def test_priority_score_orders_by_severity_then_signal():
    low = priority_score(_facts(level=5), Severity.LOW)
    crit = priority_score(_facts(level=14, lsass_access=True), Severity.CRITICAL)
    assert crit > low
