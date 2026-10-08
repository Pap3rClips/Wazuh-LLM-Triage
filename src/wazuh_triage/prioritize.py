"""Priorisation déterministe et plancher de gravité.

Deux sorties, toutes deux calculées à partir des *faits* (jamais du modèle) :

  - un *plancher de gravité* : la gravité minimale que l'incident mérite au vu
    des faits. Le modèle peut proposer plus grave, jamais moins (cf. guardrails).
  - un *score de priorité* numérique, pour trier les incidents entre eux.
"""
from __future__ import annotations

from .models import Facts, Severity


def severity_floor(facts: Facts) -> Severity:
    """Gravité minimale justifiée par les faits."""
    lvl = facts.max_rule_level
    if lvl >= 14:
        floor = Severity.CRITICAL
    elif lvl >= 12:
        floor = Severity.HIGH
    elif lvl >= 8:
        floor = Severity.MEDIUM
    elif lvl >= 4:
        floor = Severity.LOW
    else:
        floor = Severity.INFO

    ind = facts.indicators
    # Relèvements imposés par des indicateurs forts. On ne redescend jamais.
    if ind.get("lsass_access") or (ind.get("domain_controller") and ind.get("credential_access")):
        floor = max(floor, Severity.CRITICAL)
    if ind.get("webshell_exec"):
        floor = max(floor, Severity.CRITICAL)
    if ind.get("ransomware_note"):
        floor = max(floor, Severity.CRITICAL)
    if ind.get("malware_confirmed"):
        floor = max(floor, Severity.HIGH)
    if ind.get("success_after_failures"):
        floor = max(floor, Severity.HIGH)
    if ind.get("exfiltration"):
        floor = max(floor, Severity.HIGH)
    if ind.get("lateral_movement"):
        floor = max(floor, Severity.HIGH)
    # L'effacement de traces ne doit jamais faire baisser la gravité.
    if ind.get("log_cleared") or ind.get("defense_disabled"):
        floor = max(floor, Severity.HIGH)

    return floor


def priority_score(facts: Facts, floor: Severity) -> float:
    """Score numérique pour l'ordonnancement (plus haut = plus prioritaire)."""
    score = 0.0
    score += float(floor) * 100.0            # la gravité domine l'ordre
    score += facts.max_rule_level * 4.0
    score += min(facts.alert_count, 30) * 1.5
    score += len(facts.techniques) * 3.0
    score += len(set(facts.source_ips) | set(facts.dest_ips)) * 2.0

    bonus = {
        "lsass_access": 20, "webshell_exec": 18, "ransomware_note": 18,
        "exfiltration": 12, "lateral_movement": 10, "success_after_failures": 10,
        "log_cleared": 8, "defense_disabled": 6, "malware_confirmed": 8,
        "domain_controller": 6,
    }
    for ind, pts in bonus.items():
        if facts.indicators.get(ind):
            score += pts
    return score
