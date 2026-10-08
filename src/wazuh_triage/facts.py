"""Établissement de faits fiables — sans IA — à partir d'un incident.

Tout ici est calculé par des règles déterministes. Ces faits servent de
source de vérité : ils alimentent la priorisation, le plancher de gravité,
et sont fournis au modèle comme contexte vérifié (par opposition aux champs
bruts d'alerte, non fiables).
"""
from __future__ import annotations

from . import fields
from .models import Facts, Incident


def _uniq(seq):
    seen, out = set(), []
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def compute_indicators(inc: Incident) -> dict[str, bool]:
    """Drapeaux booléens dérivés des alertes, utilisés par le plancher."""
    groups, techs, descs, tactics_all = set(), set(), [], set()
    for a in inc.alerts:
        groups.update(fields.groups(a))
        techs.update(fields.techniques(a))
        tactics_all.update(fields.tactics(a))
        descs.append(fields.description(a).lower())
    text = " ".join(descs) + " " + " ".join(groups)

    has = lambda *subs: any(s in text for s in subs)  # noqa: E731

    success_after_failures = (
        any("authentication_failed" in g for g in groups)
        and any("authentication_success" in g for g in groups)
    )

    return {
        "credential_access": "Credential Access" in tactics_all,
        "lsass_access": has("lsass", "mimikatz") or "credential_dumping" in groups,
        "domain_controller": inc.agent_id == "002",
        "success_after_failures": success_after_failures,
        "webshell_exec": "webshell" in groups and has("command executed"),
        "malware_confirmed": has("virustotal", "known malware") or "malware" in groups,
        "log_cleared": has("event log cleared") or "T1070.001" in techs,
        "defense_disabled": has("defender", "audit policy", "firewall rule deleted"),
        "exfiltration": "Exfiltration" in tactics_all,
        "lateral_movement": "Lateral Movement" in tactics_all,
        "ransomware_note": has("decrypt", "ransom"),
    }


def _highlights(inc: Incident, ind: dict[str, bool]) -> list[str]:
    h = []
    if ind["success_after_failures"]:
        h.append("Connexion réussie après une rafale d'échecs d'authentification")
    if ind["lsass_access"]:
        h.append("Accès à la mémoire LSASS / vol d'identifiants")
    if ind["domain_controller"] and ind["credential_access"]:
        h.append("Contrôleur de domaine visé")
    if ind["webshell_exec"]:
        h.append("Exécution de commande via web shell")
    if ind["malware_confirmed"]:
        h.append("Malware confirmé (VirusTotal / threat intel)")
    if ind["log_cleared"]:
        h.append("Effacement du journal d'événements")
    if ind["defense_disabled"]:
        h.append("Désactivation de mécanismes de défense")
    if ind["exfiltration"]:
        h.append("Signes d'exfiltration de données")
    if ind["lateral_movement"]:
        h.append("Mouvement latéral entre hôtes")
    if ind["ransomware_note"]:
        h.append("Indice de rançongiciel (note de déchiffrement)")
    return h


def establish_facts(inc: Incident) -> Facts:
    times = [fields.timestamp(a) for a in inc.alerts]
    t0, t1 = min(times), max(times)
    ind = compute_indicators(inc)

    return Facts(
        incident_key=inc.key,
        agent=inc.agent,
        alert_count=inc.size,
        time_start=t0.isoformat().replace("+00:00", "Z"),
        time_end=t1.isoformat().replace("+00:00", "Z"),
        duration_minutes=round((t1 - t0).total_seconds() / 60.0, 1),
        max_rule_level=max(fields.level(a) for a in inc.alerts),
        tactics=_uniq(t for a in inc.alerts for t in fields.tactics(a)),
        techniques=_uniq(t for a in inc.alerts for t in fields.techniques(a)),
        rule_groups=_uniq(g for a in inc.alerts for g in fields.groups(a)),
        source_ips=_uniq(ip for a in inc.alerts for ip in fields.source_ips(a)),
        dest_ips=_uniq(ip for a in inc.alerts for ip in fields.dest_ips(a)),
        users=_uniq(u for a in inc.alerts for u in fields.users(a)),
        files=_uniq(f for a in inc.alerts for f in fields.files(a)),
        highlights=_highlights(inc, ind),
        indicators=ind,
    )
