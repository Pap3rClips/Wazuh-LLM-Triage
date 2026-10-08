"""Regroupement déterministe des alertes en incidents.

Un incident = une rafale d'activité sur un même hôte. On regroupe les alertes
par agent, triées dans le temps, puis on découpe en sessions dès qu'un écart
dépasse la fenêtre (par défaut 30 min). L'étiquette de tactique de l'incident
est celle de son alerte la plus grave.

Aucun appel à une IA : la corrélation est 100 % reproductible.
"""
from __future__ import annotations

from . import fields
from .models import Alert, Incident

DEFAULT_WINDOW_MINUTES = 30.0


def _dominant_tactic(alerts: list[Alert]) -> str:
    """Tactique de l'alerte de plus haut niveau (tie-break : la plus précoce)."""
    top = max(alerts, key=lambda a: (fields.level(a), -fields.timestamp(a).timestamp()))
    return fields.primary_tactic(top)


def correlate(alerts: list[Alert], window_minutes: float = DEFAULT_WINDOW_MINUTES) -> list[Incident]:
    """Regroupe les alertes en incidents, triés par horodatage de départ."""
    by_agent: dict[str, list[Alert]] = {}
    for a in alerts:
        by_agent.setdefault(fields.agent_id(a), []).append(a)

    incidents: list[Incident] = []
    for aid, agent_alerts in by_agent.items():
        agent_alerts.sort(key=fields.timestamp)

        session: list[Alert] = []
        for a in agent_alerts:
            if session:
                gap = (fields.timestamp(a) - fields.timestamp(session[-1])).total_seconds() / 60.0
                if gap > window_minutes:
                    incidents.append(_make_incident(aid, session))
                    session = []
            session.append(a)
        if session:
            incidents.append(_make_incident(aid, session))

    incidents.sort(key=lambda inc: fields.timestamp(inc.alerts[0]))
    return incidents


def _make_incident(aid: str, session: list[Alert]) -> Incident:
    tactic = _dominant_tactic(session)
    start = fields.timestamp(session[0]).strftime("%Y%m%dT%H%M")
    name = fields.agent_name(session[0])
    return Incident(
        key=f"{name}::{tactic}::{start}",
        agent=name,
        agent_id=aid,
        tactic=tactic,
        alerts=list(session),
    )
