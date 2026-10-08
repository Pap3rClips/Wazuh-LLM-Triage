"""Orchestration de bout en bout.

    alertes → corrélation → faits → priorité/plancher → BM25 → LLM → garde-fous

L'ordre compte : les faits et le plancher sont établis AVANT d'interroger le
modèle, et les garde-fous ont le dernier mot sur la gravité.
"""
from __future__ import annotations

from pathlib import Path

from . import guardrails, llm
from .correlate import correlate
from .facts import establish_facts
from .ingest import load_alerts
from .knowledge import KnowledgeBase
from .models import TriageResult
from .prioritize import priority_score, severity_floor


def triage_incident(inc, kb: KnowledgeBase, top_k: int = 3,
                    force_stub: bool = False) -> TriageResult:
    facts = establish_facts(inc)
    floor = severity_floor(facts)

    playbooks = kb.retrieve(facts, k=top_k)
    playbooks_text = "\n\n".join(kb.text_of(name) for name, _ in playbooks)

    injection = bool(guardrails.scan_incident(inc))
    assessment = llm.assess(facts, playbooks_text, injection_detected=injection,
                            force_stub=force_stub)

    report, final_severity = guardrails.build_report(
        inc, facts, floor, assessment.model_severity)
    score = priority_score(facts, final_severity)

    return TriageResult(
        incident=inc,
        facts=facts,
        priority_score=score,
        severity=final_severity,
        assessment=assessment,
        guardrails=report,
        playbooks=playbooks,
    )


def run(alerts_path: str | Path, kb_dir: str | Path | None = None,
        top_k: int = 3, force_stub: bool = False,
        window_minutes: float = 30.0) -> list[TriageResult]:
    """Exécute le pipeline complet et renvoie les incidents triés par priorité."""
    alerts = load_alerts(alerts_path)
    incidents = correlate(alerts, window_minutes=window_minutes)
    kb = KnowledgeBase.from_dir(kb_dir)

    results = [triage_incident(inc, kb, top_k=top_k, force_stub=force_stub)
               for inc in incidents]
    results.sort(key=lambda r: r.priority_score, reverse=True)
    return results
