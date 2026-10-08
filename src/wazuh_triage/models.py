"""Types partagés du pipeline de triage."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any


class Severity(IntEnum):
    """Échelle de gravité ordonnée (comparable avec <, max(), ...)."""

    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return {
            Severity.INFO: "Informatif",
            Severity.LOW: "Faible",
            Severity.MEDIUM: "Moyen",
            Severity.HIGH: "Élevé",
            Severity.CRITICAL: "Critique",
        }[self]

    @classmethod
    def from_name(cls, name: str) -> "Severity":
        """Tolère ce que renvoie un modèle (fr/en, casse variable)."""
        key = (name or "").strip().lower()
        mapping = {
            "info": cls.INFO, "informatif": cls.INFO, "informational": cls.INFO,
            "low": cls.LOW, "faible": cls.LOW,
            "medium": cls.MEDIUM, "moyen": cls.MEDIUM, "moderate": cls.MEDIUM,
            "high": cls.HIGH, "élevé": cls.HIGH, "eleve": cls.HIGH,
            "critical": cls.CRITICAL, "critique": cls.CRITICAL,
        }
        return mapping.get(key, cls.MEDIUM)


# Une alerte brute Wazuh est un simple dict ; on garde un alias pour la lisibilité.
Alert = dict[str, Any]


@dataclass
class Incident:
    """Groupe d'alertes corrélées."""

    key: str                       # clé de corrélation (agent::tactique::fenêtre)
    agent: str                     # nom de l'agent
    agent_id: str
    tactic: str                    # tactique MITRE dominante
    alerts: list[Alert] = field(default_factory=list)

    @property
    def size(self) -> int:
        return len(self.alerts)


@dataclass
class Facts:
    """Faits établis sans IA à partir des alertes d'un incident."""

    incident_key: str
    agent: str
    alert_count: int
    time_start: str
    time_end: str
    duration_minutes: float
    max_rule_level: int
    tactics: list[str]
    techniques: list[str]
    rule_groups: list[str]
    source_ips: list[str]
    dest_ips: list[str]
    users: list[str]
    files: list[str]
    highlights: list[str]          # signaux notables lisibles
    indicators: dict[str, bool]    # drapeaux booléens (lsass_access, log_cleared, ...)

    def as_dict(self) -> dict[str, Any]:
        d = self.__dict__.copy()
        return d


@dataclass
class GuardrailReport:
    """Trace de ce que les garde-fous ont fait."""

    injection_detected: bool = False
    injection_evidence: list[str] = field(default_factory=list)
    severity_floor: Severity = Severity.INFO
    severity_raised: bool = False   # True si le plancher a corrigé le modèle
    notes: list[str] = field(default_factory=list)


@dataclass
class ModelAssessment:
    """Sortie de l'étage LLM (conseil, jamais décision finale)."""

    summary: str
    recommended_actions: list[str]
    model_severity: Severity
    source: str                     # "api" ou "stub"


@dataclass
class TriageResult:
    """Résultat complet pour un incident, prêt à afficher."""

    incident: Incident
    facts: Facts
    priority_score: float
    severity: Severity              # gravité finale (après plancher)
    assessment: ModelAssessment
    guardrails: GuardrailReport
    playbooks: list[tuple[str, float]]  # (nom du playbook, score BM25)

    def as_dict(self) -> dict[str, Any]:
        return {
            "incident_key": self.incident.key,
            "agent": self.incident.agent,
            "tactic": self.incident.tactic,
            "alert_count": self.incident.size,
            "priority_score": round(self.priority_score, 2),
            "severity": self.severity.label,
            "facts": self.facts.as_dict(),
            "assessment": {
                "summary": self.assessment.summary,
                "recommended_actions": self.assessment.recommended_actions,
                "model_severity": self.assessment.model_severity.label,
                "source": self.assessment.source,
            },
            "guardrails": {
                "injection_detected": self.guardrails.injection_detected,
                "injection_evidence": self.guardrails.injection_evidence,
                "severity_floor": self.guardrails.severity_floor.label,
                "severity_raised_by_floor": self.guardrails.severity_raised,
                "notes": self.guardrails.notes,
            },
            "playbooks": [{"name": n, "score": round(s, 3)} for n, s in self.playbooks],
        }
