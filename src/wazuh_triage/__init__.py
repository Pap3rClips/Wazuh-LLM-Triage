"""Wazuh LLM Triage — regroupe des alertes Wazuh en incidents priorisés,
établit des faits déterministes, puis demande à un modèle un résumé et des
actions. Le modèle conseille, il ne décide jamais seul."""

__version__ = "0.1.0"

from .models import (  # noqa: F401
    Alert,
    Facts,
    GuardrailReport,
    Incident,
    ModelAssessment,
    Severity,
    TriageResult,
)
