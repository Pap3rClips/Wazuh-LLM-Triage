"""Lecture des alertes Wazuh depuis un fichier JSON Lines ou un tableau JSON."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Alert


def load_alerts(path: str | Path) -> list[Alert]:
    """Charge les alertes depuis un fichier.

    Accepte deux formats :
      - JSON Lines (une alerte par ligne), format natif de Wazuh (alerts.json) ;
      - un tableau JSON unique.

    Les lignes vides et les lignes JSON invalides sont ignorées (robuste aux
    logs réels, parfois tronqués), mais au moins une alerte valide est requise.
    """
    p = Path(path)
    text = p.read_text(encoding="utf-8").strip()
    if not text:
        return []

    # Tableau JSON unique.
    if text[0] == "[":
        data = json.loads(text)
        return [a for a in data if isinstance(a, dict)]

    # JSON Lines.
    alerts: list[Alert] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            alerts.append(obj)
    return alerts
