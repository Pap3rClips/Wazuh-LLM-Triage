"""Interface en ligne de commande.

    python -m wazuh_triage.cli --alerts data/alerts.sample.json
    python -m wazuh_triage.cli --alerts data/alerts.sample.json --json
    python -m wazuh_triage.cli --alerts data/alerts.sample.json --offline
"""
from __future__ import annotations

import argparse
import json
import sys

from .pipeline import run

_BAR = "─" * 70


def _print_human(results) -> None:
    print(f"\n{len(results)} incident(s) priorisé(s)\n")
    for i, r in enumerate(results, 1):
        g = r.guardrails
        print(_BAR)
        print(f"#{i}  [{r.severity.label.upper()}]  {r.incident.agent}  "
              f"· {r.incident.tactic}  · score {r.priority_score:.0f}")
        print(f"    {r.incident.size} alertes · niveau max {r.facts.max_rule_level} "
              f"· {r.facts.duration_minutes:.0f} min · "
              f"{r.facts.time_start} → {r.facts.time_end}")
        if r.facts.highlights:
            print("    Faits : " + " ; ".join(r.facts.highlights))
        print(f"    Modèle ({r.assessment.source}) : {r.assessment.summary}")
        print("    Actions :")
        for a in r.assessment.recommended_actions:
            print(f"      • {a}")
        if r.playbooks:
            pbs = ", ".join(f"{n} ({s:.2f})" for n, s in r.playbooks)
            print(f"    Playbooks (BM25) : {pbs}")
        if g.injection_detected:
            print(f"    ⚠ Injection détectée ({len(g.injection_evidence)} motif(s)) "
                  f"— ignorée, évaluation fondée sur les faits.")
        if g.severity_raised:
            print(f"    ⚠ Gravité relevée par le plancher : le modèle proposait "
                  f"« {r.assessment.model_severity.label} ».")
    print(_BAR)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="wazuh-triage",
        description="Regroupe des alertes Wazuh en incidents priorisés et "
                    "produit un résumé + des actions, garde-fous compris.")
    p.add_argument("--alerts", required=True, help="fichier d'alertes (JSONL ou JSON)")
    p.add_argument("--playbooks", default=None, help="répertoire des playbooks")
    p.add_argument("--top-k", type=int, default=3, help="playbooks par incident")
    p.add_argument("--window", type=float, default=30.0,
                   help="fenêtre de corrélation en minutes")
    p.add_argument("--offline", action="store_true",
                   help="forcer le stub déterministe (aucun appel API)")
    p.add_argument("--json", action="store_true", help="sortie JSON")
    args = p.parse_args(argv)

    results = run(args.alerts, kb_dir=args.playbooks, top_k=args.top_k,
                  force_stub=args.offline, window_minutes=args.window)

    if args.json:
        json.dump([r.as_dict() for r in results], sys.stdout,
                  ensure_ascii=False, indent=2)
        print()
    else:
        _print_human(results)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
