"""Base de connaissances de playbooks, interrogée par BM25."""
from __future__ import annotations

from pathlib import Path

from .bm25 import BM25
from .models import Facts

_DEFAULT_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "playbooks"


def facts_to_query(facts: Facts) -> str:
    """Construit la requête de recherche à partir des faits de l'incident."""
    parts: list[str] = []
    parts += facts.tactics
    parts += facts.techniques
    parts += facts.rule_groups
    parts += facts.highlights
    return " ".join(parts)


class KnowledgeBase:
    def __init__(self) -> None:
        self.index = BM25()
        self.texts: dict[str, str] = {}

    @classmethod
    def from_dir(cls, path: str | Path | None = None) -> "KnowledgeBase":
        directory = Path(path) if path else _DEFAULT_DIR
        kb = cls()
        files = sorted(directory.glob("*.md"))
        if not files:
            raise FileNotFoundError(f"Aucun playbook dans {directory}")
        for f in files:
            text = f.read_text(encoding="utf-8")
            name = f.stem
            kb.texts[name] = text
            kb.index.add(name, text)
        kb.index.build()
        return kb

    def retrieve(self, facts: Facts, k: int = 3) -> list[tuple[str, float]]:
        return self.index.query(facts_to_query(facts), k=k)

    def text_of(self, name: str) -> str:
        return self.texts.get(name, "")
