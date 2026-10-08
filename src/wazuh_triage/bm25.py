"""BM25 Okapi — implémentation autonome, sans dépendance.

Utilisé pour retrouver, pour chaque incident, les playbooks de réponse les
plus pertinents à partir de ses faits. Volontairement écrit à la main : le
corpus est petit, et c'est l'occasion de contrôler le tokeniseur (on garde
les identifiants de technique MITRE type « t1003 »).
"""
from __future__ import annotations

import math
import re
from collections import Counter

_TOKEN_RE = re.compile(r"[a-z0-9]+")


def tokenize(text: str) -> list[str]:
    return [t for t in _TOKEN_RE.findall(text.lower()) if len(t) >= 2]


class BM25:
    def __init__(self, k1: float = 1.5, b: float = 0.75) -> None:
        self.k1 = k1
        self.b = b
        self.names: list[str] = []
        self.docs: list[list[str]] = []
        self.doc_freqs: list[Counter] = []
        self.df: Counter = Counter()
        self.idf: dict[str, float] = {}
        self.avgdl: float = 0.0
        self._built = False

    def add(self, name: str, text: str) -> None:
        toks = tokenize(text)
        self.names.append(name)
        self.docs.append(toks)
        self.doc_freqs.append(Counter(toks))
        self._built = False

    def build(self) -> "BM25":
        n = len(self.docs)
        if n == 0:
            raise ValueError("BM25 : aucun document indexé")
        self.df = Counter()
        for tf in self.doc_freqs:
            self.df.update(tf.keys())
        self.idf = {
            term: math.log((n - dfi + 0.5) / (dfi + 0.5) + 1.0)
            for term, dfi in self.df.items()
        }
        self.avgdl = sum(len(d) for d in self.docs) / n
        self._built = True
        return self

    def _score_doc(self, q_terms: list[str], i: int) -> float:
        tf = self.doc_freqs[i]
        dl = len(self.docs[i])
        score = 0.0
        for term in q_terms:
            f = tf.get(term, 0)
            if f == 0:
                continue
            idf = self.idf.get(term, 0.0)
            denom = f + self.k1 * (1 - self.b + self.b * dl / self.avgdl)
            score += idf * (f * (self.k1 + 1)) / denom
        return score

    def query(self, text: str, k: int = 3) -> list[tuple[str, float]]:
        """Renvoie les k meilleurs (nom, score), scores strictement positifs."""
        if not self._built:
            self.build()
        q_terms = tokenize(text)
        scored = [
            (self.names[i], self._score_doc(q_terms, i))
            for i in range(len(self.docs))
        ]
        scored = [(n, s) for n, s in scored if s > 0.0]
        scored.sort(key=lambda x: (-x[1], x[0]))
        return scored[:k]
