"""Accès robuste aux champs d'une alerte Wazuh.

Les alertes Wazuh ont une structure variable selon le décodeur (syslog,
sysmon, web, virustotal...). On centralise ici l'extraction pour que le
reste du pipeline ne manipule jamais directement la forme brute.
"""
from __future__ import annotations

from datetime import datetime, timezone

from .models import Alert


def rule(a: Alert) -> dict:
    return a.get("rule", {}) or {}


def level(a: Alert) -> int:
    try:
        return int(rule(a).get("level", 0))
    except (TypeError, ValueError):
        return 0


def description(a: Alert) -> str:
    return str(rule(a).get("description", ""))


def groups(a: Alert) -> list[str]:
    g = rule(a).get("groups", []) or []
    return [str(x) for x in g]


def agent_name(a: Alert) -> str:
    return str(a.get("agent", {}).get("name", "unknown"))


def agent_id(a: Alert) -> str:
    return str(a.get("agent", {}).get("id", "0"))


def tactics(a: Alert) -> list[str]:
    m = rule(a).get("mitre", {}) or {}
    t = m.get("tactic", []) or []
    return [str(x) for x in t]


def primary_tactic(a: Alert) -> str:
    t = tactics(a)
    return t[0] if t else "Uncategorized"


def techniques(a: Alert) -> list[str]:
    m = rule(a).get("mitre", {}) or {}
    t = m.get("id", []) or []
    return [str(x) for x in t]


def timestamp(a: Alert) -> datetime:
    ts = a.get("timestamp", "")
    for parse in (
        lambda s: datetime.fromisoformat(s.replace("Z", "+00:00")),
    ):
        try:
            dt = parse(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except (ValueError, AttributeError):
            pass
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _data(a: Alert) -> dict:
    return a.get("data", {}) or {}


def _win_eventdata(a: Alert) -> dict:
    return _data(a).get("win", {}).get("eventdata", {}) or {}


def source_ips(a: Alert) -> list[str]:
    out = []
    for k in ("srcip", "src_ip"):
        v = _data(a).get(k)
        if v:
            out.append(str(v))
    return out


def dest_ips(a: Alert) -> list[str]:
    out = []
    for k in ("dstip", "dst_ip"):
        v = _data(a).get(k)
        if v:
            out.append(str(v))
    return out


def users(a: Alert) -> list[str]:
    out = []
    for k in ("srcuser", "dstuser", "user"):
        v = _data(a).get(k)
        if v:
            out.append(str(v))
    ed = _win_eventdata(a)
    if ed.get("user"):
        out.append(str(ed["user"]))
    return out


def files(a: Alert) -> list[str]:
    out = []
    d = _data(a)
    for k in ("file",):
        if d.get(k):
            out.append(str(d[k]))
    ed = _win_eventdata(a)
    for k in ("targetFilename", "image", "targetImage"):
        if ed.get(k):
            out.append(str(ed[k]))
    vt = d.get("virustotal", {})
    src = (vt.get("source", {}) or {}).get("file") if isinstance(vt, dict) else None
    if src:
        out.append(str(src))
    return out


def searchable_text(a: Alert) -> str:
    """Concatène les champs textuels pertinents d'une alerte.

    Sert à la fois à la recherche BM25 et au scan d'injection. Inclut
    explicitement les champs décodés / lignes de commande, car c'est là que
    se cachent les instructions malveillantes.
    """
    parts: list[str] = [description(a), a.get("full_log", "")]
    parts += groups(a) + tactics(a) + techniques(a)
    ed = _win_eventdata(a)
    for k in ("commandLine", "decodedCommand", "image", "targetFilename",
              "targetImage", "serviceName"):
        if ed.get(k):
            parts.append(str(ed[k]))
    d = _data(a)
    for k in ("url", "query"):
        if d.get(k):
            parts.append(str(d[k]))
    return " ".join(p for p in parts if p)
