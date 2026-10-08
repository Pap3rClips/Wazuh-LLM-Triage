from wazuh_triage.bm25 import BM25, tokenize
from wazuh_triage.knowledge import KnowledgeBase
from wazuh_triage.models import Facts


def test_tokenizer_keeps_technique_ids():
    toks = tokenize("Mimikatz T1003.001 lsass.exe")
    assert "t1003" in toks and "001" in toks and "lsass" in toks


def test_bm25_ranks_relevant_document_first():
    idx = BM25()
    idx.add("ssh", "ssh brute force authentication failure fail2ban")
    idx.add("malware", "virustotal malware hash quarantine ransomware")
    idx.add("web", "sql injection path traversal web shell upload")
    idx.build()
    top = idx.query("malware hash virustotal quarantine", k=1)
    assert top[0][0] == "malware"
    assert top[0][1] > 0


def test_bm25_empty_query_returns_nothing():
    idx = BM25()
    idx.add("a", "one two three")
    idx.build()
    assert idx.query("zzz nonexistent", k=3) == []


def _facts(**kw):
    base = dict(
        incident_key="k", agent="h", alert_count=1, time_start="", time_end="",
        duration_minutes=0.0, max_rule_level=10, tactics=[], techniques=[],
        rule_groups=[], source_ips=[], dest_ips=[], users=[], files=[],
        highlights=[], indicators={},
    )
    base.update(kw)
    return Facts(**base)


def test_knowledge_base_retrieves_matching_playbook():
    kb = KnowledgeBase.from_dir()  # data/playbooks par défaut
    f = _facts(tactics=["Credential Access"], techniques=["T1003.001"],
               rule_groups=["credential_dumping", "sysmon"],
               highlights=["Accès à la mémoire LSASS"])
    top = kb.retrieve(f, k=3)
    assert top, "aucun playbook retrouvé"
    assert top[0][0] == "pb-credential-dumping"
