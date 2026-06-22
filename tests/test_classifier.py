"""Testes do Módulo 3 — classificação (`classify/classifier.py`).

Oráculo: o mapeamento regra→GIA (TCC §3.2/§3.3.3) e os catálogos CWE (MITRE) e
OWASP Top 10 2021 referenciados pelo guia (knowledge_base.json). A classificação
associa cada achado a uma categoria de risco e sinaliza, no terceiro nível, os
achados que exigem revisão manual.
"""
from classify.classifier import classify_findings


def test_b608_mapeia_gia001_cwe89_owasp_a03(make_finding, knowledge_base):
    """B608 → GIA-001, CWE-89, OWASP A03:2021.

    Fonte: OWASP Top 10 2021 A03 (Injection); MITRE CWE-89 (SQL Injection).
    """
    classificado = classify_findings([make_finding("bandit", "B608")], knowledge_base)[0]
    assert classificado["gia_id"] == "GIA-001"
    assert "CWE-89" in classificado["cwe"]
    assert any("A03" in owasp for owasp in classificado["owasp"])
    assert classificado["requires_manual_review"] is False


def test_h006_mapeia_gia002_cwe306_owasp_a07(make_finding, knowledge_base):
    """H006 → GIA-002, CWE-306, OWASP A01/A07.

    Fonte: OWASP Top 10 2021 A01/A07; MITRE CWE-306 (Missing Authentication).
    """
    classificado = classify_findings([make_finding("heuristic", "H006")], knowledge_base)[0]
    assert classificado["gia_id"] == "GIA-002"
    assert "CWE-306" in classificado["cwe"]
    assert any("A07" in owasp for owasp in classificado["owasp"])


def test_regra_sem_mapeamento_exige_revisao_manual(make_finding, knowledge_base):
    """Regra desconhecida → 'Não classificado' + requires_manual_review.

    Fonte: terceiro nível da classificação (TCC §3.3.3) — diferenciar achados
    que exigem revisão manual.
    """
    classificado = classify_findings([make_finding("bandit", "B999")], knowledge_base)[0]
    assert classificado["gia_id"] is None
    assert classificado["gia_category"] == "Não classificado"
    assert classificado["requires_manual_review"] is True


def test_prioridade_vem_do_guia(make_finding, knowledge_base):
    """A prioridade é copiada do guia como rótulo único (Alta/Média/Baixa)."""
    classificado = classify_findings([make_finding("bandit", "B608")], knowledge_base)[0]
    assert classificado["priority"] in ("Alta", "Média", "Baixa")


def test_preserva_campos_originais_do_achado(make_finding, knowledge_base):
    """A classificação enriquece sem descartar os campos do achado original."""
    classificado = classify_findings([make_finding("bandit", "B608")], knowledge_base)[0]
    for campo in ("origin", "rule_id", "line", "severity", "description", "context"):
        assert campo in classificado
