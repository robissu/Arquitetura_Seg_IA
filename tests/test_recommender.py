"""Testes do Módulo 4 — recomendação (`recommend/recommender.py`).

Oráculo: o guia técnico (knowledge_base.json) e os padrões que ele referencia
(OWASP Cheat Sheet Series, OWASP ASVS, pip-audit). O módulo faz lookup puro: a
recomendação reflete o guia sem gerar texto novo nem corrigir código (TCC §3.3.4).
"""
from classify.classifier import classify_findings
from recommend.recommender import (
    build_recommendation,
    generate_error_report,
    generate_report,
)


def test_gia001_recomendacao_tem_os_tres_campos(knowledge_base):
    """GIA-001 → recomendação com impacto + verificar/corrigir/validar.

    Fonte: guia GIA-001; OWASP Cheat Sheet (Input Validation / SQL Injection);
    OWASP ASVS (capítulo de Validação).
    """
    finding = {"gia_id": "GIA-001", "requires_manual_review": False}
    rec = build_recommendation(finding, knowledge_base)
    assert rec["impact"]
    assert rec["what_to_check"]
    assert isinstance(rec["how_to_fix"], list) and rec["how_to_fix"]
    assert rec["how_to_validate"]
    assert rec["requires_manual_review"] is False


def test_gia003_menciona_pip_audit_e_pypi(knowledge_base):
    """GIA-003 → orientação cita pip-audit e verificação no PyPI.

    Fonte: Spracklen et al. (2025); documentação do pip-audit.
    """
    finding = {"gia_id": "GIA-003", "requires_manual_review": False}
    texto = " ".join(build_recommendation(finding, knowledge_base)["how_to_fix"]).lower()
    assert "pip-audit" in texto
    assert "pypi" in texto


def test_achado_nao_classificado_requer_revisao(knowledge_base):
    """Achado sem gia_id → nota de revisão manual e how_to_fix vazio."""
    rec = build_recommendation({"gia_id": None, "requires_manual_review": True}, knowledge_base)
    assert rec["requires_manual_review"] is True
    assert rec["how_to_fix"] == []
    assert rec["what_to_check"]  # nota orientando revisão manual


def test_generate_report_estrutura_completa(make_finding, knowledge_base):
    """O relatório tem analysis_summary + findings (aninhado) + gia_summary."""
    classified = classify_findings([make_finding("bandit", "B608")], knowledge_base)
    report = generate_report({"status": "valid"}, classified, knowledge_base, file_name="t.py")

    assert {"analysis_summary", "findings", "gia_summary"} <= set(report)
    assert report["analysis_summary"]["total_findings"] == 1
    assert report["analysis_summary"]["by_gia"] == {"GIA-001": 1}

    achado = report["findings"][0]
    assert "classification" in achado and "recommendation" in achado

    grupo = report["gia_summary"][0]
    assert grupo["gia_id"] == "GIA-001"
    assert grupo["finding_count"] == 1


def test_generate_error_report_para_entrada_invalida():
    """Entrada inválida → relatório de erro sem achados, expondo os erros.

    Fonte: NIST SP 800-218 (SSDF) — bloquear artefato inválido antes de seguir.
    """
    normalized = {"status": "invalid", "errors": [{"type": "syntax_error"}], "warnings": []}
    report = generate_error_report(normalized, file_name="bad.py")
    assert report["analysis_summary"]["status"] == "invalid"
    assert report["findings"] == []
    assert report["errors"]
