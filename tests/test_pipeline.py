"""Testes de integração — pipeline completo (end-to-end).

Oráculo: o contrato da arquitetura (TCC §3.3) aplicado ao exemplo vulnerável de
referência (data/input/exemplo_02.txt) e ao exemplo sintaticamente inválido
(exemplo_01.txt). Confirma que os quatro módulos se integram e produzem o
relatório esperado, e que a análise é bloqueada para código inválido.
"""
from pathlib import Path

from analyze.heuristics import run_heuristics
from analyze.sast import run_bandit
from classify.classifier import classify_findings
from collect.normalize import normalize_code
from recommend.recommender import generate_report

ROOT = Path(__file__).resolve().parents[1]


def _run_pipeline(raw, kb, file_name):
    norm = normalize_code(raw)
    findings = run_bandit(norm["code"]) + run_heuristics(
        norm["code"], requirements_path=str(ROOT / "requirements.txt")
    )
    classified = classify_findings(findings, kb)
    return norm, generate_report(norm, classified, kb, file_name=file_name)


def test_exemplo_vulneravel_produz_relatorio(knowledge_base):
    """exemplo_02 (válido e vulnerável) → relatório com achados das duas camadas."""
    raw = (ROOT / "data" / "input" / "exemplo_02.txt").read_text(encoding="utf-8")
    norm, report = _run_pipeline(raw, knowledge_base, "exemplo_02.txt")

    assert norm["status"] == "valid"
    assert report["analysis_summary"]["total_findings"] > 0
    # achados de ambas as camadas (SAST + heurística) chegam ao relatório
    origins = {f["origin"] for f in report["findings"]}
    assert {"bandit", "heuristic"} <= origins
    # o resumo agrupado por GIA é populado
    assert report["gia_summary"]


def test_entrada_invalida_bloqueia_analise():
    """exemplo_01 (sintaxe inválida) → normalização bloqueia a análise."""
    raw = (ROOT / "data" / "input" / "exemplo_01.txt").read_text(encoding="utf-8")
    norm = normalize_code(raw)
    assert norm["status"] == "invalid"
    assert norm["errors"]


def test_main_analyze_file_grava_relatorio(monkeypatch, tmp_path, knowledge_base):
    """main.analyze_file roda o pipeline e grava o relatório (saída em tmp)."""
    import main

    monkeypatch.setattr(main, "OUTPUT_DIR", tmp_path)
    entrada = ROOT / "data" / "input" / "exemplo_02.txt"
    report, out_path = main.analyze_file(entrada, knowledge_base)

    assert out_path.exists()
    assert report["analysis_summary"]["status"] == "valid"
    assert report["analysis_summary"]["total_findings"] > 0
