"""Ponto de entrada — pipeline completo de análise de segurança.

Fluxo: normalize -> (Bandit + heurísticas) -> classificação -> recomendação
-> relatório JSON. Processa todos os .txt em data/input/ (ou os arquivos
passados como argumento) e salva um relatório por entrada em data/output/.

Uso:
    python src/main.py                          # processa data/input/*.txt
    python src/main.py data/input/exemplo_02.txt
"""
import io
import os
import sys
from pathlib import Path

# garante que isort/black do venv sejam encontrados — normalize.py os chama por
# nome via subprocess e depende do PATH (sast.py já localiza o bandit por caminho)
os.environ["PATH"] = (
    str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
)

from collect.normalize import normalize_code
from analyze.sast import run_bandit
from analyze.heuristics import run_heuristics
from classify.classifier import classify_findings, load_knowledge_base
from recommend.recommender import (
    generate_error_report,
    generate_report,
    save_report,
)

INPUT_DIR = Path("data/input")
OUTPUT_DIR = Path("data/output")
REQUIREMENTS = "requirements.txt"


def analyze_file(input_path: Path, knowledge_base: dict) -> tuple[dict, Path]:
    """Executa o pipeline completo sobre um arquivo e salva o relatório.

    Retorna (relatório, caminho_do_relatório).
    """
    raw = input_path.read_text(encoding="utf-8")
    normalized = normalize_code(raw)

    # código sintaticamente inválido → bloqueia análise e gera relatório de erro
    if normalized["status"] == "invalid":
        report = generate_error_report(normalized, file_name=input_path.name)
    else:
        findings = run_bandit(normalized["code"]) + run_heuristics(
            normalized["code"], requirements_path=REQUIREMENTS
        )
        classified = classify_findings(findings, knowledge_base)
        report = generate_report(
            normalized, classified, knowledge_base, file_name=input_path.name
        )

    out_path = OUTPUT_DIR / f"{input_path.stem}_report.json"
    save_report(report, out_path)
    return report, out_path


def _print_summary(input_path: Path, report: dict, out_path: Path) -> None:
    """Imprime no terminal um resumo legível do relatório."""
    summary = report["analysis_summary"]
    print("\n" + "=" * 72)
    print(f"ENTRADA: {input_path.name}")
    print("=" * 72)
    print(f"status: {summary['status']} | achados: {summary['total_findings']}")

    if summary["status"] == "invalid":
        print("Código inválido — análise de segurança bloqueada.")
        for err in report.get("errors", []):
            print(f"  erro: {err}")
    else:
        print(f"por severidade: {summary['by_severity']}")
        print(f"por GIA:        {summary['by_gia']}")
        print("\nresumo por GIA:")
        for grupo in report["gia_summary"]:
            gid = grupo["gia_id"] or "Não classificado"
            categoria = (grupo["gia_category"] or "")[:40]
            print(
                f"  {gid:<16} {categoria:<40} prio={grupo['priority']} | "
                f"{grupo['finding_count']} achado(s) linhas {grupo['lines']}"
            )

    print(f"\nrelatório salvo em: {out_path}")


def main(targets: list[Path]) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    if not targets:
        print(f"Nenhum arquivo .txt encontrado em {INPUT_DIR}/")
        return

    knowledge_base = load_knowledge_base()

    for input_path in targets:
        if not input_path.exists():
            print(f"[ignorado] arquivo não encontrado: {input_path}")
            continue
        report, out_path = analyze_file(input_path, knowledge_base)
        _print_summary(input_path, report, out_path)


if __name__ == "__main__":
    # saída UTF-8 no console do Windows (evita erro com acentos/—)
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    if len(sys.argv) > 1:
        cli_targets = [Path(arg) for arg in sys.argv[1:]]
    else:
        cli_targets = sorted(INPUT_DIR.glob("*.txt"))
    main(cli_targets)
