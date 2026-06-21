"""Runner de demonstração: normalize -> SAST (Bandit) -> heurísticas.

Captura a saída concreta do Módulo 2 para evidência no TCC.
Uso: python demo_pipeline.py data/input/exemplo_02.txt
"""
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, "src")
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from collect.normalize import normalize_code
from analyze.sast import run_bandit
from analyze.heuristics import run_heuristics


def main(input_path: str):
    raw = Path(input_path).read_text(encoding="utf-8")
    norm = normalize_code(raw)

    print("=" * 70)
    print(f"ENTRADA: {input_path}")
    print("=" * 70)
    print(f"\n[1] NORMALIZAÇÃO — status: {norm['status']}")
    print(f"    linhas: {norm['metadata']['line_count']} | "
          f"funções: {norm['metadata']['functions']} | "
          f"imports: {norm['metadata']['imports']}")

    if norm["status"] == "invalid":
        print("\n  Código inválido — análise bloqueada.")
        return

    code = norm["code"]

    bandit_findings = run_bandit(code)
    heur_findings = run_heuristics(code, requirements_path="requirements.txt")
    all_findings = bandit_findings + heur_findings

    print(f"\n[2] ANÁLISE DE SEGURANÇA — {len(all_findings)} achados "
          f"({len(bandit_findings)} SAST + {len(heur_findings)} heurísticas)\n")
    print(f"  {'ORIGEM':<10} {'REGRA':<7} {'LINHA':<6} {'SEV':<7} {'CONF':<7} DESCRIÇÃO")
    print(f"  {'-'*10} {'-'*7} {'-'*6} {'-'*7} {'-'*7} {'-'*40}")
    for f in sorted(all_findings, key=lambda x: x["line"]):
        desc = f["description"][:52]
        print(f"  {f['origin']:<10} {f['rule_id']:<7} {f['line']:<6} "
              f"{f['severity']:<7} {f['confidence']:<7} {desc}")

    # saída estruturada (formato intermediário unificado)
    out = Path("data/output/exemplo_02_achados.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(all_findings, indent=2, ensure_ascii=False),
                   encoding="utf-8")
    print(f"\n[3] SAÍDA ESTRUTURADA salva em: {out}")

    print("\n--- Exemplo de achado no formato intermediário unificado ---")
    sample = next((f for f in all_findings if f["origin"] == "heuristic"), all_findings[0])
    print(json.dumps(sample, indent=2, ensure_ascii=False))


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "data/input/exemplo_02.txt"
    main(target)
