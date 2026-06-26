# -*- coding: utf-8 -*-
"""Prévia da comparação A (Bandit só) x B (arquitetura) nos 3 exemplos."""
import os
import sys
from pathlib import Path

os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
sys.path.insert(0, "src")
from collect.normalize import normalize_code
from analyze.sast import run_bandit
from analyze.heuristics import run_heuristics
from classify.classifier import classify_findings, load_knowledge_base

kb = load_knowledge_base()


def fmt(fs):
    return [(f["rule_id"], f["line"], f.get("gia_id")) for f in fs]


for name in ["exemplo_01", "exemplo_02", "exemplo_03"]:
    raw = Path(f"data/input/{name}.txt").read_text(encoding="utf-8")
    norm = normalize_code(raw)
    print("=" * 64)
    print(f"{name}  | status: {norm['status']}")
    if norm["status"] == "invalid":
        print("  -> BLOQUEADO (sintaxe inválida) — nenhuma análise em A nem em B")
        continue
    A = classify_findings(run_bandit(norm["code"]), kb)
    H = classify_findings(run_heuristics(norm["code"], requirements_path="requirements.txt"), kb)
    print(f"  A (Bandit só):        {len(A):>2} achados  {fmt(A)}")
    print(f"  Heurísticas (delta):  {len(H):>2} achados  {fmt(H)}")
    giaA = sorted({f['gia_id'] for f in A if f['gia_id']})
    giaB = sorted({f['gia_id'] for f in (A + H) if f['gia_id']})
    print(f"  GIA cobertas  A: {giaA}")
    print(f"  GIA cobertas  B: {giaB}")
    print(f"  GIA só por heurística (delta): {sorted(set(giaB) - set(giaA))}")
