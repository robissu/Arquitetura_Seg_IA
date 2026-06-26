# -*- coding: utf-8 -*-
"""Experimento A (Bandit) x B (arquitetura) sobre o SecurityEval.

Ground truth = CWE rotulado de cada amostra; mapeado para a categoria GIA que a
arquitetura mira (em escopo). Mede recall por configuração, delta (FN do baseline
recuperados pelas heurísticas) e volume de achados (proxy de precisão/ruído).
"""
import ast
import collections
import json
import os
import re
import sys
from pathlib import Path

os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
sys.path.insert(0, "src")
from analyze.sast import run_bandit
from analyze.heuristics import run_heuristics
from classify.classifier import classify_findings, load_knowledge_base

SE = Path(os.environ["SE"])
kb = load_knowledge_base()

# CWE (em escopo) -> GIA: categorias-alvo da arquitetura (guia + heurísticas)
CWE2GIA = {
    "CWE-20": "GIA-001", "CWE-78": "GIA-001", "CWE-79": "GIA-001", "CWE-89": "GIA-001",
    "CWE-306": "GIA-002", "CWE-862": "GIA-002", "CWE-863": "GIA-002", "CWE-639": "GIA-002",
    "CWE-829": "GIA-003", "CWE-1104": "GIA-003",
    "CWE-798": "GIA-004", "CWE-200": "GIA-004",
    "CWE-703": "GIA-005", "CWE-209": "GIA-005",
    "CWE-16": "GIA-006",
    "CWE-546": "GIA-007",
}

def norm_cwe(raw):  # "CWE-020" -> "CWE-20"
    m = re.match(r"CWE-0*(\d+)", raw)
    return f"CWE-{m.group(1)}" if m else raw

rows = [json.loads(l) for l in open(SE / "dataset.jsonl", encoding="utf-8")]

n_in = n_out = 0
A_hit = B_hit = 0
deltas = []                       # amostras em escopo que B pega e A não
by_gia = collections.defaultdict(lambda: [0, 0, 0])  # gia -> [n, A_hit, B_hit]
out_flagged_A = out_flagged_B = 0
findings_A = findings_B = 0       # volume total de achados (proxy precisão)
tp_find_A = tp_find_B = 0         # achados que casam a GIA-alvo

for r in rows:
    code = r["Insecure_code"]
    gt = CWE2GIA.get(norm_cwe(re.match(r"(CWE-\d+)", r["ID"]).group(1)))
    A = classify_findings(run_bandit(code), kb)
    H = classify_findings(run_heuristics(code), kb)
    A_g = {f["gia_id"] for f in A if f["gia_id"]}
    B_g = A_g | {f["gia_id"] for f in H if f["gia_id"]}
    findings_A += len(A); findings_B += len(A) + len(H)
    if gt is None:
        n_out += 1
        if A_g: out_flagged_A += 1
        if B_g: out_flagged_B += 1
        continue
    n_in += 1
    a = gt in A_g; b = gt in B_g
    A_hit += a; B_hit += b
    tp_find_A += sum(1 for f in A if f["gia_id"] == gt)
    tp_find_B += sum(1 for f in (A + H) if f["gia_id"] == gt)
    by_gia[gt][0] += 1; by_gia[gt][1] += a; by_gia[gt][2] += b
    if b and not a:
        deltas.append((r["ID"], gt))

print(f"Amostras: {len(rows)} | em escopo: {n_in} | fora de escopo: {n_out}")
print(f"\nRECALL (amostras em escopo, n={n_in}):")
print(f"  A (Bandit só):    {A_hit}/{n_in} = {A_hit/n_in:.0%}")
print(f"  B (arquitetura):  {B_hit}/{n_in} = {B_hit/n_in:.0%}")
print(f"  Delta (B pega, A não): {len(deltas)} amostras")
print(f"\nPor GIA (n | A | B):")
for g in sorted(by_gia):
    n, a, b = by_gia[g]
    print(f"  {g}: n={n:>2} | A={a:>2} ({a/n:.0%}) | B={b:>2} ({b/n:.0%})")
print(f"\nVolume de achados (proxy precisão):")
print(f"  A: {findings_A} achados, {tp_find_A} casam a GIA-alvo ({tp_find_A/findings_A:.0%})")
print(f"  B: {findings_B} achados, {tp_find_B} casam a GIA-alvo ({tp_find_B/findings_B:.0%})")
print(f"\nFora de escopo (n={n_out}): A sinalizou algo em {out_flagged_A}; B em {out_flagged_B}")
print(f"\nExemplos de delta (B recupera): {[d[0] for d in deltas[:12]]}")
