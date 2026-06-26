# -*- coding: utf-8 -*-
"""Experimento A x B sobre Pearce (Python) com ground truth CORRETO de Pearce.

Usa dow_results.csv: cada completação é rotulada vulnerável/segura pelos próprios
autores (evaluated_by = codeql p/ vulns de fluxo; authors p/ controle ausente como
CWE-306). Rótulo por completação via casamento do score mean_prob.
Mede recall (vuln) e precisão/FP (seguras), por config e por GIA.
"""
import ast
import collections
import csv
import io
import os
import re
import sys
import zipfile
from pathlib import Path

os.environ["PATH"] = str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
sys.path.insert(0, "src")
from analyze.sast import run_bandit
from analyze.heuristics import run_heuristics
from classify.classifier import classify_findings, load_knowledge_base

ZIP = Path(os.environ["PZIP"])
kb = load_knowledge_base()
CWE2GIA = {
    "CWE-20": "GIA-001", "CWE-78": "GIA-001", "CWE-79": "GIA-001", "CWE-89": "GIA-001",
    "CWE-306": "GIA-002", "CWE-798": "GIA-004", "CWE-200": "GIA-004",
}
z = zipfile.ZipFile(ZIP)
names = z.namelist()
root = "copilot-cwe-scenarios-dataset/"
rows = list(csv.DictReader(io.StringIO(z.read(root + "dow_results.csv").decode("utf-8", "replace"))))

def score_of(code):
    m = re.search(r"mean_prob:\s*([0-9.]+)", code)
    return round(float(m.group(1)), 10) if m else None

agg = {c: collections.Counter() for c in ("A", "B")}
by_gia = collections.defaultdict(lambda: collections.Counter())
evalby = collections.Counter()
n_v = n_s = 0
deltas = []

for row in rows:
    if row["language"] != "python":
        continue
    gia = CWE2GIA.get(row["cwe"])
    if gia is None:
        continue
    folder = root + row["scenario_folder"] + "/gen_scenario/"
    vuln = {round(x, 10) for x in ast.literal_eval(row["vulnerable_scores_array"])}
    secure = {round(x, 10) for x in ast.literal_eval(row["nonvulnerable_scores_array"])}
    evalby[row["evaluated_by"]] += 1
    comps = [n for n in names if n.startswith(folder) and n.endswith(".py")]
    for c in comps:
        code = z.read(c).decode("utf-8", "replace")
        sc = score_of(code)
        if sc is None:
            continue
        is_v = sc in vuln
        is_s = sc in secure
        if not (is_v or is_s):
            continue
        try:
            ast.parse(code)
        except Exception:
            continue
        A = classify_findings(run_bandit(code), kb)
        H = classify_findings(run_heuristics(code), kb)
        Ag = {f["gia_id"] for f in A if f["gia_id"]}
        Bg = Ag | {f["gia_id"] for f in H if f["gia_id"]}
        a, b = gia in Ag, gia in Bg
        if is_v:
            n_v += 1
            agg["A"]["TP" if a else "FN"] += 1
            agg["B"]["TP" if b else "FN"] += 1
            by_gia[gia]["nv"] += 1; by_gia[gia]["A"] += a; by_gia[gia]["B"] += b
            if b and not a:
                deltas.append((row["cwe"], c.rsplit("/", 1)[1]))
        else:
            n_s += 1
            agg["A"]["FP" if a else "TN"] += 1
            agg["B"]["FP" if b else "TN"] += 1
            by_gia[gia]["ns"] += 1; by_gia[gia]["Afp"] += a; by_gia[gia]["Bfp"] += b

def m(c):
    tp, fp, fn = agg[c]["TP"], agg[c]["FP"], agg[c]["FN"]
    rec = tp / (tp + fn) if tp + fn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    return tp, fp, fn, rec, prec

print(f"Ground truth Pearce | avaliação dos cenários: {dict(evalby)}")
print(f"Completações: vulneráveis={n_v} | seguras={n_s}")
print(f"\n{'cfg':>3} | {'TP':>3} {'FP':>3} {'FN':>3} | recall  precisão")
for c in ("A", "B"):
    tp, fp, fn, rec, prec = m(c)
    print(f"{c:>3} | {tp:>3} {fp:>3} {fn:>3} | {rec:>5.0%}   {prec:>5.0%}")
print(f"\nDelta (B detecta vuln que A perde): {len(deltas)}  ex={[d[0] for d in deltas[:8]]}")
print(f"\nPor GIA:")
for g in sorted(by_gia):
    b = by_gia[g]
    rA = b['A']/b['nv'] if b['nv'] else 0
    rB = b['B']/b['nv'] if b['nv'] else 0
    fpA = b['Afp']/b['ns'] if b['ns'] else 0
    fpB = b['Bfp']/b['ns'] if b['ns'] else 0
    print(f"  {g}: vuln={b['nv']:>2} recall A={rA:.0%} B={rB:.0%} | seguras={b['ns']:>2} FP A={fpA:.0%} B={fpB:.0%}")
