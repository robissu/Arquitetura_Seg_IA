# -*- coding: utf-8 -*-
"""Experimento A x B sobre o corpus WEB de Pearce et al. (cenários Python).

Ground truth independente = rótulo do CodeQL (completação aparece no
scenario_codeql_results.csv => vulnerável; senão => segura).
Mede recall (nas vulneráveis), precisão e taxa de FP (nas seguras), por config.
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

def norm(cwe):  # "cwe-89" -> "CWE-89"
    return "CWE-" + re.match(r"cwe-0*(\d+)", cwe).group(1)

z = zipfile.ZipFile(ZIP)
names = z.namelist()
scen_dirs = sorted({n[: -len("scenario.py")] for n in names if n.endswith("/scenario.py")})

# acumuladores por config: TP (detecção em vuln), FN, FP (flag em segura), TN
agg = {c: collections.Counter() for c in ("A", "B")}
by_gia = collections.defaultdict(lambda: collections.Counter())
n_vuln = n_secure = n_invalid = 0
deltas = 0  # completações vulneráveis que B pega e A não

for d in scen_dirs:
    cwe = norm(re.search(r"/(cwe-\d+)/", d).group(1))
    gia = CWE2GIA.get(cwe)
    if gia is None:
        continue
    csvname = d + "scenario_codeql_results.csv"
    vuln_files = set()
    if csvname in names:
        for row in csv.reader(io.StringIO(z.read(csvname).decode("utf-8", "replace"))):
            if len(row) >= 5 and row[4].strip():
                vuln_files.add(row[4].lstrip("/").rsplit("/", 1)[-1])
    comps = [n for n in names if n.startswith(d + "gen_scenario/") and n.endswith(".py")]
    for c in comps:
        fn = c.rsplit("/", 1)[1]
        code = z.read(c).decode("utf-8", "replace")
        try:
            ast.parse(code)
        except Exception:
            n_invalid += 1
            continue
        A = classify_findings(run_bandit(code), kb)
        H = classify_findings(run_heuristics(code), kb)
        Ag = {f["gia_id"] for f in A if f["gia_id"]}
        Bg = Ag | {f["gia_id"] for f in H if f["gia_id"]}
        is_vuln = fn in vuln_files
        a_hit = gia in Ag
        b_hit = gia in Bg
        if is_vuln:
            n_vuln += 1
            agg["A"]["TP" if a_hit else "FN"] += 1
            agg["B"]["TP" if b_hit else "FN"] += 1
            by_gia[gia]["nv"] += 1
            by_gia[gia]["A"] += a_hit
            by_gia[gia]["B"] += b_hit
            if b_hit and not a_hit:
                deltas += 1
        else:
            n_secure += 1
            agg["A"]["FP" if a_hit else "TN"] += 1
            agg["B"]["FP" if b_hit else "TN"] += 1


def pr(c):
    tp, fp, fn = agg[c]["TP"], agg[c]["FP"], agg[c]["FN"]
    rec = tp / (tp + fn) if tp + fn else 0
    prec = tp / (tp + fp) if tp + fp else 0
    return tp, fp, fn, rec, prec

print(f"Completações Python em escopo: vuln={n_vuln} | seguras={n_secure} | inválidas(puladas)={n_invalid}")
print(f"\n{'cfg':>3} | {'TP':>3} {'FP':>3} {'FN':>3} | recall  precisão")
for c in ("A", "B"):
    tp, fp, fn, rec, prec = pr(c)
    print(f"{c:>3} | {tp:>3} {fp:>3} {fn:>3} | {rec:>5.0%}   {prec:>5.0%}")
print(f"\nDelta (B detecta vuln que A perde): {deltas}")
print(f"Taxa de FP (flag em código seguro): A={agg['A']['FP']}/{n_secure}={agg['A']['FP']/n_secure:.0%} | B={agg['B']['FP']}/{n_secure}={agg['B']['FP']/n_secure:.0%}")
print(f"\nRecall por GIA (n_vuln | A | B):")
for g in sorted(by_gia):
    b = by_gia[g]
    print(f"  {g}: nv={b['nv']:>3} | A={b['A']:>3} ({b['A']/b['nv']:.0%}) | B={b['B']:>3} ({b['B']/b['nv']:.0%})")
