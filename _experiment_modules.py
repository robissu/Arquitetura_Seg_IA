# -*- coding: utf-8 -*-
"""Avaliação dos módulos 3 (classificação) e 4 (recomendação) + ablação H001-H008.

Roda sobre o corpus Pearce (Python) com o ground truth correto (dow_results.csv).
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

def reco_complete(gia):
    e = kb.get(gia, {})
    mit = e.get("mitigacao", {})
    return all([e.get("impacto"), mit.get("o_que_verificar"),
                mit.get("como_corrigir"), mit.get("como_validar")])

heur_vuln = collections.Counter()   # H00x -> fires em completação vulnerável
heur_sec = collections.Counter()    # H00x -> fires em completação segura
n_findings = n_classified = n_manual = 0
tp_cwe_total = tp_cwe_covered = 0
reco_total = reco_ok = 0

for row in rows:
    if row["language"] != "python":
        continue
    gt_cwe = row["cwe"]
    gia = CWE2GIA.get(gt_cwe)
    if gia is None:
        continue
    folder = root + row["scenario_folder"] + "/gen_scenario/"
    vuln = {round(x, 10) for x in ast.literal_eval(row["vulnerable_scores_array"])}
    secure = {round(x, 10) for x in ast.literal_eval(row["nonvulnerable_scores_array"])}
    for c in [n for n in names if n.startswith(folder) and n.endswith(".py")]:
        code = z.read(c).decode("utf-8", "replace")
        sc = score_of(code)
        if sc not in vuln and sc not in secure:
            continue
        try:
            ast.parse(code)
        except Exception:
            continue
        is_v = sc in vuln
        allf = classify_findings(run_bandit(code) + run_heuristics(code), kb)
        for f in allf:
            n_findings += 1
            if f["gia_id"]:
                n_classified += 1
            else:
                n_manual += 1
            # recomendação completa p/ achados classificados
            if f["gia_id"]:
                reco_total += 1
                reco_ok += reco_complete(f["gia_id"])
            # ablação por heurística
            rid = f["rule_id"]
            if rid.startswith("H"):
                (heur_vuln if is_v else heur_sec)[rid] += 1
            # cobertura de CWE: nas detecções TP, o CWE-alvo está na lista da GIA?
            if is_v and f["gia_id"] == gia:
                tp_cwe_total += 1
                tp_cwe_covered += gt_cwe in (f["cwe"] or [])

print("=== CLASSIFICAÇÃO (módulo 3) ===")
print(f"achados totais: {n_findings} | classificados (GIA): {n_classified} ({n_classified/n_findings:.0%}) | revisão manual: {n_manual} ({n_manual/n_findings:.0%})")
print(f"cobertura de CWE (CWE-alvo na lista da GIA, nas detecções TP): {tp_cwe_covered}/{tp_cwe_total} = {tp_cwe_covered/tp_cwe_total:.0%}")
print("\n=== RECOMENDAÇÃO (módulo 4) ===")
print(f"achados classificados com recomendação completa (impacto+verificar+corrigir+validar): {reco_ok}/{reco_total} = {reco_ok/reco_total:.0%}")
print("\n=== ABLAÇÃO POR HEURÍSTICA (fires em vulnerável | seguro) ===")
for h in sorted(set(heur_vuln) | set(heur_sec)):
    print(f"  {h}: vuln={heur_vuln[h]:>3} | seguro={heur_sec[h]:>3}")
print("(heurísticas sem disparo no corpus não aparecem)")
