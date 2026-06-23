"""Módulo 4 — Recomendação.

Consulta a base de conhecimento (guia GIA) e monta o relatório final. Para
cada achado classificado, busca a entrada correspondente no
`knowledge_base.json` pelo `gia_id` e devolve as orientações de mitigação
(impacto / o que verificar / como corrigir / como validar).

Decisões de design (alinhadas ao TCC §3.3.4):
- Lookup puro: o conteúdo das recomendações é copiado do guia, sem geração de
  texto novo nem correção automática de código.
- Relatório com chaves em inglês (consistente com o formato intermediário e a
  classificação) e valores em português (vindos do guia).
- Estrutura: lista por achado + um resumo agrupado por GIA.
"""

import json
from collections import Counter, defaultdict
from pathlib import Path

from classify.classifier import load_knowledge_base

_OUTPUT_DIR = Path(__file__).resolve().parents[2] / "data" / "output"

_MANUAL_REVIEW_NOTE = (
    "Achado sem categoria correspondente no guia — requer análise manual."
)
_SEVERITY_ORDER = ("HIGH", "MEDIUM", "LOW")


# ── recomendação por achado (lookup no guia) ───────────────────────────────────


def build_recommendation(finding: dict, knowledge_base: dict) -> dict:
    """Monta a seção `recommendation` de um achado a partir do guia.

    Lookup puro pelo `gia_id`. Achado sem entrada no guia → nota de revisão
    manual. Campos vazios no guia (GIA-004..007 a completar) são repassados
    como estão, sem inventar conteúdo.
    """
    gia_id = finding.get("gia_id")
    entry = knowledge_base.get(gia_id) if gia_id else None

    if entry is None:
        return {
            "impact": "",
            "what_to_check": _MANUAL_REVIEW_NOTE,
            "how_to_fix": [],
            "how_to_validate": "",
            "requires_manual_review": True,
        }

    mitigacao = entry.get("mitigacao", {})
    return {
        "impact": entry.get("impacto", ""),
        "what_to_check": mitigacao.get("o_que_verificar", ""),
        "how_to_fix": list(mitigacao.get("como_corrigir", [])),
        "how_to_validate": mitigacao.get("como_validar", ""),
        "requires_manual_review": finding.get("requires_manual_review", False),
    }


# ── reformatação de um achado para o relatório ─────────────────────────────────


def _to_report_finding(finding: dict, finding_id: int, knowledge_base: dict) -> dict:
    """Converte um achado classificado (plano) para o formato do relatório
    (com `classification` e `recommendation` aninhados)."""
    return {
        "id": finding_id,
        "origin": finding.get("origin"),
        "rule_id": finding.get("rule_id"),
        "line": finding.get("line"),
        "col": finding.get("col"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "description": finding.get("description"),
        "context": finding.get("context"),
        "classification": {
            "gia_id": finding.get("gia_id"),
            "gia_category": finding.get("gia_category"),
            "cwe": list(finding.get("cwe", [])),
            "owasp": list(finding.get("owasp", [])),
            "priority": finding.get("priority"),
        },
        "recommendation": build_recommendation(finding, knowledge_base),
    }


# ── seções agregadas ───────────────────────────────────────────────────────────


def _build_analysis_summary(normalized: dict, classified: list[dict],
                            file_name: str) -> dict:
    """Resumo no topo do relatório: contagens por severidade e por GIA."""
    sev_counter = Counter(f.get("severity") for f in classified)
    by_severity = {s: sev_counter[s] for s in _SEVERITY_ORDER if sev_counter[s]}

    gia_counter = Counter(
        f.get("gia_id") or "Não classificado" for f in classified
    )
    by_gia = dict(sorted(gia_counter.items()))

    return {
        "file": file_name,
        "status": normalized.get("status"),
        "total_findings": len(classified),
        "by_severity": by_severity,
        "by_gia": by_gia,
    }


def _build_gia_summary(classified: list[dict], knowledge_base: dict) -> list[dict]:
    """Resumo agrupado por GIA: a orientação aparece uma vez por categoria,
    com os achados (ids e linhas) que pertencem a ela."""
    groups: dict[str, list[tuple[int, dict]]] = defaultdict(list)
    for finding_id, finding in enumerate(classified, start=1):
        key = finding.get("gia_id") or "Não classificado"
        groups[key].append((finding_id, finding))

    summary = []
    for key in sorted(groups):
        items = groups[key]
        sample = items[0][1]
        summary.append({
            "gia_id": sample.get("gia_id"),
            "gia_category": sample.get("gia_category"),
            "priority": sample.get("priority"),
            "cwe": list(sample.get("cwe", [])),
            "owasp": list(sample.get("owasp", [])),
            "finding_count": len(items),
            "finding_ids": [fid for fid, _ in items],
            "lines": sorted(
                {f.get("line") for _, f in items if f.get("line") is not None}
            ),
            "recommendation": build_recommendation(sample, knowledge_base),
        })
    return summary


# ── pontos de entrada públicos ─────────────────────────────────────────────────


def generate_report(normalized: dict, classified: list[dict],
                    knowledge_base: dict | None = None,
                    file_name: str = "analyzed.py") -> dict:
    """Monta o relatório final a partir dos achados classificados.

    normalized: resultado de normalize_code() (usado para status do resumo).
    classified: saída de classify_findings().
    """
    kb = knowledge_base if knowledge_base is not None else load_knowledge_base()
    return {
        "analysis_summary": _build_analysis_summary(normalized, classified, file_name),
        "findings": [
            _to_report_finding(f, i, kb)
            for i, f in enumerate(classified, start=1)
        ],
        "gia_summary": _build_gia_summary(classified, kb),
    }


def generate_error_report(normalized: dict, file_name: str = "analyzed.py") -> dict:
    """Relatório para entrada bloqueada (código sintaticamente inválido).

    A análise de segurança não é executada; o relatório registra o status e os
    erros de sintaxe, sem achados nem recomendações.
    """
    return {
        "analysis_summary": {
            "file": file_name,
            "status": normalized.get("status"),
            "total_findings": 0,
            "by_severity": {},
            "by_gia": {},
        },
        "findings": [],
        "gia_summary": [],
        "errors": list(normalized.get("errors", [])),
        "warnings": list(normalized.get("warnings", [])),
    }


def save_report(report: dict, path: str | Path) -> Path:
    """Grava o relatório em JSON (UTF-8, indentado)."""
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
    )
    return out_path
