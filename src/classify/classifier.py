"""Módulo 3 — Classificação de achados.

Associa cada achado no formato intermediário unificado (saída de sast.py +
heuristics.py) a uma categoria do guia (GIA-001..007), enriquecendo-o com
`gia_id`, `gia_category`, `cwe`, `owasp` e `priority`.

A categoria, os CWE, os OWASP e a prioridade são lidos de
`data/knowledge_base.json` pelo `gia_id` — o guia permanece como única fonte
de verdade. Achados sem mapeamento direto recebem a marcação
`gia_category = "Não classificado"` e `requires_manual_review = True`.
"""

import json
from pathlib import Path

# ── Mapeamentos exatos regra → GIA ────────────────────────────────────────────

BANDIT_TO_GIA = {
    # GIA-001 — Validação inadequada de entrada e injeção
    "B601": "GIA-001", "B602": "GIA-001", "B603": "GIA-001",
    "B604": "GIA-001", "B605": "GIA-001", "B606": "GIA-001",
    "B607": "GIA-001", "B608": "GIA-001", "B609": "GIA-001",
    "B610": "GIA-001", "B611": "GIA-001",
    "B703": "GIA-001",  # Django SQL injection

    # GIA-004 — Exposição de dados sensíveis
    "B105": "GIA-004", "B106": "GIA-004", "B107": "GIA-004",
    "B108": "GIA-004",

    # GIA-001 também — uso de funções perigosas
    "B301": "GIA-001", "B302": "GIA-001", "B303": "GIA-001",
    "B304": "GIA-001", "B305": "GIA-001", "B306": "GIA-001",
    "B307": "GIA-001", "B308": "GIA-001",

    # GIA-005 — Tratamento inadequado de erros
    "B110": "GIA-005", "B112": "GIA-005",

    # GIA-004 — Geração fraca de valores aleatórios
    "B311": "GIA-004", "B312": "GIA-004", "B313": "GIA-004",
    "B314": "GIA-004", "B315": "GIA-004", "B316": "GIA-004",
    "B317": "GIA-004", "B318": "GIA-004", "B319": "GIA-004",
    "B320": "GIA-004",

    # GIA-003 — Uso inseguro de dependências
    "B401": "GIA-003", "B402": "GIA-003", "B403": "GIA-003",
    "B404": "GIA-003", "B405": "GIA-003", "B406": "GIA-003",
    "B407": "GIA-003", "B408": "GIA-003", "B409": "GIA-003",
    "B410": "GIA-003", "B411": "GIA-003", "B412": "GIA-003",
    "B413": "GIA-003",

    # GIA-006 — Configurações inseguras
    "B501": "GIA-006", "B502": "GIA-006", "B503": "GIA-006",
    "B504": "GIA-006", "B505": "GIA-006", "B506": "GIA-006",
}

HEURISTIC_TO_GIA = {
    "H001": "GIA-005", "H002": "GIA-005",
    "H003": "GIA-007", "H004": "GIA-007",
    "H005": "GIA-001",
    "H006": "GIA-002", "H007": "GIA-002",
    "H008": "GIA-003",
}

_DEFAULT_KB_PATH = Path(__file__).resolve().parents[2] / "data" / "knowledge_base.json"


# ── helpers ───────────────────────────────────────────────────────────────────


def load_knowledge_base(path: str | None = None) -> dict:
    """Carrega o guia (GIA-001..007) do knowledge_base.json."""
    kb_path = Path(path) if path else _DEFAULT_KB_PATH
    with kb_path.open(encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_gia(finding: dict) -> str | None:
    """Resolve o gia_id de um achado a partir do mapeamento exato.

    Heurísticas usam HEURISTIC_TO_GIA; demais (Bandit) usam BANDIT_TO_GIA.
    Retorna None quando não há mapeamento exato (→ revisão manual).
    """
    rule_id = finding.get("rule_id", "") or ""
    if finding.get("origin") == "heuristic":
        return HEURISTIC_TO_GIA.get(rule_id)
    return BANDIT_TO_GIA.get(rule_id)


# ── ponto de entrada público ───────────────────────────────────────────────────


def classify_finding(finding: dict, knowledge_base: dict) -> dict:
    """Enriquece um único achado com a classificação do guia.

    Mantém todos os campos originais e adiciona gia_id, gia_category, cwe,
    owasp, priority e requires_manual_review.
    """
    gia_id = _resolve_gia(finding)
    classified = dict(finding)

    entry = knowledge_base.get(gia_id) if gia_id else None
    if entry is not None:
        classified.update({
            "gia_id": gia_id,
            "gia_category": entry.get("categoria", ""),
            "cwe": list(entry.get("cwe", [])),
            "owasp": list(entry.get("owasp", [])),
            "priority": entry.get("prioridade", ""),
            "requires_manual_review": False,
        })
    else:
        # sem mapeamento exato: achado escalado para revisão manual
        classified.update({
            "gia_id": gia_id,
            "gia_category": "Não classificado",
            "cwe": [],
            "owasp": [],
            "priority": "Média",
            "requires_manual_review": True,
        })

    return classified


def classify_findings(findings: list[dict],
                      knowledge_base: dict | None = None) -> list[dict]:
    """Classifica uma lista de achados no formato intermediário unificado.

    knowledge_base: guia já carregado; quando None, é lido do caminho padrão.
    Retorna a lista de achados classificados no formato intermediário enriquecido.
    """
    kb = knowledge_base if knowledge_base is not None else load_knowledge_base()
    return [classify_finding(finding, kb) for finding in findings]
