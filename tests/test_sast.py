"""Testes do Módulo 2 — camada SAST (`analyze/sast.py`, wrapper Bandit).

Oráculo dos resultados esperados: documentação oficial do Bandit, que define
cada `test_id` e a CWE associada (https://bandit.readthedocs.io/). A versão do
Bandit está fixada em `requirements.txt` (bandit==1.9.4) para garantir que os
identificadores de regra sejam reprodutíveis e citáveis no TCC.
"""
from analyze.sast import run_bandit


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_sql_por_concatenacao_gera_b608():
    """SQL construído por concatenação de string → Bandit B608.

    Fonte: Bandit B608 (hardcoded_sql_expressions) → CWE-89 (SQL Injection).
    """
    code = (
        "def consulta(nome):\n"
        "    return \"SELECT * FROM users WHERE name = '\" + nome + \"'\"\n"
    )
    assert "B608" in _rule_ids(run_bandit(code))


def test_subprocess_shell_true_gera_b602():
    """subprocess com shell=True → Bandit B602.

    Fonte: Bandit B602 (subprocess_popen_with_shell_equals_true) → CWE-78
    (OS Command Injection).
    """
    code = (
        "import subprocess\n"
        "def executar(pasta):\n"
        "    subprocess.run('ls ' + pasta, shell=True)\n"
    )
    assert "B602" in _rule_ids(run_bandit(code))


def test_eval_de_entrada_gera_b307():
    """eval() de expressão externa → Bandit B307.

    Fonte: Bandit B307 (eval) → CWE-95 (Eval Injection).
    """
    code = "def calcular(expr):\n    return eval(expr)\n"
    assert "B307" in _rule_ids(run_bandit(code))


def test_codigo_limpo_sem_achados():
    """Código sem padrões inseguros conhecidos → lista vazia."""
    assert run_bandit("def soma(a, b):\n    return a + b\n") == []


def test_formato_intermediario_unificado():
    """Cada achado segue o formato intermediário unificado com os campos
    obrigatórios consumidos pelos módulos seguintes."""
    findings = run_bandit("def calcular(expr):\n    return eval(expr)\n")
    assert findings
    achado = findings[0]
    for campo in ("origin", "rule_id", "file", "line", "col",
                  "severity", "confidence", "description", "context"):
        assert campo in achado, f"campo ausente: {campo}"
    assert achado["origin"] == "bandit"
