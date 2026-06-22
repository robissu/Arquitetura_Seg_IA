"""Testes do Módulo 1 — coleta e normalização (`collect/normalize.py`).

Oráculo: validade sintática via `ast` (Python Language Reference; módulo `ast`,
https://docs.python.org/3/library/ast.html). A normalização bloqueia artefatos
sintaticamente inválidos antes da análise de segurança, prática alinhada ao
NIST SP 800-218 (SSDF) de validar artefatos antes de prosseguir no fluxo.
"""
from collect.normalize import normalize_code


def test_codigo_valido_status_valid():
    """Código sintaticamente válido → status 'valid' (ou 'incomplete')."""
    resultado = normalize_code("def soma(a, b):\n    return a + b\n")
    assert resultado["status"] in ("valid", "incomplete")


def test_codigo_invalido_status_invalid():
    """Código com erro de sintaxe → status 'invalid' e erros registrados.

    Fonte: módulo `ast` — `ast.parse` levanta `SyntaxError` em código inválido.
    """
    resultado = normalize_code("def soma(a, b)\n    return a + b\n")  # falta ':'
    assert resultado["status"] == "invalid"
    assert resultado["errors"]


def test_remove_cercas_markdown():
    """Cercas de markdown típicas de saídas de LLM são removidas."""
    resultado = normalize_code("```python\ndef f():\n    return 1\n```\n")
    assert "```" not in resultado["code"]


def test_metadados_estruturais_extraidos():
    """Imports, funções e classes são extraídos como metadados estruturais."""
    code = "import os\n\ndef f():\n    return 1\n\nclass C:\n    pass\n"
    metadata = normalize_code(code)["metadata"]
    assert "f" in metadata["functions"]
    assert "C" in metadata["classes"]
    assert "os" in metadata["imports"]
    assert metadata["line_count"] > 0
