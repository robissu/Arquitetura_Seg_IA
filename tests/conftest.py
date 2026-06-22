"""Configuração compartilhada da suíte de testes (pytest).

- Coloca `src/` no sys.path para importar os módulos do protótipo.
- Garante que isort/black do venv estejam no PATH (normalize.py os chama por
  nome via subprocess).
- Expõe a fixture `knowledge_base` (guia GIA carregado uma vez por sessão).
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))

os.environ["PATH"] = (
    str(Path(sys.executable).parent) + os.pathsep + os.environ.get("PATH", "")
)

import pytest  # noqa: E402

from classify.classifier import load_knowledge_base  # noqa: E402


@pytest.fixture(scope="session")
def knowledge_base():
    """Guia GIA (data/knowledge_base.json) carregado uma vez por sessão."""
    return load_knowledge_base()


@pytest.fixture
def make_finding():
    """Fixture-factory: cria um achado mínimo no formato intermediário unificado."""
    def _make(origin: str, rule_id: str, **overrides) -> dict:
        finding = {
            "origin": origin,
            "rule_id": rule_id,
            "file": "analyzed.py",
            "line": 1,
            "col": 0,
            "severity": "MEDIUM",
            "confidence": "LOW",
            "description": "achado de teste",
            "context": "",
        }
        finding.update(overrides)
        return finding

    return _make
