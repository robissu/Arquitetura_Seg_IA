"""Testes do Módulo 2 — camada de heurísticas complementares (H001-H008).

Oráculo: catálogo CWE (MITRE, https://cwe.mitre.org/) para o padrão estrutural
detectado, complementado pelas evidências de literatura que motivam cada
heurística no contexto de código gerado por IA. As heurísticas operam sobre a
AST do código (TCC §3.3.2), evitando falsos positivos de análise textual.
"""
from analyze.heuristics import run_heuristics


def _rule_ids(findings):
    return {f["rule_id"] for f in findings}


def test_h001_except_pass_silencioso():
    """`except Exception: pass` → H001.

    Fonte: CWE-703 (Improper Check or Handling of Exceptional Conditions);
    Tihanyi et al. (2025).
    """
    code = "def f():\n    try:\n        risky()\n    except Exception:\n        pass\n"
    assert "H001" in _rule_ids(run_heuristics(code))


def test_h002_except_com_nome_silencioso():
    """`except ... as e: pass` → H002.

    Fonte: CWE-703 (Improper Check or Handling of Exceptional Conditions).
    """
    code = "def f():\n    try:\n        risky()\n    except Exception as e:\n        pass\n"
    assert "H002" in _rule_ids(run_heuristics(code))


def test_h003_todo_em_funcao_de_seguranca():
    """TODO em função com nome sensível (`validate_token`) → H003.

    Fonte: CWE-546 (Suspicious Comment); Sajadi et al. (2025).
    """
    code = "def validate_token(t):\n    # TODO: validar assinatura\n    return t\n"
    assert "H003" in _rule_ids(run_heuristics(code))


def test_h004_verificacao_de_acesso_stub():
    """`def is_authorized(): return True` → H004.

    Fonte: CWE-862/CWE-863 (Missing/Incorrect Authorization).
    """
    code = "def is_authorized(user):\n    return True\n"
    assert "H004" in _rule_ids(run_heuristics(code))


def test_h005_entrada_externa_sem_validacao():
    """Entrada externa usada diretamente como argumento → H005.

    Fonte: CWE-20 (Improper Input Validation); Pearce et al. (2022).
    """
    code = "def view():\n    return salvar(request.form.get('x'))\n"
    assert "H005" in _rule_ids(run_heuristics(code))


def test_h006_rota_sensivel_sem_autenticacao():
    """Rota com método sensível sem decorator de autenticação → H006.

    Fonte: CWE-306 (Missing Authentication for Critical Function);
    Dora et al. (2025).
    """
    code = (
        "@app.route('/delete', methods=['POST'])\n"
        "def delete():\n"
        "    return ''\n"
    )
    assert "H006" in _rule_ids(run_heuristics(code))


def test_h007_rota_com_id_sem_checar_dono():
    """Rota com parâmetro ID sem checagem de propriedade → H007 (IDOR).

    Fonte: CWE-639 (Authorization Bypass Through User-Controlled Key);
    Zhao et al. (2025).
    """
    code = (
        "@app.route('/users/<int:user_id>')\n"
        "def get_user(user_id):\n"
        "    return User.query.get(user_id)\n"
    )
    assert "H007" in _rule_ids(run_heuristics(code))


def test_h008_import_ausente_em_requirements(tmp_path):
    """Import de pacote não declarado em requirements.txt → H008.

    Fonte: CWE-1104 (Use of Unmaintained Third Party Components); risco de
    package hallucination / slopsquatting (Spracklen et al., 2025).
    """
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.0.0\n", encoding="utf-8")
    findings = run_heuristics("import requests\n", requirements_path=str(req))
    assert "H008" in _rule_ids(findings)


def test_h008_parse_requirements_em_utf16(tmp_path):
    """`_parse_requirements` decodifica requirements.txt em UTF-16 (BOM).

    Pacote declarado (flask) não deve gerar H008 mesmo com o arquivo em UTF-16
    — confirma o tratamento defensivo de codificação.
    """
    req = tmp_path / "requirements.txt"
    req.write_text("flask==3.0.0\n", encoding="utf-16")
    findings = run_heuristics("import flask\n", requirements_path=str(req))
    assert "H008" not in _rule_ids(findings)


def test_codigo_limpo_sem_heuristicas():
    """Código sem os padrões-alvo → nenhuma heurística disparada."""
    assert run_heuristics("def soma(a, b):\n    return a + b\n") == []
