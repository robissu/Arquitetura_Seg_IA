import ast
import re
import sys
from pathlib import Path

# ── H003 — nomes de funções sensíveis ──────────────────────────────────────────
_SECURITY_FUNC_KEYWORDS = frozenset({
    "auth", "login", "validate", "check", "verify",
    "encrypt", "hash", "token", "permission", "role",
})

# ── H004 — funções de verificação de acesso ────────────────────────────────────
_ACCESS_CHECK_SUBSTRINGS = (
    "is_admin", "is_authorized", "has_permission", "is_authenticated",
    "can_access", "is_owner", "check_permission", "verify_access",
)

# ── H005 — fontes de entrada externa ──────────────────────────────────────────
_EXTERNAL_SOURCES = frozenset({
    "request", "args", "form", "query_params", "headers",
    "environ", "stdin",
})

# ── H006 — decorators de autenticação conhecidos ──────────────────────────────
_AUTH_DECORATORS = frozenset({
    "login_required", "jwt_required", "token_required",
    "auth_required", "require_auth", "authenticated",
    "permission_required", "roles_required",
})
_SENSITIVE_HTTP_METHODS = frozenset({"POST", "PUT", "DELETE", "PATCH"})

# ── H008 — módulos da stdlib (Python ≥ 3.10) ──────────────────────────────────
_STDLIB = getattr(sys, "stdlib_module_names", frozenset())


# ── helpers ───────────────────────────────────────────────────────────────────


def _ctx(lines: list[str], lineno: int, radius: int = 1) -> str:
    """Retorna linhas ao redor de `lineno` (1-based) como string de contexto."""
    start = max(0, lineno - 1 - radius)
    end = min(len(lines), lineno + radius)
    return "".join(lines[start:end]).rstrip()


def _finding(
    rule_id: str,
    line: int,
    severity: str,
    confidence: str,
    description: str,
    context: str,
    col: int | None = None,
) -> dict:
    return {
        "origin": "heuristic",
        "rule_id": rule_id,
        "file": "analyzed.py",
        "line": line,
        "col": col,
        "severity": severity,
        "confidence": confidence,
        "description": description,
        "context": context,
    }


def _is_truthy_literal(node: ast.expr | None) -> bool:
    """Retorna True se o nó AST é a constante True ou 1."""
    if node is None:
        return False
    if isinstance(node, ast.Constant):
        return node.value is True or node.value == 1
    return False


def _is_external_input(node: ast.expr) -> bool:
    """Retorna True se o nó raiz representa acesso direto a fonte externa."""
    if isinstance(node, ast.Name):
        return node.id in _EXTERNAL_SOURCES
    if isinstance(node, ast.Attribute):
        return _is_external_input(node.value)
    if isinstance(node, ast.Subscript):
        return _is_external_input(node.value)
    if isinstance(node, ast.Call):
        return _is_external_input(node.func)
    return False


def _contains_external_input(node: ast.expr) -> tuple[bool, int]:
    """Busca recursivamente entrada externa em qualquer subexpressão.

    Retorna (encontrou, line_number).
    """
    for subnode in ast.walk(node):
        if isinstance(subnode, ast.expr) and _is_external_input(subnode):
            lineno = getattr(subnode, "lineno", getattr(node, "lineno", 0))
            return True, lineno
    return False, 0


def _parse_requirements(req_path: str) -> set[str]:
    """Lê requirements.txt e retorna conjunto de nomes de pacotes normalizados."""
    raw = Path(req_path).read_bytes()
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = raw.decode("utf-16")
    elif raw[:3] == b"\xef\xbb\xbf":
        text = raw[3:].decode("utf-8")
    else:
        text = raw.decode("utf-8")
    packages: set[str] = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # extrai nome antes de operador de versão ou extras
        name = re.split(r"[>=<!~\[\s;]", line)[0].strip()
        packages.add(name.lower().replace("-", "_"))
    return packages


# ── H001 / H002 ───────────────────────────────────────────────────────────────


def _h001_h002(tree: ast.AST, lines: list[str]) -> list[dict]:
    """
    H001: except sem nome (bare ou Exception) com corpo apenas `pass`.
    H002: except com ligação de nome (as e) e corpo apenas `pass`.

    Fonte: CWE-703 (Improper Check or Handling of Exceptional Conditions);
    evidência em código gerado por IA: Tihanyi et al. (2025), Sajadi et al.
    (2025). Categoria do guia: GIA-005.
    """
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        if len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            lineno = node.lineno
            ctx = _ctx(lines, lineno, radius=2)
            if node.name:
                findings.append(_finding(
                    "H002", lineno, "MEDIUM", "HIGH",
                    f"Exceção capturada como '{node.name}' e silenciada com pass — "
                    "erros serão ignorados sem registro.",
                    ctx,
                ))
            else:
                type_name = ast.unparse(node.type) if node.type else "bare except"
                findings.append(_finding(
                    "H001", lineno, "MEDIUM", "HIGH",
                    f"Cláusula '{type_name}:' com corpo apenas pass — "
                    "falhas serão silenciadas.",
                    ctx,
                ))
    return findings


# ── H003 ──────────────────────────────────────────────────────────────────────


def _h003(tree: ast.AST, lines: list[str]) -> list[dict]:
    """H003: TODO/FIXME dentro de funções com nome sensível de segurança.

    Fonte: CWE-546 (Suspicious Comment) — controle de segurança possivelmente
    incompleto; evidência: Sajadi et al. (2025), Tihanyi et al. (2025).
    Categoria do guia: GIA-007.
    """
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name_lower = node.name.lower()
        if not any(kw in name_lower for kw in _SECURITY_FUNC_KEYWORDS):
            continue
        start = node.lineno
        end = getattr(node, "end_lineno", len(lines))
        for lineno in range(start, end + 1):
            line = lines[lineno - 1]
            if re.search(r"#.*\b(TODO|FIXME)\b", line, re.IGNORECASE):
                findings.append(_finding(
                    "H003", lineno, "HIGH", "MEDIUM",
                    f"TODO/FIXME encontrado na função de segurança '{node.name}' "
                    "— controle pode estar incompleto.",
                    _ctx(lines, lineno),
                ))
    return findings


# ── H004 ──────────────────────────────────────────────────────────────────────


def _h004(tree: ast.AST, lines: list[str]) -> list[dict]:
    """H004: Função de verificação de acesso que retorna sempre True ou 1.

    Fonte: CWE-862/CWE-863 (Missing/Incorrect Authorization) — verificação de
    acesso implementada como stub. Categoria do guia: GIA-007.
    """
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        name_lower = node.name.lower()
        if not any(kw in name_lower for kw in _ACCESS_CHECK_SUBSTRINGS):
            continue
        returns = [n for n in ast.walk(node) if isinstance(n, ast.Return)]
        if returns and all(_is_truthy_literal(r.value) for r in returns):
            findings.append(_finding(
                "H004", node.lineno, "HIGH", "HIGH",
                f"Função '{node.name}' retorna sempre True/1 — "
                "verificação de acesso pode ser um stub.",
                _ctx(lines, node.lineno, radius=2),
            ))
    return findings


# ── H005 ──────────────────────────────────────────────────────────────────────


def _h005(tree: ast.AST, lines: list[str]) -> list[dict]:
    """H005: Entrada externa usada diretamente como argumento sem validação.

    Fonte: CWE-20 (Improper Input Validation); evidência em código gerado por
    IA: Pearce et al. (2022), Fu et al. (2025). Categoria do guia: GIA-001.
    """
    findings = []
    seen_lines: set[int] = set()

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        all_args = list(node.args) + [kw.value for kw in node.keywords]
        for arg in all_args:
            found, lineno = _contains_external_input(arg)
            if found and lineno not in seen_lines:
                seen_lines.add(lineno)
                findings.append(_finding(
                    "H005", lineno, "MEDIUM", "LOW",
                    "Entrada externa usada diretamente como argumento sem "
                    "função de validação intermediária visível.",
                    _ctx(lines, lineno),
                ))
    return findings


# ── H006 ──────────────────────────────────────────────────────────────────────


def _h006(tree: ast.AST, lines: list[str]) -> list[dict]:
    """H006: Rota Flask/Django com método sensível sem decorator de autenticação.

    Fonte: CWE-306 (Missing Authentication for Critical Function); evidência em
    aplicações web geradas por LLM: Dora et al. (2025), Zhao et al. (2025).
    Categoria do guia: GIA-002.
    """
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        has_sensitive_route = False
        has_auth = False

        for dec in node.decorator_list:
            dec_src = ast.unparse(dec)

            # detecta @app.route / @blueprint.route com métodos sensíveis
            if "route" in dec_src:
                if any(m in dec_src for m in _SENSITIVE_HTTP_METHODS):
                    has_sensitive_route = True

            # detecta decorators de autenticação
            if any(a in dec_src for a in _AUTH_DECORATORS):
                has_auth = True

        if has_sensitive_route and not has_auth:
            findings.append(_finding(
                "H006", node.lineno, "HIGH", "MEDIUM",
                f"Rota '{node.name}' aceita método sensível "
                "(POST/PUT/DELETE/PATCH) sem decorator de autenticação.",
                _ctx(lines, node.lineno, radius=2),
            ))
    return findings


# ── H007 ──────────────────────────────────────────────────────────────────────


def _h007(tree: ast.AST, lines: list[str]) -> list[dict]:
    """H007: Rota com parâmetro ID sem checar propriedade do recurso.

    Fonte: CWE-639 (Authorization Bypass Through User-Controlled Key, IDOR) /
    CWE-862 (Missing Authorization); evidência: Dora et al. (2025), Zhao et al.
    (2025). Categoria do guia: GIA-002.
    """
    findings = []

    _OWNERSHIP_MARKERS = frozenset({
        "user_id", "owner_id", "current_user", "get_current_user",
        "current_identity",
    })

    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        is_route = False
        has_id_param = False

        for dec in node.decorator_list:
            dec_src = ast.unparse(dec)
            if "route" in dec_src:
                is_route = True
                # detecta variáveis de rota contendo "id" ex.: <int:user_id>, <id>
                if re.search(r"<[^>]*id[^>]*>", dec_src, re.IGNORECASE):
                    has_id_param = True

        if not (is_route and has_id_param):
            continue

        # verifica se existe checagem de propriedade no corpo da função
        # (não conta a declaração do próprio parâmetro — busca padrões de query)
        has_ownership = False
        for child in ast.walk(node):
            # filter_by(user_id=...) / filter_by(owner_id=...)
            if isinstance(child, ast.keyword) and child.arg in _OWNERSHIP_MARKERS:
                has_ownership = True
                break
            # current_user usado em qualquer chamada (ex.: current_user.id)
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                if child.value.id in {"current_user", "g"} and child.attr in {"id", "user_id"}:
                    has_ownership = True
                    break
            # .filter(Model.user_id == ...) ou expressão similar
            if isinstance(child, ast.Compare):
                child_src = ast.unparse(child)
                if any(m in child_src for m in _OWNERSHIP_MARKERS):
                    has_ownership = True
                    break

        if not has_ownership:
            findings.append(_finding(
                "H007", node.lineno, "HIGH", "MEDIUM",
                f"Rota '{node.name}' recebe parâmetro ID sem checagem de "
                "propriedade do recurso (possível IDOR).",
                _ctx(lines, node.lineno, radius=2),
            ))
    return findings


# ── H008 ──────────────────────────────────────────────────────────────────────


def _h008(tree: ast.AST, lines: list[str], requirements_path: str | None) -> list[dict]:
    """H008: Import de pacote ausente em requirements.txt.

    Fonte: CWE-1104 (Use of Unmaintained Third Party Components) e CWE-829
    (Inclusion of Functionality from Untrusted Control Sphere); risco de package
    hallucination / slopsquatting documentado por Spracklen et al. (2025)
    (taxas de 5,2%–21,7%). Categoria do guia: GIA-003.
    """
    if requirements_path is None:
        return []
    req_path = Path(requirements_path)
    if not req_path.exists():
        return []

    req_packages = _parse_requirements(str(req_path))
    findings = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                pkg = alias.name.split(".")[0]
                if _is_third_party(pkg, req_packages):
                    findings.append(_finding(
                        "H008", node.lineno, "HIGH", "LOW",
                        f"Pacote '{pkg}' importado mas não encontrado em "
                        "requirements.txt — risco de alucinação ou dependência não declarada.",
                        _ctx(lines, node.lineno),
                    ))
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                pkg = node.module.split(".")[0]
                if _is_third_party(pkg, req_packages):
                    findings.append(_finding(
                        "H008", node.lineno, "HIGH", "LOW",
                        f"Pacote '{pkg}' importado mas não encontrado em "
                        "requirements.txt — risco de alucinação ou dependência não declarada.",
                        _ctx(lines, node.lineno),
                    ))
    return findings


def _is_third_party(pkg: str, req_packages: set[str]) -> bool:
    pkg_lower = pkg.lower()
    if not pkg_lower or pkg_lower.startswith("_"):
        return False
    if pkg_lower in _STDLIB:
        return False
    # alguns alias comuns de stdlib não cobertos pelo stdlib_module_names
    if pkg_lower in {"__future__", "typing_extensions"}:
        return False
    return pkg_lower.replace("-", "_") not in req_packages


# ── ponto de entrada público ───────────────────────────────────────────────────


def run_heuristics(code: str, requirements_path: str | None = None) -> list[dict]:
    """
    Executa todas as heurísticas H001-H008 sobre o código Python normalizado.

    requirements_path: caminho para requirements.txt (usado em H008).
    Retorna lista de achados no formato intermediário unificado.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []

    lines = code.splitlines(keepends=True)

    findings: list[dict] = []
    findings.extend(_h001_h002(tree, lines))
    findings.extend(_h003(tree, lines))
    findings.extend(_h004(tree, lines))
    findings.extend(_h005(tree, lines))
    findings.extend(_h006(tree, lines))
    findings.extend(_h007(tree, lines))
    findings.extend(_h008(tree, lines, requirements_path))

    return findings
