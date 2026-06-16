import ast
import re
import subprocess
import tempfile
import unicodedata
from pathlib import Path


CODE_START_PATTERN = re.compile(
    r"^\s*(import\s+|from\s+|def\s+|class\s+|if\s+|for\s+|while\s+|try:|with\s+|@|print\(|[a-zA-Z_]\w*\s*=)"
)


def normalize_text_encoding(text: str) -> str:
    """
    Normaliza problemas de codificação e serialização textual.
    """
    text = unicodedata.normalize("NFKC", text)

    replacements = {
        "\u200b": "",   # zero-width space
        "\ufeff": "",   # BOM
        "“": '"',
        "”": '"',
        "‘": "'",
        "’": "'",
    }

    for old, new in replacements.items():
        text = text.replace(old, new)

    return text


def normalize_newlines(text: str) -> str:
    """
    Padroniza quebras de linha.
    """
    return text.replace("\r\n", "\n").replace("\r", "\n").strip()


def extract_code_block(text: str) -> tuple[str, list[str]]:
    """
    Extrai o código de uma saída bruta de LLM.
    Trata blocos markdown completos e incompletos.
    """
    warnings = []
    text = text.strip()

    complete_python_block = re.search(
        r"```python\s*(.*?)```",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if complete_python_block:
        return complete_python_block.group(1).strip(), warnings

    complete_generic_block = re.search(
        r"```\s*(.*?)```",
        text,
        flags=re.DOTALL,
    )

    if complete_generic_block:
        return complete_generic_block.group(1).strip(), warnings

    incomplete_python_block = re.search(
        r"```python\s*(.*)$",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )

    if incomplete_python_block:
        warnings.append("Bloco markdown Python sem fechamento foi detectado.")
        return incomplete_python_block.group(1).strip(), warnings

    incomplete_generic_block = re.search(
        r"```\s*(.*)$",
        text,
        flags=re.DOTALL,
    )

    if incomplete_generic_block:
        warnings.append("Bloco markdown genérico sem fechamento foi detectado.")
        return incomplete_generic_block.group(1).strip(), warnings

    # Caso não exista cerca markdown, tenta remover texto introdutório.
    lines = text.splitlines()
    first_code_line = None

    for index, line in enumerate(lines):
        if CODE_START_PATTERN.match(line):
            first_code_line = index
            break

    if first_code_line is not None and first_code_line > 0:
        warnings.append("Texto introdutório antes do código foi removido.")
        return "\n".join(lines[first_code_line:]).strip(), warnings

    return text, warnings


def remove_markdown_fences(code: str) -> str:
    """
    Remove resíduos de cercas markdown que possam ter sobrado.
    """
    code = code.strip()
    code = re.sub(r"^```python\s*", "", code, flags=re.IGNORECASE)
    code = re.sub(r"^```\s*", "", code)
    code = re.sub(r"\s*```$", "", code)
    return code.strip()


def detect_incomplete_fragment(code: str) -> list[str]:
    """
    Detecta sinais de incompletude comuns em saídas de LLM.
    """
    warnings = []
    lines = [line.strip() for line in code.splitlines() if line.strip()]

    if not lines:
        warnings.append("Código vazio após limpeza textual.")
        return warnings

    placeholder_patterns = [
        r"^\.\.\.$",
        r"#\s*restante\s+omitido",
        r"#\s*código\s+omitido",
        r"#\s*continua",
        r"#\s*implementar\s+depois",
        r"pass\s*#\s*TODO",
    ]

    for line in lines:
        for pattern in placeholder_patterns:
            if re.search(pattern, line, flags=re.IGNORECASE):
                warnings.append(f"Possível trecho incompleto detectado: {line}")

    last_line = lines[-1]

    if last_line.endswith(":"):
        warnings.append(
            "O último comando termina com ':', indicando possível bloco sem corpo."
        )

    return warnings


def validate_syntax(code: str) -> tuple[bool, dict | None]:
    """
    Valida sintaxe usando ast.parse.
    Retorna detalhes do erro quando inválido.
    """
    try:
        ast.parse(code)
        return True, None
    except SyntaxError as error:
        return False, {
            "message": error.msg,
            "line": error.lineno,
            "column": error.offset,
            "text": error.text.strip() if error.text else None,
        }


def run_isort_and_black(code: str) -> tuple[str, list[str]]:
    """
    Executa isort e Black sobre código já sintaticamente válido.
    """
    warnings = []

    with tempfile.TemporaryDirectory() as tmpdir:
        temp_file = Path(tmpdir) / "temp_code.py"
        temp_file.write_text(code, encoding="utf-8")

        isort_result = subprocess.run(
            ["isort", str(temp_file)],
            check=False,
            capture_output=True,
            text=True,
        )

        if isort_result.returncode != 0:
            warnings.append(f"isort retornou aviso/erro: {isort_result.stderr.strip()}")

        black_result = subprocess.run(
            ["black", str(temp_file), "--quiet"],
            check=False,
            capture_output=True,
            text=True,
        )

        if black_result.returncode != 0:
            warnings.append(f"Black retornou aviso/erro: {black_result.stderr.strip()}")

        return temp_file.read_text(encoding="utf-8"), warnings


def extract_metadata(code: str) -> dict:
    """
    Extrai metadados estruturais do código.
    """
    tree = ast.parse(code)

    imports = []
    functions = []
    classes = []
    commented_code_lines = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imports.append(alias.name)

        elif isinstance(node, ast.ImportFrom):
            module = node.module if node.module else ""
            imports.append(module)

        elif isinstance(node, ast.FunctionDef):
            functions.append(node.name)

        elif isinstance(node, ast.ClassDef):
            classes.append(node.name)

    for line_number, line in enumerate(code.splitlines(), start=1):
        stripped = line.strip()
        if stripped.startswith("#") and re.search(
            r"\b(def|class|import|if|for|while|subprocess|eval|exec)\b",
            stripped,
        ):
            commented_code_lines.append(
                {
                    "line": line_number,
                    "content": stripped,
                }
            )

    duplicate_imports = sorted(
        {item for item in imports if imports.count(item) > 1}
    )

    duplicate_functions = sorted(
        {item for item in functions if functions.count(item) > 1}
    )

    return {
        "line_count": len(code.splitlines()),
        "imports": imports,
        "functions": functions,
        "classes": classes,
        "duplicate_imports": duplicate_imports,
        "duplicate_functions": duplicate_functions,
        "commented_code_lines": commented_code_lines,
    }


def normalize_code(raw_code: str) -> dict:
    """
    Pipeline principal do módulo de coleta e normalização.
    """
    warnings = []
    errors = []

    text = normalize_text_encoding(raw_code)
    text = normalize_newlines(text)

    code, extraction_warnings = extract_code_block(text)
    warnings.extend(extraction_warnings)

    code = remove_markdown_fences(code)
    code = normalize_newlines(code)

    completeness_warnings = detect_incomplete_fragment(code)
    warnings.extend(completeness_warnings)
    has_completeness_issues = bool(completeness_warnings)

    is_valid_before_formatting, syntax_error = validate_syntax(code)

    if not is_valid_before_formatting:
        errors.append(
            {
                "type": "syntax_error",
                "details": syntax_error,
            }
        )

        return {
            "status": "invalid",
            "code": code,
            "warnings": warnings,
            "errors": errors,
            "metadata": None,
        }

    formatted_code, formatting_warnings = run_isort_and_black(code)
    warnings.extend(formatting_warnings)

    is_valid_after_formatting, syntax_error_after = validate_syntax(formatted_code)

    if not is_valid_after_formatting:
        errors.append(
            {
                "type": "syntax_error_after_formatting",
                "details": syntax_error_after,
            }
        )

        return {
            "status": "invalid",
            "code": formatted_code,
            "warnings": warnings,
            "errors": errors,
            "metadata": None,
        }

    metadata = extract_metadata(formatted_code)

    if metadata["duplicate_imports"]:
        warnings.append(
            f"Imports duplicados detectados: {metadata['duplicate_imports']}"
        )

    if metadata["duplicate_functions"]:
        warnings.append(
            f"Funções duplicadas detectadas: {metadata['duplicate_functions']}"
        )

    if metadata["commented_code_lines"]:
        warnings.append("Possível código comentado detectado.")

    status = "incomplete" if has_completeness_issues else "valid"

    return {
        "status": status,
        "code": formatted_code,
        "warnings": warnings,
        "errors": errors,
        "metadata": metadata,
    }