import re
import ast
import tempfile
import subprocess
from pathlib import Path


def remove_markdown_fences(code: str) -> str:
    code = code.strip()

    code = re.sub(r"^```python\s*", "", code, flags=re.IGNORECASE)
    code = re.sub(r"^```\s*", "", code)
    code = re.sub(r"\s*```$", "", code)

    return code.strip()


def extract_code_block(text: str) -> str:
    text = text.strip()

    # Caso ideal: bloco markdown completo
    match = re.search(r"```python\s*(.*?)```", text, flags=re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()

    # Caso incompleto: abriu ```python mas não fechou
    match = re.search(r"```python\s*(.*)$", text, flags=re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()

    # Caso incompleto genérico: abriu ``` mas não fechou
    match = re.search(r"```\s*(.*)$", text, flags=re.DOTALL)
    if match:
        return match.group(1).strip()

    return text

def normalize_newlines(code: str) -> str:
    return code.replace("\r\n", "\n").replace("\r", "\n").strip()


def run_isort_and_black(code: str) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        temp_file = Path(tmpdir) / "temp_code.py"
        temp_file.write_text(code, encoding="utf-8")

        subprocess.run(
            ["isort", str(temp_file)],
            check=False,
            capture_output=True,
            text=True,
        )

        subprocess.run(
            ["black", str(temp_file), "--quiet"],
            check=False,
            capture_output=True,
            text=True,
        )

        return temp_file.read_text(encoding="utf-8")


def validate_syntax(code: str) -> bool:
    try:
        ast.parse(code)
        return True
    except SyntaxError:
        return False


def extract_metadata(code: str) -> dict:
    tree = ast.parse(code)

    imports = []
    functions = []
    classes = []

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

    return {
        "num_lines": len(code.splitlines()),
        "imports": imports,
        "functions": functions,
        "classes": classes,
    }


def normalize_code(raw_code: str) -> dict:
    code = extract_code_block(raw_code)
    code = remove_markdown_fences(code)
    code = normalize_newlines(code)
    code = run_isort_and_black(code)

    is_valid = validate_syntax(code)

    result = {
        "normalized_code": code,
        "is_valid_python": is_valid,
        "metadata": None,
    }

    if is_valid:
        result["metadata"] = extract_metadata(code)

    return result