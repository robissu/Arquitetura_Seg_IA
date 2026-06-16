import json
import subprocess
import sys
import tempfile
from pathlib import Path


def _bandit_exe() -> str:
    """Localiza o executável bandit no Scripts do venv atual."""
    scripts = Path(sys.executable).parent
    for name in ("bandit.exe", "bandit"):
        candidate = scripts / name
        if candidate.exists():
            return str(candidate)
    return "bandit"


def run_bandit(code: str) -> list[dict]:
    """
    Executa Bandit sobre o código Python fornecido como string.

    Retorna lista de achados no formato intermediário unificado.
    Lista vazia quando não há achados.
    Lança RuntimeError em caso de falha do próprio Bandit (exit code 2).
    """
    with tempfile.NamedTemporaryFile(
        suffix=".py", mode="w", encoding="utf-8", delete=False
    ) as tmp:
        tmp.write(code)
        tmp_path = Path(tmp.name)

    try:
        result = subprocess.run(
            [_bandit_exe(), str(tmp_path), "-f", "json", "-q"],
            capture_output=True,
            text=True,
            check=False,
        )

        # exit code 0 = sem achados; 1 = achados encontrados; 2 = erro do bandit
        if result.returncode == 2:
            raise RuntimeError(f"Bandit encerrou com erro: {result.stderr.strip()}")

        if not result.stdout.strip():
            return []

        bandit_output = json.loads(result.stdout)
        findings = []

        for issue in bandit_output.get("results", []):
            findings.append(
                {
                    "origin": "bandit",
                    "rule_id": issue["test_id"],
                    "file": "analyzed.py",
                    "line": issue["line_number"],
                    "col": issue.get("col_offset"),
                    "severity": issue["issue_severity"],
                    "confidence": issue["issue_confidence"],
                    "description": issue["issue_text"],
                    "context": issue.get("code", "").strip(),
                }
            )

        return findings

    finally:
        tmp_path.unlink(missing_ok=True)
