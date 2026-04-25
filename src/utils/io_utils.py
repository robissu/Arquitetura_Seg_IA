from pathlib import Path


def read_text_file(file_path: str) -> str:
    return Path(file_path).read_text(encoding="utf-8")


def write_text_file(file_path: str, content: str) -> None:
    Path(file_path).write_text(content, encoding="utf-8")