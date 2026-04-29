from pathlib import Path

from collect.normalize import normalize_code


INPUT_DIR = Path("data/input")
OUTPUT_DIR = Path("data/output")


def print_section(title: str, content: str) -> None:
    print(f"\n--- {title} ---")
    print(content if content.strip() else "[vazio]")


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    input_files = sorted(INPUT_DIR.glob("*.txt"))

    if not input_files:
        print("Nenhum arquivo .txt encontrado em data/input/")
        return

    for input_path in input_files:
        raw_code = input_path.read_text(encoding="utf-8")
        result = normalize_code(raw_code)

        output_path = OUTPUT_DIR / f"{input_path.stem}_normalizado.py"
        output_path.write_text(result["normalized_code"], encoding="utf-8")

        print("\n" + "=" * 80)
        print(f"TESTE: {input_path.name}")
        print("=" * 80)

        if result["status"] == "ready":
            print_section("DEPOIS DA NORMALIZAÇÃO", result["normalized_code"])
        else:
            print_section("CÓDIGO EXTRAÍDO/PREPARADO ATÉ A FALHA", result["normalized_code"])

        print("\n--- STATUS ---")
        print(result["status"])

        print("\n--- CÓDIGO VÁLIDO? ---")
        print(result["is_valid_python"])

        print("\n--- AVISOS ---")
        if result["warnings"]:
            for warning in result["warnings"]:
                print(f"- {warning}")
        else:
            print("[nenhum aviso]")

        print("\n--- ERROS ---")
        if result["errors"]:
            for error in result["errors"]:
                print(f"- {error}")
        else:
            print("[nenhum erro]")

        print("\n--- METADADOS ---")
        print(result["metadata"])

        print("\n--- ARQUIVO GERADO ---")
        print(output_path)


if __name__ == "__main__":
    main()