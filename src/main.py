from collect.normalize import normalize_code
from utils.io_utils import read_text_file, write_text_file


def main():
    input_path = "data/input/exemplo_01.txt"
    output_path = "data/output/exemplo_01_normalizado.py"

    raw_code = read_text_file(input_path)
    result = normalize_code(raw_code)

    print("=== CÓDIGO NORMALIZADO ===")
    print(result["normalized_code"])
    print("\n=== CÓDIGO VÁLIDO? ===")
    print(result["is_valid_python"])
    print("\n=== METADADOS ===")
    print(result["metadata"])

    write_text_file(output_path, result["normalized_code"])


if __name__ == "__main__":
    main()