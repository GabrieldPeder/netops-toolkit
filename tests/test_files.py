"""Testes do leitor de arquivos compartilhado (JSON/YAML)."""

import json

import pytest

from netops_toolkit.files import (
    MAX_STRUCTURED_FILE_BYTES,
    InputFileError,
    check_input_file,
    load_structured_file,
)


def test_json_with_utf8_bom_is_accepted(tmp_path):
    path = tmp_path / "rules.json"
    path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"rules": []}).encode())

    assert load_structured_file(path) == {"rules": []}


def test_yaml_and_yml_are_accepted(tmp_path):
    for name in ("a.yaml", "b.yml", "C.YAML"):
        path = tmp_path / name
        path.write_text("key: value\n", encoding="utf-8")

        assert load_structured_file(path) == {"key": "value"}


def test_malformed_json(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text('{"rules": [', encoding="utf-8")

    with pytest.raises(InputFileError, match=r"JSON inválido \(linha 1"):
        load_structured_file(path)


def test_malformed_yaml(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("rules:\n  - id: [unclosed\n", encoding="utf-8")

    with pytest.raises(InputFileError, match="YAML inválido"):
        load_structured_file(path)


def test_missing_file(tmp_path):
    with pytest.raises(InputFileError, match="não encontrado"):
        load_structured_file(tmp_path / "nope.json")


def test_directory_instead_of_file(tmp_path):
    folder = tmp_path / "dir.json"
    folder.mkdir()

    with pytest.raises(InputFileError, match="não é um arquivo"):
        load_structured_file(folder)


def test_unsupported_extension(tmp_path):
    path = tmp_path / "rules.txt"
    path.write_text("{}", encoding="utf-8")

    with pytest.raises(InputFileError, match="extensão não suportada"):
        load_structured_file(path)


def test_file_too_large(tmp_path):
    path = tmp_path / "big.json"
    path.write_bytes(b" " * (MAX_STRUCTURED_FILE_BYTES + 1))

    with pytest.raises(InputFileError, match="muito grande"):
        load_structured_file(path)


def test_custom_suffixes_and_size(tmp_path):
    path = tmp_path / "events.jsonl"
    path.write_text("{}\n", encoding="utf-8")

    check_input_file(path, (".jsonl",), max_bytes=10)
    with pytest.raises(InputFileError, match="muito grande"):
        check_input_file(path, (".jsonl",), max_bytes=1)


def test_non_utf8_file(tmp_path):
    path = tmp_path / "rules.json"
    path.write_bytes('{"name": "configuração"}'.encode("latin-1"))

    with pytest.raises(InputFileError, match="UTF-8"):
        load_structured_file(path)


def test_yaml_does_not_build_python_objects(tmp_path):
    path = tmp_path / "evil.yaml"
    path.write_text("rules: !!python/object/apply:os.system ['echo x']\n", encoding="utf-8")

    with pytest.raises(InputFileError, match="YAML inválido"):
        load_structured_file(path)


def test_yaml_sexagesimal_port_stays_text(tmp_path):
    path = tmp_path / "rules.yaml"
    path.write_text("ports: 22:80\nplain: 8080\nhex: 0x1F\n", encoding="utf-8")

    assert load_structured_file(path) == {"ports": "22:80", "plain": 8080, "hex": 31}
