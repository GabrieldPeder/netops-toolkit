"""Leitura segura de arquivos de entrada (regras, configurações e logs).

Concentra as verificações comuns a todos os módulos: existência, tipo,
extensão, tamanho, encoding e decodificação segura de JSON/YAML.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

MAX_STRUCTURED_FILE_BYTES = 5 * 1024 * 1024
STRUCTURED_SUFFIXES = {".json": "json", ".yaml": "yaml", ".yml": "yaml"}

_YAML_INT_TAG = "tag:yaml.org,2002:int"


class InputFileError(Exception):
    """Arquivo ilegível ou com estrutura inválida.

    É um erro fatal: nenhuma análise é feita. A mensagem é destinada ao usuário.
    """


class _SafeLoaderWithoutSexagesimal(yaml.SafeLoader):
    """SafeLoader que não converte ``22:80`` em inteiro.

    No YAML 1.1 (usado pelo PyYAML), ``22:80`` é um número em base 60 e vira
    1360, que é uma porta válida. O erro passaria despercebido. Aqui o resolvedor
    de inteiros é substituído por um sem a forma sexagesimal; o valor chega como
    texto e é recusado na validação.
    """


_SafeLoaderWithoutSexagesimal.yaml_implicit_resolvers = {
    first_char: [(tag, regexp) for tag, regexp in resolvers if tag != _YAML_INT_TAG]
    for first_char, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
_SafeLoaderWithoutSexagesimal.add_implicit_resolver(
    _YAML_INT_TAG,
    re.compile(
        r"""^(?:[-+]?0b[0-1_]+
            |[-+]?0[0-7_]+
            |[-+]?(?:0|[1-9][0-9_]*)
            |[-+]?0x[0-9a-fA-F_]+)$""",
        re.VERBOSE,
    ),
    list("-+0123456789"),
)


def check_input_file(path: Path, suffixes: Iterable[str], max_bytes: int) -> None:
    """Verifica se o caminho é um arquivo legível, com extensão e tamanho aceitos."""
    if not path.exists():
        raise InputFileError(f"arquivo não encontrado: {path}")
    if not path.is_file():
        raise InputFileError(f"o caminho não é um arquivo: {path}")

    accepted = tuple(suffixes)
    if path.suffix.lower() not in accepted:
        shown = path.suffix or "(sem extensão)"
        raise InputFileError(f"extensão não suportada: {shown}. Use {', '.join(accepted)}")

    size = path.stat().st_size
    if size > max_bytes:
        raise InputFileError(f"arquivo muito grande ({size} bytes); o limite é {max_bytes} bytes")


def load_structured_file(path: Path, max_bytes: int = MAX_STRUCTURED_FILE_BYTES) -> Any:
    """Lê um arquivo JSON ou YAML e devolve o conteúdo decodificado."""
    check_input_file(path, STRUCTURED_SUFFIXES, max_bytes)
    try:
        # utf-8-sig aceita o BOM que o Bloco de Notas e o PowerShell 5 costumam gravar.
        text = path.read_bytes().decode("utf-8-sig")
    except UnicodeDecodeError:
        raise InputFileError("o arquivo não está codificado em UTF-8") from None
    except OSError as exc:
        raise InputFileError(f"não foi possível ler o arquivo: {exc.strerror}") from None
    return parse_structured_text(text, STRUCTURED_SUFFIXES[path.suffix.lower()])


def parse_structured_text(text: str, file_format: str) -> Any:
    """Decodifica o texto como JSON ou YAML (sempre com carregador seguro)."""
    if file_format == "json":
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise InputFileError(
                f"JSON inválido (linha {exc.lineno}, coluna {exc.colno}): {exc.msg}"
            ) from None

    try:
        # A subclasse de SafeLoader não constrói objetos Python arbitrários.
        return yaml.load(text, Loader=_SafeLoaderWithoutSexagesimal)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" (linha {mark.line + 1}, coluna {mark.column + 1})" if mark else ""
        problem = getattr(exc, "problem", None) or "erro de sintaxe"
        raise InputFileError(f"YAML inválido{where}: {problem}") from None
