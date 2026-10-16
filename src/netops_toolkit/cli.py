"""Interface de linha de comando do NetOps Toolkit.

A CLI só valida argumentos, chama a lógica dos módulos e formata a saída.

Códigos de saída:
    0  sucesso
    1  dado de entrada inválido (ex.: endereço IP malformado)
    2  erro de uso (opção inexistente, argumento ausente) - gerado pelo Click
"""

from __future__ import annotations

from typing import Annotated

import typer

from netops_toolkit import __version__
from netops_toolkit.network import SubnetError, SubnetInfo, calculate_subnet

EXIT_INPUT_ERROR = 1

ADDRESS_TYPE_LABELS = {
    "default": "rota padrão (todos os endereços)",
    "unspecified": "não especificado",
    "loopback": "loopback",
    "link_local": "link-local",
    "multicast": "multicast",
    "documentation": "documentação (exemplos)",
    "shared": "espaço compartilhado (CGNAT, RFC 6598)",
    "reserved": "reservado",
    "private": "privado / uso especial",
    "global": "público (global)",
    "other": "outro / misto",
}

app = typer.Typer(
    name="netops",
    help="Utilitários de linha de comando para redes, infraestrutura e segurança defensiva.",
    no_args_is_help=True,
    add_completion=False,
    pretty_exceptions_show_locals=False,
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"netops-toolkit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Mostra a versão e encerra.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Utilitários de linha de comando para redes, infraestrutura e segurança defensiva."""


@app.command()
def subnet(
    cidr: Annotated[
        str,
        typer.Argument(
            help="Endereço com prefixo CIDR, ex.: 192.168.10.0/24 ou 2001:db8::/64.",
            metavar="CIDR",
            show_default=False,
        ),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Exibe o resultado em JSON."),
    ] = False,
) -> None:
    """Calcula informações de uma sub-rede IPv4 ou IPv6."""
    try:
        info = calculate_subnet(cidr)
    except SubnetError as exc:
        typer.echo(f"Erro: {exc}", err=True)
        raise typer.Exit(code=EXIT_INPUT_ERROR) from None

    typer.echo(info.to_json() if json_output else format_subnet(info))


def format_subnet(info: SubnetInfo) -> str:
    """Formata o resultado para leitura humana no terminal."""
    rows: list[tuple[str, str]] = [
        ("Entrada", info.input),
        ("Versão", f"IPv{info.version}"),
        ("Rede", info.network),
        ("Endereço de rede", info.network_address),
    ]
    if info.version == 4:
        rows += [
            ("Máscara", f"{info.netmask} (/{info.prefix_length})"),
            ("Wildcard", str(info.wildcard_mask)),
            ("Broadcast", info.broadcast_address or "não se aplica"),
            ("Total de endereços", _format_count(info.total_addresses)),
            ("Hosts utilizáveis", _format_count(info.usable_hosts or 0)),
            ("Primeiro utilizável", str(info.first_usable)),
            ("Último utilizável", str(info.last_usable)),
        ]
    else:
        rows += [
            ("Forma expandida", str(info.exploded)),
            ("Prefixo", f"/{info.prefix_length}"),
            (
                "Total de endereços",
                f"{_format_count(info.total_addresses)} (2^{128 - info.prefix_length})",
            ),
            ("Primeiro endereço", info.first_address),
            ("Último endereço", info.last_address),
        ]
    rows.append(("Tipo", ADDRESS_TYPE_LABELS.get(info.address_type, info.address_type)))

    width = max(len(label) for label, _ in rows)
    lines = [f"{label:<{width}}  {value}" for label, value in rows]
    if info.notes:
        lines.append("")
        lines.append("Observações:")
        lines += [f"  - {note}" for note in info.notes]
    return "\n".join(lines)


def _format_count(value: int) -> str:
    """Formata números com separador de milhar no padrão brasileiro."""
    return f"{value:,}".replace(",", ".")
