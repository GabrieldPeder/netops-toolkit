"""Interface de linha de comando do NetOps Toolkit.

A CLI só valida argumentos, chama a lógica dos módulos e formata a saída.

Códigos de saída:
    0  sucesso (em auditorias: análise concluída, mesmo com achados)
    1  dado de entrada inválido (ex.: endereço IP malformado, arquivo ilegível)
    2  erro de uso (opção inexistente, argumento ausente) - gerado pelo Click
    3  auditoria com achado igual ou acima do limite de --fail-on
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, NoReturn

import typer

from netops_toolkit import __version__
from netops_toolkit.files import InputFileError
from netops_toolkit.firewall import FirewallConfig, audit_file, load_firewall_config
from netops_toolkit.models import AuditResult, Category, Severity
from netops_toolkit.network import SubnetError, SubnetInfo, calculate_subnet

EXIT_INPUT_ERROR = 1
EXIT_FINDINGS_THRESHOLD = 3

SEVERITY_LABELS = {
    Severity.CRITICAL: "CRÍTICA",
    Severity.HIGH: "ALTA",
    Severity.MEDIUM: "MÉDIA",
    Severity.LOW: "BAIXA",
    Severity.INFO: "INFO",
}
CATEGORY_LABELS = {
    Category.ERROR: "erro objetivo",
    Category.WARNING: "alerta heurístico",
    Category.RECOMMENDATION: "recomendação",
}

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


firewall_app = typer.Typer(
    help="Auditoria de regras de firewall em arquivos JSON ou YAML (sem acessar firewalls reais).",
    no_args_is_help=True,
)
app.add_typer(firewall_app, name="firewall")


@firewall_app.command("audit")
def firewall_audit(
    file: Annotated[
        Path,
        typer.Argument(
            help="Arquivo de regras (.json, .yaml ou .yml).", metavar="ARQUIVO", show_default=False
        ),
    ],
    config: Annotated[
        Path | None,
        typer.Option(
            "--config",
            "-c",
            help="Arquivo de configuração (serviços sensíveis e limites). Veja a documentação.",
            metavar="ARQUIVO",
        ),
    ] = None,
    json_output: Annotated[
        bool, typer.Option("--json", help="Exibe o resultado completo em JSON.")
    ] = False,
    output: Annotated[
        Path | None,
        typer.Option(
            "--output", "-o", help="Grava o resultado em JSON neste arquivo.", metavar="ARQUIVO"
        ),
    ] = None,
    overwrite: Annotated[
        bool, typer.Option("--overwrite", help="Permite sobrescrever o arquivo de --output.")
    ] = False,
    fail_on: Annotated[
        Severity | None,
        typer.Option(
            "--fail-on",
            help="Retorna código 3 se houver achado com esta severidade ou maior.",
            case_sensitive=False,
        ),
    ] = None,
) -> None:
    """Audita regras de firewall e aponta erros, alertas e recomendações."""
    try:
        firewall_config = load_firewall_config(config) if config else FirewallConfig()
    except InputFileError as exc:
        _fail(f"{exc} (arquivo de configuração: {config})")
    try:
        result = audit_file(file, firewall_config)
    except InputFileError as exc:
        _fail(str(exc))

    if output is not None:
        _write_output(output, result.to_json(), overwrite)

    typer.echo(result.to_json() if json_output else format_audit(result))
    if output is not None and not json_output:
        typer.echo(f"\nResultado JSON gravado em: {output}")

    if fail_on is not None and result.has_findings_at_or_above(fail_on):
        raise typer.Exit(code=EXIT_FINDINGS_THRESHOLD)


def format_audit(result: AuditResult) -> str:
    """Formata o resultado de uma auditoria para leitura no terminal."""
    stats = result.stats
    lines = [
        f"Auditoria de {result.module}: {result.input_file}",
        f"Regras: {stats.get('rules_total', 0)} "
        f"(válidas: {stats.get('rules_valid', 0)}, inválidas: {stats.get('rules_invalid', 0)}, "
        f"desabilitadas: {stats.get('rules_disabled', 0)})",
    ]
    by_severity = result.count_by_severity()
    by_category = result.count_by_category()
    lines.append(
        f"Achados: {len(result.findings)}  |  "
        + "  ".join(f"{SEVERITY_LABELS[s].lower()}: {by_severity[s]}" for s in Severity)
    )
    lines.append(
        "Por categoria: " + "  ".join(f"{CATEGORY_LABELS[c]}: {by_category[c]}" for c in Category)
    )

    if not result.findings:
        lines += ["", "Nenhum achado."]
    for finding in result.findings:
        rules = f"  (regra: {', '.join(finding.rule_ids)})" if finding.rule_ids else ""
        lines += [
            "",
            f"[{SEVERITY_LABELS[finding.severity]}] {finding.code} {finding.title}{rules}",
            f"  Tipo: {CATEGORY_LABELS[finding.category]}",
            f"  Motivo: {finding.description}",
            f"  Sugestão: {finding.recommendation}",
        ]

    lines += [
        "",
        "Atenção: alertas heurísticos indicam pontos a verificar, não falhas confirmadas.",
        "Avalie cada achado no contexto do ambiente.",
    ]
    return "\n".join(lines)


def _write_output(path: Path, content: str, overwrite: bool) -> None:
    """Grava um arquivo de resultado sem sobrescrever nada por acidente."""
    if path.is_dir():
        _fail(f"o destino é uma pasta, não um arquivo: {path}")
    parent = path.parent if str(path.parent) else Path(".")
    if not parent.is_dir():
        _fail(f"a pasta de destino não existe: {parent}")
    # Modo "x" falha se o arquivo já existir, sem janela entre verificar e criar.
    mode = "w" if overwrite else "x"
    try:
        with path.open(mode, encoding="utf-8", newline="\n") as handle:
            handle.write(content + "\n")
    except FileExistsError:
        _fail(f"o arquivo já existe: {path}. Use --overwrite para substituí-lo")
    except OSError as exc:
        _fail(f"não foi possível gravar {path}: {exc.strerror}")


def _fail(message: str) -> NoReturn:
    typer.echo(f"Erro: {message}", err=True)
    raise typer.Exit(code=EXIT_INPUT_ERROR)


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
