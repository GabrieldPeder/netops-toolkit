"""Testes da interface de linha de comando."""

import json

from typer.testing import CliRunner

from netops_toolkit import __version__
from netops_toolkit.cli import app

runner = CliRunner()


def test_help_lists_subnet_command():
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "subnet" in result.output


def test_no_arguments_shows_help():
    result = runner.invoke(app, [])

    assert "subnet" in result.output


def test_version():
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert __version__ in result.output


def test_subnet_help():
    result = runner.invoke(app, ["subnet", "--help"])

    assert result.exit_code == 0
    assert "--json" in result.output


def test_subnet_text_output():
    result = runner.invoke(app, ["subnet", "192.168.10.0/24"])

    assert result.exit_code == 0
    assert "255.255.255.0" in result.output
    assert "192.168.10.255" in result.output
    assert "254" in result.output


def test_subnet_text_output_ipv4_slash_31():
    result = runner.invoke(app, ["subnet", "10.0.0.0/31"])

    assert result.exit_code == 0
    assert "não se aplica" in result.output
    assert "RFC 3021" in result.output


def test_subnet_text_output_ipv6():
    result = runner.invoke(app, ["subnet", "2001:db8::/64"])

    assert result.exit_code == 0
    assert "2^64" in result.output
    assert "Broadcast" not in result.output


def test_subnet_large_counts_use_thousands_separator():
    result = runner.invoke(app, ["subnet", "10.0.0.0/8"])

    assert "16.777.214" in result.output


def test_subnet_json_output_is_valid_json():
    result = runner.invoke(app, ["subnet", "192.168.10.0/24", "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["network"] == "192.168.10.0/24"
    assert data["usable_hosts"] == 254


def test_invalid_address_exits_with_code_1_without_traceback():
    result = runner.invoke(app, ["subnet", "300.1.1.1/24"])

    assert result.exit_code == 1
    assert "Erro:" in result.output
    assert "endereço IP inválido" in result.output
    assert "Traceback" not in result.output


def test_invalid_prefix_exits_with_code_1():
    result = runner.invoke(app, ["subnet", "192.168.10.0/33"])

    assert result.exit_code == 1
    assert "prefixo inválido" in result.output


def test_missing_argument_is_usage_error():
    result = runner.invoke(app, ["subnet"])

    assert result.exit_code == 2


def test_unknown_option_is_usage_error():
    result = runner.invoke(app, ["subnet", "10.0.0.0/8", "--xml"])

    assert result.exit_code == 2


def test_unknown_command_is_usage_error():
    result = runner.invoke(app, ["scan", "10.0.0.0/8"])

    assert result.exit_code == 2
