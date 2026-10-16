"""Testes da interface de linha de comando."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from netops_toolkit import __version__
from netops_toolkit.cli import app

runner = CliRunner()
EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
GOOD_RULES = str(EXAMPLES / "firewall-rules.json")
BAD_RULES = str(EXAMPLES / "firewall-rules-issues.yaml")


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


# --- firewall audit ----------------------------------------------------------


def test_help_lists_firewall_group():
    result = runner.invoke(app, ["firewall", "--help"])

    assert result.exit_code == 0
    assert "audit" in result.output


def test_firewall_audit_help():
    result = runner.invoke(app, ["firewall", "audit", "--help"])

    assert result.exit_code == 0
    assert "--fail-on" in result.output


def test_firewall_audit_clean_file():
    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES])

    assert result.exit_code == 0
    assert "Nenhum achado." in result.output


def test_firewall_audit_text_output_with_findings():
    result = runner.invoke(app, ["firewall", "audit", BAD_RULES])

    assert result.exit_code == 0
    assert "[CRÍTICA] FW002" in result.output
    assert "Sugestão:" in result.output
    assert "não falhas confirmadas" in result.output


def test_firewall_audit_json_output():
    result = runner.invoke(app, ["firewall", "audit", BAD_RULES, "--json"])

    assert result.exit_code == 0
    data = json.loads(result.output)
    assert data["module"] == "firewall"
    assert data["summary"]["by_severity"]["critical"] == 1


def test_firewall_audit_writes_output_file(tmp_path):
    destination = tmp_path / "result.json"

    result = runner.invoke(app, ["firewall", "audit", BAD_RULES, "--output", str(destination)])

    assert result.exit_code == 0
    assert "gravado em" in result.output
    data = json.loads(destination.read_text(encoding="utf-8"))
    assert data["input_file"] == "firewall-rules-issues.yaml"


def test_firewall_audit_refuses_to_overwrite(tmp_path):
    destination = tmp_path / "result.json"
    destination.write_text("conteúdo anterior", encoding="utf-8")

    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES, "-o", str(destination)])

    assert result.exit_code == 1
    assert "--overwrite" in result.output
    assert destination.read_text(encoding="utf-8") == "conteúdo anterior"


def test_firewall_audit_overwrite_flag(tmp_path):
    destination = tmp_path / "result.json"
    destination.write_text("antigo", encoding="utf-8")

    result = runner.invoke(
        app, ["firewall", "audit", GOOD_RULES, "-o", str(destination), "--overwrite"]
    )

    assert result.exit_code == 0
    assert json.loads(destination.read_text(encoding="utf-8"))["module"] == "firewall"


def test_firewall_audit_output_folder_must_exist(tmp_path):
    destination = tmp_path / "missing" / "result.json"

    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES, "-o", str(destination)])

    assert result.exit_code == 1
    assert "pasta de destino não existe" in result.output


def test_firewall_audit_output_cannot_be_a_folder(tmp_path):
    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES, "-o", str(tmp_path)])

    assert result.exit_code == 1
    assert "é uma pasta" in result.output


def test_firewall_audit_missing_file_exits_1_without_traceback(tmp_path):
    result = runner.invoke(app, ["firewall", "audit", str(tmp_path / "nope.json")])

    assert result.exit_code == 1
    assert "Erro: arquivo não encontrado" in result.output
    assert "Traceback" not in result.output


def test_firewall_audit_malformed_file_exits_1(tmp_path):
    path = tmp_path / "rules.json"
    path.write_text("{not json", encoding="utf-8")

    result = runner.invoke(app, ["firewall", "audit", str(path)])

    assert result.exit_code == 1
    assert "JSON inválido" in result.output


@pytest.mark.parametrize(
    ("threshold", "expected_code"),
    [("critical", 3), ("CRITICAL", 3), ("high", 3), ("info", 3)],
)
def test_firewall_audit_fail_on_triggers(threshold, expected_code):
    result = runner.invoke(app, ["firewall", "audit", BAD_RULES, "--fail-on", threshold])

    assert result.exit_code == expected_code


def test_firewall_audit_fail_on_without_findings_exits_0():
    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES, "--fail-on", "info"])

    assert result.exit_code == 0


def test_firewall_audit_invalid_fail_on_is_usage_error():
    result = runner.invoke(app, ["firewall", "audit", GOOD_RULES, "--fail-on", "severe"])

    assert result.exit_code == 2


def test_firewall_audit_missing_argument_is_usage_error():
    result = runner.invoke(app, ["firewall", "audit"])

    assert result.exit_code == 2
