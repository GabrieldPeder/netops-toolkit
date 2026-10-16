"""Testes da auditoria de firewall (lógica, sem CLI)."""

import json
from pathlib import Path

import pytest

from netops_toolkit.firewall import RulesFileError, audit_file, audit_ruleset, parse_ruleset
from netops_toolkit.firewall.loader import MAX_FILE_BYTES, load_rules_file
from netops_toolkit.models import Category, Severity

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def rule(**overrides):
    """Regra válida e inofensiva; cada teste altera só o que interessa."""
    base = {
        "id": "r1",
        "description": "regra de teste",
        "action": "allow",
        "protocol": "tcp",
        "source": "10.20.0.0/24",
        "destination": "10.10.0.10",
        "ports": [443],
    }
    base.update(overrides)
    return {key: value for key, value in base.items() if value is not None}


DENY_ALL = {
    "id": "deny-all",
    "description": "nega o restante",
    "action": "deny",
    "protocol": "any",
    "source": "any",
    "destination": "any",
}


def audit(*rules, **top_level):
    data = {"version": 1, "rules": list(rules), **top_level}
    return audit_ruleset(parse_ruleset(data))


def codes(result):
    return [finding.code for finding in result.findings]


def findings_with(result, code):
    return [finding for finding in result.findings if finding.code == code]


# --- Leitura de arquivos -----------------------------------------------------


class TestLoader:
    def test_valid_json_example(self):
        result = audit_file(EXAMPLES / "firewall-rules.json")

        assert result.module == "firewall"
        assert result.input_file == "firewall-rules.json"
        assert result.stats["rules_total"] == 13
        assert result.stats["rules_invalid"] == 0

    def test_valid_yaml(self, tmp_path):
        path = tmp_path / "rules.yml"
        path.write_text(
            "rules:\n"
            "  - id: web\n"
            "    description: web\n"
            "    action: allow\n"
            "    protocol: tcp\n"
            "    source: 10.0.0.0/24\n"
            "    destination: 10.0.1.10\n"
            "    ports: [443]\n",
            encoding="utf-8",
        )

        result = audit_file(path)

        assert result.stats["rules_valid"] == 1

    def test_json_with_utf8_bom_is_accepted(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_bytes(b"\xef\xbb\xbf" + json.dumps({"rules": []}).encode())

        assert load_rules_file(path) == {"rules": []}

    def test_malformed_json(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_text('{"rules": [', encoding="utf-8")

        with pytest.raises(RulesFileError, match=r"JSON inválido \(linha 1"):
            load_rules_file(path)

    def test_malformed_yaml(self, tmp_path):
        path = tmp_path / "rules.yaml"
        path.write_text("rules:\n  - id: [unclosed\n", encoding="utf-8")

        with pytest.raises(RulesFileError, match="YAML inválido"):
            load_rules_file(path)

    def test_missing_file(self, tmp_path):
        with pytest.raises(RulesFileError, match="não encontrado"):
            load_rules_file(tmp_path / "nope.json")

    def test_directory_instead_of_file(self, tmp_path):
        folder = tmp_path / "dir.json"
        folder.mkdir()

        with pytest.raises(RulesFileError, match="não é um arquivo"):
            load_rules_file(folder)

    def test_unsupported_extension(self, tmp_path):
        path = tmp_path / "rules.txt"
        path.write_text("{}", encoding="utf-8")

        with pytest.raises(RulesFileError, match="extensão não suportada"):
            load_rules_file(path)

    def test_file_too_large(self, tmp_path):
        path = tmp_path / "big.json"
        path.write_bytes(b" " * (MAX_FILE_BYTES + 1))

        with pytest.raises(RulesFileError, match="muito grande"):
            load_rules_file(path)

    def test_non_utf8_file(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_bytes('{"name": "configuração"}'.encode("latin-1"))

        with pytest.raises(RulesFileError, match="UTF-8"):
            load_rules_file(path)

    def test_yaml_does_not_build_python_objects(self, tmp_path):
        path = tmp_path / "evil.yaml"
        path.write_text("rules: !!python/object/apply:os.system ['echo x']\n", encoding="utf-8")

        with pytest.raises(RulesFileError, match="YAML inválido"):
            load_rules_file(path)

    def test_yaml_sexagesimal_port_stays_text(self, tmp_path):
        path = tmp_path / "rules.yaml"
        path.write_text("ports: 22:80\nplain: 8080\n", encoding="utf-8")

        assert load_rules_file(path) == {"ports": "22:80", "plain": 8080}


class TestRootStructure:
    @pytest.mark.parametrize("data", [None, [], "rules", 42])
    def test_root_must_be_object(self, data):
        with pytest.raises(RulesFileError, match="raiz"):
            parse_ruleset(data)

    def test_rules_required(self):
        with pytest.raises(RulesFileError, match="'rules'"):
            parse_ruleset({"version": 1})

    def test_rules_must_be_list(self):
        with pytest.raises(RulesFileError, match="lista"):
            parse_ruleset({"rules": {"id": "x"}})

    @pytest.mark.parametrize("version", [2, "1", True])
    def test_unsupported_version(self, version):
        with pytest.raises(RulesFileError, match="versão"):
            parse_ruleset({"version": version, "rules": []})

    def test_empty_rule_list_is_valid(self):
        result = audit()

        assert result.stats["rules_total"] == 0
        assert codes(result) == ["FW011"]

    def test_invalid_default_policy(self):
        result = audit(DENY_ALL, default_policy="maybe")

        assert codes(result) == ["FW001"]
        assert result.findings[0].evidence["field"] == "default_policy"

    def test_unknown_top_level_field(self):
        result = audit(DENY_ALL, polcy="deny")

        assert codes(result) == ["FW014"]


# --- Validação de regras (FW001 / FW014) -----------------------------------


class TestRuleValidation:
    def assert_invalid(self, entry, field, message=None):
        result = audit(entry, DENY_ALL)
        invalid = findings_with(result, "FW001")

        assert result.stats["rules_invalid"] == 1
        assert any(f.evidence.get("field") == field for f in invalid), invalid
        if message:
            assert any(message in f.description for f in invalid), invalid
        assert all(f.category is Category.ERROR for f in invalid)

    @pytest.mark.parametrize("field", ["id", "action", "protocol", "source", "destination"])
    def test_required_fields(self, field):
        self.assert_invalid(rule(**{field: None}), field, "obrigatório")

    def test_rule_must_be_object(self):
        result = audit("not-a-rule", DENY_ALL)

        assert findings_with(result, "FW001")[0].rule_ids == ("#1",)

    def test_duplicate_id(self):
        result = audit(rule(id="dup"), rule(id="dup", ports=[80]), DENY_ALL)

        invalid = findings_with(result, "FW001")
        assert len(invalid) == 1
        assert "duplicado" in invalid[0].description

    @pytest.mark.parametrize("action", ["permit", "drop", ""])
    def test_unsupported_action(self, action):
        self.assert_invalid(rule(action=action), "action", "não suportado")

    def test_action_is_case_insensitive(self):
        result = audit(rule(action="ALLOW"), DENY_ALL)

        assert result.stats["rules_invalid"] == 0

    def test_yaml_boolean_action_has_hint(self):
        self.assert_invalid(rule(action=False), "action", "aspas")

    @pytest.mark.parametrize("protocol", ["gre", "esp", "http"])
    def test_unsupported_protocol(self, protocol):
        self.assert_invalid(rule(protocol=protocol), "protocol", "não suportado")

    @pytest.mark.parametrize("ports", [[0], [65536], [70000], ["-1"], ["abc"], [True], [], [1.5]])
    def test_invalid_ports(self, ports):
        self.assert_invalid(rule(ports=ports), "ports")

    def test_inverted_port_range(self):
        self.assert_invalid(rule(ports=["90-80"]), "ports", "invertida")

    def test_colon_range_gets_hint(self):
        self.assert_invalid(rule(ports="22:80"), "ports", "'-'")

    def test_any_cannot_be_combined_with_ports(self):
        self.assert_invalid(rule(ports=["any", 22]), "ports")

    @pytest.mark.parametrize("protocol", ["icmp", "any"])
    def test_ports_not_allowed_for_portless_protocols(self, protocol):
        self.assert_invalid(rule(protocol=protocol), "ports", "tcp ou udp")

    @pytest.mark.parametrize(
        "source", ["10.0.0.300", "10.0.0.0/33", "not-an-ip", [], [10], ["any", "10.0.0.0/8"]]
    )
    def test_invalid_source(self, source):
        self.assert_invalid(rule(source=source), "source")

    def test_host_bits_set_suggests_network(self):
        self.assert_invalid(rule(source="10.20.0.5/24"), "source", "10.20.0.0/24")

    def test_mixed_ip_versions(self):
        self.assert_invalid(rule(destination="2001:db8::/64"), "destination", "IPv4 x IPv6")

    def test_any_matches_both_ip_versions(self):
        result = audit(rule(source="any", destination="2001:db8::10"), DENY_ALL)

        assert result.stats["rules_invalid"] == 0

    def test_enabled_must_be_boolean(self):
        self.assert_invalid(rule(enabled="yes"), "enabled")

    def test_description_must_be_text(self):
        self.assert_invalid(rule(description=["x"]), "description")

    def test_reports_every_problem_of_a_rule(self):
        result = audit(rule(action="permit", ports=[0]), DENY_ALL)

        assert len(findings_with(result, "FW001")) == 2

    def test_unknown_rule_field_is_warning_and_rule_stays_valid(self):
        result = audit(rule(comment="x"), DENY_ALL)

        assert codes(result) == ["FW014"]
        assert result.findings[0].category is Category.WARNING
        assert result.stats["rules_invalid"] == 0

    def test_invalid_rules_are_excluded_from_heuristics(self):
        result = audit(rule(source="any", destination="any", ports=[0]), DENY_ALL)

        assert "FW002" not in codes(result)

    def test_valid_port_formats(self):
        parsed = parse_ruleset({"rules": [rule(ports=[22, "80", "8000-8080", " 443 "])]})

        assert [str(p) for p in parsed.rules[0].ports] == ["22", "80", "443", "8000-8080"]

    def test_tcp_without_ports_means_all_ports(self):
        parsed = parse_ruleset({"rules": [rule(ports=None)]})

        assert parsed.rules[0].port_count == 65535


# --- Detecções -----------------------------------------------------------------


class TestAnyAny:
    def test_any_any_any_is_critical(self):
        result = audit(rule(protocol="any", ports=None, source="any", destination="any"))

        finding = findings_with(result, "FW002")[0]
        assert finding.severity is Severity.CRITICAL
        assert finding.category is Category.WARNING

    def test_any_any_single_protocol_is_high(self):
        result = audit(rule(source="any", destination="any", ports=None), DENY_ALL)

        assert findings_with(result, "FW002")[0].severity is Severity.HIGH

    def test_any_any_suppresses_per_port_alerts(self):
        result = audit(rule(source="any", destination="any", ports=[22]), DENY_ALL)

        assert "FW002" in codes(result)
        assert "FW003" not in codes(result)

    def test_ipv4_default_route_counts_as_any(self):
        result = audit(rule(source="0.0.0.0/0", destination="0.0.0.0/0"), DENY_ALL)

        assert "FW002" in codes(result)

    def test_deny_any_any_is_not_flagged(self):
        assert codes(audit(DENY_ALL)) == []

    def test_any_source_specific_destination_is_not_any_any(self):
        result = audit(rule(source="any"), DENY_ALL)

        assert "FW002" not in codes(result)


class TestSensitiveServices:
    @pytest.mark.parametrize(
        ("protocol", "port"), [("tcp", 22), ("tcp", 3389), ("tcp", 3306), ("udp", 161)]
    )
    def test_sensitive_port_from_any(self, protocol, port):
        result = audit(rule(source="any", protocol=protocol, ports=[port]), DENY_ALL)

        finding = findings_with(result, "FW003")[0]
        assert finding.severity is Severity.HIGH
        assert finding.evidence["services"]

    def test_sensitive_port_inside_small_range(self):
        result = audit(rule(source="any", ports=["20-25"]), DENY_ALL)

        assert "FW003" in codes(result)

    def test_sensitive_port_from_management_network_is_not_flagged(self):
        result = audit(rule(source="10.20.0.0/24", ports=[22]), DENY_ALL)

        assert "FW003" not in codes(result)

    def test_sensitive_port_with_wrong_protocol_is_not_flagged(self):
        result = audit(rule(source="any", protocol="udp", ports=[22]), DENY_ALL)

        assert "FW003" not in codes(result)

    def test_deny_rule_is_not_flagged(self):
        result = audit(rule(action="deny", source="any", ports=[22]), DENY_ALL)

        assert "FW003" not in codes(result)


class TestBroadPermissions:
    def test_any_protocol_from_specific_source_is_medium(self):
        result = audit(rule(protocol="any", ports=None), DENY_ALL)

        assert findings_with(result, "FW004")[0].severity is Severity.MEDIUM

    def test_any_protocol_from_any_source_is_high(self):
        result = audit(rule(protocol="any", ports=None, source="any"), DENY_ALL)

        assert findings_with(result, "FW004")[0].severity is Severity.HIGH

    def test_icmp_is_not_any_protocol(self):
        result = audit(rule(protocol="icmp", ports=None), DENY_ALL)

        assert codes(result) == []

    def test_wide_port_range(self):
        result = audit(rule(ports=["1024-65535"]), DENY_ALL)

        finding = findings_with(result, "FW005")[0]
        assert finding.severity is Severity.MEDIUM
        assert "64512" in finding.description

    def test_port_range_at_threshold_is_not_flagged(self):
        result = audit(rule(ports=["8000-8999"]), DENY_ALL)

        assert "FW005" not in codes(result)

    def test_wide_range_suppresses_per_port_alerts(self):
        result = audit(rule(source="any", ports=None), DENY_ALL)

        assert "FW005" in codes(result)
        assert "FW003" not in codes(result)
        assert "FW007" not in codes(result)

    @pytest.mark.parametrize("source", ["10.0.0.0/7", "2000::/3"])
    def test_broad_source(self, source):
        destination = "10.10.0.10" if ":" not in source else "2001:db8::10"
        result = audit(rule(source=source, destination=destination), DENY_ALL)

        assert findings_with(result, "FW006")[0].severity is Severity.LOW

    @pytest.mark.parametrize("source", ["10.0.0.0/8", "fd00::/16", "any"])
    def test_source_not_broad(self, source):
        destination = "2001:db8::10" if ":" in source else "10.10.0.10"
        result = audit(rule(source=source, destination=destination), DENY_ALL)

        assert "FW006" not in codes(result)


class TestCleartext:
    @pytest.mark.parametrize(("protocol", "port"), [("tcp", 21), ("tcp", 23), ("udp", 69)])
    def test_cleartext_protocols(self, protocol, port):
        result = audit(rule(protocol=protocol, ports=[port]), DENY_ALL)

        finding = findings_with(result, "FW007")[0]
        assert finding.category is Category.RECOMMENDATION

    def test_https_is_not_cleartext(self):
        result = audit(rule(ports=[443]), DENY_ALL)

        assert "FW007" not in codes(result)


class TestShadowing:
    def test_duplicate(self):
        result = audit(rule(id="a"), rule(id="b"), DENY_ALL)

        finding = findings_with(result, "FW008")[0]
        assert finding.rule_ids == ("b", "a")
        assert finding.severity is Severity.LOW

    def test_duplicate_ignores_item_order(self):
        result = audit(rule(id="a", ports=[80, 443]), rule(id="b", ports=[443, 80]), DENY_ALL)

        assert "FW008" in codes(result)

    def test_shadowed_by_opposite_action(self):
        broad_deny = rule(
            id="deny-net",
            action="deny",
            protocol="any",
            ports=None,
            source="10.50.0.0/16",
            destination="any",
        )
        narrow_allow = rule(id="allow-host", source="10.50.1.0/24", ports=[9100])

        result = audit(broad_deny, narrow_allow, DENY_ALL)

        finding = findings_with(result, "FW009")[0]
        assert finding.rule_ids == ("allow-host", "deny-net")
        assert finding.severity is Severity.MEDIUM

    def test_redundant_same_action(self):
        broad = rule(id="web", source="10.10.0.0/16", destination="any", ports=[80, 443])
        narrow = rule(id="web-dev", source="10.10.8.0/24", destination="any", ports=[443])

        result = audit(broad, narrow, DENY_ALL)

        assert findings_with(result, "FW010")[0].rule_ids == ("web-dev", "web")

    def test_deny_and_reject_have_same_effect(self):
        result = audit(rule(id="a", action="deny"), rule(id="b", action="reject"), DENY_ALL)

        assert "FW010" in codes(result)

    def test_narrow_rule_before_broad_is_not_shadowing(self):
        narrow_deny = rule(id="deny-host", action="deny", source="10.50.1.0/24")
        broad_allow = rule(id="allow-net", source="10.50.0.0/16")

        result = audit(narrow_deny, broad_allow, DENY_ALL)

        assert not {"FW008", "FW009", "FW010"} & set(codes(result))

    def test_partial_port_overlap_is_not_shadowing(self):
        result = audit(rule(id="a", ports=["80-90"]), rule(id="b", ports=["85-95"]), DENY_ALL)

        assert not {"FW008", "FW009", "FW010"} & set(codes(result))

    def test_union_of_rules_is_not_detected(self):
        # Limitação documentada: a cobertura por várias regras não é detectada.
        result = audit(
            rule(id="a", ports=["80-85"]),
            rule(id="b", ports=["86-90"]),
            rule(id="c", ports=["80-90"]),
            DENY_ALL,
        )

        assert not {"FW008", "FW009", "FW010"} & set(codes(result))

    def test_any_protocol_covers_tcp(self):
        result = audit(
            rule(id="all", protocol="any", ports=None, action="deny"), rule(id="web"), DENY_ALL
        )

        assert "FW009" in codes(result)

    def test_tcp_does_not_cover_udp(self):
        result = audit(rule(id="t"), rule(id="u", protocol="udp"), DENY_ALL)

        assert not {"FW008", "FW009", "FW010"} & set(codes(result))

    def test_disabled_rules_do_not_shadow(self):
        result = audit(rule(id="a", enabled=False), rule(id="b"), DENY_ALL)

        assert "FW008" not in codes(result)

    def test_final_deny_all_is_not_shadowed_by_specific_rules(self):
        result = audit(rule(id="a"), DENY_ALL)

        assert codes(result) == []


class TestDefaultDeny:
    def test_missing_default_deny(self):
        result = audit(rule())

        finding = findings_with(result, "FW011")[0]
        assert finding.category is Category.RECOMMENDATION
        assert "não foi declarada" in finding.description

    def test_explicit_allow_policy(self):
        result = audit(rule(), default_policy="allow")

        assert "'allow'" in findings_with(result, "FW011")[0].description

    def test_default_policy_deny_is_enough(self):
        assert codes(audit(rule(), default_policy="deny")) == []

    def test_final_reject_all_is_enough(self):
        assert codes(audit(rule(), {**DENY_ALL, "action": "reject"})) == []

    def test_final_deny_all_that_is_disabled_does_not_count(self):
        result = audit(rule(), {**DENY_ALL, "enabled": False})

        assert "FW011" in codes(result)


class TestHygiene:
    def test_disabled_rule(self):
        result = audit(rule(enabled=False), DENY_ALL)

        assert findings_with(result, "FW012")[0].severity is Severity.INFO

    @pytest.mark.parametrize("description", [None, "", "   "])
    def test_missing_description(self, description):
        result = audit(rule(description=description), DENY_ALL)

        assert findings_with(result, "FW013")[0].severity is Severity.INFO

    def test_disabled_rule_skips_exposure_checks(self):
        result = audit(rule(source="any", destination="any", enabled=False), DENY_ALL)

        assert "FW002" not in codes(result)


# --- Exemplos e resultado ---------------------------------------------------


class TestExamples:
    def test_reference_example_has_no_findings(self):
        """Proteção contra falsos positivos óbvios em uma configuração normal."""
        result = audit_file(EXAMPLES / "firewall-rules.json")

        assert result.findings == ()

    def test_issues_example_triggers_every_code(self):
        result = audit_file(EXAMPLES / "firewall-rules-issues.yaml")

        expected = {f"FW{number:03d}" for number in range(1, 15)}
        assert set(codes(result)) == expected
        assert result.stats == {
            "rules_total": 19,
            "rules_valid": 13,
            "rules_invalid": 6,
            "rules_disabled": 1,
        }


class TestResult:
    def test_findings_sorted_by_severity_then_position(self):
        result = audit_file(EXAMPLES / "firewall-rules-issues.yaml")

        ranks = [finding.severity.rank for finding in result.findings]
        assert ranks == sorted(ranks, reverse=True)
        assert result.findings[0].code == "FW002"

    def test_json_structure(self):
        result = audit(rule(source="any", ports=[22]), DENY_ALL)
        data = json.loads(result.to_json())

        assert data["module"] == "firewall"
        assert data["summary"]["findings_total"] == 1
        assert data["summary"]["by_severity"]["high"] == 1
        assert set(data["summary"]["by_category"]) == {"error", "warning", "recommendation"}
        finding = data["findings"][0]
        assert finding["code"] == "FW003"
        assert finding["rule_ids"] == ["r1"]
        assert finding["evidence"]["source"] == ["any"]
        assert {"description", "recommendation", "severity", "category"} <= set(finding)

    def test_json_contains_only_file_name(self, tmp_path):
        path = tmp_path / "rules.json"
        path.write_text(json.dumps({"rules": [DENY_ALL]}), encoding="utf-8")

        data = json.loads(audit_file(path).to_json())

        assert data["input_file"] == "rules.json"
        assert str(tmp_path) not in json.dumps(data)

    @pytest.mark.parametrize(
        ("threshold", "expected"),
        [(Severity.CRITICAL, False), (Severity.HIGH, True), (Severity.INFO, True)],
    )
    def test_threshold(self, threshold, expected):
        result = audit(rule(source="any", ports=[22]), DENY_ALL)

        assert result.has_findings_at_or_above(threshold) is expected
