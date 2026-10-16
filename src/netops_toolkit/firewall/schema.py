"""Esquema das regras de firewall: modelo tipado e validação.

O formato está documentado em ``docs/firewall-format.md``. Cada problema de
validação vira um achado FW001; regras inválidas ficam fora da análise
heurística para não gerar achados em cascata.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

from netops_toolkit.files import InputFileError
from netops_toolkit.models import Category, Finding, Severity

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

SUPPORTED_VERSIONS = (1,)
ACTIONS = ("allow", "deny", "reject")
PROTOCOLS = ("tcp", "udp", "icmp", "any")
PORT_PROTOCOLS = ("tcp", "udp")
DEFAULT_POLICIES = ("allow", "deny")
TOP_LEVEL_FIELDS = frozenset({"version", "name", "default_policy", "rules"})
RULE_FIELDS = frozenset(
    {"id", "description", "action", "protocol", "source", "destination", "ports", "enabled"}
)
ANY_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("0.0.0.0/0"),
    ipaddress.ip_network("::/0"),
)
MIN_PORT, MAX_PORT = 1, 65535

_PORT_RE = re.compile(r"^(\d+)$")
_PORT_RANGE_RE = re.compile(r"^(\d+)\s*-\s*(\d+)$")
_YAML_BOOL_HINT = (
    " Em YAML, palavras como yes/no/on/off viram booleanos; coloque o valor entre aspas."
)


@dataclass(frozen=True, order=True)
class PortRange:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start + 1

    def contains(self, other: PortRange) -> bool:
        return self.start <= other.start and other.end <= self.end

    def contains_port(self, port: int) -> bool:
        return self.start <= port <= self.end

    def __str__(self) -> str:
        return str(self.start) if self.start == self.end else f"{self.start}-{self.end}"


FULL_PORT_RANGE = PortRange(MIN_PORT, MAX_PORT)


@dataclass(frozen=True)
class Rule:
    """Regra validada. ``ports`` é ``None`` para protocolos sem porta (icmp, any)."""

    id: str
    position: int
    action: str
    protocol: str
    sources: tuple[IPNetwork, ...]
    destinations: tuple[IPNetwork, ...]
    ports: tuple[PortRange, ...] | None
    enabled: bool = True
    description: str | None = None

    @property
    def is_allow(self) -> bool:
        return self.action == "allow"

    @property
    def source_is_any(self) -> bool:
        return any(network.prefixlen == 0 for network in self.sources)

    @property
    def destination_is_any(self) -> bool:
        return any(network.prefixlen == 0 for network in self.destinations)

    @property
    def port_count(self) -> int:
        """Total de portas de destino; ``0`` para protocolos sem porta."""
        return sum(port_range.size for port_range in self.ports or ())

    def match_key(self) -> tuple[Any, ...]:
        """Identifica o tráfego casado pela regra, independente da ordem dos itens."""
        return (
            self.protocol,
            frozenset(self.sources),
            frozenset(self.destinations),
            frozenset(self.ports) if self.ports is not None else None,
        )

    def describe_match(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "action": self.action,
            "protocol": self.protocol,
            "source": _format_networks(self.sources),
            "destination": _format_networks(self.destinations),
            "ports": [str(p) for p in self.ports] if self.ports is not None else None,
        }


@dataclass(frozen=True)
class RuleSet:
    """Resultado da validação: regras válidas e achados FW001/FW014."""

    name: str | None
    default_policy: str | None
    rules: tuple[Rule, ...]
    total_entries: int
    findings: tuple[Finding, ...]

    @property
    def invalid_count(self) -> int:
        return self.total_entries - len(self.rules)


def parse_ruleset(data: Any) -> RuleSet:
    """Valida o conteúdo já decodificado de um arquivo de regras.

    Raises:
        InputFileError: se a estrutura raiz impedir qualquer análise.
    """
    if not isinstance(data, dict):
        raise InputFileError("a raiz do arquivo deve ser um objeto com o campo 'rules'")
    if "rules" not in data:
        raise InputFileError("campo obrigatório ausente na raiz: 'rules'")
    if not isinstance(data["rules"], list):
        raise InputFileError("o campo 'rules' deve ser uma lista de regras")

    version = data.get("version", 1)
    if isinstance(version, bool) or version not in SUPPORTED_VERSIONS:
        raise InputFileError(
            f"versão de formato não suportada: {version!r}. Versões aceitas: "
            + ", ".join(str(v) for v in SUPPORTED_VERSIONS)
        )

    findings: list[Finding] = []
    findings += _unknown_fields(data, TOP_LEVEL_FIELDS, label=None, position=None)

    name = data.get("name")
    if name is not None and not isinstance(name, str):
        findings.append(_invalid_config("'name' deve ser texto", "name"))
        name = None

    default_policy = _parse_default_policy(data, findings)

    rules: list[Rule] = []
    seen_ids: set[str] = set()
    for position, entry in enumerate(data["rules"], start=1):
        rule, rule_findings = _parse_rule(entry, position, seen_ids)
        findings += rule_findings
        if rule is not None:
            rules.append(rule)

    return RuleSet(
        name=name,
        default_policy=default_policy,
        rules=tuple(rules),
        total_entries=len(data["rules"]),
        findings=tuple(findings),
    )


def _parse_default_policy(data: dict[Any, Any], findings: list[Finding]) -> str | None:
    value = data.get("default_policy")
    if value is None:
        return None
    if isinstance(value, str) and value.strip().lower() in DEFAULT_POLICIES:
        return value.strip().lower()
    findings.append(
        _invalid_config(
            f"valor não suportado em 'default_policy': {value!r}. "
            f"Aceitos: {', '.join(DEFAULT_POLICIES)}",
            "default_policy",
        )
    )
    return None


def _parse_rule(entry: Any, position: int, seen_ids: set[str]) -> tuple[Rule | None, list[Finding]]:
    label = f"#{position}"
    if not isinstance(entry, dict):
        message = f"a regra na posição {position} deve ser um objeto (campo: valor)"
        return None, [_invalid_rule(label, position, message, field=None)]

    errors: list[tuple[str, str]] = []
    rule_id = _parse_id(entry, errors)
    if rule_id is not None:
        if rule_id in seen_ids:
            errors.append(("id", f"id duplicado: '{rule_id}' já foi usado em uma regra anterior"))
            label = f"{rule_id} (posição {position})"
        else:
            label = rule_id
            seen_ids.add(rule_id)

    action = _parse_choice(entry, "action", ACTIONS, errors)
    protocol = _parse_choice(entry, "protocol", PROTOCOLS, errors)
    sources = _parse_addresses(entry, "source", errors)
    destinations = _parse_addresses(entry, "destination", errors)
    ports = _parse_ports(entry, protocol, errors)
    enabled = _parse_enabled(entry, errors)
    description = _parse_description(entry, errors)

    if sources and destinations:
        source_versions = {network.version for network in sources}
        destination_versions = {network.version for network in destinations}
        if not source_versions & destination_versions:
            errors.append(
                (
                    "destination",
                    "origem e destino são de versões IP diferentes (IPv4 x IPv6); "
                    "a regra nunca casaria com nenhum tráfego",
                )
            )

    findings = _unknown_fields(entry, RULE_FIELDS, label=label, position=position)
    findings += [_invalid_rule(label, position, message, field) for field, message in errors]
    if errors:
        return None, findings

    # Após a validação sem erros, os campos obrigatórios estão preenchidos.
    assert rule_id is not None and action is not None and protocol is not None
    assert sources is not None and destinations is not None
    rule = Rule(
        id=rule_id,
        position=position,
        action=action,
        protocol=protocol,
        sources=sources,
        destinations=destinations,
        ports=ports,
        enabled=enabled,
        description=description,
    )
    return rule, findings


def _parse_id(entry: dict[Any, Any], errors: list[tuple[str, str]]) -> str | None:
    if "id" not in entry:
        errors.append(("id", "campo obrigatório ausente: 'id'"))
        return None
    value = entry["id"]
    if isinstance(value, bool) or not isinstance(value, str | int):
        errors.append(("id", f"'id' deve ser texto (valor recebido: {value!r})"))
        return None
    text = str(value).strip()
    if not text:
        errors.append(("id", "'id' não pode ser vazio"))
        return None
    return text


def _parse_choice(
    entry: dict[Any, Any], field: str, choices: tuple[str, ...], errors: list[tuple[str, str]]
) -> str | None:
    if field not in entry:
        errors.append((field, f"campo obrigatório ausente: '{field}'"))
        return None
    value = entry[field]
    if not isinstance(value, str):
        hint = _YAML_BOOL_HINT if isinstance(value, bool) else ""
        errors.append((field, f"'{field}' deve ser texto (valor recebido: {value!r}).{hint}"))
        return None
    normalized = value.strip().lower()
    if normalized not in choices:
        errors.append(
            (field, f"valor não suportado em '{field}': '{value}'. Aceitos: {', '.join(choices)}")
        )
        return None
    return normalized


def _parse_addresses(
    entry: dict[Any, Any], field: str, errors: list[tuple[str, str]]
) -> tuple[IPNetwork, ...] | None:
    if field not in entry:
        errors.append((field, f"campo obrigatório ausente: '{field}'"))
        return None
    items = _as_list(entry[field])
    if items is None or not items:
        errors.append((field, f"'{field}' deve ser um endereço, uma rede, 'any' ou uma lista"))
        return None

    if any(isinstance(item, str) and item.strip().lower() == "any" for item in items):
        if len(items) > 1:
            errors.append((field, f"'any' não pode ser combinado com outros itens em '{field}'"))
            return None
        return ANY_NETWORKS

    networks: list[IPNetwork] = []
    valid = True
    for item in items:
        network = _parse_network(item, field, errors)
        if network is None:
            valid = False
        elif network not in networks:
            networks.append(network)
    return tuple(networks) if valid else None


def _parse_network(item: Any, field: str, errors: list[tuple[str, str]]) -> IPNetwork | None:
    if not isinstance(item, str):
        errors.append((field, f"item inválido em '{field}': {item!r} (esperado texto)"))
        return None
    text = item.strip()
    try:
        return ipaddress.ip_network(text)
    except ValueError:
        pass
    try:
        normalized = ipaddress.ip_network(text, strict=False)
    except ValueError:
        errors.append((field, f"endereço ou rede inválida em '{field}': '{text}'"))
        return None
    errors.append(
        (
            field,
            f"'{text}' tem bits de host ligados; informe a rede ({normalized}) "
            "ou o host isolado (sem prefixo)",
        )
    )
    return None


def _parse_ports(
    entry: dict[Any, Any], protocol: str | None, errors: list[tuple[str, str]]
) -> tuple[PortRange, ...] | None:
    uses_ports = protocol in PORT_PROTOCOLS
    if "ports" not in entry:
        return (FULL_PORT_RANGE,) if uses_ports else None
    if protocol is not None and not uses_ports:
        errors.append(
            ("ports", f"'ports' só pode ser usado com tcp ou udp (protocolo: {protocol})")
        )
        return None

    items = _as_list(entry["ports"])
    if items is None or not items:
        errors.append(("ports", "'ports' deve ser uma porta, uma faixa, 'any' ou uma lista"))
        return None
    if any(isinstance(item, str) and item.strip().lower() == "any" for item in items):
        if len(items) > 1:
            errors.append(("ports", "'any' não pode ser combinado com outras portas"))
            return None
        return (FULL_PORT_RANGE,)

    ranges = [_parse_port_item(item, errors) for item in items]
    if any(port_range is None for port_range in ranges):
        return None
    return tuple(sorted({port_range for port_range in ranges if port_range is not None}))


def _parse_port_item(item: Any, errors: list[tuple[str, str]]) -> PortRange | None:
    if isinstance(item, bool) or not isinstance(item, int | str):
        errors.append(("ports", f"porta inválida: {item!r}"))
        return None
    if isinstance(item, int):
        start = end = item
    else:
        text = item.strip()
        single, interval = _PORT_RE.match(text), _PORT_RANGE_RE.match(text)
        if single:
            start = end = int(single.group(1))
        elif interval:
            start, end = int(interval.group(1)), int(interval.group(2))
        else:
            hint = " Use '-' para faixas (ex.: '22-80')." if ":" in text else ""
            errors.append(("ports", f"porta inválida: '{text}'.{hint}"))
            return None

    for port in (start, end):
        if not MIN_PORT <= port <= MAX_PORT:
            errors.append(("ports", f"porta fora do intervalo {MIN_PORT}-{MAX_PORT}: {port}"))
            return None
    if start > end:
        errors.append(("ports", f"faixa de portas invertida: {start}-{end}"))
        return None
    return PortRange(start, end)


def _parse_enabled(entry: dict[Any, Any], errors: list[tuple[str, str]]) -> bool:
    value = entry.get("enabled", True)
    if not isinstance(value, bool):
        errors.append(("enabled", f"'enabled' deve ser true ou false (valor recebido: {value!r})"))
        return True
    return value


def _parse_description(entry: dict[Any, Any], errors: list[tuple[str, str]]) -> str | None:
    value = entry.get("description")
    if value is None:
        return None
    if not isinstance(value, str):
        errors.append(("description", f"'description' deve ser texto (valor recebido: {value!r})"))
        return None
    return value.strip() or None


def _as_list(value: Any) -> list[Any] | None:
    if isinstance(value, list):
        return value
    if isinstance(value, str | int) and not isinstance(value, bool):
        return [value]
    return None


def _unknown_fields(
    data: dict[Any, Any], allowed: frozenset[str], label: str | None, position: int | None
) -> list[Finding]:
    unknown = sorted(str(key) for key in data if key not in allowed)
    if not unknown:
        return []
    where = f"na regra '{label}'" if label else "na raiz do arquivo"
    evidence: dict[str, Any] = {"fields": unknown}
    if position is not None:
        evidence["position"] = position
    return [
        Finding(
            code="FW014",
            category=Category.WARNING,
            severity=Severity.LOW,
            title="Campo desconhecido",
            description=(
                f"Campo(s) não reconhecido(s) {where}: {', '.join(unknown)}. "
                "O campo é ignorado, o que pode esconder um erro de digitação "
                "(ex.: 'destnation' em vez de 'destination')."
            ),
            recommendation="Corrija o nome do campo ou remova-o. Veja docs/firewall-format.md.",
            rule_ids=(label,) if label else (),
            evidence=evidence,
        )
    ]


def _invalid_rule(label: str, position: int, message: str, field: str | None) -> Finding:
    evidence: dict[str, Any] = {"position": position}
    if field:
        evidence["field"] = field
    return Finding(
        code="FW001",
        category=Category.ERROR,
        severity=Severity.HIGH,
        title="Regra inválida",
        description=_sentence(message),
        recommendation=(
            "Corrija a regra conforme docs/firewall-format.md. Regras inválidas são "
            "ignoradas na análise e o firewall real poderia rejeitá-las ou interpretá-las "
            "de forma diferente."
        ),
        rule_ids=(label,),
        evidence=evidence,
    )


def _invalid_config(message: str, field: str) -> Finding:
    return Finding(
        code="FW001",
        category=Category.ERROR,
        severity=Severity.HIGH,
        title="Configuração inválida",
        description=_sentence(message),
        recommendation="Corrija o campo conforme docs/firewall-format.md.",
        evidence={"field": field},
    )


def _sentence(message: str) -> str:
    """Primeira letra maiúscula e ponto final, sem duplicar a pontuação."""
    text = message[0].upper() + message[1:]
    return text if text.endswith(".") else f"{text}."


def _format_networks(networks: tuple[IPNetwork, ...]) -> list[str]:
    if networks == ANY_NETWORKS:
        return ["any"]
    return [str(network) for network in networks]
