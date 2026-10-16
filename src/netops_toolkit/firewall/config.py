"""Configuração ajustável da auditoria de firewall (``--config``).

Sem arquivo, valem os padrões abaixo. Listas informadas no arquivo
**substituem** a lista padrão correspondente (lista vazia desativa a
detecção). O exemplo completo está em ``examples/firewall-config.yaml``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from netops_toolkit.files import InputFileError, load_structured_file

SERVICE_PROTOCOLS = ("tcp", "udp")


@dataclass(frozen=True)
class Service:
    protocol: str
    port: int
    name: str

    def to_dict(self) -> dict[str, Any]:
        return {"protocol": self.protocol, "port": self.port, "name": self.name}


# Serviços de administração remota ou bancos de dados que raramente precisam
# ser acessíveis de qualquer origem.
DEFAULT_SENSITIVE_SERVICES: tuple[Service, ...] = (
    Service("tcp", 22, "SSH"),
    Service("tcp", 23, "Telnet"),
    Service("tcp", 445, "SMB"),
    Service("tcp", 1433, "Microsoft SQL Server"),
    Service("tcp", 3306, "MySQL"),
    Service("tcp", 3389, "RDP"),
    Service("tcp", 5432, "PostgreSQL"),
    Service("tcp", 5900, "VNC"),
    Service("tcp", 6379, "Redis"),
    Service("tcp", 9200, "Elasticsearch"),
    Service("tcp", 27017, "MongoDB"),
    Service("udp", 161, "SNMP"),
)
DEFAULT_CLEARTEXT_SERVICES: tuple[Service, ...] = (
    Service("tcp", 21, "FTP"),
    Service("tcp", 23, "Telnet"),
    Service("udp", 69, "TFTP"),
)

# (mínimo, máximo) aceitos para cada limite. Prefixo 0 desativa o FW006.
THRESHOLD_LIMITS = {
    "broad_port_count": (1, 65535),
    "broad_prefix_ipv4": (0, 32),
    "broad_prefix_ipv6": (0, 128),
}
TOP_LEVEL_KEYS = frozenset({"version", "sensitive_services", "cleartext_services", "thresholds"})
SERVICE_KEYS = frozenset({"protocol", "port", "name"})


@dataclass(frozen=True)
class FirewallConfig:
    sensitive_services: tuple[Service, ...] = DEFAULT_SENSITIVE_SERVICES
    cleartext_services: tuple[Service, ...] = DEFAULT_CLEARTEXT_SERVICES
    broad_port_count: int = 1000
    broad_prefix_ipv4: int = 8
    broad_prefix_ipv6: int = 16

    def broad_prefix(self, version: int) -> int:
        return self.broad_prefix_ipv4 if version == 4 else self.broad_prefix_ipv6

    def to_dict(self) -> dict[str, Any]:
        return {
            "sensitive_services": [service.to_dict() for service in self.sensitive_services],
            "cleartext_services": [service.to_dict() for service in self.cleartext_services],
            "thresholds": {
                "broad_port_count": self.broad_port_count,
                "broad_prefix_ipv4": self.broad_prefix_ipv4,
                "broad_prefix_ipv6": self.broad_prefix_ipv6,
            },
        }


def load_firewall_config(path: Path) -> FirewallConfig:
    """Lê e valida um arquivo de configuração.

    Raises:
        InputFileError: arquivo ilegível ou configuração inválida.
    """
    return parse_firewall_config(load_structured_file(path))


def parse_firewall_config(data: Any) -> FirewallConfig:
    if not isinstance(data, dict):
        _fail("a raiz deve ser um objeto")
    _reject_unknown(data, TOP_LEVEL_KEYS, "na raiz")

    version = data.get("version", 1)
    if isinstance(version, bool) or version != 1:
        _fail(f"versão não suportada: {version!r}. Versão aceita: 1")

    values: dict[str, Any] = {}
    for key in ("sensitive_services", "cleartext_services"):
        if key in data:
            values[key] = _parse_services(data[key], key)
    if "thresholds" in data:
        values.update(_parse_thresholds(data["thresholds"]))
    return FirewallConfig(**values)


def _parse_services(value: Any, key: str) -> tuple[Service, ...]:
    if not isinstance(value, list):
        _fail(f"'{key}' deve ser uma lista")
    services = []
    for index, item in enumerate(value, start=1):
        where = f"{key}[{index}]"
        if not isinstance(item, dict):
            _fail(f"{where} deve ser um objeto com protocol, port e name")
        _reject_unknown(item, SERVICE_KEYS, f"em {where}")
        missing = sorted(SERVICE_KEYS - set(item))
        if missing:
            _fail(f"{where}: campo(s) obrigatório(s) ausente(s): {', '.join(missing)}")

        protocol, port, name = item["protocol"], item["port"], item["name"]
        if not isinstance(protocol, str) or protocol.strip().lower() not in SERVICE_PROTOCOLS:
            _fail(f"{where}: protocolo inválido {protocol!r}. Aceitos: tcp, udp")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            _fail(f"{where}: porta inválida {port!r}. Use um inteiro de 1 a 65535")
        if not isinstance(name, str) or not name.strip():
            _fail(f"{where}: 'name' deve ser um texto não vazio")
        services.append(Service(protocol.strip().lower(), port, name.strip()))
    return tuple(services)


def _parse_thresholds(value: Any) -> dict[str, int]:
    if not isinstance(value, dict):
        _fail("'thresholds' deve ser um objeto")
    _reject_unknown(value, frozenset(THRESHOLD_LIMITS), "em 'thresholds'")
    parsed = {}
    for key, raw in value.items():
        low, high = THRESHOLD_LIMITS[key]
        if isinstance(raw, bool) or not isinstance(raw, int) or not low <= raw <= high:
            _fail(f"'thresholds.{key}' deve ser um inteiro de {low} a {high} (recebido: {raw!r})")
        parsed[key] = raw
    return parsed


def _reject_unknown(data: dict[Any, Any], allowed: frozenset[str], where: str) -> None:
    unknown = sorted(str(key) for key in data if key not in allowed)
    if unknown:
        # Na configuração, um erro de digitação mudaria a análise em silêncio.
        _fail(f"campo(s) desconhecido(s) {where}: {', '.join(unknown)}")


def _fail(message: str) -> Any:
    raise InputFileError(f"configuração inválida: {message}")
