"""Cálculo de sub-redes IPv4 e IPv6.

Este módulo contém apenas lógica de negócio: não lê argumentos de linha de
comando nem escreve no terminal. A CLI (``cli.py``) apenas chama
``calculate_subnet`` e formata o resultado.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from typing import Any

IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

# Blocos reservados para documentação e exemplos. São verificados antes de
# "private" porque o módulo ipaddress também os considera privados, o que
# esconderia a informação mais útil para o usuário.
DOCUMENTATION_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("192.0.2.0/24"),  # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # RFC 5737 TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # RFC 5737 TEST-NET-3
    ipaddress.ip_network("2001:db8::/32"),  # RFC 3849
    ipaddress.ip_network("3fff::/20"),  # RFC 9637
)
SHARED_ADDRESS_SPACE = ipaddress.ip_network("100.64.0.0/10")  # RFC 6598 (CGNAT)

# Principais blocos não globais. O ipaddress avalia um bloco apenas pelas suas
# extremidades, então um bloco amplo como 0.0.0.0/1 seria considerado "global"
# mesmo contendo 10.0.0.0/8. Se um bloco "global" contiver algum destes, ele é
# classificado como "other" (misto).
NON_GLOBAL_NETWORKS: tuple[IPNetwork, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("ff00::/8"),
    *DOCUMENTATION_NETWORKS,
)


class SubnetError(ValueError):
    """Entrada inválida para o cálculo de sub-rede.

    A mensagem é destinada ao usuário final e deve explicar o problema.
    """


@dataclass(frozen=True)
class SubnetInfo:
    """Resultado do cálculo de uma sub-rede.

    Campos que não se aplicam a uma versão ou prefixo ficam como ``None``
    (por exemplo, ``broadcast`` em IPv6 ou em IPv4 /31 e /32).
    """

    input: str
    version: int
    network: str
    network_address: str
    prefix_length: int
    total_addresses: int
    first_address: str
    last_address: str
    address_type: str
    host_bits_set: bool
    netmask: str | None = None
    wildcard_mask: str | None = None
    broadcast_address: str | None = None
    usable_hosts: int | None = None
    first_usable: str | None = None
    last_usable: str | None = None
    exploded: str | None = None
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def parse_network(text: str) -> tuple[IPNetwork, bool]:
    """Converte ``"endereço/prefixo"`` em uma rede.

    Retorna a rede e um indicador de que o endereço informado tinha bits de
    host ligados (ex.: ``192.168.10.5/24``). Nesse caso a entrada é aceita e a
    rede correspondente é calculada.

    Raises:
        SubnetError: se o texto não for um endereço IP válido com prefixo CIDR.
    """
    cleaned = text.strip()
    if not cleaned:
        raise SubnetError("informe um endereço no formato endereço/prefixo, ex.: 192.168.10.0/24")
    if cleaned.count("/") != 1:
        raise SubnetError(
            f"'{cleaned}' não está no formato endereço/prefixo "
            "(ex.: 192.168.10.0/24 ou 2001:db8::/64)"
        )

    address_text, prefix_text = cleaned.split("/")
    address = _parse_address(address_text)
    prefix = _parse_prefix(prefix_text, address.max_prefixlen)

    interface = ipaddress.ip_interface(f"{address}/{prefix}")
    network = interface.network
    return network, interface.ip != network.network_address


def calculate_subnet(text: str) -> SubnetInfo:
    """Calcula as informações de uma sub-rede IPv4 ou IPv6."""
    network, host_bits_set = parse_network(text)
    common: dict[str, Any] = {
        "input": text.strip(),
        "version": network.version,
        "network": str(network),
        "network_address": str(network.network_address),
        "prefix_length": network.prefixlen,
        "total_addresses": network.num_addresses,
        "first_address": str(network.network_address),
        "last_address": str(network.broadcast_address),
        "address_type": classify_network(network),
        "host_bits_set": host_bits_set,
    }
    notes = []
    if host_bits_set:
        notes.append(f"O endereço informado é um host; a rede correspondente é {network}.")

    if isinstance(network, ipaddress.IPv4Network):
        return _ipv4_info(network, common, notes)
    return _ipv6_info(network, common, notes)


def classify_network(network: IPNetwork) -> str:
    """Retorna uma categoria estável (em inglês) para uso em JSON.

    A ordem das verificações importa: categorias mais específicas vêm antes de
    ``private``, que no módulo ipaddress abrange vários blocos especiais.
    """
    if network.prefixlen == 0:
        # 0.0.0.0/0 e ::/0 abrangem todo o espaço; o ipaddress os trata como
        # "global", o que seria enganoso.
        return "default"
    if network.is_unspecified:
        return "unspecified"
    if network.is_loopback:
        return "loopback"
    if network.is_link_local:
        return "link_local"
    if network.is_multicast:
        return "multicast"
    if any(_contained_in(network, doc) for doc in DOCUMENTATION_NETWORKS):
        return "documentation"
    if _contained_in(network, SHARED_ADDRESS_SPACE):
        return "shared"
    if network.is_reserved:
        return "reserved"
    if network.is_private:
        return "private"
    if network.is_global:
        if any(_contained_in(special, network) for special in NON_GLOBAL_NETWORKS):
            return "other"
        return "global"
    return "other"


def _ipv4_info(
    network: ipaddress.IPv4Network, common: dict[str, Any], notes: list[str]
) -> SubnetInfo:
    prefix = network.prefixlen
    if prefix == 32:
        # Rota de host: um único endereço, sem rede/broadcast separados.
        broadcast = None
        usable = 1
        first_usable = last_usable = network.network_address
        notes.append("Prefixo /32 representa um único host (rota de host); não há broadcast.")
    elif prefix == 31:
        # RFC 3021: enlaces ponto a ponto usam os dois endereços.
        broadcast = None
        usable = 2
        first_usable, last_usable = network.network_address, network.broadcast_address
        notes.append(
            "Prefixo /31 (RFC 3021): enlace ponto a ponto com 2 endereços utilizáveis; "
            "não há broadcast."
        )
    else:
        broadcast = str(network.broadcast_address)
        usable = network.num_addresses - 2
        first_usable = network.network_address + 1
        last_usable = network.broadcast_address - 1

    return SubnetInfo(
        **common,
        netmask=str(network.netmask),
        wildcard_mask=str(network.hostmask),
        broadcast_address=broadcast,
        usable_hosts=usable,
        first_usable=str(first_usable),
        last_usable=str(last_usable),
        notes=notes,
    )


def _ipv6_info(
    network: ipaddress.IPv6Network, common: dict[str, Any], notes: list[str]
) -> SubnetInfo:
    prefix = network.prefixlen
    notes.append(
        "IPv6 não possui broadcast; o conceito de hosts utilizáveis do IPv4 não se aplica."
    )
    if prefix == 64:
        notes.append("Prefixo /64 é o tamanho recomendado para LANs (necessário para SLAAC).")
    elif prefix == 127:
        notes.append("Prefixo /127 (RFC 6164) é recomendado para enlaces ponto a ponto.")
    elif prefix == 128:
        notes.append("Prefixo /128 representa um único endereço.")
    elif prefix > 64:
        notes.append("Prefixos maiores que /64 impedem o uso de SLAAC na sub-rede.")

    return SubnetInfo(**common, exploded=network.exploded, notes=notes)


def _parse_address(text: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    try:
        return ipaddress.ip_address(text.strip())
    except ValueError:
        raise SubnetError(f"endereço IP inválido: '{text.strip()}'") from None


def _parse_prefix(text: str, max_prefix: int) -> int:
    stripped = text.strip()
    # Aceita apenas o comprimento do prefixo em decimal. Máscaras no formato
    # 255.255.255.0 são recusadas para manter uma única notação documentada.
    if not stripped.isascii() or not stripped.isdigit():
        raise SubnetError(
            f"prefixo inválido: '{stripped}'. Use um número entre 0 e {max_prefix}, ex.: /24"
        )
    prefix = int(stripped)
    if prefix > max_prefix:
        version = "IPv4" if max_prefix == 32 else "IPv6"
        raise SubnetError(
            f"prefixo inválido: /{prefix}. {version} aceita prefixos de 0 a {max_prefix}"
        )
    return prefix


def _contained_in(network: IPNetwork, container: IPNetwork) -> bool:
    return network.version == container.version and network.subnet_of(container)  # type: ignore[arg-type]
