"""Planejamento de sub-redes IPv4 com VLSM (máscara de tamanho variável).

Algoritmo clássico: as necessidades são ordenadas da maior para a menor e
cada uma recebe o menor bloco alinhado que comporta seus hosts, em sequência
a partir do início do bloco principal. Como os blocos são potências de 2 em
ordem decrescente, cada novo bloco já começa alinhado e não sobram lacunas
entre eles.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import asdict, dataclass, field
from typing import Any

from netops_toolkit.network import SubnetError, parse_network

MAX_NAME_LENGTH = 64


class VlsmError(ValueError):
    """Entrada inválida ou necessidades que não cabem no bloco."""


@dataclass(frozen=True)
class SubnetNeed:
    name: str
    hosts: int


@dataclass(frozen=True)
class Allocation:
    name: str
    hosts_requested: int
    network: str
    prefix_length: int
    netmask: str
    first_usable: str
    last_usable: str
    broadcast_address: str | None
    usable_hosts: int
    spare_hosts: int


@dataclass(frozen=True)
class VlsmPlan:
    block: str
    total_addresses: int
    allocated_addresses: int
    allocations: tuple[Allocation, ...]
    free_blocks: tuple[str, ...]
    use_31: bool
    notes: list[str] = field(default_factory=list)

    @property
    def utilization_percent(self) -> float:
        return round(100 * self.allocated_addresses / self.total_addresses, 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "block": self.block,
            "total_addresses": self.total_addresses,
            "allocated_addresses": self.allocated_addresses,
            "free_addresses": self.total_addresses - self.allocated_addresses,
            "utilization_percent": self.utilization_percent,
            "use_31": self.use_31,
            "allocations": [asdict(allocation) for allocation in self.allocations],
            "free_blocks": list(self.free_blocks),
            "notes": self.notes,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)


def parse_need(text: str) -> SubnetNeed:
    """Converte ``"nome=hosts"`` em uma necessidade."""
    name, separator, hosts_text = text.rpartition("=")
    name, hosts_text = name.strip(), hosts_text.strip()
    if not separator or not name:
        raise VlsmError(
            f"necessidade inválida: '{text}'. Use o formato nome=hosts, ex.: vendas=100"
        )
    if len(name) > MAX_NAME_LENGTH:
        raise VlsmError(f"nome muito longo (máximo {MAX_NAME_LENGTH} caracteres): '{name}'")
    if not hosts_text.isascii() or not hosts_text.isdigit() or int(hosts_text) < 1:
        raise VlsmError(f"quantidade de hosts inválida em '{text}'. Use um inteiro maior que zero")
    return SubnetNeed(name=name, hosts=int(hosts_text))


def plan_vlsm(block_text: str, needs: list[SubnetNeed], use_31: bool = False) -> VlsmPlan:
    """Distribui as necessidades dentro do bloco.

    Raises:
        VlsmError: bloco inválido, IPv6, nomes repetidos ou falta de espaço.
    """
    if not needs:
        raise VlsmError("informe ao menos uma necessidade (--need nome=hosts)")
    _check_unique_names(needs)

    try:
        block, host_bits_set = parse_network(block_text)
    except SubnetError as exc:
        raise VlsmError(str(exc)) from None
    if block.version != 4:
        raise VlsmError("VLSM está disponível apenas para IPv4; em IPv6 use um /64 por sub-rede")

    notes = []
    if host_bits_set:
        notes.append(f"O endereço informado é um host; o bloco usado é {block}.")

    # Maior primeiro; empate mantém a ordem informada pelo usuário.
    ordered = sorted(needs, key=lambda need: -need.hosts)
    prefixes = [_prefix_for(need.hosts, use_31) for need in ordered]
    required = sum(2 ** (32 - prefix) for prefix in prefixes)
    if required > block.num_addresses:
        details = ", ".join(
            f"{need.name}=/{prefix}" for need, prefix in zip(ordered, prefixes, strict=True)
        )
        raise VlsmError(
            f"as necessidades não cabem em {block}: são necessários {required} endereços "
            f"({details}) e o bloco tem {block.num_addresses}"
        )

    allocations = []
    cursor = int(block.network_address)
    for need, prefix in zip(ordered, prefixes, strict=True):
        network = ipaddress.IPv4Network((cursor, prefix))
        allocations.append(_allocation(need, network))
        cursor += network.num_addresses

    end = int(block.broadcast_address)
    free_blocks: tuple[str, ...] = ()
    if cursor <= end:
        free_blocks = tuple(
            str(network)
            for network in ipaddress.summarize_address_range(
                ipaddress.IPv4Address(cursor), ipaddress.IPv4Address(end)
            )
        )

    if use_31 and any(allocation.prefix_length == 31 for allocation in allocations):
        notes.append("Sub-redes /31 seguem a RFC 3021: 2 endereços utilizáveis, sem broadcast.")

    return VlsmPlan(
        block=str(block),
        total_addresses=block.num_addresses,
        allocated_addresses=cursor - int(block.network_address),
        allocations=tuple(allocations),
        free_blocks=free_blocks,
        use_31=use_31,
        notes=notes,
    )


def _prefix_for(hosts: int, use_31: bool) -> int:
    """Menor sub-rede (maior prefixo) cujo número de hosts utilizáveis atende."""
    if use_31 and hosts <= 2:
        return 31
    for prefix in range(30, -1, -1):
        if 2 ** (32 - prefix) - 2 >= hosts:
            return prefix
    raise VlsmError(f"{hosts} hosts não cabem em nenhuma sub-rede IPv4")


def _allocation(need: SubnetNeed, network: ipaddress.IPv4Network) -> Allocation:
    if network.prefixlen == 31:
        first, last, broadcast = network.network_address, network.broadcast_address, None
        usable = 2
    else:
        first = network.network_address + 1
        last = network.broadcast_address - 1
        broadcast = str(network.broadcast_address)
        usable = network.num_addresses - 2
    return Allocation(
        name=need.name,
        hosts_requested=need.hosts,
        network=str(network),
        prefix_length=network.prefixlen,
        netmask=str(network.netmask),
        first_usable=str(first),
        last_usable=str(last),
        broadcast_address=broadcast,
        usable_hosts=usable,
        spare_hosts=usable - need.hosts,
    )


def _check_unique_names(needs: list[SubnetNeed]) -> None:
    seen: set[str] = set()
    for need in needs:
        key = need.name.casefold()
        if key in seen:
            raise VlsmError(f"nome repetido: '{need.name}'")
        seen.add(key)
