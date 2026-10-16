"""Cobertura de uma regra pela combinação de regras anteriores (FW015).

Uma regra B é inalcançável quando todo o tráfego que ela casa já é casado por
regras anteriores, mesmo que nenhuma delas o cubra sozinha. Exemplo: ``80-85``
e ``86-90`` antes de ``80-90``.

Método: o espaço de B (protocolo x origem x destino x porta) é dividido em
células usando os limites das regras anteriores que o interceptam. Dentro de
uma célula, cada regra anterior cobre a célula inteira ou não a toca, então
basta testar um ponto. Para cada célula procura-se a primeira regra anterior
que a cobre (primeira que casa vence); se alguma célula não for coberta, B é
alcançável.
"""

from __future__ import annotations

from dataclasses import dataclass

from netops_toolkit.firewall.schema import MAX_PORT, MIN_PORT, IPNetwork, Rule

# "other" representa protocolos sem regra específica (GRE, ESP etc.), que só
# uma regra com protocolo "any" cobre.
PROTOCOL_ATOMS = ("tcp", "udp", "icmp", "other")
PORT_PROTOCOLS = ("tcp", "udp")
MAX_CELLS = 100_000

# Intervalo fechado [início, fim]. Endereços carregam a versão IP para que
# IPv4 e IPv6 nunca se misturem; portas usam versão 0.
Interval = tuple[int, int, int]
_NO_PORT: Interval = (0, 0, 0)
_ALL_PORTS: Interval = (0, MIN_PORT, MAX_PORT)


class CellLimitExceeded(Exception):
    """O número de células passou do limite; a regra não foi avaliada."""


@dataclass(frozen=True)
class UnionCoverage:
    """Regras anteriores que, juntas, cobrem a regra analisada."""

    covering: tuple[Rule, ...]
    opposite_effect: bool


def union_coverage(
    later: Rule, earlier: list[Rule], max_cells: int | None = None
) -> UnionCoverage | None:
    """Retorna as regras que cobrem ``later`` em conjunto, ou ``None``.

    Raises:
        CellLimitExceeded: se a análise exigir mais células que o limite.
    """
    limit = MAX_CELLS if max_cells is None else max_cells
    first_matches: dict[int, Rule] = {}
    cells = 0

    for protocol in _protocols(later):
        target = _RuleSpace.of(later, protocol)
        candidates = [
            _RuleSpace.of(rule, protocol) for rule in earlier if protocol in _protocols(rule)
        ]
        candidates = [space for space in candidates if space.overlaps(target)]
        if not candidates:
            return None

        sources = _segments(target.sources, [c.sources for c in candidates])
        destinations = _segments(target.destinations, [c.destinations for c in candidates])
        ports = _segments(target.ports, [c.ports for c in candidates])
        cells += len(sources) * len(destinations) * len(ports)
        if cells > limit:
            raise CellLimitExceeded

        for source in sources:
            for destination in destinations:
                if source[0] != destination[0]:
                    # Origem IPv4 com destino IPv6 (ou vice-versa) não é tráfego real.
                    continue
                for port in ports:
                    match = next(
                        (c for c in candidates if c.contains(source, destination, port)), None
                    )
                    if match is None:
                        return None
                    first_matches[match.rule.position] = match.rule

    covering = tuple(first_matches[position] for position in sorted(first_matches))
    opposite = any(rule.is_allow != later.is_allow for rule in covering)
    return UnionCoverage(covering=covering, opposite_effect=opposite)


@dataclass(frozen=True)
class _RuleSpace:
    """Projeção de uma regra em um único protocolo, como listas de intervalos."""

    rule: Rule
    sources: tuple[Interval, ...]
    destinations: tuple[Interval, ...]
    ports: tuple[Interval, ...]

    @classmethod
    def of(cls, rule: Rule, protocol: str) -> _RuleSpace:
        if protocol not in PORT_PROTOCOLS:
            ports: tuple[Interval, ...] = (_NO_PORT,)
        elif rule.ports is None:
            ports = (_ALL_PORTS,)
        else:
            ports = tuple((0, p.start, p.end) for p in rule.ports)
        return cls(
            rule, _address_intervals(rule.sources), _address_intervals(rule.destinations), ports
        )

    def overlaps(self, other: _RuleSpace) -> bool:
        return (
            _any_overlap(self.sources, other.sources)
            and _any_overlap(self.destinations, other.destinations)
            and _any_overlap(self.ports, other.ports)
        )

    def contains(self, source: Interval, destination: Interval, port: Interval) -> bool:
        return (
            _contained(source, self.sources)
            and _contained(destination, self.destinations)
            and _contained(port, self.ports)
        )


def _protocols(rule: Rule) -> tuple[str, ...]:
    return PROTOCOL_ATOMS if rule.protocol == "any" else (rule.protocol,)


def _address_intervals(networks: tuple[IPNetwork, ...]) -> tuple[Interval, ...]:
    return tuple(
        (network.version, int(network.network_address), int(network.broadcast_address))
        for network in networks
    )


def _segments(target: tuple[Interval, ...], others: list[tuple[Interval, ...]]) -> list[Interval]:
    """Divide os intervalos de ``target`` nos limites dos intervalos de ``others``."""
    segments: list[Interval] = []
    for version, low, high in target:
        cuts = {low}
        for intervals in others:
            for other_version, start, end in intervals:
                if other_version != version:
                    continue
                if low < start <= high:
                    cuts.add(start)
                if low < end + 1 <= high:
                    cuts.add(end + 1)
        ordered = sorted(cuts)
        bounds = [*ordered[1:], high + 1]
        segments += [
            (version, start, stop - 1) for start, stop in zip(ordered, bounds, strict=True)
        ]
    return segments


def _contained(segment: Interval, intervals: tuple[Interval, ...]) -> bool:
    version, start, end = segment
    return any(v == version and s <= start and end <= e for v, s, e in intervals)


def _any_overlap(first: tuple[Interval, ...], second: tuple[Interval, ...]) -> bool:
    return any(v1 == v2 and s1 <= e2 and s2 <= e1 for v1, s1, e1 in first for v2, s2, e2 in second)
