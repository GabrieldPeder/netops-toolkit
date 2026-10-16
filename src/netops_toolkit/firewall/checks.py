"""Detecções da auditoria de firewall (FW002 a FW013).

Premissa: as regras são avaliadas de cima para baixo e a primeira que casa
vence. Os critérios estão descritos em ``docs/firewall-format.md``.

Os alertas heurísticos (categoria ``warning``) indicam algo a verificar, não
uma falha confirmada: uma regra ampla pode ser intencional no contexto real.
"""

from __future__ import annotations

from pathlib import Path

from netops_toolkit.firewall.loader import load_rules_file
from netops_toolkit.firewall.schema import IPNetwork, Rule, RuleSet, parse_ruleset
from netops_toolkit.models import AuditResult, Category, Finding, Severity

MODULE_NAME = "firewall"

# (protocolo, porta, serviço). Serviços de administração remota ou bancos de
# dados que raramente precisam ser acessíveis de qualquer origem.
SENSITIVE_SERVICES: tuple[tuple[str, int, str], ...] = (
    ("tcp", 22, "SSH"),
    ("tcp", 23, "Telnet"),
    ("tcp", 445, "SMB"),
    ("tcp", 1433, "Microsoft SQL Server"),
    ("tcp", 3306, "MySQL"),
    ("tcp", 3389, "RDP"),
    ("tcp", 5432, "PostgreSQL"),
    ("tcp", 5900, "VNC"),
    ("tcp", 6379, "Redis"),
    ("tcp", 9200, "Elasticsearch"),
    ("tcp", 27017, "MongoDB"),
    ("udp", 161, "SNMP"),
)
CLEARTEXT_SERVICES: tuple[tuple[str, int, str], ...] = (
    ("tcp", 21, "FTP"),
    ("tcp", 23, "Telnet"),
    ("udp", 69, "TFTP"),
)
BROAD_PORT_THRESHOLD = 1000
# Prefixos mais curtos que estes (mas diferentes de /0) são considerados amplos.
BROAD_PREFIX_BY_VERSION = {4: 8, 6: 16}


def audit_file(path: Path) -> AuditResult:
    """Lê, valida e audita um arquivo de regras.

    Raises:
        RulesFileError: se o arquivo não puder ser lido ou tiver raiz inválida.
    """
    ruleset = parse_ruleset(load_rules_file(path))
    return audit_ruleset(ruleset, input_file=path.name)


def audit_ruleset(ruleset: RuleSet, input_file: str = "-") -> AuditResult:
    active = [rule for rule in ruleset.rules if rule.enabled]

    findings = list(ruleset.findings)
    for rule in active:
        findings += check_exposure(rule)
    findings += check_shadowing(active)
    findings += check_default_deny(ruleset, active)
    for rule in ruleset.rules:
        findings += check_hygiene(rule)

    findings.sort(key=_sort_key)
    stats = {
        "rules_total": ruleset.total_entries,
        "rules_valid": len(ruleset.rules),
        "rules_invalid": ruleset.invalid_count,
        "rules_disabled": len(ruleset.rules) - len(active),
    }
    return AuditResult(
        module=MODULE_NAME, input_file=input_file, findings=tuple(findings), stats=stats
    )


def check_exposure(rule: Rule) -> list[Finding]:
    """FW002-FW007: permissões amplas ou exposição de serviços sensíveis.

    Quando a regra já é ampla demais (FW002, FW004, FW005), os alertas por
    porta (FW003, FW007) não são emitidos, para não repetir o mesmo problema.
    """
    if not rule.is_allow:
        return []
    if rule.source_is_any and rule.destination_is_any:
        return [_any_any(rule)]

    findings: list[Finding] = []
    if rule.protocol == "any":
        findings.append(_any_protocol(rule))
    elif rule.ports is not None and rule.port_count > BROAD_PORT_THRESHOLD:
        findings.append(_broad_ports(rule))
    elif rule.ports is not None:
        if rule.source_is_any:
            exposed = _services_matched(rule, SENSITIVE_SERVICES)
            if exposed:
                findings.append(_sensitive_exposed(rule, exposed))
        cleartext = _services_matched(rule, CLEARTEXT_SERVICES)
        if cleartext:
            findings.append(_cleartext(rule, cleartext))

    broad_sources = [
        network
        for network in rule.sources
        if 0 < network.prefixlen < BROAD_PREFIX_BY_VERSION[network.version]
    ]
    if broad_sources:
        findings.append(_broad_source(rule, broad_sources))
    return findings


def check_shadowing(active: list[Rule]) -> list[Finding]:
    """FW008-FW010: regras que nunca serão aplicadas por causa de uma anterior.

    O critério é conservador: só aponta quando uma única regra anterior cobre
    totalmente a posterior. Coberturas pela união de várias regras não são
    detectadas (falso negativo possível, falso positivo não).
    """
    findings = []
    for index, later in enumerate(active):
        for earlier in active[:index]:
            if covers(earlier, later):
                findings.append(_shadow_finding(earlier, later))
                break
    return findings


def covers(earlier: Rule, later: Rule) -> bool:
    """Indica se todo tráfego casado por ``later`` também casa com ``earlier``."""
    if earlier.protocol not in ("any", later.protocol):
        return False
    if not _networks_covered(later.sources, earlier.sources):
        return False
    if not _networks_covered(later.destinations, earlier.destinations):
        return False
    if earlier.ports is None:
        return True
    if later.ports is None:
        return False
    return all(any(outer.contains(inner) for outer in earlier.ports) for inner in later.ports)


def check_default_deny(ruleset: RuleSet, active: list[Rule]) -> list[Finding]:
    """FW011: ausência de negação explícita para o tráfego não listado."""
    if ruleset.default_policy == "deny":
        return []
    if active:
        last = active[-1]
        if (
            not last.is_allow
            and last.protocol == "any"
            and last.source_is_any
            and last.destination_is_any
        ):
            return []

    if ruleset.default_policy == "allow":
        situation = "A política padrão declarada é 'allow'"
    else:
        situation = "A política padrão não foi declarada"
    return [
        Finding(
            code="FW011",
            category=Category.RECOMMENDATION,
            severity=Severity.MEDIUM,
            title="Sem negação padrão explícita",
            description=(
                f"{situation} e a última regra ativa não é um 'deny any any'. O tráfego "
                "não listado depende do comportamento padrão do equipamento, que pode "
                "ser permitir."
            ),
            recommendation=(
                "Declare 'default_policy: deny' ou termine a lista com uma regra deny/reject "
                "de qualquer origem para qualquer destino, protocolo 'any'."
            ),
            evidence={"default_policy": ruleset.default_policy},
        )
    ]


def check_hygiene(rule: Rule) -> list[Finding]:
    """FW012-FW013: boas práticas de manutenção."""
    findings = []
    if not rule.enabled:
        findings.append(
            Finding(
                code="FW012",
                category=Category.RECOMMENDATION,
                severity=Severity.INFO,
                title="Regra desabilitada",
                description=f"A regra '{rule.id}' está desabilitada e não tem efeito.",
                recommendation=(
                    "Se não for mais necessária, remova-a para simplificar a revisão. "
                    "Se for temporária, registre o motivo na descrição."
                ),
                rule_ids=(rule.id,),
                evidence={"position": rule.position},
            )
        )
    if rule.description is None:
        findings.append(
            Finding(
                code="FW013",
                category=Category.RECOMMENDATION,
                severity=Severity.INFO,
                title="Regra sem descrição",
                description=f"A regra '{rule.id}' não tem descrição.",
                recommendation=(
                    "Descreva a finalidade, o solicitante ou o chamado. Isso facilita "
                    "auditorias futuras e a remoção de regras obsoletas."
                ),
                rule_ids=(rule.id,),
                evidence={"position": rule.position},
            )
        )
    return findings


def _any_any(rule: Rule) -> Finding:
    all_traffic = rule.protocol == "any"
    scope = "todo o tráfego (qualquer protocolo)" if all_traffic else f"tráfego {rule.protocol}"
    return _rule_finding(
        rule,
        code="FW002",
        severity=Severity.CRITICAL if all_traffic else Severity.HIGH,
        title="Permissão de qualquer origem para qualquer destino",
        description=(
            f"A regra '{rule.id}' permite {scope} de qualquer origem para qualquer destino. "
            "Na prática, ela desativa a filtragem para esse tráfego e anula as regras "
            "posteriores que ela cobre."
        ),
        recommendation=(
            "Restrinja origem, destino e serviços ao mínimo necessário. Se a regra for um "
            "teste ou uma exceção temporária, remova-a ou documente prazo e responsável."
        ),
    )


def _any_protocol(rule: Rule) -> Finding:
    from_anywhere = rule.source_is_any
    return _rule_finding(
        rule,
        code="FW004",
        severity=Severity.HIGH if from_anywhere else Severity.MEDIUM,
        title="Permissão para qualquer protocolo e porta",
        description=(
            f"A regra '{rule.id}' permite qualquer protocolo e porta"
            + (" de qualquer origem" if from_anywhere else "")
            + ". Isso inclui serviços administrativos e serviços que podem nem estar "
            "previstos no destino."
        ),
        recommendation="Liste apenas os protocolos e portas de que a aplicação precisa.",
    )


def _broad_ports(rule: Rule) -> Finding:
    from_anywhere = rule.source_is_any
    return _rule_finding(
        rule,
        code="FW005",
        severity=Severity.HIGH if from_anywhere else Severity.MEDIUM,
        title="Faixa de portas ampla",
        description=(
            f"A regra '{rule.id}' libera {rule.port_count} portas {rule.protocol}"
            + (" de qualquer origem" if from_anywhere else "")
            + f" (limite de referência: {BROAD_PORT_THRESHOLD}). Faixas amplas costumam "
            "ser atalhos de configuração e expõem serviços não previstos."
        ),
        recommendation=(
            "Restrinja às portas usadas. Se a faixa for exigida (ex.: portas dinâmicas de "
            "uma aplicação), documente o motivo na descrição da regra."
        ),
    )


def _sensitive_exposed(rule: Rule, services: list[str]) -> Finding:
    return _rule_finding(
        rule,
        code="FW003",
        severity=Severity.HIGH,
        title="Serviço sensível acessível de qualquer origem",
        description=(
            f"A regra '{rule.id}' permite acesso a {', '.join(services)} de qualquer "
            "origem. Esses serviços são alvos frequentes de força bruta e exploração. "
            "Pode ser intencional (ex.: bastion host), mas deve ser verificado."
        ),
        recommendation=(
            "Restrinja a origem a redes de gestão, VPN ou endereços conhecidos. Considere "
            "um bastion host ou acesso via VPN em vez de exposição direta."
        ),
        extra={"services": services},
    )


def _cleartext(rule: Rule, services: list[str]) -> Finding:
    return _rule_finding(
        rule,
        code="FW007",
        severity=Severity.MEDIUM,
        title="Protocolo sem criptografia permitido",
        description=(
            f"A regra '{rule.id}' permite {', '.join(services)}. Esse tipo de protocolo "
            "transmite dados e credenciais sem criptografia."
        ),
        recommendation=(
            "Prefira alternativas cifradas (SSH/SFTP em vez de Telnet/FTP/TFTP). Se o uso "
            "for legado e necessário, restrinja ao segmento mínimo."
        ),
        category=Category.RECOMMENDATION,
        extra={"services": services},
    )


def _broad_source(rule: Rule, networks: list[IPNetwork]) -> Finding:
    shown = ", ".join(str(network) for network in networks)
    return _rule_finding(
        rule,
        code="FW006",
        severity=Severity.LOW,
        title="Origem muito ampla",
        description=(
            f"A regra '{rule.id}' aceita origem {shown}, um bloco muito grande "
            "(IPv4 maior que /8 ou IPv6 maior que /16). Pode ser um erro de prefixo."
        ),
        recommendation="Confirme o prefixo e restrinja a origem às redes realmente necessárias.",
    )


def _shadow_finding(earlier: Rule, later: Rule) -> Finding:
    rule_ids = (later.id, earlier.id)
    evidence = {
        "position": later.position,
        "rule": later.describe_match(),
        "covered_by": earlier.describe_match(),
    }
    if earlier.match_key() == later.match_key() and earlier.action == later.action:
        return Finding(
            code="FW008",
            category=Category.ERROR,
            severity=Severity.LOW,
            title="Regra duplicada",
            description=(
                f"A regra '{later.id}' é idêntica à regra '{earlier.id}' "
                f"(posição {earlier.position}) e nunca será aplicada."
            ),
            recommendation=f"Remova a regra '{later.id}'.",
            rule_ids=rule_ids,
            evidence=evidence,
        )
    if earlier.is_allow == later.is_allow:
        return Finding(
            code="FW010",
            category=Category.ERROR,
            severity=Severity.LOW,
            title="Regra redundante",
            description=(
                f"Todo o tráfego da regra '{later.id}' já é tratado pela regra "
                f"'{earlier.id}' (posição {earlier.position}) com o mesmo efeito. "
                f"A regra '{later.id}' nunca será aplicada."
            ),
            recommendation=(
                f"Remova a regra '{later.id}' ou, se ela for a intenção mais específica, "
                f"verifique se a regra '{earlier.id}' está ampla demais."
            ),
            rule_ids=rule_ids,
            evidence=evidence,
        )
    return Finding(
        code="FW009",
        category=Category.ERROR,
        severity=Severity.MEDIUM,
        title="Regra sombreada por outra com ação oposta",
        description=(
            f"A regra '{later.id}' ({later.action}) nunca será aplicada: a regra "
            f"'{earlier.id}' ({earlier.action}), na posição {earlier.position}, já cobre "
            "todo o tráfego dela. O comportamento pretendido pela regra posterior não "
            "acontece."
        ),
        recommendation=(
            f"Se a intenção é que '{later.id}' prevaleça, mova-a para antes de "
            f"'{earlier.id}'. Caso contrário, remova-a."
        ),
        rule_ids=rule_ids,
        evidence=evidence,
    )


def _rule_finding(
    rule: Rule,
    *,
    code: str,
    severity: Severity,
    title: str,
    description: str,
    recommendation: str,
    category: Category = Category.WARNING,
    extra: dict[str, object] | None = None,
) -> Finding:
    evidence = rule.describe_match()
    if extra:
        evidence.update(extra)
    return Finding(
        code=code,
        category=category,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation,
        rule_ids=(rule.id,),
        evidence=evidence,
    )


def _services_matched(rule: Rule, services: tuple[tuple[str, int, str], ...]) -> list[str]:
    matched = []
    for protocol, port, name in services:
        if rule.protocol != protocol or rule.ports is None:
            continue
        if any(port_range.contains_port(port) for port_range in rule.ports):
            matched.append(f"{name} ({protocol}/{port})")
    return matched


def _networks_covered(inner: tuple[IPNetwork, ...], outer: tuple[IPNetwork, ...]) -> bool:
    return all(
        any(
            network.version == container.version and network.subnet_of(container)  # type: ignore[arg-type]
            for container in outer
        )
        for network in inner
    )


def _sort_key(finding: Finding) -> tuple[int, float, str]:
    position = finding.evidence.get("position")
    return (
        -finding.severity.rank,
        float(position) if isinstance(position, int) else float("inf"),
        finding.code,
    )
