"""Modelo de resultado compartilhado pelos módulos de auditoria.

Firewall (Fase 3), logs (Fase 4) e relatórios (Fase 5) usam as mesmas
estruturas, para que a exportação JSON/HTML seja única.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from netops_toolkit import __version__


class Severity(StrEnum):
    """Impacto potencial de um achado, do maior para o menor."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Quanto maior, mais grave (info = 0, critical = 4)."""
        return len(SEVERITY_ORDER) - 1 - SEVERITY_ORDER.index(self)


SEVERITY_ORDER: tuple[Severity, ...] = tuple(Severity)


class Category(StrEnum):
    """Natureza da evidência de um achado."""

    ERROR = "error"  # fato objetivo (dado inválido, regra inalcançável etc.)
    WARNING = "warning"  # indício heurístico; depende de contexto
    RECOMMENDATION = "recommendation"  # boa prática, sem risco direto evidente


@dataclass(frozen=True)
class Finding:
    """Um achado de auditoria, com motivo e sugestão de correção."""

    code: str
    category: Category
    severity: Severity
    title: str
    description: str
    recommendation: str
    rule_ids: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "category": str(self.category),
            "severity": str(self.severity),
            "title": self.title,
            "rule_ids": list(self.rule_ids),
            "description": self.description,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class AuditResult:
    """Resultado completo de uma auditoria.

    ``stats`` guarda contagens específicas do módulo (ex.: regras analisadas);
    as contagens por severidade e categoria são calculadas a partir dos achados.
    ``details`` guarda informações complementares do módulo (ex.: a
    configuração usada), para que o resultado seja reproduzível.
    """

    module: str
    input_file: str
    findings: tuple[Finding, ...]
    stats: dict[str, int] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )
    tool_version: str = __version__

    def count_by_severity(self) -> dict[str, int]:
        counts = {str(severity): 0 for severity in Severity}
        for finding in self.findings:
            counts[str(finding.severity)] += 1
        return counts

    def count_by_category(self) -> dict[str, int]:
        counts = {str(category): 0 for category in Category}
        for finding in self.findings:
            counts[str(finding.category)] += 1
        return counts

    def has_findings_at_or_above(self, threshold: Severity) -> bool:
        return any(finding.severity.rank >= threshold.rank for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "module": self.module,
            "tool_version": self.tool_version,
            "generated_at": self.generated_at,
            "input_file": self.input_file,
            "summary": {
                **self.stats,
                "findings_total": len(self.findings),
                "by_severity": self.count_by_severity(),
                "by_category": self.count_by_category(),
            },
            "findings": [finding.to_dict() for finding in self.findings],
            "details": self.details,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, ensure_ascii=False)
