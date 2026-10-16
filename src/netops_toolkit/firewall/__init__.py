"""Auditoria de regras de firewall armazenadas em JSON ou YAML.

Nenhum firewall real é acessado ou modificado: a análise é feita apenas sobre
o arquivo informado.
"""

from netops_toolkit.firewall.checks import audit_file, audit_ruleset
from netops_toolkit.firewall.loader import RulesFileError
from netops_toolkit.firewall.schema import parse_ruleset

__all__ = ["RulesFileError", "audit_file", "audit_ruleset", "parse_ruleset"]
