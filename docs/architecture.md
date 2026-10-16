# Arquitetura

## Visão geral

```text
usuário ──► cli.py (Typer) ──┬─► network.py ─────────► SubnetInfo ──► to_json()
              │              ├─► vlsm.py ────────────► VlsmPlan ────► to_json()
              │              │     (usa network.parse_network)
              │              │
              │              └─► firewall/
              │                   files.py   (arquivo ──► dict/list, seguro; compartilhado)
              │                   config.py  (--config ──► FirewallConfig)
              │                   schema.py  (dict ──► Rule + achados FW001/FW014)
              │                   checks.py  (Rule ──► achados FW002–FW013)
              │                   coverage.py(combinação de regras ──► FW015)
              │                        │
              │                        └─► models.AuditResult ──► to_json()
              │
              └─► stdout / stderr + código de saída (0, 1, 2, 3)
```

- **`cli.py`**: camada de apresentação. Recebe argumentos, chama a lógica, formata a saída,
  grava arquivos com segurança (`--output`/`--overwrite`) e converte exceções de domínio
  em mensagens e códigos de saída. Não faz cálculo nem análise.
- **`network.py`**: cálculo de sub-redes. Função pura que retorna `SubnetInfo` ou lança
  `SubnetError`.
- **`vlsm.py`**: planejamento de sub-redes IPv4 de tamanhos variáveis. Reaproveita a
  validação de entrada de `network.py`.
- **`files.py`**: leitura segura de JSON/YAML compartilhada (limite de tamanho, UTF-8,
  `SafeLoader` sem sexagesimais) e a exceção `InputFileError`.
- **`models.py`**: modelo de resultado comum às auditorias (`Severity`, `Category`,
  `Finding`, `AuditResult`). Será reaproveitado pela análise de logs (Fase 4) e pelos
  relatórios (Fase 5).
- **`firewall/`**: pacote com etapas independentes e testáveis:
  1. `files.load_structured_file` lê o arquivo e lança `InputFileError` para problemas
     fatais;
  2. `config.py` valida a configuração opcional (`--config`) e define os padrões;
  3. `schema.py` valida cada regra e produz objetos `Rule` imutáveis e tipados;
  4. `checks.py` aplica as detecções sobre regras já validadas e monta o `AuditResult`;
  5. `coverage.py` decide se uma regra é coberta pela combinação de regras anteriores
     (FW015).
- **`__main__.py`**: permite `python -m netops_toolkit`.

A lógica não lê argumentos, não imprime e não encerra o processo. Por isso os testes
chamam funções diretamente (`test_network.py`, `test_firewall.py`) e testam a CLI com o
`CliRunner` do Typer (`test_cli.py`), sem subprocessos.

## Evolução planejada

| Fase | Arquivo | Responsabilidade |
|---|---|---|
| 4 | `logs.py` (ou `logs/`) | ler JSON Lines, validar e detectar padrões, produzindo `Finding` |
| 5 | `reports.py` | exportação JSON e HTML com escapamento, a partir de `AuditResult` |

Na Fase 5, a gravação de arquivos (`_write_output`) e a formatação de auditorias devem
migrar de `cli.py` para `reports.py`.

## Princípios

- Execução 100% local: sem rede, sem privilégios, sem alteração do sistema.
- Erros de entrada esperados viram mensagens claras, nunca tracebacks.
- Saída para humanos em português; chaves e valores enumerados do JSON em inglês e
  estáveis, para automação.
- Nenhum arquivo é sobrescrito sem opção explícita.
- Dependências mínimas: `typer` e `pyyaml` em tempo de execução.
