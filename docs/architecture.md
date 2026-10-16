# Arquitetura

## Visão geral

```text
usuário ──► cli.py (Typer) ──► network.py  (lógica pura)
              │                   │
              │ formata texto     └─► SubnetInfo (dataclass) ──► to_json()
              └─► stdout / stderr + código de saída
```

- **`cli.py`** — camada de apresentação. Recebe argumentos, chama a lógica, formata a saída
  e converte exceções de domínio em mensagens e códigos de saída. Não faz cálculo.
- **`network.py`** — lógica de negócio. Não lê argumentos, não imprime e não encerra o
  processo. Retorna dataclasses imutáveis ou lança `SubnetError`.
- **`__main__.py`** — permite `python -m netops_toolkit`, útil quando a pasta `Scripts` do
  ambiente virtual não está no `PATH`.

Essa separação permite testar a lógica com chamadas de função comuns (`tests/test_network.py`)
e a CLI com o `CliRunner` do Typer (`tests/test_cli.py`), sem iniciar subprocessos.

## Evolução planejada

| Fase | Arquivo | Responsabilidade |
|---|---|---|
| 3 | `firewall.py` | carregar, validar e auditar regras (JSON/YAML) |
| 4 | `logs.py` | ler JSON Lines, validar e detectar padrões |
| 5 | `models.py` | modelo de resultado comum (`Finding`, `Severity`, `Report`) |
| 5 | `reports.py` | exportação JSON e HTML com escapamento |

`models.py` será criado só quando houver pelo menos dois módulos produzindo achados. A
calculadora de sub-redes não produz achados de severidade, então não precisa dele.

Na CLI, cada módulo novo será um subgrupo Typer (`netops firewall audit`,
`netops logs analyze`, `netops report html`).

## Princípios

- Execução 100% local: sem rede, sem privilégios, sem alteração do sistema.
- Erros de entrada esperados viram mensagens claras, nunca tracebacks.
- Saída para humanos em português; chaves JSON em inglês e estáveis, para automação.
- Dependências mínimas: só `typer` em tempo de execução.
