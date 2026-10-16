# Testes

## Como executar

Windows (PowerShell):

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

Linux: troque `.\.venv\Scripts\python.exe` por `.venv/bin/python`.

## Organização

| Arquivo | Escopo |
|---|---|
| `tests/test_network.py` | lógica de cálculo, chamada diretamente, sem CLI |
| `tests/test_cli.py` | comandos via `typer.testing.CliRunner`: saída, JSON e códigos de saída |

Os testes são determinísticos: não acessam rede, relógio nem arquivos externos. Os
endereços usados são privados (RFC 1918) ou de documentação (RFC 5737 / RFC 3849).

## Cobertura atual

**Rede:** IPv4 /0, /24, /30, /31, /32; endereço com bits de host; IPv6 /64, /127, /128;
ausência de conceitos IPv4 em IPv6; classificação de tipos de endereço; prefixos inválidos
(/33, /129, negativo, texto, vazio, máscara decimal); endereços malformados (octeto > 255,
octetos faltando, zero à esquerda, texto, `:::` em IPv6, vazio); ausência de prefixo;
JSON válido e com chaves estáveis.

**CLI:** `--help`, `--version`, ajuda do subcomando, saída de texto IPv4/IPv6/31,
separador de milhar, `--json`, entrada inválida (código 1, sem traceback), argumento
ausente, opção desconhecida e comando desconhecido (código 2).
