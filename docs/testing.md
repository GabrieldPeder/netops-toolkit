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
| `tests/test_files.py` | leitor compartilhado de JSON/YAML |
| `tests/test_firewall.py` | validação, detecções e configuração do firewall, sem CLI |
| `tests/test_cli.py` | comandos via `typer.testing.CliRunner`: saída, JSON, arquivos e códigos de saída |

Os testes são determinísticos: não acessam rede nem dependem do relógio (o campo
`generated_at` nunca é comparado). Arquivos temporários são criados no `tmp_path` do pytest.
Os endereços usados são privados (RFC 1918) ou de documentação (RFC 5737 / RFC 3849).

Nos testes de firewall, a função auxiliar `rule(**overrides)` cria uma regra válida e
inofensiva. Cada teste altera só o campo que interessa, o que deixa claro o que está sendo
verificado.

## Cobertura atual

**Rede:** IPv4 /0, /24, /30, /31, /32; endereço com bits de host; IPv6 /64, /127, /128;
ausência de conceitos IPv4 em IPv6; classificação de tipos de endereço; prefixos inválidos
(/33, /129, negativo, texto, vazio, máscara decimal); endereços malformados (octeto > 255,
octetos faltando, zero à esquerda, texto, `:::` em IPv6, vazio); ausência de prefixo;
JSON válido e com chaves estáveis.

**Firewall: leitura:** JSON e YAML válidos, JSON com BOM, JSON/YAML malformados,
arquivo inexistente, pasta no lugar de arquivo, extensão não suportada, arquivo acima de
5 MB, arquivo fora de UTF-8, tag YAML `!!python/object` recusada, `22:80` mantido como texto.

**Firewall: estrutura e validação (FW001/FW014):** raiz inválida, `rules` ausente ou não
lista, versão não suportada, lista vazia, `default_policy` inválido, campos obrigatórios,
ID duplicado, ação e protocolo não suportados, booleano YAML em `action`, portas inválidas
(0, 65536, 70000, negativa, texto, booleano, decimal, lista vazia), faixa invertida, `22:80`,
`any` combinado, portas com icmp/any, origem inválida, bits de host, mistura IPv4/IPv6,
`enabled` e `description` com tipo errado, vários erros na mesma regra, campo desconhecido.

**Firewall: detecções:** cada código de FW002 a FW013 tem testes positivos e negativos.
Também são testadas as supressões (FW002 suprime FW003; faixa ampla suprime alertas por
porta), o limite exato de 1000 portas, a equivalência entre deny e reject, a cobertura com
protocolo `any`, regras desabilitadas que não sombreiam, e origem `any` com destino IPv4
coberta por `0.0.0.0/0`.

**Firewall: combinação de regras (FW015):** união exata de faixas de portas, de origens e
de destinos; lacuna de uma porta (não dispara); efeitos mistos (medium); a primeira regra
que casa decide cada célula; prioridade de FW008 a FW010 quando uma regra cobre sozinha;
protocolo `any` exige regra `any` para "outros protocolos"; regra dual-stack que exige
cobertura IPv6; união em IPv6; regras desabilitadas ignoradas; limite de células com
registro em `details.union_check_skipped`.

**Firewall: configuração:** o exemplo é igual aos padrões; serviço sensível personalizado;
lista que substitui a padrão; lista vazia que desativa a detecção; limites de portas e de
prefixo; prefixo 0 que desativa FW006; normalização; 17 casos de configuração inválida.

**Firewall: exemplos e resultado:** `examples/firewall-rules.json` sem nenhum achado
(proteção contra falsos positivos), `examples/firewall-rules-issues.yaml` acionando os 15
códigos, ordenação por severidade, estrutura do JSON, ausência do caminho absoluto no JSON,
limites de `--fail-on`.

**CLI:** `--help`, `--version`, ajuda dos subcomandos, saída de texto IPv4/IPv6/31,
separador de milhar, `--json`, entrada inválida (código 1, sem traceback), argumento
ausente, opção desconhecida e comando desconhecido (código 2). Em `firewall audit`:
arquivo sem achados, texto com achados, `--json`, `--output`, recusa de sobrescrita,
`--overwrite`, pasta de destino inexistente, destino que é uma pasta, arquivo inexistente e
malformado (código 1), `--fail-on` (código 3, sem diferenciar maiúsculas e minúsculas),
`--fail-on` inválido (código 2).
