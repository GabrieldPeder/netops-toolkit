# Registro de decisões técnicas

Formato curto: contexto, decisão e alternativas consideradas.

## D1 — Python 3.12+ como versão mínima

- **Decisão:** `requires-python = ">=3.12"`. Desenvolvimento local em Python 3.13.
- **Motivo:** sintaxe moderna de tipos (`X | Y`), mensagens de erro melhores e suporte
  ativo. O módulo `ipaddress` recebeu correções de classificação nessas versões.
- **Alternativas:** 3.10+ (maior compatibilidade, mas classificação de blocos especiais
  menos precisa).

## D2 — Ambiente virtual em `.venv`, chamado por caminho

- **Decisão:** a documentação usa `.\.venv\Scripts\python.exe` diretamente.
- **Motivo:** evita a `ExecutionPolicy` do PowerShell, que bloqueia `Activate.ps1` em
  muitas máquinas Windows, e evita o atalho `python` da Microsoft Store.
- **Alternativas:** `uv` ou `pipx` (mais rápidos, mas são mais uma ferramenta a instalar).

## D3 — Layout `src/`, hatchling e dependências mínimas

- **Decisão:** pacote em `src/netops_toolkit`, build com `hatchling` e versão lida de
  `__init__.py` (fonte única). Execução: `typer`. Desenvolvimento: `pytest` e `ruff`
  (extra `dev`).
- **Motivo:** o layout `src/` obriga os testes a usar o pacote instalado e pega erros de
  empacotamento cedo. Hatchling é leve e segue os padrões PEP 517/621.
- **Alternativas:** setuptools (mais configuração), Poetry (mais uma ferramenta).
  PyYAML só entra na Fase 3, quando for necessário.

## D4 — Estrutura de comandos

- **Decisão:** `netops subnet <CIDR> [--json]` como comando de primeiro nível. Os próximos
  módulos serão subgrupos (`netops firewall audit`, `netops logs analyze`,
  `netops report html`). Também é possível executar com `python -m netops_toolkit`.
- **Motivo:** segue a interface pedida. `subnet` tem uma única ação, então não precisa de
  subgrupo.

## D5 — Códigos de saída

- **Decisão:** `0` sucesso; `1` dado de entrada inválido; `2` erro de uso (padrão do
  Click/Typer).
- **Motivo:** separa "o usuário digitou o comando errado" de "o dado está errado", o que é
  útil em scripts. Nas fases de auditoria será avaliado um código específico para "achados
  encontrados".

## D6 — Endereço com bits de host

- **Decisão:** `192.168.10.77/24` é aceito, a rede `192.168.10.0/24` é calculada,
  `host_bits_set = true` e uma observação é adicionada.
- **Motivo:** é como as pessoas copiam endereços de interfaces (`ip addr`, `ipconfig`).
  Recusar seria pedante; aceitar em silêncio esconderia a correção.
- **Alternativas:** `strict=True` do `ipaddress` (recusar a entrada).

## D7 — Semântica de /31, /32 e IPv6

- **Decisão:** IPv4 /31 segue a RFC 3021 (2 utilizáveis, sem broadcast); /32 é um host
  único. Em IPv6, broadcast, máscara decimal e "hosts utilizáveis" são `null`; são
  informados total de endereços, intervalo e forma expandida.
- **Motivo:** aplicar "total − 2" a esses casos é um erro comum em calculadoras.
- **Detalhe:** as chaves JSON são as mesmas para IPv4 e IPv6, o que facilita o consumo.

## D8 — Licença e controle de versão

- **Decisão:** licença MIT em nome de "GabrieldPeder" (nome do `git config`). O
  repositório Git só é inicializado e só recebe commits sob pedido explícito.

## D9 — Prefixo obrigatório e máscara decimal recusada

- **Decisão:** `192.168.10.0` (sem prefixo) e `192.168.10.0/255.255.255.0` são recusados.
- **Motivo:** o `ipaddress` interpretaria a ausência de prefixo como /32 em silêncio, o que
  provavelmente não é o que o usuário quis. Uma única notação deixa a ferramenta previsível.

## D10 — Saída de texto sem tabelas Rich

- **Decisão:** a saída da calculadora é texto alinhado simples.
- **Motivo:** funciona da mesma forma no console do Windows, em pipes e em redirecionamento
  para arquivo, sem caracteres de borda. A ajuda (`--help`) continua formatada pelo Typer.
