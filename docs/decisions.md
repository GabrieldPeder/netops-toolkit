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

## D11 — PyYAML com carregador seguro e sem sexagesimais (Fase 3)

- **Decisão:** PyYAML como dependência de execução, usando uma subclasse de `SafeLoader`
  que não converte `22:80` em inteiro.
- **Motivo:** YAML é requisito do módulo. `SafeLoader` impede a construção de objetos
  Python arbitrários. No YAML 1.1, `22:80` vira 1360, uma porta válida, e o erro passaria
  despercebido. Com a subclasse, o valor chega como texto e é recusado com uma dica.
- **Alternativas:** extra opcional `[yaml]` (complica a instalação e a documentação);
  `ruamel.yaml` (YAML 1.2, porém mais pesado).

## D12 — Códigos de saída das auditorias

- **Decisão:** `0` análise concluída (mesmo com achados), `1` erro fatal de entrada ou de
  `--output`, `2` uso incorreto, `3` com `--fail-on` quando há achado igual ou acima do
  limite.
- **Motivo:** encontrar problemas é o resultado esperado de uma auditoria, não uma falha
  da ferramenta. O `--fail-on` permite usar a ferramenta em CI sem mudar esse padrão.

## D13 — `models.py` criado na Fase 3

- **Decisão:** antecipar o modelo de achado, antes previsto para a Fase 5.
- **Motivo:** o firewall é o primeiro produtor de achados. Desenhar `Finding`/`AuditResult`
  agora, já pensando em logs e relatórios, evita reescrever o formato depois.

## D14 — Firewall como pacote (`loader`, `schema`, `checks`)

- **Decisão:** `firewall/` em vez de um único `firewall.py`.
- **Motivo:** o plano previa dividir acima de ~400 linhas, e a implementação passa de 1.000.
  As três etapas (ler, validar, analisar) têm responsabilidades e testes distintos.

## D15 — Categoria separada da severidade

- **Decisão:** cada achado tem `category` (`error`, `warning`, `recommendation`) e
  `severity` (`critical` a `info`).
- **Motivo:** atende ao requisito de distinguir erros objetivos de alertas heurísticos. Uma
  regra duplicada é um fato objetivo de baixa severidade; um SSH aberto para a internet é
  um alerta heurístico de alta severidade.

## D16 — Critério conservador de sombreamento e supressão de ruído

- **Decisão:** só aponta sombreamento quando **uma** regra anterior cobre totalmente a
  posterior. Não aponta sobreposição parcial. Alertas por porta não são emitidos quando a
  regra já foi apontada como ampla demais.
- **Motivo:** prefere falsos negativos documentados a falsos positivos, que minam a
  confiança na ferramenta.

## D17 — Campo desconhecido como código próprio (FW014)

- **Decisão:** o plano associava campos desconhecidos à validação. Na implementação eles
  ganharam o código FW014 (`warning`, `low`) e a regra continua válida.
- **Motivo:** FW001 é sempre um erro objetivo que invalida a regra. Misturar um aviso no
  mesmo código tornaria a categoria imprevisível.

## D18 — Relatório guarda só o nome do arquivo

- **Decisão:** `input_file` contém `firewall-rules.json`, não o caminho completo.
- **Motivo:** caminhos absolutos no Windows expõem o nome de usuário. O relatório não deve
  conter informação sensível desnecessária.

## D19 — Configuração do firewall substitui listas

- **Decisão:** `--config` aceita `sensitive_services`, `cleartext_services` e `thresholds`.
  Listas informadas substituem a padrão (lista vazia desativa a detecção) e campos
  desconhecidos são recusados.
- **Motivo:** é explícito e previsível. Um modelo de "adicionar/remover" seria mais
  compacto, mas exigiria entender as duas listas para saber o resultado. O exemplo traz a
  lista completa, pronta para editar.

## D20 — Leitor de arquivos compartilhado (`files.py`)

- **Decisão:** a leitura segura de JSON/YAML saiu de `firewall/loader.py` e foi para
  `files.py`, com a exceção genérica `InputFileError`.
- **Motivo:** regras, configuração do firewall e configuração dos logs (Fase 4) precisam
  das mesmas proteções (tamanho, UTF-8, YAML seguro sem sexagesimais).

## D21 — FW015: cobertura pela combinação de regras

- **Decisão:** um novo código, avaliado só quando nenhuma regra cobre a posterior sozinha.
  O espaço é dividido em células nos limites das regras anteriores, com um limite de
  100.000 células por regra. As regras puladas ficam listadas em
  `details.union_check_skipped`.
- **Motivo:** fecha o falso negativo documentado na Fase 3 sem gerar falsos positivos (a
  cobertura é exata, não heurística). Manter FW008 a FW010 inalterados preserva o
  significado dos achados existentes.
- **Alternativa:** tentar simplificar a geometria (subtração de hiper-retângulos). É mais
  eficiente em casos extremos, porém bem mais difícil de implementar e de verificar.

## D22 — Somente tráfego real na análise de cobertura

- **Decisão:** combinações de origem IPv4 com destino IPv6 (ou o contrário) são ignoradas
  em FW008 a FW010 e em FW015.
- **Motivo:** um teste do FW015 revelou que uma regra com origem `any` e destino IPv4 nunca
  era considerada coberta por regras IPv4, porque a parte IPv6 de `any` ficava "descoberta".
  Esse tráfego não existe, então isso era um falso negativo.

## D23 — VLSM como comando próprio, IPv4, /30 por padrão

- **Decisão:** `netops vlsm BLOCO --need nome=hosts ...`. Enlaces de 2 hosts recebem /30;
  `--use-31` usa /31. Somente IPv4.
- **Motivo:** transformar `subnet` em grupo (`subnet plan`) quebraria
  `netops subnet 192.168.10.0/24`, que faz parte da especificação. O /30 é o padrão mais
  compatível com equipamentos antigos; /31 é opcional. Em IPv6 a prática é um /64 por
  sub-rede, então o "menor bloco que cabe" não se aplica.
- **Alternativa:** ler as necessidades de um arquivo YAML. Isso fica para quando houver
  demanda por planos grandes.

## D24 — CI no Ubuntu e no Windows, Python 3.12 a 3.14

- **Decisão:** matriz de 6 jobs, com permissão somente leitura e cancelamento de execuções
  antigas.
- **Motivo:** o projeto declara suporte a Windows e Linux e a Python 3.12 ou superior. O
  desenvolvimento local usa só Windows com 3.13, então o CI cobre o resto, inclusive
  diferenças de classificação do `ipaddress` entre versões.
