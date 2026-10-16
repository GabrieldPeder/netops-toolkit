# NetOps Toolkit

Ferramenta de linha de comando (CLI) em Python com utilitários para profissionais de redes,
infraestrutura e segurança defensiva. Roda 100% local, sem rede, sem serviços externos e sem
privilégios administrativos.

> **Estado atual (v0.2.0):** **calculadora de sub-redes** e **auditoria de regras de
> firewall** estão implementadas. Análise de logs e relatórios HTML estão no
> [roadmap](#roadmap).

## Problema que o projeto resolve

Tarefas comuns do dia a dia de redes — calcular sub-redes, revisar regras de firewall,
procurar padrões suspeitos em logs — costumam ser feitas manualmente ou com ferramentas
espalhadas. O NetOps Toolkit reúne esses utilitários em uma única CLI, com saída legível
para humanos e em JSON para automação.

## Funcionalidades

| Módulo | Comando | Estado |
|---|---|---|
| Planejamento de redes IP (IPv4/IPv6) | `netops subnet` | Implementado |
| Auditoria de regras de firewall (JSON/YAML) | `netops firewall audit` | Implementado |
| Análise de logs de segurança | `netops logs analyze` | Planejado |
| Relatórios HTML | `netops report html` | Planejado |

### Calculadora de sub-redes

- Aceita IPv4 e IPv6 no formato `endereço/prefixo`.
- Valida endereço e prefixo com mensagens de erro claras (sem traceback).
- IPv4: endereço de rede, máscara, wildcard, broadcast, total de endereços, hosts
  utilizáveis, primeiro e último utilizável.
- Trata corretamente IPv4 **/31** (RFC 3021, enlace ponto a ponto, sem broadcast) e
  **/32** (host único).
- IPv6: forma comprimida e expandida, total de endereços e intervalo — **sem** aplicar
  broadcast ou "hosts utilizáveis", que não existem em IPv6.
- Classifica o bloco (privado, público, documentação, loopback, link-local, CGNAT etc.).
- Aceita endereço de host (ex.: `192.168.10.77/24`), calcula a rede e avisa.
- Saída em JSON com `--json`.

### Auditoria de regras de firewall

Analisa regras **fictícias**, escritas em um formato documentado pelo projeto
([docs/firewall-format.md](docs/firewall-format.md)). Não se conecta a nenhum firewall real.

- Valida a estrutura e cada campo: endereços, redes CIDR, portas, protocolos, ações e IDs
  duplicados. Também trata armadilhas do YAML, como `22:80` virar o número 1360.
- Detecta permissões *any → any*, serviços sensíveis expostos (SSH, RDP, bancos de dados
  etc.), faixas amplas de portas, protocolos sem criptografia, origens muito amplas, regras
  duplicadas, regras sombreadas por outra com ação oposta, regras redundantes e ausência de
  negação padrão.
- Separa **erros objetivos**, **alertas heurísticos** e **recomendações**, cada um com
  severidade (`critical` a `info`), motivo e sugestão de correção.
- Exporta em JSON (`--json` ou `--output`), sem sobrescrever arquivos sem `--overwrite`.
- `--fail-on <severidade>` retorna o código 3 quando há achado igual ou acima dela (útil
  em CI).

## Tecnologias

- Python 3.12+ (módulo `ipaddress` da biblioteca padrão)
- [Typer](https://typer.tiangolo.com/) para a CLI
- PyYAML (somente `SafeLoader`) para arquivos YAML
- pytest para testes
- Ruff para lint e formatação

## Pré-requisitos

- Python **3.12 ou superior**
- Windows 10/11 ou Linux

## Instalação

### Windows 10/11 (PowerShell)

```powershell
# 1. Na pasta do projeto, crie um ambiente virtual
py -3.13 -m venv .venv          # ou: python -m venv .venv

# 2. Instale o projeto em modo editável com as dependências de desenvolvimento
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"

# 3. Execute
.\.venv\Scripts\netops.exe --help
```

> Os comandos chamam o Python do `.venv` diretamente, sem `Activate.ps1`. Isso evita
> erros da política de execução de scripts do PowerShell. Se preferir ativar o ambiente,
> use `.\.venv\Scripts\Activate.ps1` (pode exigir ajuste da ExecutionPolicy).
>
> Se `python` abrir a Microsoft Store, desative os atalhos em *Configurações > Aplicativos >
> Configurações avançadas de aplicativos > Aliases de execução de aplicativos*, ou use o
> caminho completo do Python instalado.

### Linux

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
.venv/bin/netops --help
```

Também é possível executar como módulo: `python -m netops_toolkit --help`.

## Uso

```text
netops --help
netops --version
netops subnet 192.168.10.0/24
netops subnet 192.168.10.0/24 --json
netops subnet 2001:db8:abcd:12::/64
netops firewall audit examples/firewall-rules.json
netops firewall audit examples/firewall-rules-issues.yaml --json
netops firewall audit examples/firewall-rules-issues.yaml --output resultado.json
netops firewall audit examples/firewall-rules-issues.yaml --fail-on high
```

### Exemplos: calculadora de sub-redes

IPv4 /24:

```text
> netops subnet 192.168.10.0/24
Entrada              192.168.10.0/24
Versão               IPv4
Rede                 192.168.10.0/24
Endereço de rede     192.168.10.0
Máscara              255.255.255.0 (/24)
Wildcard             0.0.0.255
Broadcast            192.168.10.255
Total de endereços   256
Hosts utilizáveis    254
Primeiro utilizável  192.168.10.1
Último utilizável    192.168.10.254
Tipo                 privado / uso especial
```

IPv4 /31 (enlace ponto a ponto):

```text
> netops subnet 10.0.0.0/31
...
Broadcast            não se aplica
Total de endereços   2
Hosts utilizáveis    2
Primeiro utilizável  10.0.0.0
Último utilizável    10.0.0.1
...
Observações:
  - Prefixo /31 (RFC 3021): enlace ponto a ponto com 2 endereços utilizáveis; não há broadcast.
```

IPv6 /64:

```text
> netops subnet 2001:db8:abcd:12::/64
Entrada             2001:db8:abcd:12::/64
Versão              IPv6
Rede                2001:db8:abcd:12::/64
Endereço de rede    2001:db8:abcd:12::
Forma expandida     2001:0db8:abcd:0012:0000:0000:0000:0000/64
Prefixo             /64
Total de endereços  18.446.744.073.709.551.616 (2^64)
Primeiro endereço   2001:db8:abcd:12::
Último endereço     2001:db8:abcd:12:ffff:ffff:ffff:ffff
Tipo                documentação (exemplos)

Observações:
  - IPv6 não possui broadcast; o conceito de hosts utilizáveis do IPv4 não se aplica.
  - Prefixo /64 é o tamanho recomendado para LANs (necessário para SLAAC).
```

Saída JSON:

```text
> netops subnet 192.168.10.0/24 --json
{
  "input": "192.168.10.0/24",
  "version": 4,
  "network": "192.168.10.0/24",
  "network_address": "192.168.10.0",
  "prefix_length": 24,
  "total_addresses": 256,
  "first_address": "192.168.10.0",
  "last_address": "192.168.10.255",
  "address_type": "private",
  "host_bits_set": false,
  "netmask": "255.255.255.0",
  "wildcard_mask": "0.0.0.255",
  "broadcast_address": "192.168.10.255",
  "usable_hosts": 254,
  "first_usable": "192.168.10.1",
  "last_usable": "192.168.10.254",
  "exploded": null,
  "notes": []
}
```

Entrada inválida (código de saída `1`, sem traceback):

```text
> netops subnet 300.1.1.1/24
Erro: endereço IP inválido: '300.1.1.1'

> netops subnet 10.0.0.0/33
Erro: prefixo inválido: /33. IPv4 aceita prefixos de 0 a 32
```

O formato do JSON e as regras de cálculo estão em
[docs/subnet-calculator.md](docs/subnet-calculator.md).

### Exemplos: auditoria de firewall

Configuração de referência (`examples/firewall-rules.json`), sem achados:

```text
> netops firewall audit examples/firewall-rules.json
Auditoria de firewall: firewall-rules.json
Regras: 13 (válidas: 13, inválidas: 0, desabilitadas: 0)
Achados: 0  |  crítica: 0  alta: 0  média: 0  baixa: 0  info: 0
Por categoria: erro objetivo: 0  alerta heurístico: 0  recomendação: 0

Nenhum achado.
...
```

Arquivo com problemas propositais (`examples/firewall-rules-issues.yaml`). Trecho da saída
real, com 4 dos 19 achados:

```text
> netops firewall audit examples/firewall-rules-issues.yaml
Auditoria de firewall: firewall-rules-issues.yaml
Regras: 19 (válidas: 13, inválidas: 6, desabilitadas: 1)
Achados: 19  |  crítica: 1  alta: 7  média: 5  baixa: 4  info: 2
Por categoria: erro objetivo: 9  alerta heurístico: 6  recomendação: 4

[CRÍTICA] FW002 Permissão de qualquer origem para qualquer destino  (regra: allow-all-test)
  Tipo: alerta heurístico
  Motivo: A regra 'allow-all-test' permite todo o tráfego (qualquer protocolo) de qualquer
  origem para qualquer destino. Na prática, ela desativa a filtragem para esse tráfego e
  anula as regras posteriores que ela cobre.
  Sugestão: Restrinja origem, destino e serviços ao mínimo necessário. ...

[ALTA] FW003 Serviço sensível acessível de qualquer origem  (regra: ssh-from-internet)
  Tipo: alerta heurístico
  Motivo: A regra 'ssh-from-internet' permite acesso a SSH (tcp/22) de qualquer origem. ...

[ALTA] FW001 Regra inválida  (regra: yaml-sexagesimal)
  Tipo: erro objetivo
  Motivo: Porta inválida: '22:80'. Use '-' para faixas (ex.: '22-80').

[MÉDIA] FW009 Regra sombreada por outra com ação oposta  (regra: guest-printer, block-guest-wifi)
  Tipo: erro objetivo
  Motivo: A regra 'guest-printer' (allow) nunca será aplicada: a regra 'block-guest-wifi'
  (deny), na posição 8, já cobre todo o tráfego dela. ...
...
Atenção: alertas heurísticos indicam pontos a verificar, não falhas confirmadas.
Avalie cada achado no contexto do ambiente.
```

(As linhas longas foram quebradas aqui para facilitar a leitura.)

O formato das regras, os 14 critérios de detecção (FW001 a FW014), as severidades e as
limitações estão em [docs/firewall-format.md](docs/firewall-format.md).

### Códigos de saída

| Código | Significado |
|---|---|
| `0` | Sucesso (em auditorias: análise concluída, mesmo com achados) |
| `1` | Entrada inválida (endereço, prefixo, arquivo ilegível) ou destino de `--output` inválido |
| `2` | Erro de uso (argumento ausente, opção ou comando inexistente) |
| `3` | Auditoria com achado igual ou acima da severidade de `--fail-on` |

## Testes e qualidade

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m ruff format --check .
```

No Linux, troque `.\.venv\Scripts\python.exe` por `.venv/bin/python`.
Veja [docs/testing.md](docs/testing.md).

## Estrutura do projeto

```text
netops-toolkit/
├── docs/
│   ├── architecture.md       # visão geral da arquitetura
│   ├── decisions.md          # registro das decisões técnicas
│   ├── firewall-format.md    # formato das regras e critérios de detecção
│   ├── subnet-calculator.md  # regras de cálculo e formato JSON
│   └── testing.md            # como e o que é testado
├── examples/
│   ├── firewall-rules.json         # configuração de referência (sem achados)
│   └── firewall-rules-issues.yaml  # problemas propositais (FW001 a FW014)
├── src/netops_toolkit/
│   ├── __init__.py           # versão do pacote
│   ├── __main__.py           # python -m netops_toolkit
│   ├── cli.py                # interface Typer (apenas apresentação)
│   ├── models.py             # Finding, Severity, Category, AuditResult
│   ├── network.py            # cálculo de sub-redes (lógica pura)
│   └── firewall/
│       ├── loader.py         # leitura segura de JSON/YAML
│       ├── schema.py         # modelo das regras e validação
│       └── checks.py         # detecções e auditoria
├── tests/
│   ├── test_cli.py
│   ├── test_firewall.py
│   └── test_network.py
├── .gitattributes
├── .gitignore
├── LICENSE
├── pyproject.toml
└── README.md
```

Novos arquivos (`logs.py`, `reports.py`, CI) serão adicionados nas fases correspondentes.

## Limitações conhecidas

- Análise de logs e relatórios HTML ainda não estão disponíveis.
- O prefixo precisa ser informado em notação CIDR (`/24`); máscara decimal
  (`/255.255.255.0`) é recusada de propósito.
- A classificação do tipo de endereço usa o módulo `ipaddress`; versões diferentes do
  Python podem classificar alguns blocos especiais de forma ligeiramente diferente.
- Ainda não há planejamento de múltiplas sub-redes (VLSM).
- Auditoria de firewall: formato próprio (não lê configurações de fabricantes), análise só
  de porta de destino, cobertura pela união de várias regras não é detectada, sobreposição
  parcial com ações opostas não é apontada, e a lista de serviços sensíveis é fixa. Detalhes
  em [docs/firewall-format.md](docs/firewall-format.md#4-limitações-e-falsos-positivosnegativos-conhecidos).

## Aviso sobre auditorias

Os módulos de auditoria geram **indicadores para investigação**, não conclusões
definitivas. Uma regra "ampla" ou uma sequência de falhas de login pode ser legítima no
contexto do seu ambiente. Por isso a auditoria de firewall separa erros objetivos de
alertas heurísticos e recomendações. Os resultados sempre precisam de interpretação humana.

## Roadmap

- [x] Fase 1 — Fundação (pacote, CLI, testes, lint)
- [x] Fase 2 — Calculadora de sub-redes IPv4/IPv6 com saída JSON
- [ ] Fase 2+ — Planejamento de múltiplas sub-redes (VLSM)
- [x] Fase 3 — Auditoria de regras de firewall (JSON/YAML)
- [ ] Fase 3+ — Lista de serviços sensíveis e limites configuráveis; detecção de cobertura
  pela união de regras
- [ ] Fase 4 — Análise de logs de segurança (JSON Lines)
- [ ] Fase 5 — Relatórios JSON/HTML compartilhados
- [ ] Fase 6 — GitHub Actions, revisão final e instalação limpa

## Licença

Distribuído sob a licença MIT. Veja [LICENSE](LICENSE).
