# Auditoria de firewall: formato das regras e critérios

Implementação: `src/netops_toolkit/firewall/`. Comando:

```text
netops firewall audit ARQUIVO [--json] [--output ARQUIVO] [--overwrite] [--fail-on SEVERIDADE]
```

As regras são **fictícias** e seguem um formato próprio do projeto. Nenhum firewall real é
acessado ou modificado.

## 1. Formato do arquivo (versão 1)

O mesmo esquema vale para JSON (`.json`) e YAML (`.yaml`/`.yml`). O arquivo deve estar em
UTF-8 (com ou sem BOM) e ter no máximo 5 MB.

```yaml
version: 1                      # opcional; só a versão 1 existe
name: "Firewall de borda"       # opcional
default_policy: deny            # opcional: deny | allow
rules:
  - id: web-https-in            # obrigatório, único
    description: "HTTPS público para o proxy reverso"   # opcional (recomendado)
    action: allow               # obrigatório: allow | deny | reject
    protocol: tcp               # obrigatório: tcp | udp | icmp | any
    source: any                 # obrigatório
    destination: 203.0.113.10   # obrigatório
    ports: [443]                # opcional; só tcp/udp
    enabled: true               # opcional, padrão true
```

### Campos

| Campo | Regras de validação |
|---|---|
| `id` | Texto ou número, não vazio, único no arquivo |
| `action` | `allow`, `deny` ou `reject`, sem diferenciar maiúsculas e minúsculas. `deny` e `reject` têm o mesmo efeito na análise (bloquear) |
| `protocol` | `tcp`, `udp`, `icmp` ou `any` |
| `source`, `destination` | `"any"`, um IP (`10.0.0.5`), uma rede CIDR (`10.0.0.0/24`) ou uma lista. IPv4 e IPv6 são aceitos. `any` não pode ser combinado com outros itens. Rede com bits de host (`10.0.0.5/24`) é recusada |
| `ports` | Porta (`443` ou `"443"`), faixa (`"8000-8080"`), `"any"` ou uma lista. Intervalo de 1 a 65535. Só é permitido com `tcp`/`udp`. Se ausente em tcp/udp, significa todas as portas |
| `enabled` | `true` ou `false` |
| `description` | Texto |

Campos desconhecidos geram o aviso FW014, mas não invalidam a regra.

### Semântica

- **A primeira regra que casa vence.** As regras são avaliadas de cima para baixo, como na
  maioria dos firewalls. As detecções de sombreamento dependem dessa premissa.
- `ports` se refere à **porta de destino**. Porta de origem, interfaces, direção, objetos e
  grupos não fazem parte da v1.
- `0.0.0.0/0` e `::/0` são tratados como "qualquer endereço" nas detecções.

### Cuidados com YAML

| Escrito | YAML 1.1 entenderia | O que o NetOps faz |
|---|---|---|
| `ports: 22:80` | o inteiro 1360 (base 60) | lê como texto e recusa, sugerindo `"22-80"` |
| `action: no` | o booleano `false` | recusa e sugere usar aspas |
| `!!python/object/...` | construir um objeto Python | recusa (carregador seguro) |

Recomendação: coloque faixas de portas entre aspas (`"8000-8080"`).

### Erros fatais (código de saída 1, sem análise)

Arquivo inexistente, pasta no lugar de arquivo, extensão não suportada, arquivo maior que
5 MB, encoding diferente de UTF-8, JSON/YAML malformado, raiz que não é objeto, `rules`
ausente ou não lista, `version` diferente de 1.

## 2. Modelo de achado

| Dimensão | Valores |
|---|---|
| **Categoria** | `error`: fato objetivo (regra inválida, duplicada, inalcançável). `warning`: indício heurístico que depende de contexto. `recommendation`: boa prática |
| **Severidade** | `critical`, `high`, `medium`, `low`, `info` |

Cada achado traz `code`, `title`, `rule_ids`, `description` (o motivo), `recommendation` e
`evidence` (os campos da regra que justificam o achado, incluindo `position`).

## 3. Critérios de detecção

| Código | Detecção | Categoria | Severidade |
|---|---|---|---|
| FW001 | Regra ou configuração inválida (um achado por problema) | error | high |
| FW002 | `allow` de qualquer origem para qualquer destino | warning | critical (protocolo `any`) / high |
| FW003 | Serviço sensível liberado de qualquer origem: SSH 22, Telnet 23, SMB 445, MSSQL 1433, MySQL 3306, RDP 3389, PostgreSQL 5432, VNC 5900, Redis 6379, Elasticsearch 9200, MongoDB 27017 (tcp), SNMP 161 (udp) | warning | high |
| FW004 | `allow` com protocolo `any` (todas as portas) | warning | high (origem `any`) / medium |
| FW005 | `allow` tcp/udp com mais de 1000 portas | warning | high (origem `any`) / medium |
| FW006 | Origem ampla sem ser `any`: IPv4 mais curto que /8, IPv6 mais curto que /16 | warning | low |
| FW007 | Protocolo sem criptografia: FTP 21, Telnet 23 (tcp), TFTP 69 (udp) | recommendation | medium |
| FW008 | Duplicada: mesmo match e mesma ação de uma regra anterior | error | low |
| FW009 | Sombreada: uma regra anterior com efeito oposto cobre todo o tráfego desta | error | medium |
| FW010 | Redundante: uma regra anterior com o mesmo efeito cobre todo o tráfego desta | error | low |
| FW011 | `default_policy` diferente de `deny` e última regra ativa não é deny/reject any→any com protocolo `any` | recommendation | medium |
| FW012 | Regra desabilitada | recommendation | info |
| FW013 | Regra sem descrição | recommendation | info |
| FW014 | Campo desconhecido (provável erro de digitação) | warning | low |

### Regras de supressão (para evitar ruído)

- Só regras `allow` passam por FW002 a FW007.
- Quando FW002 dispara, FW003 a FW007 não são avaliados para a mesma regra.
- Quando a regra já é ampla (FW004 ou FW005), os alertas por porta (FW003, FW007) não são
  emitidos.
- Regras inválidas não passam pelas detecções FW002 a FW013.
- Regras desabilitadas recebem apenas FW012 e FW013 e não sombreiam outras regras.

### Cobertura (FW008 a FW010)

A regra A (anterior) cobre a regra B (posterior) quando todas as condições abaixo valem:

1. o protocolo de A é `any` ou igual ao de B;
2. cada rede de origem de B está contida em alguma rede de origem de A (`subnet_of`);
3. o mesmo vale para o destino;
4. A não restringe portas (icmp/any) ou cada faixa de portas de B cabe em uma faixa de A.

O achado aponta a **primeira** regra que cobre B.

## 4. Limitações e falsos positivos/negativos conhecidos

- **Heurísticas dependem de contexto.** Um bastion host com SSH aberto (FW003), um
  servidor FTP legado isolado (FW007) ou uma faixa de portas exigida por uma aplicação
  (FW005) podem ser legítimos. Os achados são pontos de verificação, não falhas confirmadas.
- **Cobertura pela união de regras não é detectada.** Se `80-85` e `86-90` vêm antes de
  `80-90`, a terceira regra também nunca é aplicada, mas nenhum achado é gerado. É um falso
  negativo por escolha: o critério conservador evita falsos positivos.
- **Sobreposição parcial com ações opostas não é apontada.** O padrão "negar algo
  específico e liberar algo amplo depois" é legítimo e muito comum.
- **Chaves duplicadas** no mesmo objeto JSON/YAML são resolvidas pelo parser (vale a
  última) sem aviso.
- A lista de serviços sensíveis e os limites (1000 portas, /8, /16) são fixos no código.
- FW011 considera só a última regra **válida e ativa**. Se a regra de negação final for
  inválida, FW011 também é emitido.
- A análise de cobertura compara cada regra com todas as anteriores (O(n²)). É adequada
  para centenas ou poucos milhares de regras.

## 5. Formato do resultado JSON

```json
{
  "module": "firewall",
  "tool_version": "0.2.0",
  "generated_at": "2026-10-16T14:00:00+00:00",
  "input_file": "firewall-rules-issues.yaml",
  "summary": {
    "rules_total": 19, "rules_valid": 13, "rules_invalid": 6, "rules_disabled": 1,
    "findings_total": 19,
    "by_severity": {"critical": 1, "high": 7, "medium": 5, "low": 4, "info": 2},
    "by_category": {"error": 9, "warning": 6, "recommendation": 4}
  },
  "findings": [
    {
      "code": "FW002",
      "category": "warning",
      "severity": "critical",
      "title": "Permissão de qualquer origem para qualquer destino",
      "rule_ids": ["allow-all-test"],
      "description": "...",
      "recommendation": "...",
      "evidence": {"position": 19, "action": "allow", "protocol": "any",
                   "source": ["any"], "destination": ["any"], "ports": null}
    }
  ]
}
```

Os achados são ordenados por severidade (da maior para a menor), depois pela posição da
regra. `input_file` guarda apenas o nome do arquivo, sem o caminho, para não expor
diretórios locais.

## 6. Códigos de saída

| Código | Situação |
|---|---|
| `0` | Análise concluída (mesmo com achados) |
| `1` | Erro fatal de arquivo, ou problema com `--output` (arquivo já existe sem `--overwrite`, pasta inexistente) |
| `2` | Erro de uso (argumento ausente, opção inválida, severidade inválida em `--fail-on`) |
| `3` | `--fail-on` informado e há achado com severidade igual ou maior |
