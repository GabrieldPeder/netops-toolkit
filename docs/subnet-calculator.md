# Calculadora de sub-redes

Implementação: `src/netops_toolkit/network.py`. Comando: `netops subnet <CIDR> [--json]`.

## Entrada aceita

- Formato obrigatório `endereço/prefixo`, com exatamente uma `/`.
- O endereço é validado por `ipaddress.ip_address` (IPv4 ou IPv6). Octetos IPv4 com zero à
  esquerda (`192.168.01.1`) são recusados pelo próprio Python por serem ambíguos (octal).
- O prefixo deve ser um inteiro decimal entre `0` e `32` (IPv4) ou `0` e `128` (IPv6).
- Máscara em notação decimal (`/255.255.255.0`) é **recusada**, para manter uma única
  notação documentada.
- Espaços nas extremidades são ignorados.
- Endereço com bits de host ligados (`192.168.10.77/24`) é aceito: a rede é calculada,
  `host_bits_set` fica `true` e uma observação é adicionada.

Qualquer violação gera `SubnetError` (subclasse de `ValueError`) com mensagem em português,
e a CLI encerra com código `1`.

## Regras de cálculo

### IPv4

| Prefixo | Broadcast | Hosts utilizáveis | Primeiro / último utilizável |
|---|---|---|---|
| `/0` a `/30` | último endereço do bloco | total − 2 | rede + 1 / broadcast − 1 |
| `/31` | não se aplica (`null`) | 2 | os dois endereços (RFC 3021) |
| `/32` | não se aplica (`null`) | 1 | o próprio endereço |

A wildcard é o complemento da máscara (`hostmask`), útil em ACLs Cisco e OSPF.

### IPv6

IPv6 não tem broadcast, e não existe a regra "rede e broadcast reservados". Por isso os
campos `netmask`, `wildcard_mask`, `broadcast_address`, `usable_hosts`, `first_usable` e
`last_usable` são sempre `null`. São informados:

- forma comprimida (`network`) e expandida (`exploded`);
- total de endereços (`2^(128 - prefixo)`);
- primeiro e último endereço do bloco (`first_address`, `last_address`);
- observações para `/64` (SLAAC), `/127` (RFC 6164), `/128` e prefixos maiores que `/64`.

## Classificação (`address_type`)

Valores estáveis em inglês, verificados nesta ordem (o primeiro que casar vence):

| Valor | Critério |
|---|---|
| `default` | prefixo `/0` (`0.0.0.0/0`, `::/0`): todo o espaço de endereços |
| `unspecified` | `0.0.0.0/32`, `::/128` |
| `loopback` | `127.0.0.0/8`, `::1/128` |
| `link_local` | `169.254.0.0/16`, `fe80::/10` |
| `multicast` | `224.0.0.0/4`, `ff00::/8` |
| `documentation` | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `3fff::/20` |
| `shared` | `100.64.0.0/10` (CGNAT, RFC 6598) |
| `reserved` | `ipaddress.is_reserved` (ex.: `240.0.0.0/4`) |
| `private` | `ipaddress.is_private` (RFC 1918, ULA `fc00::/7` e outros blocos de uso especial) |
| `global` | `ipaddress.is_global`, desde que o bloco não contenha faixas não globais |
| `other` | blocos que misturam categorias (ex.: `0.0.0.0/1`, que contém `10.0.0.0/8`) |

`default` é verificado primeiro porque o `ipaddress` classifica `0.0.0.0/0` como global.
`documentation` e `shared` vêm antes de `private` porque o `ipaddress` também os trata como
não globais, e a categoria específica é mais útil. A classificação depende da tabela de
blocos especiais da versão do Python em uso.

## Formato JSON

Todas as chaves estão sempre presentes, em IPv4 e IPv6; campos que não se aplicam são
`null`. Números são inteiros JSON. Atenção: `total_addresses` em IPv6 pode passar de
`2^53`, e consumidores em JavaScript precisam de `BigInt` para lê-lo sem perda de precisão.

| Chave | Tipo | Descrição |
|---|---|---|
| `input` | string | entrada sem espaços nas extremidades |
| `version` | int | `4` ou `6` |
| `network` | string | rede normalizada com prefixo |
| `network_address` | string | endereço de rede |
| `prefix_length` | int | comprimento do prefixo |
| `total_addresses` | int | total de endereços do bloco |
| `first_address` / `last_address` | string | limites do bloco |
| `address_type` | string | ver tabela acima |
| `host_bits_set` | bool | a entrada era um endereço de host |
| `netmask` / `wildcard_mask` | string \| null | só IPv4 |
| `broadcast_address` | string \| null | só IPv4 `/0`–`/30` |
| `usable_hosts` | int \| null | só IPv4 |
| `first_usable` / `last_usable` | string \| null | só IPv4 |
| `exploded` | string \| null | só IPv6 |
| `notes` | lista de strings | observações em português |
