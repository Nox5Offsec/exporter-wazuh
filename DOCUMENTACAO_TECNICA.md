# Documentação Técnica — SOC Exporter

**Versão:** 1.0.0
**Autores:** Cumbuc4 · Nox5
**Repositório:** https://github.com/Nox5Offsec/exporter-wazuh

---

## Sumário

1. [Objetivo](#1-objetivo)
2. [Arquitetura geral](#2-arquitetura-geral)
3. [Fluxo de execução](#3-fluxo-de-execução)
4. [Componentes e funções](#4-componentes-e-funções)
5. [Integrações e payloads de API](#5-integrações-e-payloads-de-api)
6. [Configuração](#6-configuração)
7. [Regras de negócio](#7-regras-de-negócio)
8. [Dependências](#8-dependências)
9. [Instalação e uso](#9-instalação-e-uso)
10. [Pontos de atenção](#10-pontos-de-atenção)

---

## 1. Objetivo

O SOC Exporter é um agente leve instalado no servidor do cliente que:

- Monitora o arquivo de alertas do Wazuh em tempo real (`alerts.json`)
- Enriquece cada evento com metadados de identificação do ambiente
- Armazena eventos localmente em buffer SQLite com garantia de entrega
- Envia eventos em batch para a API central do SOC via HTTP
- Mantém o backend informado sobre a associação de agentes a grupos do Wazuh
- Envia heartbeats periódicos para monitoramento de disponibilidade do agente

O exporter garante **entrega confiável** mesmo em cenários de indisponibilidade da API (retry com backoff exponencial) e **zero perda de eventos** durante downtime ou rotação de logs.

---

## 2. Arquitetura geral

```
┌──────────────────────────────────────────────────────────────┐
│                        SERVIDOR DO CLIENTE                   │
│                                                              │
│  /var/ossec/logs/alerts/alerts.json                          │
│              │                                               │
│              │ tail -F (polling 0.2s)                        │
│              ▼                                               │
│        [ Collector ]  ──enriquece──►  hostname               │
│              │                        installation_id        │
│              │ push()                 sent_at                │
│              ▼                                               │
│         [ Buffer ]  ◄── SQLite WAL /var/lib/soc-exporter/    │
│              │              buffer.db                        │
│              │ fetch_ready() / ack() / nack()                │
│              ▼                                               │
│         [ Sender ]  ──────────────────────────────────────►  │
│              │              POST /v1/ingest/wazuh            │
│              │                                               │
│       [ Heartbeat ] ──────────────────────────────────────►  │
│                             POST /v1/agents/heartbeat        │
│                                                              │
│   [ AgentGroupCache ]  ◄── Wazuh REST API (primário)         │
│         (thread)       ◄── global.db (fallback)              │
│                        ◄── filesystem (fallback)             │
└──────────────────────────────────────────────────────────────┘
                                  │
                                  ▼
                      API CENTRAL DO SOC
```

O serviço roda como daemon systemd com **5 threads simultâneas**:

| Thread | Responsabilidade |
|--------|-----------------|
| `collector` | Lê alertas do Wazuh e popula o buffer |
| `sender` | Drena o buffer e envia à API |
| `heartbeat` | Envia keep-alive a cada 60s |
| `agent-group-cache` | Mantém o mapa agente→grupo atualizado |
| `main` | Orquestra inicialização e shutdown gracioso |

---

## 3. Fluxo de execução

### 3.1 Inicialização (`soc-exporter init`)

```
Operador executa: soc-exporter init
         │
         ├─ [1/2] Coleta credenciais da API SOC
         │        ├─ URL da API
         │        ├─ Activation Key
         │        ├─ Nome do agente
         │        └─ Ambiente (prod/staging/dev)
         │
         ├─ [2/2] Coleta credenciais da API Wazuh
         │        ├─ URL da API Wazuh (default: https://localhost:55000)
         │        ├─ Usuário (default: wazuh-wui)
         │        └─ Senha (entrada silenciosa via getpass)
         │
         ├─ Testa autenticação na API Wazuh (aviso se falhar, não aborta)
         │
         ├─ POST /v1/agents/register → recebe installation_id + ingestion_token
         │
         └─ Salva config em /etc/soc-exporter/config.json (modo 640)
```

### 3.2 Operação contínua (`systemctl start soc-exporter`)

```
service.py: run()
    │
    ├─ Verifica registro (installation_id + ingestion_token presentes)
    ├─ Inicializa Buffer (SQLite WAL)
    ├─ Inicializa APIClient (Bearer token)
    ├─ AgentGroupCache.load_once()  ← carga síncrona antes de iniciar threads
    │
    ├─ Inicia threads:
    │    ├─ Collector.start()
    │    ├─ Sender.start()
    │    ├─ Heartbeat.start()
    │    └─ AgentGroupCache.start()
    │
    ├─ Aguarda SIGTERM / SIGINT
    │
    └─ Shutdown:
         ├─ Sinaliza stop_event para todas as threads
         └─ join(timeout=10s) em cada thread
```

### 3.3 Coleta de eventos (Collector)

```
Loop principal (a cada 0.2s):
    │
    ├─ os.stat(alerts.json)
    │    ├─ FileNotFoundError → aguarda 10s, tenta novamente
    │    ├─ inode diferente → rotação rename detectada → reabre arquivo
    │    └─ size < posição atual → rotação copytruncate → volta ao início
    │
    ├─ Lê próxima linha (até 2 MB)
    │
    ├─ json.loads(linha)
    │    └─ JSONDecodeError → incrementa contador de erros, continua
    │
    ├─ _enrich(event):
    │    ├─ event["_hostname"] = socket.gethostname()
    │    ├─ event["_installation_id"] = config.installation_id
    │    └─ event["_sent_at"] = datetime.utcnow().isoformat()
    │
    └─ buffer.push(event)
```

### 3.4 Envio de eventos (Sender)

```
Loop principal (a cada 5s):
    │
    ├─ buffer.fetch_ready(limit=100)
    │    └─ SELECT eventos com next_retry <= now()
    │
    ├─ agent_groups = AgentGroupCache.get_for_batch(events)
    │    └─ Retorna TODOS os agentes do cache (mapa completo)
    │
    ├─ POST /v1/ingest/wazuh  {events, agent_groups}
    │
    └─ Resultado:
         ├─ 2xx → buffer.ack(ids)      ← remove do buffer
         ├─ 400/422 → buffer.ack(ids)  ← descarta (payload inválido)
         ├─ 401/403 → buffer.nack()    ← suspende sender, log CRITICAL
         └─ 429/5xx / timeout → buffer.nack() + backoff exponencial
```

### 3.5 Cache de grupos de agentes (AgentGroupCache)

```
load_once() [síncrono antes do start]
    │
    └─ _refresh()
         │
         ├─ Se wazuh_api_user + wazuh_api_password configurados:
         │    └─ _read_from_wazuh_api()
         │         ├─ _get_jwt() → POST /security/user/authenticate
         │         │    └─ Token cacheado por 840s (900s - 60s de buffer)
         │         └─ GET /agents?select=name,group&limit=500
         │
         ├─ Senão, se global.db existir:
         │    └─ _read_from_global_db()
         │         ├─ Tenta: JOIN belongs + "group" tables
         │         └─ Fallback: coluna agent."group"
         │
         └─ Senão:
              └─ _read_from_filesystem()
                   ├─ Lê /var/ossec/etc/client.keys
                   └─ Lê /var/ossec/queue/agent-groups/{id}

Thread background: repete _refresh() a cada 300s
```

---

## 4. Componentes e funções

### 4.1 `service.py` — Orquestrador

| Função | Descrição |
|--------|-----------|
| `run(config)` | Ponto de entrada do serviço. Inicializa todos os componentes, inicia threads e bloqueia até SIGTERM/SIGINT |
| `_shutdown(workers, stop_event)` | Para todas as threads com timeout de 10s |

**Responsabilidades:**
- Verifica registro antes de iniciar (`config.is_registered()`)
- Cria o `stop_event` compartilhado entre todas as threads
- Chama `AgentGroupCache.load_once()` de forma síncrona — garante que o primeiro batch já vai com grupos
- Trata `KeyboardInterrupt` e `SystemExit` para shutdown gracioso

---

### 4.2 `collector.py` — Coletor de Alertas

| Função | Descrição |
|--------|-----------|
| `run()` | Loop principal da thread; reinicia automaticamente após crash (pausa 5s) |
| `_tail()` | Abre o arquivo e itera linha a linha com polling |
| `_check_rotation(fd, path, inode, pos)` | Detecta rotação por inode ou por shrink |
| `_enrich(event)` | Adiciona `_hostname`, `_installation_id`, `_sent_at` ao evento |
| `get_stats()` | Retorna `{"parsed": int, "json_errors": int}` |

**Constantes:**
- `_POLL_INTERVAL = 0.2s` — frequência de leitura
- `_MISSING_FILE_RETRY = 10s` — pausa quando alerts.json não existe
- `_MAX_LINE_BYTES = 2 * 1024 * 1024` — limite por linha (2 MB)

---

### 4.3 `buffer.py` — Buffer SQLite

| Função | Descrição |
|--------|-----------|
| `push(event)` | Insere um evento na fila |
| `push_batch(events)` | Insere múltiplos eventos em uma transação |
| `fetch_ready(limit)` | Retorna até `limit` eventos prontos para envio (`next_retry <= now`) |
| `ack(ids)` | Remove eventos confirmados da fila |
| `nack(ids, base_delay, max_delay)` | Reagenda eventos com backoff exponencial: `min(base * 2^attempts, max)` |
| `pending_count()` | Conta total de eventos na fila |
| `set_meta(key, value)` | Persiste metadado de runtime |
| `get_meta(key)` | Recupera metadado de runtime |

**Schema SQLite:**
```sql
CREATE TABLE events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    payload     TEXT    NOT NULL,        -- JSON serializado
    queued_at   TEXT    NOT NULL,        -- ISO-8601 UTC
    attempts    INTEGER DEFAULT 0,       -- número de tentativas
    next_retry  TEXT    NOT NULL         -- ISO-8601 UTC, indexado
);

CREATE TABLE metadata (
    key   TEXT PRIMARY KEY,
    value TEXT
);
```

**Configuração SQLite:** `PRAGMA journal_mode=WAL`, `PRAGMA synchronous=NORMAL` — balanceia durabilidade e performance.

---

### 4.4 `sender.py` — Sender com Retry

| Função | Descrição |
|--------|-----------|
| `run()` | Loop principal (intervalo configurável, default 5s) |
| `_flush()` | Lê um batch do buffer, consulta grupos, chama API, trata resultado |
| `_write_meta(last_error)` | Persiste `last_send_at` e `last_send_error` no buffer |
| `get_stats()` | Retorna `{"sent", "failed_batches", "retried", "dropped", "auth_failed"}` |

**Estratégia de retry:**

| Exceção | Ação |
|---------|------|
| `NetworkError` | `nack()` + backoff exponencial |
| `APIError` retryable (429, 5xx) | `nack()` + backoff exponencial |
| `AuthError` (401/403) | `nack()` + log CRITICAL + latch (para de enviar) |
| `PayloadError` (400/422) | `ack()` + drop (nunca vai melhorar) |
| Outros `APIError` | `ack()` + drop |

---

### 4.5 `heartbeat.py` — Heartbeat

| Função | Descrição |
|--------|-----------|
| `run()` | Loop com intervalo de 60s (configurável) |
| `_send()` | POST `/v1/agents/heartbeat` com stats do buffer |

**Payload enviado:**
```json
{
  "installation_id": "inst_xxx",
  "hostname": "servidor-cliente",
  "stats": {
    "buffer_pending": 0,
    "sent": 1500,
    "failed_batches": 0,
    "retried": 2,
    "dropped": 0
  }
}
```

---

### 4.6 `agent_groups.py` — Cache de Grupos

| Função | Descrição |
|--------|-----------|
| `load_once()` | Carga síncrona inicial (bloqueia até concluir) |
| `get_for_batch(events)` | Retorna todos os pares `{agent_name, group_name}` do cache |
| `run()` | Thread background que chama `_refresh()` a cada `refresh_interval` |
| `_refresh()` | Seleciona fonte e atualiza `_cache` atomicamente (sob RLock) |
| `_get_jwt()` | Retorna token JWT válido; autentica se expirado ou ausente |
| `_read_from_wazuh_api()` | Lê grupos via `GET /agents?select=name,group` |
| `_read_from_global_db()` | Lê grupos do SQLite do Wazuh (`/var/ossec/var/db/global.db`) |
| `_query_belongs_table()` | Query via tabelas `belongs` + `"group"` (Wazuh 4.x) |
| `_query_agent_group_column()` | Query via coluna `agent."group"` (fallback) |
| `_read_from_filesystem()` | Lê via `client.keys` + arquivos em `queue/agent-groups/` |

**Normalização de grupos:**
- `group.strip().lower()` em todos os valores
- Agente com `group: null` é omitido do cache
- Agente em múltiplos grupos gera uma entrada por grupo

**Constantes:**
- `_TOKEN_EXPIRY_BUFFER = 60s` — renova JWT 60s antes de expirar
- `_AGENTS_PAGE_LIMIT = 500` — limite de paginação da API Wazuh

---

### 4.7 `api_client.py` — Cliente HTTP

| Função | Descrição |
|--------|-----------|
| `register_agent(activation_key, agent_name, hostname, environment)` | POST `/v1/agents/register` |
| `heartbeat(installation_id, hostname, stats)` | POST `/v1/agents/heartbeat` |
| `ingest_events(installation_id, events, agent_groups)` | POST `/v1/ingest/wazuh` |

**Timeouts:** `connect=10s`, `read=30s`
**Retry HTTP nativo (urllib3):** 2 tentativas para 502/503/504

---

### 4.8 `config.py` — Configuração

| Função | Descrição |
|--------|-----------|
| `load()` | Carrega config do disco; lança `FileNotFoundError` se ausente |
| `load_or_default()` | Carrega config ou retorna defaults |
| `save()` | Persiste config em JSON com modo 640 |
| `is_registered()` | Verifica se `installation_id` e `ingestion_token` estão presentes |
| `update(data)` | Atualiza campos e salva |
| `get(key, default)` | Acessa chave com valor padrão |

---

### 4.9 `logger.py` — Logger com Sanitização

| Função | Descrição |
|--------|-----------|
| `setup(level, log_file)` | Configura handlers de console e arquivo rotativo |
| `get()` | Retorna o logger global `soc_exporter` |

**Filtro de sanitização:** remove tokens Bearer e senhas dos logs via regex antes de qualquer handler escrever. Garante que credenciais nunca apareçam em `/var/log/soc-exporter/soc-exporter.log` nem no journald.

---

### 4.10 `cli.py` — Interface de Linha de Comando

| Comando | Descrição |
|---------|-----------|
| `soc-exporter init` | Wizard de registro interativo |
| `soc-exporter start` | Inicia o forwarder em foreground |
| `soc-exporter status` | Exibe estado do agente, buffer e conectividade |

**Saída do `status`:**
```
installation_id : <uuid>
api_url         : https://<soc-api-host>
alerts_file     : /var/ossec/logs/alerts/alerts.json  [OK]
buffer_pending  : 0
last_heartbeat  : <timestamp>  [OK]
last_send       : <timestamp>  [OK]
systemd         : active (running)
```

---

## 5. Integrações e payloads de API

### 5.1 `POST /v1/agents/register`

**Request:**
```json
{
  "activation_key": "ACT-XXXX-XXXX",
  "agent_name": "cliente-prod-01",
  "hostname": "srv-wazuh-01",
  "environment": "prod"
}
```

**Response:**
```json
{
  "data": {
    "installation_id": "inst_xxxxxxxxxxxxxxxx",
    "ingestion_token": "eyJhbGc...",
    "api_url": "https://<soc-api-host>"
  }
}
```

---

### 5.2 `POST /v1/ingest/wazuh`

**Headers:**
```
Authorization: Bearer <ingestion_token>
Content-Type: application/json
```

**Request:**
```json
{
  "installation_id": "inst_xxxxxxxxxxxxxxxx",
  "events": [
    {
      "rule": { "id": 1001, "level": 5, "description": "Exemplo de alerta" },
      "agent": { "name": "agent-hostname", "id": "001" },
      "timestamp": "2024-01-01T00:00:00.000Z",
      "_hostname": "wazuh-server",
      "_installation_id": "inst_xxxxxxxxxxxxxxxx",
      "_sent_at": "2024-01-01T00:00:01.000Z"
    }
  ],
  "agent_groups": [
    { "agent_name": "agent-a",  "group_name": "default" },
    { "agent_name": "agent-b",  "group_name": "default" },
    { "agent_name": "agent-b",  "group_name": "grupo-customizado" },
    { "agent_name": "agent-c",  "group_name": "outro-grupo" }
  ]
}
```

> `agent_groups` contém **o mapa completo** de todos os agentes conhecidos, não apenas os que aparecem no batch. O backend deve fazer upsert idempotente.
> O campo é omitido se `send_agent_groups: false` ou se o cache estiver vazio.

**Response:**
```json
{ "_request_id": "req-uuid-xxx" }
```

---

### 5.3 `POST /v1/agents/heartbeat`

**Request:**
```json
{
  "installation_id": "inst_xxxxxxxxxxxxxxxx",
  "hostname": "wazuh-server",
  "stats": {
    "buffer_pending": 0,
    "sent": 1500,
    "failed_batches": 0,
    "retried": 0,
    "dropped": 0
  }
}
```

---

### 5.4 `POST /security/user/authenticate` (Wazuh API)

**Auth:** HTTP Basic (`wazuh_api_user:wazuh_api_password`)
**SSL:** verify=False (certificado autoassinado do Wazuh)

**Response:**
```json
{ "data": { "token": "eyJhbGc..." } }
```

Token válido por **900s**. O exporter renova 60s antes de expirar.

---

### 5.5 `GET /agents?select=name,group` (Wazuh API)

**Headers:** `Authorization: Bearer <jwt>`

**Response:**
```json
{
  "data": {
    "affected_items": [
      { "name": "agent-a", "group": ["default", "grupo-customizado"] },
      { "name": "agent-b", "group": ["default"] },
      { "name": "agent-c", "group": null }
    ],
    "total_affected_items": 3
  }
}
```

---

## 6. Configuração

Arquivo: `/etc/soc-exporter/config.json`
Permissões: `root:soc-exporter 640`

| Chave | Tipo | Default | Descrição |
|-------|------|---------|-----------|
| `api_url` | string | — | URL da API SOC central |
| `installation_id` | string | — | ID único desta instalação (gerado no registro) |
| `ingestion_token` | string | — | Bearer token para autenticação na API |
| `agent_name` | string | — | Nome descritivo deste agente |
| `environment` | string | `prod` | Ambiente: prod / staging / dev |
| `wazuh_alerts_path` | string | `/var/ossec/logs/alerts/alerts.json` | Caminho do arquivo de alertas |
| `heartbeat_interval` | int | `60` | Intervalo entre heartbeats (segundos) |
| `send_batch_size` | int | `100` | Máximo de eventos por batch |
| `send_interval` | int | `5` | Intervalo entre tentativas de envio (segundos) |
| `retry_base_delay` | float | `2.0` | Delay base do backoff exponencial (segundos) |
| `retry_max_delay` | float | `300.0` | Delay máximo do backoff (segundos) |
| `buffer_db_path` | string | `/var/lib/soc-exporter/buffer.db` | Caminho do buffer SQLite |
| `log_level` | string | `INFO` | Nível de log: DEBUG / INFO / WARNING / ERROR |
| `send_agent_groups` | bool | `true` | Habilita envio do mapa agente→grupo |
| `agent_groups_refresh` | int | `300` | Intervalo de atualização do cache de grupos (segundos) |
| `wazuh_api_url` | string | `https://localhost:55000` | URL da API REST do Wazuh |
| `wazuh_api_user` | string | `null` | Usuário da API Wazuh |
| `wazuh_api_password` | string | `null` | Senha da API Wazuh |

---

## 7. Regras de negócio

### 7.1 Garantia de entrega
- Nenhum evento é removido do buffer antes de receber `2xx` da API
- Eventos com erro retryable ficam no buffer indefinidamente com backoff exponencial
- O buffer sobrevive a reinicializações do serviço (SQLite persistente)

### 7.2 Drop intencional
- Eventos com resposta `400/422` são descartados permanentemente — um payload malformado não vai melhorar com retry
- Em caso de `AuthError`, o sender para imediatamente (latch) para não repetir um token inválido em loop; requer intervenção do operador (`soc-exporter init`)

### 7.3 Agent groups — envio completo
- O campo `agent_groups` contém **todos** os agentes conhecidos a cada batch, não apenas os ativos no momento
- Isso garante que o backend sempre tem o mapa completo, mesmo para agentes que geram poucos alertas
- O backend deve tratar `agent_groups` como upsert idempotente
- Grupos com `null` ou lista vazia são excluídos do cache e nunca enviados

### 7.4 Normalização de grupos
- Todos os nomes de grupo passam por `strip().lower()` antes de armazenar
- Ex: `" GRUPO-EXEMPLO "` → `"grupo-exemplo"`

### 7.5 Fallback de grupos (3 fontes)
1. **API Wazuh** (primário) — sempre preferida quando credenciais configuradas
2. **global.db** (fallback) — requer que `soc-exporter` esteja no grupo `wazuh`
3. **Filesystem** (último recurso) — compatível com Wazuh 3.x

### 7.6 Rotação de log
O collector detecta 3 modos de rotação automaticamente sem perder eventos:
- `rename` (padrão logrotate): detectado por mudança de inode
- `copytruncate`: detectado por `st_size < posição atual`
- Remoção total do arquivo: detectado por `FileNotFoundError`

### 7.7 Sanitização de tokens
Nenhum Bearer token ou senha aparece em nenhum log. O filtro de sanitização é aplicado no nível do logger, antes de qualquer handler (arquivo, console, journald).

### 7.8 JWT Wazuh
- Token válido por 900s, renovado 60s antes de expirar
- Em caso de `401` durante uma chamada de grupos, invalida o cache e autentica novamente uma vez

---

## 8. Dependências

### 8.1 Sistema

| Dependência | Versão mínima | Finalidade |
|-------------|--------------|-----------|
| Python | 3.10+ | Runtime |
| systemd | qualquer | Gerenciamento do serviço |
| Linux | qualquer distro | SO suportado |
| Wazuh | 4.x (recomendado) | Fonte de alertas |

### 8.2 Python (runtime)

| Pacote | Finalidade |
|--------|-----------|
| `requests` | Chamadas HTTP para SOC API e Wazuh API |
| `urllib3` | Retry nativo e supressão de warnings SSL |

### 8.3 Python (desenvolvimento/testes)

| Pacote | Finalidade |
|--------|-----------|
| `pytest` | Framework de testes |
| `responses` | Mock de requisições HTTP nos testes |

### 8.4 Diretórios e arquivos

| Caminho | Proprietário | Modo | Conteúdo |
|---------|-------------|------|----------|
| `/etc/soc-exporter/config.json` | `root:soc-exporter` | `640` | Configuração e credenciais |
| `/var/lib/soc-exporter/buffer.db` | `soc-exporter` | `750` (dir) | Buffer SQLite de eventos |
| `/var/log/soc-exporter/soc-exporter.log` | `soc-exporter` | `750` (dir) | Logs rotativos (10 MB × 5) |
| `/opt/soc-exporter/` | `root` | — | Virtualenv Python isolado |
| `/usr/local/bin/soc-exporter` | `root` | `755` | Binário CLI (symlink para venv) |

---

## 9. Instalação e uso

### 9.1 Instalação

```bash
# 1. Copiar o repositório para o servidor
scp -r exporter-wazuh/ root@<servidor>:/tmp/

# 2. Executar o instalador como root
sudo bash /tmp/exporter-wazuh/install.sh
```

O instalador realiza automaticamente:
- Instalação de dependências Python via apt/yum/dnf
- Criação do usuário de sistema `soc-exporter` (sem shell de login)
- Adição do usuário ao grupo `wazuh` (acesso ao `global.db`)
- Criação dos diretórios com permissões corretas
- Instalação do pacote Python em virtualenv isolado em `/opt/soc-exporter/`
- Registro e habilitação do serviço systemd
- Auditoria de permissões ao final

### 9.2 Registro

```bash
# Wizard interativo — coleta credenciais SOC e Wazuh API
soc-exporter init
```

### 9.3 Operação

```bash
# Iniciar
systemctl start soc-exporter

# Verificar status
soc-exporter status

# Logs em tempo real
journalctl -u soc-exporter -f

# Reiniciar (gracioso — aguarda flush do buffer)
systemctl restart soc-exporter

# Parar
systemctl stop soc-exporter
```

### 9.4 Desinstalação

```bash
# Remove binário e serviço, preserva config e dados
sudo bash install.sh --uninstall

# Para remover config e buffer também (perda de eventos não entregues)
sudo rm -rf /etc/soc-exporter /var/lib/soc-exporter /var/log/soc-exporter
```

---

## 10. Pontos de atenção

### 10.1 Credenciais

- O `config.json` contém o `ingestion_token` em plaintext — protegido por modo 640 (`root:soc-exporter`)
- Nunca compartilhar o `config.json` entre instalações — cada cliente tem credenciais únicas
- A senha da API Wazuh fica armazenada em plaintext no config — restringir acesso ao arquivo

### 10.2 Compatibilidade com Wazuh

- **Wazuh 4.x**: totalmente suportado; API REST disponível na porta 55000
- **Wazuh 3.x**: API REST com endpoints diferentes; grupos de agentes podem não ser coletados via API — o cache cai para `global.db` ou filesystem automaticamente

### 10.3 Espaço em disco

- O buffer SQLite cresce indefinidamente se a API ficar indisponível por tempo prolongado
- Recomendado: ao menos 1 GB livre em `/var/lib/` para ambientes com alto volume de alertas
- Logs rotativos limitados a 50 MB total (10 MB × 5 arquivos)

### 10.4 Segurança de rede

- A API Wazuh usa certificado autoassinado → SSL verify=False nas chamadas ao Wazuh
- A API SOC usa HTTPS com certificado válido → SSL verify=True (padrão)
- O token JWT do Wazuh expira em 900s; o exporter renova automaticamente

### 10.5 Erros de encoding no collector

- O arquivo `alerts.json` pode conter caracteres não-UTF-8 em alguns ambientes Wazuh
- O collector reinicia automaticamente após 5s em caso de `UnicodeDecodeError`
- Para diagnóstico: `journalctl -u soc-exporter | grep "Collector crashed"`

### 10.6 AUTH_FAILURE

- Quando o sender recebe 401/403, ele para completamente (latch)
- Eventos continuam sendo coletados e armazenados no buffer
- Para retomar: `soc-exporter init` com nova activation key → `systemctl restart soc-exporter`

### 10.7 Permissão para grupos de agentes

- Para usar o fallback `global.db`, o usuário `soc-exporter` precisa estar no grupo `wazuh`:
  ```bash
  sudo usermod -aG wazuh soc-exporter
  ```
- O `install.sh` já faz isso automaticamente; necessário apenas em reinstalações manuais

---

**Author:** Cumbuc4
**Co-Author:** Nox5
