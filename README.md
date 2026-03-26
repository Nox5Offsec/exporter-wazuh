# SOC Exporter

Agente leve que roda no servidor do cliente para encaminhar alertas do Wazuh
para a API central do SOC em tempo real.

---

## Instalação

```bash
# 1. Copiar o código para o servidor
scp -r exporter_wazuh/ root@<cliente>:/opt/soc-exporter

# 2. Instalar como root
sudo bash /opt/soc-exporter/install.sh
```

O instalador:
- Cria usuário/grupo de sistema `soc-exporter`
- Instala o pacote Python via pip
- Cria e protege os diretórios necessários
- Registra e habilita o serviço no systemd
- Executa auditoria de permissões ao final

---

## Uso rápido

```bash
# 1. Registrar o agente (interativo)
soc-exporter init

# 2. Iniciar
systemctl start soc-exporter

# 3. Verificar
soc-exporter status
```

---

## Arquitetura e fluxo de dados

```
/var/ossec/logs/alerts/alerts.json
           │
           │  tail -F  (segue rotação de log automaticamente)
           ▼
      [ Collector ]   thread — lê e enriquece eventos
           │  push()
           ▼
       [ Buffer ]  ←── SQLite /var/lib/soc-exporter/buffer.db
           │
           │  fetch_ready() / ack() / nack()
           ▼
       [ Sender ]  ────►  POST /v1/ingest/wazuh
           │               retry com backoff exponencial
           │
      [ Heartbeat ] ────►  POST /v1/agents/heartbeat  (a cada 60s)
```

---

## Tratamento de erros da API

| Código HTTP | Classificação | Comportamento |
|-------------|---------------|---------------|
| 2xx | Sucesso | Evento removido do buffer (ack) |
| 400 / 422 | PayloadError | Drop — payload inválido não vai melhorar no retry |
| 401 / 403 | AuthError | Sender é suspenso; erro CRITICAL no log; nenhum retry automático |
| 429 / 5xx | APIError (retryable) | Nack + backoff exponencial (2s → 300s) |
| Timeout / recusa | NetworkError | Nack + backoff exponencial |

---

## Rotação de log do Wazuh

| Modo logrotate | Detecção |
|----------------|----------|
| `rename` (padrão) | Mudança de inode do arquivo |
| `copytruncate` | Arquivo encolheu (st_size < posição atual) |
| Arquivo removido | `FileNotFoundError` no `os.stat()` |
| Arquivo ausente no boot | Loop de espera com aviso a cada 10s |

---

## Diretórios e permissões

| Caminho | Proprietário | Modo | Conteúdo |
|---------|-------------|------|----------|
| `/etc/soc-exporter/` | root:soc-exporter | 750 | Diretório de config |
| `/etc/soc-exporter/config.json` | root:soc-exporter | **600** | installation_id, token |
| `/var/lib/soc-exporter/buffer.db` | soc-exporter | 750 (dir) | Fila SQLite de eventos |
| `/var/log/soc-exporter/soc-exporter.log` | soc-exporter | 750 (dir) | Logs rotativos 10 MB × 5 |

---

## Observabilidade

Todos os logs incluem `[installation_id]` para correlação fácil:

```
2024-06-01T10:00:01 [INFO]  [inst-abc123] Sending batch of 50 events (queue=150)
2024-06-01T10:00:02 [INFO]  [inst-abc123] Sent 50 events rid=req-xyz (total_sent=5000)
2024-06-01T10:00:05 [WARN]  [inst-abc123] Send failed (timeout) — 50 events rescheduled
2024-06-01T10:01:00 [DEBUG] [inst-abc123] Heartbeat sent.
```

Tokens nunca aparecem em logs (filtro de sanitização automático).

---

## Troubleshooting

### `soc-exporter status` mostra AUTH_FAILURE

O token de ingestão foi revogado ou a activation key expirou.

```bash
# Re-registrar o agente
systemctl stop soc-exporter
soc-exporter init              # use uma nova activation key
systemctl start soc-exporter
```

---

### Serviço parado, eventos acumulados no buffer

O buffer SQLite é persistente — os eventos não são perdidos durante downtime.
Ao reiniciar o serviço, o Sender entrega tudo automaticamente com backoff.

```bash
soc-exporter status            # ver quantos eventos estão pendentes
systemctl start soc-exporter   # retomar envio
```

---

### Arquivo de alertas não encontrado

```bash
# Verificar caminho real do Wazuh
ls -la /var/ossec/logs/alerts/

# Se o caminho for diferente, editar o config:
vi /etc/soc-exporter/config.json
# alterar "wazuh_alerts_path"

systemctl restart soc-exporter
```

---

### Validar conectividade com a API manualmente

```bash
# Testar DNS e TLS
curl -v https://soc-api.nox5.com.br/v1/agents/heartbeat \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(jq -r .ingestion_token /etc/soc-exporter/config.json)" \
  -d '{"installation_id":"test","hostname":"test","stats":{}}'

# Ping simples
curl -sf https://soc-api.nox5.com.br/health && echo OK
```

---

### Ver logs em tempo real

```bash
# Via journald (systemd)
journalctl -u soc-exporter -f

# Via arquivo de log
tail -f /var/log/soc-exporter/soc-exporter.log
```

---

### Testar com um alerts.json fake

Útil para validar o pipeline sem o Wazuh instalado:

```bash
# 1. Criar arquivo de alertas fake
ALERTS=/tmp/fake-alerts.json
touch $ALERTS

# 2. Apontar o config para ele
jq '.wazuh_alerts_path = "/tmp/fake-alerts.json"' \
  /etc/soc-exporter/config.json > /tmp/cfg.json \
  && sudo cp /tmp/cfg.json /etc/soc-exporter/config.json

# 3. Iniciar o serviço (ou rodar em foreground para ver os logs)
soc-exporter start &

# 4. Injetar alertas fake
for i in $(seq 1 5); do
  echo '{"rule":{"id":1001,"level":5,"description":"Test alert"},"agent":{"name":"test-agent"}}' >> $ALERTS
  sleep 1
done

# 5. Verificar status
soc-exporter status
```

---

### Reinicializar com segurança

```bash
# Graceful restart (aguarda flush do buffer)
systemctl restart soc-exporter

# Ver se reiniciou sem erros
journalctl -u soc-exporter -n 20
```

---

### Desregistrar e reinstalar do zero

```bash
# 1. Parar e desinstalar binário/serviço (preserva dados)
sudo bash install.sh --uninstall

# 2. Remover dados antigos (ATENÇÃO: perde buffer não entregue)
sudo rm -rf /etc/soc-exporter /var/lib/soc-exporter

# 3. Reinstalar
sudo bash install.sh

# 4. Registrar com nova activation key
soc-exporter init
```

---

## Testes

```bash
# Instalar dependências de desenvolvimento
pip install -r requirements-dev.txt

# Executar todos os testes
pytest tests/ -v

# Testes por categoria
pytest tests/test_buffer.py   -v   # buffer + persistência
pytest tests/test_collector.py -v  # rotação de log
pytest tests/test_sender.py   -v   # retry, auth, 5xx
pytest tests/test_logger.py   -v   # sem vazamento de token
pytest tests/test_api_client.py -v # classificação de erros HTTP
```

---

## API Endpoints

| Endpoint | Método | Auth | Descrição |
|----------|--------|------|-----------|
| `/v1/agents/register` | POST | activation_key | Registro inicial |
| `/v1/agents/heartbeat` | POST | Bearer token | Keep-alive periódico |
| `/v1/ingest/wazuh` | POST | Bearer token | Envio de eventos em batch |

---

## Checklist de produção

### Segurança
- [ ] `config.json` com modo 600
- [ ] Serviço rodando como usuário `soc-exporter` (não root)
- [ ] `NoNewPrivileges=true` no systemd unit
- [ ] Token não aparece em logs (`soc-exporter status` + `journalctl`)

### Resiliência
- [ ] Buffer SQLite em partição com espaço suficiente (≥ 1 GB)
- [ ] `Restart=always` configurado no systemd
- [ ] Testado restart do serviço com eventos pendentes no buffer
- [ ] Testado com API offline por > 5 minutos

### Conectividade
- [ ] HTTPS funciona do servidor do cliente para `soc-api.nox5.com.br`
- [ ] Heartbeat aparece no dashboard da API central
- [ ] Eventos chegam na API após `soc-exporter init`

### Monitoramento
- [ ] `soc-exporter status` mostra RUNNING
- [ ] Último heartbeat há menos de 2 minutos
- [ ] Buffer pending = 0 em condição normal

---

## Checklist de piloto

- [ ] `install.sh` executado sem erros em servidor de homologação
- [ ] `soc-exporter init` com activation key do cliente
- [ ] Alertas reais do Wazuh chegando na API central (verificar no dashboard)
- [ ] Simular queda de rede (block firewall) → buffer acumula → restaurar → buffer drena
- [ ] Simular rotação de log (`logrotate -f /etc/logrotate.d/wazuh`) → collector continua
- [ ] `systemctl restart soc-exporter` não perde eventos
- [ ] Revisar logs por 24h em busca de erros recorrentes
- [ ] Confirmar que token não vazou em nenhum log (`grep -r "Bearer" /var/log/soc-exporter/`)

---

## Autores

**Author:** Cumbuc4
**Co-Author:** Nox5
