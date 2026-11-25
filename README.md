# AuthWatch Log Auditor

CLI em Python puro (somente stdlib, Python 3.11+) que analisa logs de autenticação e aponta três padrões de ataque/abuso:

| Regra | Dispara quando | Severidade |
|---|---|---|
| **Brute Force** | ≥ `--threshold` falhas do mesmo IP dentro de `--window` minutos | `MEDIUM`; `HIGH` com ≥ 2× o threshold; **`CRITICAL`** se o mesmo IP faz login com sucesso até `--window` min depois |
| **User Enumeration** | falhas em ≥ `--min-users` usuários distintos pelo mesmo IP dentro da janela | `MEDIUM`; `HIGH` com ≥ 2× o mínimo ou se houver usuários inexistentes (`invalid user`) |
| **Off-Hours Login** | login **bem-sucedido** entre 00:00 e 04:59 | `LOW` |

Formatos de entrada (detectados linha a linha, podem estar misturados):

- **SSH** — `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL) e saída do `journalctl -o short-iso`. Lê `Failed password` / `Accepted password|publickey`, incluindo `invalid user` e o processo `sshd-session` do OpenSSH 9.8+. IPv4 e IPv6.
- **JSONL de API** — um objeto JSON por linha. Campos aceitos: timestamp (`timestamp`, `@timestamp`, `time`, `ts`), IP (`ip`, `source_ip`, `client_ip`, `remote_addr`), usuário (`user`, `username`, `login`, `email`) e status textual (`failed`, `success`, `denied`…) ou HTTP (`2xx` = sucesso, `401`/`403` = falha).

Linhas que não são eventos de autenticação (cron, sudo, `Connection closed`…) são ignoradas.

## Como funciona

```
log ──► parser.py ──► AuthEvent(timestamp, ip, user, FAILED|SUCCESS)
                         │
                         ▼
                    detector.py ──► Incident(rule, severity, ip, users, linhas)
                         │
                         ▼
                    reporter.py ──► resumo no terminal  +  relatório JSON (--export)
```

- As regras de IP usam **janela deslizante** por IP. Um ataque contínuo gera **um único incidente**, que cresce enquanto a regra continua disparando, em vez de um alerta por tentativa. Rajadas separadas por mais que a janela viram incidentes distintos.
- Cada incidente aponta as **linhas do log** que o compõem, para inspeção direta no arquivo original.
- Horários são comparados como aparecem no log (sem conversão de fuso). Para logs em UTC, o filtro de 00h–05h vale em UTC.

## Instalação

```bash
git clone https://github.com/Pedro-Dirickson/authwatch-log-auditor.git
cd authwatch-log-auditor
pip install .            # instala o comando `authwatch`
# ou, sem instalar:
PYTHONPATH=src python -m authwatch --help
```

Sem dependências externas.

## Uso

```
authwatch --file ARQUIVO [--threshold N] [--window MIN] [--min-users N]
          [--year AAAA] [--export ARQUIVO.json] [--quiet]
```

| Opção | Padrão | Descrição |
|---|---|---|
| `-f`, `--file` | — | log a analisar (obrigatório) |
| `-t`, `--threshold` | `5` | falhas do mesmo IP para Brute Force |
| `-w`, `--window` | `5` | janela deslizante em minutos (aceita decimais) |
| `-u`, `--min-users` | `3` | usuários distintos para User Enumeration |
| `-y`, `--year` | ano atual | ano das linhas syslog, que não registram o ano |
| `-e`, `--export` | — | grava o relatório em JSON (cria diretórios) |
| `-q`, `--quiet` | — | não imprime o relatório no terminal |

**Códigos de saída:** `0` nenhum incidente · `1` incidentes detectados · `2` erro (arquivo ilegível, argumento inválido).

### Exemplo com `samples/sample_auth.log`

O arquivo de exemplo simula um dia de um servidor: logins por chave da equipe, erros de senha isolados, cron e sudo, mais um ataque de força bruta de `185.220.101.47` e um login de `backup_admin` às 03:17 vindo de um IP externo.

```console
$ authwatch --file samples/sample_auth.log --year 2026
========================================================================
AuthWatch - Authentication Log Audit
========================================================================
File            : samples/sample_auth.log
Settings        : threshold=5, window_minutes=5.0, min_users=3
Events parsed   : 24 (16 failed, 8 successful)
Source IPs      : 5
Incidents       : 3
By severity     : HIGH 2, LOW 1
========================================================================
[1] HIGH     Brute Force - 185.220.101.47
    14 failed logins from 185.220.101.47 between 2026-11-24 10:14:04 and 10:15:26 (threshold 5 in 5 min)
    Users : admin, oracle, postgres, root, test, ubuntu
    Time  : 2026-11-24 10:14:04 -> 10:15:26
    Lines : 20-22, 24-25, 27-28, 30-32, 34-37

[2] HIGH     User Enumeration - 185.220.101.47
    185.220.101.47 tried 6 distinct usernames in 14 failed attempts within 5 min (5 non-existent: admin, oracle, postgres, test, ubuntu)
    Users : admin, oracle, postgres, root, test, ubuntu
    Time  : 2026-11-24 10:14:04 -> 10:15:26
    Lines : 20-22, 24-25, 27-28, 30-32, 34-37

[3] LOW      Off-Hours Login - 91.214.124.33
    Successful ssh login as 'backup_admin' from 91.214.124.33 at 2026-11-24 03:17:44 (off-hours 00:00-05:00)
    Users : backup_admin
    Time  : 2026-11-24 03:17:44
    Lines : 4
```

Os usuários legítimos que erraram a senha uma vez (`maria`, `deploy`) não geram alerta.

**Ajustando a sensibilidade:**

```bash
# Política mais rígida: 3 falhas em 10 minutos
authwatch -f samples/sample_auth.log -y 2026 --threshold 3 --window 10

# Mais tolerante: o ataque do sample (14 falhas) não atinge 20
authwatch -f samples/sample_auth.log -y 2026 --threshold 20
```

**Exportando para JSON:**

```bash
authwatch -f samples/sample_auth.log -y 2026 --export reports/incidents.json --quiet
```

```json
{
  "tool": "authwatch",
  "version": "0.1.0",
  "generated_at": "2026-11-24T22:37:35-03:00",
  "source_file": "samples/sample_auth.log",
  "settings": { "threshold": 5, "window_minutes": 5.0, "min_users": 3 },
  "summary": {
    "events_parsed": 24, "failed_logins": 16, "successful_logins": 8,
    "unique_source_ips": 5, "incidents_total": 3,
    "incidents_by_rule": { "BRUTE_FORCE": 1, "USER_ENUMERATION": 1, "OFF_HOURS_LOGIN": 1 },
    "incidents_by_severity": { "HIGH": 2, "LOW": 1 }
  },
  "incidents": [
    {
      "rule": "BRUTE_FORCE",
      "severity": "HIGH",
      "source_ip": "185.220.101.47",
      "first_seen": "2026-11-24T10:14:04",
      "last_seen": "2026-11-24T10:15:26",
      "event_count": 14,
      "users": ["admin", "oracle", "postgres", "root", "test", "ubuntu"],
      "description": "14 failed logins from 185.220.101.47 between ...",
      "lines": [20, 21, 22, 24, 25, 27, 28, 30, 31, 32, 34, 35, 36, 37]
    }
  ]
}
```

O JSON é fácil de consumir com `jq`:

```bash
# IPs com Brute Force ou User Enumeration (candidatos a bloqueio)
jq -r '.incidents[] | select(.rule != "OFF_HOURS_LOGIN") | .source_ip' reports/incidents.json | sort -u

# Somente incidentes HIGH/CRITICAL
jq '.incidents[] | select(.severity == "HIGH" or .severity == "CRITICAL")' reports/incidents.json
```

**Logs de API (JSONL):**

```bash
authwatch --file /var/log/api/auth-events.jsonl --threshold 10 --window 1
```

## Integração em servidores Linux

O AuthWatch é uma ferramenta de **análise em lote**: lê um arquivo, reporta e sai. Para monitoramento contínuo, execute-o periodicamente sobre a janela de log mais recente e use o código de saída para decidir se alerta.

> Permissões: `/var/log/auth.log` pertence a `root:adm`. Rode como root ou com um usuário do grupo `adm` (Debian/Ubuntu); em RHEL, `/var/log/secure` exige root. Para `journalctl`, o usuário precisa estar em `adm` ou `systemd-journal`.

### 1. Script de verificação

`/usr/local/bin/authwatch-check.sh`:

```bash
#!/usr/bin/env bash
# Analisa a última hora de logs SSH e alerta se houver incidentes.
set -uo pipefail

REPORT_DIR=/var/lib/authwatch
STAMP=$(date +%Y%m%d-%H%M)
LOG=$(mktemp)
trap 'rm -f "$LOG"' EXIT

mkdir -p "$REPORT_DIR"

# Só a última hora: evita reportar de novo incidentes já alertados.
# -t cobre sshd (OpenSSH < 9.8) e sshd-session (>= 9.8); short-iso inclui o ano.
journalctl -t sshd -t sshd-session --since "1 hour ago" -o short-iso --no-pager > "$LOG"

authwatch --file "$LOG" --threshold 5 --window 5 \
          --export "$REPORT_DIR/report-$STAMP.json" --quiet
status=$?

case $status in
  0) rm -f "$REPORT_DIR/report-$STAMP.json" ;;           # limpo: descarta o relatório vazio
  1) logger -t authwatch -p auth.warning \
       "incidentes detectados: $(jq -c .summary.incidents_by_severity "$REPORT_DIR/report-$STAMP.json")"
     # Exemplo de alerta por webhook (Slack, Teams, Discord...):
     # curl -fsS -X POST -H 'Content-Type: application/json' \
     #      --data @"$REPORT_DIR/report-$STAMP.json" "$AUTHWATCH_WEBHOOK_URL"
     ;;
  *) logger -t authwatch -p auth.err "falha na execução (exit $status)" ;;
esac
exit "$status"
```

Sem journald, troque o `journalctl` por `/var/log/auth.log` (ou `/var/log/secure`) e passe `--year "$(date +%Y)"`. Nesse caso o arquivo inteiro é reanalisado a cada execução, então ajuste o intervalo à rotação do `logrotate` ou filtre as linhas recentes antes de analisar.

### 2. Agendamento com cron

```cron
# /etc/cron.d/authwatch — executa a cada hora, no minuto 5
5 * * * * root /usr/local/bin/authwatch-check.sh
```

### 3. Agendamento com systemd timer

`/etc/systemd/system/authwatch.service`:

```ini
[Unit]
Description=AuthWatch - auditoria de logs de autenticação

[Service]
Type=oneshot
ExecStart=/usr/local/bin/authwatch-check.sh
# exit 1 = incidentes encontrados, não uma falha do serviço
SuccessExitStatus=1
```

`/etc/systemd/system/authwatch.timer`:

```ini
[Unit]
Description=Executa o AuthWatch a cada hora

[Timer]
OnCalendar=hourly
Persistent=true

[Install]
WantedBy=timers.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now authwatch.timer
systemctl list-timers authwatch.timer
journalctl -t authwatch          # alertas emitidos pelo script
```

### 4. Auditoria de logs rotacionados

Para investigar um período passado, descompacte e analise os arquivos rotacionados:

```bash
zcat /var/log/auth.log.*.gz | cat - /var/log/auth.log.1 > /tmp/auth-history.log
authwatch --file /tmp/auth-history.log --year 2026 --export auth-history.json
```

Linhas syslog clássicas não têm ano; se o histórico atravessar a virada de ano, analise cada ano separadamente com `--year`.

### 5. Resposta a incidentes

O AuthWatch **detecta, não bloqueia**. Para bloqueio automático, use o relatório como entrada de outra ferramenta. Por exemplo, alimentar um set do nftables com os IPs de Brute Force:

```bash
jq -r '.incidents[] | select(.rule == "BRUTE_FORCE") | .source_ip' report.json | sort -u |
  xargs -r -I{} nft add element inet filter blocklist '{ {} }'
```

Mantenha IPs internos e de administração fora do bloqueio automático. Para bloqueio em tempo real, `fail2ban` é a ferramenta adequada; o AuthWatch complementa com visão consolidada, enumeração de usuários, logins fora de horário e relatórios em JSON.

## Limitações

- Análise em lote, não em tempo real (veja a seção de integração).
- O horário de Off-Hours Login é fixo em 00:00–04:59 na CLI (configurável via API em `detect_off_hours`).
- O parser SSH cobre autenticação por senha e chave pública; eventos como `keyboard-interactive/pam` aparecem como `Failed`/`Accepted` e são reconhecidos, mas mensagens apenas do PAM (`pam_unix(sshd:auth): authentication failure`) não são contadas, para evitar contagem dupla.

## Desenvolvimento

```bash
python -m unittest discover -s tests -t . -v
```

```
src/authwatch/
├── parser.py     # auth.log / JSONL -> AuthEvent
├── detector.py   # regras Brute Force, User Enumeration, Off-Hours Login
├── reporter.py   # resumo no terminal e exportação JSON
├── cli.py        # argparse: --file, --threshold, --window, --export...
└── __main__.py   # python -m authwatch
samples/sample_auth.log   # log realista para demonstração
tests/                    # unittest (parser, detector, CLI, reporter)
```
