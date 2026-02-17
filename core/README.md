# Core

Core - набор сервисов мониторинга: Prometheus + Grafana + Alertmanager + Target Manager.

## Порты (UI/API)

- Prometheus: http://127.0.0.1:9981
- Alertmanager: http://127.0.0.1:9982
- Grafana: http://127.0.0.1:9983
- Target Manager: http://127.0.0.1:9984

## Local-only

Требование: перед запуском Core должен быть поднят `probe/` (он создаёт сеть `probe_default`).

```sh
cd ..\probe
docker compose up -d --build

cd ..\core
docker compose -f compose.local.yml up -d --build
```

Grafana credentials: default `admin` / `admin` (см. `GRAFANA_ADMIN_PASSWORD`).

## VPS Core + Home Probe

`core/compose.yml` использует `network_mode: host` и рассчитан на Linux VPS.

1) На VPS:

```sh
cd core
docker compose up -d --build
```

2) Дома: поднять `probe/` и открыть reverse SSH (см. `probe/README.md`). Core ожидает, что на VPS появятся:

- blackbox exporter: `127.0.0.1:19115`
- icmp-prober: `127.0.0.1:9985`

3) Доступ к UI через SSH port-forward (на локальной машине):

```sh
ssh -L 9983:127.0.0.1:9983 -L 9981:127.0.0.1:9981 -L 9982:127.0.0.1:9982 -L 9984:127.0.0.1:9984 user@vps
```

Если локальные порты заняты, используй альтернативы (пример):

```sh
ssh -L 19983:127.0.0.1:9983 -L 19981:127.0.0.1:9981 -L 19982:127.0.0.1:9982 -L 19984:127.0.0.1:9984 user@vps
```

## Проверка

Prometheus:
- `http://127.0.0.1:9981/targets` - `blackbox_*` и `icmp_diag*` в `UP`
- queries:
  - `probe_success`
  - `home_noc_icmp_packet_loss_ratio`
  - `home_noc_icmp_rtt_stddev_seconds`

Grafana:
- дашборд **Home NOC - Blackbox**
- дашборд **Home NOC - ICMP Diagnostics**

## Target Manager

Target Manager хранит таргеты в SQLite и отдаёт их в формате Prometheus HTTP Service Discovery.

- API: `GET/POST/PATCH/DELETE /api/targets`
- SD: `/sd/http`, `/sd/tcp`, `/sd/dns`, `/sd/icmp`

## Scrape profiles (1s/5s/15s/60s)

Для каждой цели задаётся `scrape_profile`: `1s` / `5s` / `15s` (default) / `60s`.

Профиль применяется через HTTP SD (refresh interval = 30s). Для ICMP один `scrape_profile` используется для `icmp_diag`.
