# Probe (home)

Probe - локальные пробы для Home NOC: `blackbox-exporter` + `icmp-prober` (loss/jitter).

## Порты (localhost)

- Blackbox exporter: http://127.0.0.1:9115
- ICMP prober: http://127.0.0.1:9985

## Запуск

```sh
cd probe
docker compose up -d --build
```

## Проверка

```powershell
curl.exe -fsS http://localhost:9115/-/healthy
curl.exe -fsS http://localhost:9985/healthz
```

## Blackbox modules

Доступные модули:

- `http_2xx`
- `tcp_connect`
- `dns_udp`
- `dns_tcp`

Ручная проверка (пример):

```powershell
curl.exe -fsS "http://localhost:9115/probe?module=http_2xx&target=https://example.com" | Select-String -Pattern "^(probe_success|probe_http_status_code)"
```

ICMP выполняет только `icmp-prober`.

## ICMP diagnostics (loss/jitter)

`icmp-prober` делает ping в соответствии с установленным профилем и отдаёт метрики `home_noc_icmp_*`.

```powershell
curl.exe -fsS "http://localhost:9985/probe?target=1.1.1.1&count=4&interval_ms=1000&timeout_ms=1000&packet_size=56&df=false" | Select-String -Pattern "^(home_noc_icmp_probe_success|home_noc_icmp_packet_loss_ratio|home_noc_icmp_rtt_stddev_seconds)"
```

## Reverse SSH (VPS Core + Home Probe)

Команда выполняется дома, 2 reverse forward’а:

- `127.0.0.1:19115` (VPS) → `127.0.0.1:9115` (home blackbox)
- `127.0.0.1:9985` (VPS) → `127.0.0.1:9985` (home icmp-prober)

```sh
ssh -N -R 127.0.0.1:19115:127.0.0.1:9115 -R 127.0.0.1:9985:127.0.0.1:9985 -o ServerAliveInterval=30 -o ServerAliveCountMax=3 user@your-vps-host
```

Требование на VPS (`sshd_config`):

```text
AllowTcpForwarding yes
```

Core на VPS скрейпит домашние пробы с:

- `127.0.0.1:19115` (blackbox exporter)
- `127.0.0.1:9985` (icmp-prober)

## Примечание про ICMP

ICMP требует прав для raw sockets. В `probe/compose.yml` включён `cap_add: NET_RAW` для `icmp-prober`.
