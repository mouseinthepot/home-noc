from __future__ import annotations

import os
import re
import subprocess
import math
import time
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

DEFAULT_COUNT = 4
DEFAULT_INTERVAL_MS = 1000
DEFAULT_TIMEOUT_MS = 1000
DEFAULT_PACKET_SIZE = 56
DEFAULT_DF = False

MAX_COUNT = 500
MIN_INTERVAL_MS = 10
MAX_INTERVAL_MS = 1000
MIN_TIMEOUT_MS = 200
MAX_TIMEOUT_MS = 5000
MIN_PACKET_SIZE = 0
MAX_PACKET_SIZE = 1472

_PACKET_STATS_RE = re.compile(
    r"(?m)^(?P<tx>\d+)\s+packets\s+transmitted,\s+"
    r"(?P<rx>\d+)\s+(?:packets\s+)?received,.*?"
    r"(?P<loss>[\d.]+)%\s+packet\s+loss"
)

_RTT_RE = re.compile(
    r"(?m)^(?:rtt|round-trip)\s+min/avg/max/(?:mdev|stddev)\s*=\s*"
    r"(?P<min>[\d.]+)/(?P<avg>[\d.]+)/(?P<max>[\d.]+)/(?P<stddev>[\d.]+)\s*ms"
)

_REPLY_TIME_RE = re.compile(r"(?m)^\s*\d+\s+bytes\s+from\s+.+?\s+time[=<](?P<ms>[\d.]+)\s*ms\s*$")
_REPLY_RE = re.compile(r"(?m)^\s*\d+\s+bytes\s+from\s+.+?\s+icmp_seq=\d+")


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def _bool_from_any(value: Any, *, field: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "1", "yes", "y", "on"):
            return True
        if lowered in ("false", "0", "no", "n", "off"):
            return False
    raise HttpError(HTTPStatus.BAD_REQUEST, f"{field} must be a boolean")

def _looks_truthy(value: str | None) -> bool:
    if value is None:
        return False
    lowered = value.strip().lower()
    return lowered in ("1", "true", "yes", "y", "on")


def _int_from_query(query: dict[str, list[str]], key: str, *, default: int) -> int:
    raw = query.get(key, [None])[0]
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError as exc:
        raise HttpError(HTTPStatus.BAD_REQUEST, f"{key} must be an integer") from exc


def _require_in_range(value: int, *, field: str, min_value: int, max_value: int) -> None:
    if not (min_value <= value <= max_value):
        raise HttpError(HTTPStatus.BAD_REQUEST, f"{field} must be in range {min_value}..{max_value}")


def _format_metric_line(name: str, value: float | int) -> str:
    if isinstance(value, float):
        if value != value:  # NaN
            return f"{name} NaN\n"
        return f"{name} {value:.6f}\n"
    return f"{name} {value}\n"


def _looks_like_ipv6(target: str) -> bool:
    return ":" in target


def _parse_ping_output(text: str, *, expected_count: int) -> dict[str, float]:
    result: dict[str, float] = {"packets_sent": float(expected_count)}

    stats = _PACKET_STATS_RE.search(text)
    if stats:
        tx = float(stats.group("tx"))
        rx = float(stats.group("rx"))
        loss_percent = float(stats.group("loss"))
        result["packets_sent"] = tx
        result["packets_received"] = rx
        result["packet_loss_ratio"] = max(0.0, min(1.0, loss_percent / 100.0))

    rtt = _RTT_RE.search(text)
    if rtt:
        result["rtt_min_seconds"] = float(rtt.group("min")) / 1000.0
        result["rtt_avg_seconds"] = float(rtt.group("avg")) / 1000.0
        result["rtt_max_seconds"] = float(rtt.group("max")) / 1000.0
        result["rtt_stddev_seconds"] = float(rtt.group("stddev")) / 1000.0

    times_ms = []
    for match in _REPLY_TIME_RE.finditer(text):
        try:
            times_ms.append(float(match.group("ms")))
        except ValueError:
            continue

    if "packets_received" not in result:
        replies = len(times_ms)
        if replies == 0:
            replies = len(_REPLY_RE.findall(text))
        result["packets_received"] = float(replies)
        tx = float(expected_count)
        rx = float(replies)
        if tx > 0:
            result["packet_loss_ratio"] = max(0.0, min(1.0, 1.0 - (rx / tx)))
        else:
            result["packet_loss_ratio"] = 1.0

    if "rtt_avg_seconds" not in result and times_ms:
        n = len(times_ms)
        avg_ms = sum(times_ms) / n
        var_ms = sum((x - avg_ms) ** 2 for x in times_ms) / n
        std_ms = math.sqrt(var_ms)
        result["rtt_min_seconds"] = min(times_ms) / 1000.0
        result["rtt_avg_seconds"] = avg_ms / 1000.0
        result["rtt_max_seconds"] = max(times_ms) / 1000.0
        result["rtt_stddev_seconds"] = std_ms / 1000.0

    return result


def _run_ping(
    *,
    target: str,
    count: int,
    interval_ms: int,
    timeout_ms: int,
    packet_size: int,
    df: bool,
) -> tuple[int, str, float]:
    interval_s = max(0.001, interval_ms / 1000.0)
    timeout_s = max(1, math.ceil(timeout_ms / 1000.0))
    deadline_s = max(1, math.ceil((count - 1) * interval_s + timeout_s + 1.0))

    args = ["ping"]

    if _looks_like_ipv6(target):
        args.append("-6")
    else:
        args.append("-4")

    args.extend(["-n", "-c", str(count), "-i", f"{interval_s:.3f}", "-W", str(timeout_s), "-w", str(deadline_s)])
    args.extend(["-s", str(packet_size)])

    if df and not _looks_like_ipv6(target):
        args.extend(["-M", "do"])

    args.append(target)

    start = time.monotonic()
    proc = subprocess.run(args, capture_output=True, text=True)  # noqa: S603
    duration = time.monotonic() - start
    output = (proc.stdout or "") + (proc.stderr or "")
    return proc.returncode, output, duration


class Handler(BaseHTTPRequestHandler):
    server_version = "home-noc-icmp-prober/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print("[%s] %s" % (self.log_date_time_string(), format % args))

    def _send_text(self, status: int, text: str) -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            path = parsed.path

            if path == "/healthz":
                self._send_text(HTTPStatus.OK, "ok\n")
                return

            if path != "/probe":
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            query = urllib.parse.parse_qs(parsed.query or "")
            debug = _looks_truthy(query.get("debug", [None])[0])
            target = (query.get("target", [None])[0] or "").strip()
            if not target:
                raise HttpError(HTTPStatus.BAD_REQUEST, "target is required")
            if any(ch.isspace() for ch in target):
                raise HttpError(HTTPStatus.BAD_REQUEST, "target must not contain whitespace")
            if target.startswith("[") and target.endswith("]"):
                target = target[1:-1]

            count = _int_from_query(query, "count", default=DEFAULT_COUNT)
            interval_ms = _int_from_query(query, "interval_ms", default=DEFAULT_INTERVAL_MS)
            timeout_ms = _int_from_query(query, "timeout_ms", default=DEFAULT_TIMEOUT_MS)
            packet_size = _int_from_query(query, "packet_size", default=DEFAULT_PACKET_SIZE)
            df = _bool_from_any((query.get("df", [None])[0] if "df" in query else DEFAULT_DF), field="df")

            _require_in_range(count, field="count", min_value=1, max_value=MAX_COUNT)
            _require_in_range(interval_ms, field="interval_ms", min_value=MIN_INTERVAL_MS, max_value=MAX_INTERVAL_MS)
            _require_in_range(timeout_ms, field="timeout_ms", min_value=MIN_TIMEOUT_MS, max_value=MAX_TIMEOUT_MS)
            _require_in_range(packet_size, field="packet_size", min_value=MIN_PACKET_SIZE, max_value=MAX_PACKET_SIZE)

            code, output, duration = _run_ping(
                target=target,
                count=count,
                interval_ms=interval_ms,
                timeout_ms=timeout_ms,
                packet_size=packet_size,
                df=df,
            )

            parsed_stats = _parse_ping_output(output, expected_count=count)
            tx = int(parsed_stats.get("packets_sent", float(count)))
            rx = int(parsed_stats.get("packets_received", 0.0))
            loss = parsed_stats.get("packet_loss_ratio", 1.0 if rx == 0 else 0.0)

            success = 1 if rx > 0 else 0

            lines = []
            if debug:
                lines.append(f"# debug ping_exit_code={code}\n")
                lines.append("# debug ping_output_begin\n")
                for line in output.splitlines()[:80]:
                    lines.append(f"# {line}\n")
                lines.append("# debug ping_output_end\n")

            lines.append("# HELP home_noc_icmp_probe_success 1 if at least one reply was received.\n")
            lines.append("# TYPE home_noc_icmp_probe_success gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_probe_success", success))

            lines.append("# HELP home_noc_icmp_packets_sent Number of ICMP echo requests sent in the last probe.\n")
            lines.append("# TYPE home_noc_icmp_packets_sent gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_packets_sent", tx))

            lines.append("# HELP home_noc_icmp_packets_received Number of ICMP echo replies received in the last probe.\n")
            lines.append("# TYPE home_noc_icmp_packets_received gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_packets_received", rx))

            lines.append("# HELP home_noc_icmp_packet_loss_ratio Packet loss ratio (0..1) for the last probe burst.\n")
            lines.append("# TYPE home_noc_icmp_packet_loss_ratio gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_packet_loss_ratio", float(loss)))

            rtt_min = parsed_stats.get("rtt_min_seconds", float("nan"))
            rtt_avg = parsed_stats.get("rtt_avg_seconds", float("nan"))
            rtt_max = parsed_stats.get("rtt_max_seconds", float("nan"))
            rtt_stddev = parsed_stats.get("rtt_stddev_seconds", float("nan"))

            lines.append("# HELP home_noc_icmp_rtt_min_seconds Minimum round-trip time (seconds) in the last probe burst.\n")
            lines.append("# TYPE home_noc_icmp_rtt_min_seconds gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_rtt_min_seconds", float(rtt_min)))

            lines.append("# HELP home_noc_icmp_rtt_avg_seconds Average round-trip time (seconds) in the last probe burst.\n")
            lines.append("# TYPE home_noc_icmp_rtt_avg_seconds gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_rtt_avg_seconds", float(rtt_avg)))

            lines.append("# HELP home_noc_icmp_rtt_max_seconds Maximum round-trip time (seconds) in the last probe burst.\n")
            lines.append("# TYPE home_noc_icmp_rtt_max_seconds gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_rtt_max_seconds", float(rtt_max)))

            lines.append("# HELP home_noc_icmp_rtt_stddev_seconds Round-trip time stddev (seconds) in the last probe burst.\n")
            lines.append("# TYPE home_noc_icmp_rtt_stddev_seconds gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_rtt_stddev_seconds", float(rtt_stddev)))

            lines.append("# HELP home_noc_icmp_probe_duration_seconds Total time spent running the last probe.\n")
            lines.append("# TYPE home_noc_icmp_probe_duration_seconds gauge\n")
            lines.append(_format_metric_line("home_noc_icmp_probe_duration_seconds", float(duration)))

            self._send_text(HTTPStatus.OK, "".join(lines))
        except HttpError as exc:
            self._send_text(int(exc.status), f"error: {exc.message}\n")
        except Exception as exc:  # noqa: BLE001
            self._send_text(HTTPStatus.INTERNAL_SERVER_ERROR, f"error: {exc}\n")


def main() -> None:
    bind = os.environ.get("BIND", "0.0.0.0")
    port = int(os.environ.get("PORT", "9985"))
    print(f"[server] listening on http://{bind}:{port}")
    server = ThreadingHTTPServer((bind, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
