from __future__ import annotations

import datetime as _dt
import json
import os
import re
import sqlite3
import urllib.parse
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

ALLOWED_TYPES = {"http", "tcp", "dns", "icmp"}

DB_PATH = Path(os.environ.get("DB_PATH", "/data/targets.db"))
STATIC_DIR = Path(os.environ.get("STATIC_DIR", "/app/static"))
SEED_FILE = Path(os.environ.get("SEED_FILE", "/app/seed.json"))

_PORT_SUFFIX_RE = re.compile(r"^[^:]+:\d+$")
_BRACKET_PORT_RE = re.compile(r"^\[.+\]:\d+$")

ICMP_DEFAULT_COUNT = 4
ICMP_DEFAULT_INTERVAL_MS = 1000
ICMP_DEFAULT_TIMEOUT_MS = 1000
ICMP_DEFAULT_PACKET_SIZE = 56
ICMP_DEFAULT_DF = False

ICMP_COUNT_MIN = 1
ICMP_COUNT_MAX = 500
ICMP_INTERVAL_MS_MIN = 10
ICMP_INTERVAL_MS_MAX = 1000
ICMP_TIMEOUT_MS_MIN = 200
ICMP_TIMEOUT_MS_MAX = 5000
ICMP_PACKET_SIZE_MIN = 0
ICMP_PACKET_SIZE_MAX = 1472

ALLOWED_SCRAPE_PROFILES = {"1s", "5s", "15s", "60s"}
DEFAULT_SCRAPE_PROFILE = "15s"

ICMP_PROFILE_ESTIMATED_MS_MAX_BY_SCRAPE_PROFILE = {
    "1s": 900,
    "5s": 4500,
    "15s": 9000,
    "60s": 9000,
}


class HttpError(Exception):
    def __init__(self, status: int, message: str):
        self.status = status
        self.message = message
        super().__init__(message)


def _now_iso() -> str:
    return _dt.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


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


def _int_from_any(value: Any, *, field: str) -> int:
    if isinstance(value, bool):
        raise HttpError(HTTPStatus.BAD_REQUEST, f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        raw = value.strip()
        if raw.isdigit():
            return int(raw)
    raise HttpError(HTTPStatus.BAD_REQUEST, f"{field} must be an integer")


def _optional_int_from_any(value: Any, *, field: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, str) and value.strip() == "":
        return None
    return _int_from_any(value, field=field)


def _validate_int_range(value: int, *, field: str, min_value: int, max_value: int) -> int:
    if not (min_value <= value <= max_value):
        raise HttpError(HTTPStatus.BAD_REQUEST, f"{field} must be in range {min_value}..{max_value}")
    return value


def _normalize_scrape_profile(raw_profile: Any) -> str | None:
    if raw_profile is None:
        return None
    if not isinstance(raw_profile, str):
        raise HttpError(HTTPStatus.BAD_REQUEST, "scrape_profile must be a string")
    profile = raw_profile.strip()
    if profile == "":
        return None
    if profile not in ALLOWED_SCRAPE_PROFILES:
        raise HttpError(HTTPStatus.BAD_REQUEST, "scrape_profile must be one of: 1s, 5s, 15s, 60s")
    return profile


def _effective_scrape_profile(profile: Any) -> str:
    if isinstance(profile, str) and profile in ALLOWED_SCRAPE_PROFILES:
        return profile
    return DEFAULT_SCRAPE_PROFILE


def _icmp_effective_profile(
    *,
    icmp_count: int | None,
    icmp_interval_ms: int | None,
    icmp_timeout_ms: int | None,
    icmp_packet_size: int | None,
    icmp_df: bool | None,
) -> dict[str, Any]:
    return {
        "icmp_count": ICMP_DEFAULT_COUNT if icmp_count is None else icmp_count,
        "icmp_interval_ms": ICMP_DEFAULT_INTERVAL_MS if icmp_interval_ms is None else icmp_interval_ms,
        "icmp_timeout_ms": ICMP_DEFAULT_TIMEOUT_MS if icmp_timeout_ms is None else icmp_timeout_ms,
        "icmp_packet_size": ICMP_DEFAULT_PACKET_SIZE if icmp_packet_size is None else icmp_packet_size,
        "icmp_df": ICMP_DEFAULT_DF if icmp_df is None else icmp_df,
    }


def _validate_icmp_profile_duration(
    *,
    icmp_count: int,
    icmp_interval_ms: int,
    icmp_timeout_ms: int,
    scrape_profile: str,
) -> None:
    estimated_ms = max(0, icmp_count - 1) * icmp_interval_ms + icmp_timeout_ms
    max_ms = ICMP_PROFILE_ESTIMATED_MS_MAX_BY_SCRAPE_PROFILE.get(
        scrape_profile, ICMP_PROFILE_ESTIMATED_MS_MAX_BY_SCRAPE_PROFILE[DEFAULT_SCRAPE_PROFILE]
    )
    if estimated_ms > max_ms:
        raise HttpError(
            HTTPStatus.BAD_REQUEST,
            f"icmp profile too long for scrape_profile={scrape_profile} (estimated {estimated_ms}ms > {max_ms}ms)",
        )


def _normalize_type(raw_type: Any) -> str:
    if not isinstance(raw_type, str):
        raise HttpError(HTTPStatus.BAD_REQUEST, "type must be a string")
    target_type = raw_type.strip().lower()
    if target_type not in ALLOWED_TYPES:
        raise HttpError(HTTPStatus.BAD_REQUEST, "type must be one of: http, tcp, dns, icmp")
    return target_type


def _normalize_name(raw_name: Any) -> str | None:
    if raw_name is None:
        return None
    if not isinstance(raw_name, str):
        raise HttpError(HTTPStatus.BAD_REQUEST, "name must be a string")
    name = raw_name.strip()
    return name or None


def _validate_port(port: int) -> None:
    if not (1 <= port <= 65535):
        raise HttpError(HTTPStatus.BAD_REQUEST, "port must be in range 1..65535")


def _normalize_host_port(raw: str, *, default_port: int) -> str:
    if "://" in raw:
        raise HttpError(HTTPStatus.BAD_REQUEST, "target must not include a URL scheme")
    if any(ch.isspace() for ch in raw):
        raise HttpError(HTTPStatus.BAD_REQUEST, "target must not contain whitespace")
    if any(sep in raw for sep in ("/", "?", "#")):
        raise HttpError(HTTPStatus.BAD_REQUEST, "target must be in host:port format")

    if raw.startswith("["):
        end = raw.find("]")
        if end == -1:
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid IPv6 target: missing closing ']'")
        host = raw[1:end].strip()
        rest = raw[end + 1 :]
        if not host:
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: empty host")

        if rest == "":
            port = default_port
        elif rest.startswith(":"):
            port_str = rest[1:].strip()
            if not port_str.isdigit():
                raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: port must be numeric")
            port = int(port_str)
        else:
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: unexpected characters after ']'")

        _validate_port(port)
        return f"[{host.lower()}]:{port}"

    colon_count = raw.count(":")
    if colon_count == 0:
        host = raw.strip()
        port = default_port
    elif colon_count == 1:
        host, port_str = raw.rsplit(":", 1)
        host = host.strip()
        port_str = port_str.strip()
        if not port_str.isdigit():
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: port must be numeric")
        port = int(port_str)
    else:
        raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: IPv6 must be in [addr]:port format")

    if not host:
        raise HttpError(HTTPStatus.BAD_REQUEST, "invalid target: empty host")
    _validate_port(port)
    return f"{host.lower()}:{port}"


def _normalize_target(target_type: str, raw_target: Any) -> str:
    if not isinstance(raw_target, str):
        raise HttpError(HTTPStatus.BAD_REQUEST, "target must be a string")

    target = raw_target.strip()
    if not target:
        raise HttpError(HTTPStatus.BAD_REQUEST, "target must not be empty")

    if target_type == "http":
        if "://" not in target:
            target = "https://" + target
        parsed = urllib.parse.urlparse(target)
        scheme = parsed.scheme.lower()
        if scheme not in ("http", "https"):
            raise HttpError(HTTPStatus.BAD_REQUEST, "http target scheme must be http or https")
        if not parsed.netloc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "http target must include a hostname")

        normalized = urllib.parse.urlunparse(
            (
                scheme,
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
        return normalized

    if target_type == "tcp":
        return _normalize_host_port(target, default_port=443)

    if target_type == "dns":
        return _normalize_host_port(target, default_port=53)

    if target_type == "icmp":
        if "://" in target:
            raise HttpError(HTTPStatus.BAD_REQUEST, "icmp target must not include a URL scheme")
        if any(ch.isspace() for ch in target):
            raise HttpError(HTTPStatus.BAD_REQUEST, "target must not contain whitespace")
        if any(sep in target for sep in ("/", "?", "#")):
            raise HttpError(HTTPStatus.BAD_REQUEST, "icmp target must be a hostname or IP address")

        if _BRACKET_PORT_RE.match(target) or _PORT_SUFFIX_RE.match(target):
            raise HttpError(HTTPStatus.BAD_REQUEST, "icmp target must not include a port")

        if target.startswith("[") and target.endswith("]"):
            target = target[1:-1]

        return target.lower()

    raise HttpError(HTTPStatus.BAD_REQUEST, "unsupported type")


def _db_connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def _db_init() -> None:
    with _db_connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                target TEXT NOT NULL,
                name TEXT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                scrape_profile TEXT NULL,
                icmp_count INTEGER NULL,
                icmp_interval_ms INTEGER NULL,
                icmp_timeout_ms INTEGER NULL,
                icmp_packet_size INTEGER NULL,
                icmp_df INTEGER NULL,
                UNIQUE(type, target)
            )
            """
        )
        _db_ensure_columns(conn)


def _db_ensure_columns(conn: sqlite3.Connection) -> None:
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(targets)").fetchall()}
    columns: dict[str, str] = {
        "scrape_profile": "TEXT NULL",
        "icmp_count": "INTEGER NULL",
        "icmp_interval_ms": "INTEGER NULL",
        "icmp_timeout_ms": "INTEGER NULL",
        "icmp_packet_size": "INTEGER NULL",
        "icmp_df": "INTEGER NULL",
    }
    for name, spec in columns.items():
        if name in existing:
            continue
        conn.execute(f"ALTER TABLE targets ADD COLUMN {name} {spec}")


def _db_is_empty() -> bool:
    with _db_connect() as conn:
        row = conn.execute("SELECT COUNT(*) AS cnt FROM targets").fetchone()
        return int(row["cnt"]) == 0


def _db_insert_target(
    *,
    target_type: str,
    target: str,
    name: str | None,
    enabled: bool,
    scrape_profile: str | None,
    icmp_count: int | None,
    icmp_interval_ms: int | None,
    icmp_timeout_ms: int | None,
    icmp_packet_size: int | None,
    icmp_df: bool | None,
) -> int:
    now = _now_iso()
    with _db_connect() as conn:
        try:
            cursor = conn.execute(
                """
                INSERT INTO targets(
                    type,
                    target,
                    name,
                    enabled,
                    created_at,
                    updated_at,
                    scrape_profile,
                    icmp_count,
                    icmp_interval_ms,
                    icmp_timeout_ms,
                    icmp_packet_size,
                    icmp_df
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    target_type,
                    target,
                    name,
                    1 if enabled else 0,
                    now,
                    now,
                    scrape_profile,
                    icmp_count,
                    icmp_interval_ms,
                    icmp_timeout_ms,
                    icmp_packet_size,
                    (1 if icmp_df else 0) if icmp_df is not None else None,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HttpError(HTTPStatus.CONFLICT, "target already exists") from exc
        return int(cursor.lastrowid)


def _db_get_target(target_id: int) -> dict[str, Any] | None:
    with _db_connect() as conn:
        row = conn.execute("SELECT * FROM targets WHERE id = ?", (target_id,)).fetchone()
        if row is None:
            return None
        return dict(row)


def _db_list_targets(*, target_type: str | None, enabled: bool | None) -> list[dict[str, Any]]:
    where = []
    params: list[Any] = []
    if target_type is not None:
        where.append("type = ?")
        params.append(target_type)
    if enabled is not None:
        where.append("enabled = ?")
        params.append(1 if enabled else 0)

    sql = "SELECT * FROM targets"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY type, target"

    with _db_connect() as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]


def _db_update_target(
    target_id: int,
    *,
    name: str | None,
    target: str,
    enabled: bool,
    scrape_profile: str | None,
    icmp_count: int | None,
    icmp_interval_ms: int | None,
    icmp_timeout_ms: int | None,
    icmp_packet_size: int | None,
    icmp_df: bool | None,
) -> dict[str, Any]:
    now = _now_iso()
    with _db_connect() as conn:
        try:
            cursor = conn.execute(
                """
                UPDATE targets
                SET
                    name = ?,
                    target = ?,
                    enabled = ?,
                    updated_at = ?,
                    scrape_profile = ?,
                    icmp_count = ?,
                    icmp_interval_ms = ?,
                    icmp_timeout_ms = ?,
                    icmp_packet_size = ?,
                    icmp_df = ?
                WHERE id = ?
                """,
                (
                    name,
                    target,
                    1 if enabled else 0,
                    now,
                    scrape_profile,
                    icmp_count,
                    icmp_interval_ms,
                    icmp_timeout_ms,
                    icmp_packet_size,
                    (1 if icmp_df else 0) if icmp_df is not None else None,
                    target_id,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise HttpError(HTTPStatus.CONFLICT, "target already exists") from exc

        if cursor.rowcount == 0:
            raise HttpError(HTTPStatus.NOT_FOUND, "target not found")

    updated = _db_get_target(target_id)
    if updated is None:
        raise HttpError(HTTPStatus.NOT_FOUND, "target not found")
    return updated


def _db_delete_target(target_id: int) -> None:
    with _db_connect() as conn:
        cursor = conn.execute("DELETE FROM targets WHERE id = ?", (target_id,))
        if cursor.rowcount == 0:
            raise HttpError(HTTPStatus.NOT_FOUND, "target not found")


def _seed_if_empty() -> None:
    if not SEED_FILE.exists():
        return
    if not _db_is_empty():
        return

    try:
        seed = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        print(f"[seed] failed to read seed file {SEED_FILE}: {exc}")
        return

    if not isinstance(seed, list):
        print("[seed] seed.json must be a list")
        return

    for idx, item in enumerate(seed):
        if not isinstance(item, dict):
            print(f"[seed] skipping item #{idx}: not an object")
            continue
        try:
            target_type = _normalize_type(item.get("type"))
            target = _normalize_target(target_type, item.get("target"))
            name = _normalize_name(item.get("name"))
            enabled = _bool_from_any(item.get("enabled", True), field="enabled")
            scrape_profile = _normalize_scrape_profile(item.get("scrape_profile"))

            icmp_count = None
            icmp_interval_ms = None
            icmp_timeout_ms = None
            icmp_packet_size = None
            icmp_df = None

            icmp_fields_present = any(
                key in item for key in ("icmp_count", "icmp_interval_ms", "icmp_timeout_ms", "icmp_packet_size", "icmp_df")
            )
            if target_type != "icmp" and icmp_fields_present:
                raise HttpError(HTTPStatus.BAD_REQUEST, "icmp_* fields are only valid for icmp targets")

            if target_type == "icmp":
                icmp_count = _optional_int_from_any(item.get("icmp_count"), field="icmp_count")
                if icmp_count is not None:
                    icmp_count = _validate_int_range(
                        icmp_count, field="icmp_count", min_value=ICMP_COUNT_MIN, max_value=ICMP_COUNT_MAX
                    )

                icmp_interval_ms = _optional_int_from_any(item.get("icmp_interval_ms"), field="icmp_interval_ms")
                if icmp_interval_ms is not None:
                    icmp_interval_ms = _validate_int_range(
                        icmp_interval_ms,
                        field="icmp_interval_ms",
                        min_value=ICMP_INTERVAL_MS_MIN,
                        max_value=ICMP_INTERVAL_MS_MAX,
                    )

                icmp_timeout_ms = _optional_int_from_any(item.get("icmp_timeout_ms"), field="icmp_timeout_ms")
                if icmp_timeout_ms is not None:
                    icmp_timeout_ms = _validate_int_range(
                        icmp_timeout_ms,
                        field="icmp_timeout_ms",
                        min_value=ICMP_TIMEOUT_MS_MIN,
                        max_value=ICMP_TIMEOUT_MS_MAX,
                    )

                icmp_packet_size = _optional_int_from_any(item.get("icmp_packet_size"), field="icmp_packet_size")
                if icmp_packet_size is not None:
                    icmp_packet_size = _validate_int_range(
                        icmp_packet_size,
                        field="icmp_packet_size",
                        min_value=ICMP_PACKET_SIZE_MIN,
                        max_value=ICMP_PACKET_SIZE_MAX,
                    )

                if "icmp_df" in item:
                    icmp_df = _bool_from_any(item.get("icmp_df"), field="icmp_df")

                effective = _icmp_effective_profile(
                    icmp_count=icmp_count,
                    icmp_interval_ms=icmp_interval_ms,
                    icmp_timeout_ms=icmp_timeout_ms,
                    icmp_packet_size=icmp_packet_size,
                    icmp_df=icmp_df,
                )
                _validate_icmp_profile_duration(
                    icmp_count=effective["icmp_count"],
                    icmp_interval_ms=effective["icmp_interval_ms"],
                    icmp_timeout_ms=effective["icmp_timeout_ms"],
                    scrape_profile=_effective_scrape_profile(scrape_profile),
                )

            _db_insert_target(
                target_type=target_type,
                target=target,
                name=name,
                enabled=enabled,
                scrape_profile=scrape_profile,
                icmp_count=icmp_count,
                icmp_interval_ms=icmp_interval_ms,
                icmp_timeout_ms=icmp_timeout_ms,
                icmp_packet_size=icmp_packet_size,
                icmp_df=icmp_df,
            )
        except HttpError as exc:
            print(f"[seed] skipping item #{idx}: {exc.message}")
        except Exception as exc:  # noqa: BLE001
            print(f"[seed] skipping item #{idx}: {exc}")


def _content_type_for(path: Path) -> str:
    suffix = path.suffix.lower()
    if suffix == ".html":
        return "text/html; charset=utf-8"
    if suffix == ".css":
        return "text/css; charset=utf-8"
    if suffix == ".js":
        return "application/javascript; charset=utf-8"
    if suffix == ".json":
        return "application/json; charset=utf-8"
    if suffix == ".svg":
        return "image/svg+xml"
    if suffix == ".png":
        return "image/png"
    if suffix == ".ico":
        return "image/x-icon"
    return "application/octet-stream"


class Handler(BaseHTTPRequestHandler):
    server_version = "home-noc-target-manager/1.0"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        print("[%s] %s" % (self.log_date_time_string(), format % args))

    def _send_json(self, status: int, payload: Any) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _send_text(self, status: int, text: str, *, content_type: str = "text/plain; charset=utf-8") -> None:
        data = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json_body(self) -> dict[str, Any]:
        length_raw = self.headers.get("Content-Length")
        if not length_raw:
            raise HttpError(HTTPStatus.BAD_REQUEST, "missing Content-Length")
        try:
            length = int(length_raw)
        except ValueError as exc:
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid Content-Length") from exc
        body = self.rfile.read(length)
        try:
            payload = json.loads(body.decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            raise HttpError(HTTPStatus.BAD_REQUEST, "invalid JSON") from exc
        if not isinstance(payload, dict):
            raise HttpError(HTTPStatus.BAD_REQUEST, "JSON body must be an object")
        return payload

    def _serve_static(self, rel_path: str) -> None:
        rel = Path(rel_path)
        if rel.is_absolute() or ".." in rel.parts:
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        path = (STATIC_DIR / rel).resolve()
        if not str(path).startswith(str(STATIC_DIR.resolve())):
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        if not path.exists() or not path.is_file():
            raise HttpError(HTTPStatus.NOT_FOUND, "not found")

        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", _content_type_for(path))
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

            if path == "/" or path == "/index.html":
                self._serve_static("index.html")
                return

            if path.startswith("/static/"):
                self._serve_static(path.removeprefix("/static/"))
                return

            if path in ("/sd/http", "/sd/tcp", "/sd/dns", "/sd/icmp"):
                target_type = path.split("/")[-1]
                rows = _db_list_targets(target_type=target_type, enabled=True)
                groups = []
                for row in rows:
                    name = (row.get("name") or "").strip() or row["target"]
                    labels = {
                        "target_name": name,
                        "target_type": target_type,
                        "scrape_profile": _effective_scrape_profile(row.get("scrape_profile")),
                    }
                    if target_type == "icmp":
                        effective = _icmp_effective_profile(
                            icmp_count=row.get("icmp_count"),
                            icmp_interval_ms=row.get("icmp_interval_ms"),
                            icmp_timeout_ms=row.get("icmp_timeout_ms"),
                            icmp_packet_size=row.get("icmp_packet_size"),
                            icmp_df=(None if row.get("icmp_df") is None else bool(row.get("icmp_df"))),
                        )
                        labels.update(
                            {
                                "icmp_count": str(effective["icmp_count"]),
                                "icmp_interval_ms": str(effective["icmp_interval_ms"]),
                                "icmp_timeout_ms": str(effective["icmp_timeout_ms"]),
                                "icmp_packet_size": str(effective["icmp_packet_size"]),
                                "icmp_df": "true" if effective["icmp_df"] else "false",
                            }
                        )
                    groups.append(
                        {
                            "targets": [row["target"]],
                            "labels": labels,
                        }
                    )
                self._send_json(HTTPStatus.OK, groups)
                return

            if path == "/api/targets":
                query = urllib.parse.parse_qs(parsed.query or "")
                q_type = query.get("type", [None])[0]
                q_enabled = query.get("enabled", [None])[0]

                target_type = _normalize_type(q_type) if q_type is not None else None
                enabled = None if q_enabled is None else _bool_from_any(q_enabled, field="enabled")

                items = _db_list_targets(target_type=target_type, enabled=enabled)
                self._send_json(HTTPStatus.OK, items)
                return

            raise HttpError(HTTPStatus.NOT_FOUND, "not found")
        except HttpError as exc:
            self._send_json(int(exc.status), {"error": exc.message})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path != "/api/targets":
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            body = self._read_json_body()
            target_type = _normalize_type(body.get("type"))
            target = _normalize_target(target_type, body.get("target"))
            name = _normalize_name(body.get("name"))
            enabled = _bool_from_any(body.get("enabled", True), field="enabled")
            scrape_profile = _normalize_scrape_profile(body.get("scrape_profile"))

            icmp_count = None
            icmp_interval_ms = None
            icmp_timeout_ms = None
            icmp_packet_size = None
            icmp_df = None

            icmp_fields_present = any(
                key in body for key in ("icmp_count", "icmp_interval_ms", "icmp_timeout_ms", "icmp_packet_size", "icmp_df")
            )
            if target_type != "icmp" and icmp_fields_present:
                raise HttpError(HTTPStatus.BAD_REQUEST, "icmp_* fields are only valid for icmp targets")

            if target_type == "icmp":
                icmp_count = _optional_int_from_any(body.get("icmp_count"), field="icmp_count")
                if icmp_count is not None:
                    icmp_count = _validate_int_range(
                        icmp_count, field="icmp_count", min_value=ICMP_COUNT_MIN, max_value=ICMP_COUNT_MAX
                    )

                icmp_interval_ms = _optional_int_from_any(body.get("icmp_interval_ms"), field="icmp_interval_ms")
                if icmp_interval_ms is not None:
                    icmp_interval_ms = _validate_int_range(
                        icmp_interval_ms,
                        field="icmp_interval_ms",
                        min_value=ICMP_INTERVAL_MS_MIN,
                        max_value=ICMP_INTERVAL_MS_MAX,
                    )

                icmp_timeout_ms = _optional_int_from_any(body.get("icmp_timeout_ms"), field="icmp_timeout_ms")
                if icmp_timeout_ms is not None:
                    icmp_timeout_ms = _validate_int_range(
                        icmp_timeout_ms,
                        field="icmp_timeout_ms",
                        min_value=ICMP_TIMEOUT_MS_MIN,
                        max_value=ICMP_TIMEOUT_MS_MAX,
                    )

                icmp_packet_size = _optional_int_from_any(body.get("icmp_packet_size"), field="icmp_packet_size")
                if icmp_packet_size is not None:
                    icmp_packet_size = _validate_int_range(
                        icmp_packet_size,
                        field="icmp_packet_size",
                        min_value=ICMP_PACKET_SIZE_MIN,
                        max_value=ICMP_PACKET_SIZE_MAX,
                    )

                if "icmp_df" in body:
                    icmp_df = _bool_from_any(body.get("icmp_df"), field="icmp_df")

                effective = _icmp_effective_profile(
                    icmp_count=icmp_count,
                    icmp_interval_ms=icmp_interval_ms,
                    icmp_timeout_ms=icmp_timeout_ms,
                    icmp_packet_size=icmp_packet_size,
                    icmp_df=icmp_df,
                )
                _validate_icmp_profile_duration(
                    icmp_count=effective["icmp_count"],
                    icmp_interval_ms=effective["icmp_interval_ms"],
                    icmp_timeout_ms=effective["icmp_timeout_ms"],
                    scrape_profile=_effective_scrape_profile(scrape_profile),
                )

            target_id = _db_insert_target(
                target_type=target_type,
                target=target,
                name=name,
                enabled=enabled,
                scrape_profile=scrape_profile,
                icmp_count=icmp_count,
                icmp_interval_ms=icmp_interval_ms,
                icmp_timeout_ms=icmp_timeout_ms,
                icmp_packet_size=icmp_packet_size,
                icmp_df=icmp_df,
            )
            created = _db_get_target(target_id)
            self._send_json(HTTPStatus.CREATED, created)
        except HttpError as exc:
            self._send_json(int(exc.status), {"error": exc.message})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_PATCH(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if not parsed.path.startswith("/api/targets/"):
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")

            try:
                target_id = int(parsed.path.removeprefix("/api/targets/"))
            except ValueError as exc:
                raise HttpError(HTTPStatus.NOT_FOUND, "not found") from exc

            existing = _db_get_target(target_id)
            if existing is None:
                raise HttpError(HTTPStatus.NOT_FOUND, "target not found")

            body = self._read_json_body()

            name = existing.get("name")
            target = existing["target"]
            enabled = bool(existing["enabled"])
            scrape_profile = existing.get("scrape_profile")
            icmp_count = existing.get("icmp_count")
            icmp_interval_ms = existing.get("icmp_interval_ms")
            icmp_timeout_ms = existing.get("icmp_timeout_ms")
            icmp_packet_size = existing.get("icmp_packet_size")
            icmp_df = None if existing.get("icmp_df") is None else bool(existing.get("icmp_df"))

            if "name" in body:
                name = _normalize_name(body.get("name"))
            if "enabled" in body:
                enabled = _bool_from_any(body.get("enabled"), field="enabled")
            if "target" in body:
                target = _normalize_target(existing["type"], body.get("target"))
            if "scrape_profile" in body:
                scrape_profile = _normalize_scrape_profile(body.get("scrape_profile"))

            icmp_fields_present = any(
                key in body for key in ("icmp_count", "icmp_interval_ms", "icmp_timeout_ms", "icmp_packet_size", "icmp_df")
            )
            if existing["type"] != "icmp" and icmp_fields_present:
                raise HttpError(HTTPStatus.BAD_REQUEST, "icmp_* fields are only valid for icmp targets")

            if existing["type"] == "icmp":
                if "icmp_count" in body:
                    icmp_count = _optional_int_from_any(body.get("icmp_count"), field="icmp_count")
                    if icmp_count is not None:
                        icmp_count = _validate_int_range(
                            icmp_count, field="icmp_count", min_value=ICMP_COUNT_MIN, max_value=ICMP_COUNT_MAX
                        )

                if "icmp_interval_ms" in body:
                    icmp_interval_ms = _optional_int_from_any(body.get("icmp_interval_ms"), field="icmp_interval_ms")
                    if icmp_interval_ms is not None:
                        icmp_interval_ms = _validate_int_range(
                            icmp_interval_ms,
                            field="icmp_interval_ms",
                            min_value=ICMP_INTERVAL_MS_MIN,
                            max_value=ICMP_INTERVAL_MS_MAX,
                        )

                if "icmp_timeout_ms" in body:
                    icmp_timeout_ms = _optional_int_from_any(body.get("icmp_timeout_ms"), field="icmp_timeout_ms")
                    if icmp_timeout_ms is not None:
                        icmp_timeout_ms = _validate_int_range(
                            icmp_timeout_ms,
                            field="icmp_timeout_ms",
                            min_value=ICMP_TIMEOUT_MS_MIN,
                            max_value=ICMP_TIMEOUT_MS_MAX,
                        )

                if "icmp_packet_size" in body:
                    icmp_packet_size = _optional_int_from_any(body.get("icmp_packet_size"), field="icmp_packet_size")
                    if icmp_packet_size is not None:
                        icmp_packet_size = _validate_int_range(
                            icmp_packet_size,
                            field="icmp_packet_size",
                            min_value=ICMP_PACKET_SIZE_MIN,
                            max_value=ICMP_PACKET_SIZE_MAX,
                        )

                if "icmp_df" in body:
                    icmp_df = _bool_from_any(body.get("icmp_df"), field="icmp_df") if body.get("icmp_df") is not None else None

                effective = _icmp_effective_profile(
                    icmp_count=icmp_count,
                    icmp_interval_ms=icmp_interval_ms,
                    icmp_timeout_ms=icmp_timeout_ms,
                    icmp_packet_size=icmp_packet_size,
                    icmp_df=icmp_df,
                )
                _validate_icmp_profile_duration(
                    icmp_count=effective["icmp_count"],
                    icmp_interval_ms=effective["icmp_interval_ms"],
                    icmp_timeout_ms=effective["icmp_timeout_ms"],
                    scrape_profile=_effective_scrape_profile(scrape_profile),
                )

            updated = _db_update_target(
                target_id,
                name=name,
                target=target,
                enabled=enabled,
                scrape_profile=scrape_profile,
                icmp_count=icmp_count,
                icmp_interval_ms=icmp_interval_ms,
                icmp_timeout_ms=icmp_timeout_ms,
                icmp_packet_size=icmp_packet_size,
                icmp_df=icmp_df,
            )
            self._send_json(HTTPStatus.OK, updated)
        except HttpError as exc:
            self._send_json(int(exc.status), {"error": exc.message})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})

    def do_DELETE(self) -> None:  # noqa: N802
        try:
            parsed = urllib.parse.urlparse(self.path)
            if not parsed.path.startswith("/api/targets/"):
                raise HttpError(HTTPStatus.NOT_FOUND, "not found")
            try:
                target_id = int(parsed.path.removeprefix("/api/targets/"))
            except ValueError as exc:
                raise HttpError(HTTPStatus.NOT_FOUND, "not found") from exc

            _db_delete_target(target_id)
            self.send_response(HTTPStatus.NO_CONTENT)
            self.end_headers()
        except HttpError as exc:
            self._send_json(int(exc.status), {"error": exc.message})
        except Exception as exc:  # noqa: BLE001
            self._send_json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})


def main() -> None:
    bind = os.environ.get("BIND", "127.0.0.1")
    port = int(os.environ.get("PORT", "8080"))

    _db_init()
    _seed_if_empty()

    print(f"[server] DB_PATH={DB_PATH}")
    print(f"[server] STATIC_DIR={STATIC_DIR}")
    print(f"[server] listening on http://{bind}:{port}")

    server = ThreadingHTTPServer((bind, port), Handler)
    server.serve_forever()


if __name__ == "__main__":
    main()
