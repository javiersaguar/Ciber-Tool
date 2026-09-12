"""Persistencia acotada. Este módulo nunca recibe contraseñas sin seudonimizar."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import sqlite3
import stat
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import maxminddb

from atalaya.core.finding import Finding, Severity


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("El directorio de estado no puede ser un enlace")
    new = not path.exists()
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "nt" and new:
        identity = subprocess.check_output(["whoami"], text=True).strip()
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{identity}:(OI)(CI)F"],
            check=True,
            capture_output=True,
        )
    elif os.name != "nt" and path.stat().st_mode & 0o077:
        raise ValueError("El directorio de estado requiere permisos 0700")


def private_file(path: Path, initial: bytes, *, read: bool = True) -> bytes:
    """Creación exclusiva y rechazo de enlaces/permisos abiertos en POSIX."""
    if path.is_symlink():
        raise ValueError("No se permiten enlaces en el estado")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if not stat.S_ISREG(path.stat().st_mode):
            raise ValueError("El estado debe ser un fichero regular") from None
        if os.name != "nt" and path.stat().st_mode & 0o077:
            raise ValueError("El fichero de estado requiere permisos 0600") from None
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(initial)
    return path.read_bytes() if read else b""


class Pseudonymizer:
    def __init__(self, key: bytes):
        if len(key) != 32:
            raise ValueError("La clave HMAC debe tener 32 bytes")
        self._key = key

    def attempt(self, ip: str, username: str, password: str, client: str, now: float) -> dict:
        stamp = datetime.fromtimestamp(now, timezone.utc)
        day = stamp.date().isoformat()
        key = hmac.digest(self._key, day.encode(), "sha256")

        def digest(domain: str, *values: str) -> str:
            data = json.dumps([domain, *values], ensure_ascii=True).encode()
            return hmac.new(key, data, hashlib.sha256).hexdigest()

        # No vistas parciales, ni longitud de la contraseña, ni hash sin clave.
        return {
            "id": uuid4().hex,
            "timestamp": stamp.isoformat(),
            "epoch": now,
            "ip": normalize_ip(ip),
            "username_id": digest("username", username),
            "password_id": digest("password", password),
            "credential_id": digest("credential", username, password),
            "fingerprint": digest("attempt", normalize_ip(ip), username, password, client),
            "client_version": "".join(c if c.isprintable() else "�" for c in client)[:255],
            "key_day": day,
        }


def normalize_ip(value: str) -> str:
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return str(address)


class Store:
    """Usar desde un único worker; SQLite y GeoIP no bloquean el event loop."""

    def __init__(self, inputs):
        self.inputs = inputs
        self.geo = maxminddb.open_database(str(inputs.geoip_db)) if inputs.geoip_db else None
        path = inputs.data_dir / "events.sqlite3"
        private_file(path, b"", read=False)
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA secure_delete=ON")
        self.db.execute("PRAGMA max_page_count=65536")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS attempts (
                id TEXT PRIMARY KEY, epoch REAL NOT NULL, ip TEXT NOT NULL,
                password_id TEXT NOT NULL, credential_id TEXT NOT NULL, data TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS attempt_time ON attempts(epoch);
            CREATE INDEX IF NOT EXISTS attempt_ip_time ON attempts(ip, epoch);
            CREATE TABLE IF NOT EXISTS alerts (
                ip TEXT PRIMARY KEY, epoch REAL NOT NULL, data TEXT NOT NULL
            );
        """)
        self.prune(datetime.now(timezone.utc).timestamp())

    def close(self):
        self.db.close()
        if self.geo:
            self.geo.close()

    def location(self, ip: str) -> dict | None:
        if not self.geo or not ipaddress.ip_address(ip).is_global:
            return None
        record = self.geo.get(ip) or {}
        loc = record.get("location", {})
        if "latitude" not in loc or "longitude" not in loc:
            return None
        return {
            "latitude": loc["latitude"],
            "longitude": loc["longitude"],
            "accuracy_km": loc.get("accuracy_radius"),
            "country": record.get("country", {}).get("iso_code", "?"),
        }

    def prune(self, now: float) -> None:
        with self.db:
            self.db.execute(
                "DELETE FROM attempts WHERE epoch < ?",
                (now - self.inputs.retention_hours * 3600,),
            )
            self.db.execute(
                "DELETE FROM attempts WHERE id IN (SELECT id FROM attempts "
                "ORDER BY epoch DESC LIMIT -1 OFFSET ?)",
                (self.inputs.max_events,),
            )
            self.db.execute(
                "DELETE FROM alerts WHERE epoch < ?", (now - self.inputs.report_window,)
            )
            self.db.execute(
                "DELETE FROM alerts WHERE ip IN (SELECT ip FROM alerts "
                "ORDER BY epoch DESC LIMIT -1 OFFSET 1000)"
            )

    def record(self, events: list[dict], now: float) -> list[tuple[dict, Finding | None]]:
        result = []
        with self.db:
            for event in events:
                event["location"] = self.location(event["ip"])
                self.db.execute(
                    "INSERT INTO attempts VALUES (?, ?, ?, ?, ?, ?)",
                    (
                        event["id"],
                        event["epoch"],
                        event["ip"],
                        event["password_id"],
                        event["credential_id"],
                        json.dumps(event),
                    ),
                )
                finding = self._detect(event)
                result.append((event, finding))
        self.prune(now)
        return result

    def _detect(self, event: dict) -> Finding | None:
        now, ip = event["epoch"], event["ip"]
        last = self.db.execute("SELECT epoch FROM alerts WHERE ip = ?", (ip,)).fetchone()
        if last and last[0] >= now - self.inputs.report_window:
            return None
        # Los seudónimos rotan a medianoche: no contar dos veces una clave
        # que cruce el cambio de día. La detección reinicia su ventana ahí.
        midnight = (
            datetime.fromtimestamp(now, timezone.utc)
            .replace(hour=0, minute=0, second=0, microsecond=0)
            .timestamp()
        )
        count = self.db.execute(
            "SELECT COUNT(DISTINCT password_id) FROM attempts WHERE ip = ? AND epoch >= ?",
            (ip, max(midnight, now - self.inputs.alert_window)),
        ).fetchone()[0]
        if count < self.inputs.alert_threshold:
            return None
        finding = Finding(
            severity=Severity.HIGH,
            title=f"Intentos de fuerza bruta desde {ip}",
            description=f"{count} contraseñas distintas en {self.inputs.alert_window} segundos.",
            evidence=f"IP: {ip}; hasta {event['timestamp']}; todos los accesos denegados.",
            remediation="Revisar actividad y límites de red; no atribuir identidad por la IP.",
        )
        self.db.execute(
            "INSERT OR REPLACE INTO alerts VALUES (?, ?, ?)",
            (ip, now, finding.model_dump_json()),
        )
        return finding

    def restore_findings(self, now: float) -> list[tuple[float, Finding]]:
        return [
            (row["epoch"], Finding.model_validate_json(row["data"]))
            for row in self.db.execute(
                "SELECT * FROM alerts WHERE epoch >= ? ORDER BY epoch",
                (now - self.inputs.report_window,),
            )
        ]

    def dashboard(self, now: float) -> dict:
        self.prune(now)
        total = self.db.execute("SELECT COUNT(*) FROM attempts").fetchone()[0]
        recent = [
            json.loads(r[0])
            for r in self.db.execute("SELECT data FROM attempts ORDER BY epoch DESC LIMIT 50")
        ]
        ranking = []
        for row in self.db.execute(
            "SELECT credential_id, COUNT(*) AS count, MAX(data) AS data FROM attempts "
            "GROUP BY credential_id ORDER BY count DESC, credential_id LIMIT 15"
        ):
            event = json.loads(row["data"])
            ranking.append(
                {
                    "username_id": event["username_id"],
                    "password_id": event["password_id"],
                    "key_day": event["key_day"],
                    "count": row["count"],
                }
            )
        origins = []
        for row in self.db.execute(
            "SELECT ip, COUNT(*) AS count, MAX(data) AS data FROM attempts "
            "GROUP BY ip ORDER BY count DESC, ip LIMIT 100"
        ):
            origins.append(
                {
                    "ip": row["ip"],
                    "count": row["count"],
                    "location": json.loads(row["data"]).get("location"),
                }
            )
        counts = dict(
            self.db.execute(
                "SELECT CAST(epoch / 60 AS INTEGER), COUNT(*) FROM attempts "
                "WHERE epoch >= ? GROUP BY CAST(epoch / 60 AS INTEGER)",
                (now - 3600,),
            )
        )
        minute = int(now // 60)
        timeline = [
            {"epoch": t * 60, "count": counts.get(t, 0)} for t in range(minute - 59, minute + 1)
        ]
        unique = self.db.execute("SELECT COUNT(DISTINCT ip) FROM attempts").fetchone()[0]
        return {
            "total": total,
            "unique_ips": unique,
            "recent": recent,
            "ranking": ranking,
            "origins": origins,
            "timeline": timeline,
            "geoip_enabled": self.geo is not None,
            "retention_hours": self.inputs.retention_hours,
            "max_events": self.inputs.max_events,
        }


def initialize_secrets(path: Path) -> tuple[Pseudonymizer, str, bytes]:
    import asyncssh

    private_directory(path)
    key = private_file(path / "hmac.key", secrets.token_bytes(32))
    token = (
        private_file(path / "dashboard.token", secrets.token_urlsafe(32).encode()).decode().strip()
    )
    if len(token) < 32:
        raise ValueError("Token del panel inválido")
    host_key = private_file(
        path / "ssh_host_key", asyncssh.generate_private_key("ssh-ed25519").export_private_key()
    )
    return Pseudonymizer(key), token, host_key
