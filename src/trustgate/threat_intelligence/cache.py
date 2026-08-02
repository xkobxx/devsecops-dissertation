"""Content-addressed local cache for normalized threat-feed records."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import tempfile
from typing import Any


CACHE_FORMAT_VERSION = 1


@dataclass(frozen=True)
class CacheEntry:
    source: str
    key: str
    payload: Any
    fetched_at: datetime
    expires_at: datetime
    stale: bool


class ThreatCache:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def path_for(self, source: str, key: str) -> Path:
        identity = json.dumps(
            {"source": source, "key": key},
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()
        return self.root / f"{digest}.json"

    def get(
        self,
        source: str,
        key: str,
        *,
        now: datetime | None = None,
    ) -> CacheEntry | None:
        path = self.path_for(source, key)
        if not path.exists():
            return None
        return self.read_path(path, now=now)

    def read_path(
        self,
        path: Path,
        *,
        now: datetime | None = None,
    ) -> CacheEntry:
        path = Path(path)
        if path.is_symlink():
            raise ValueError(f"threat cache entry must not be a symlink: {path}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise ValueError(f"invalid threat cache entry {path}: {error}") from error
        if not isinstance(data, dict) or data.get("format_version") != 1:
            raise ValueError(f"unsupported threat cache entry: {path}")
        try:
            fetched_at = _parse_timestamp(data["fetched_at"])
            expires_at = _parse_timestamp(data["expires_at"])
            source = str(data["source"])
            key = str(data["key"])
            payload = data["payload"]
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"invalid threat cache entry {path}: {error}") from error
        observed = _utc(now or datetime.now(timezone.utc))
        return CacheEntry(
            source=source,
            key=key,
            payload=payload,
            fetched_at=fetched_at,
            expires_at=expires_at,
            stale=observed >= expires_at,
        )

    def put(
        self,
        source: str,
        key: str,
        payload: Any,
        *,
        fetched_at: datetime,
        ttl: timedelta,
    ) -> CacheEntry:
        if ttl.total_seconds() <= 0:
            raise ValueError("threat cache TTL must be positive")
        if self.root.is_symlink():
            raise ValueError(
                f"threat cache directory must not be a symlink: {self.root}"
            )
        self.root.mkdir(parents=True, exist_ok=True)
        path = self.path_for(source, key)
        if path.is_symlink():
            raise ValueError(f"threat cache entry must not be a symlink: {path}")
        fetched = _utc(fetched_at)
        expires = fetched + ttl
        envelope = {
            "format_version": CACHE_FORMAT_VERSION,
            "source": source,
            "key": key,
            "fetched_at": fetched.isoformat(),
            "expires_at": expires.isoformat(),
            "payload": payload,
        }
        temporary_path: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                dir=self.root,
                prefix=".threat-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                json.dump(envelope, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
                temporary_path = Path(handle.name)
            temporary_path.replace(path)
        finally:
            if temporary_path is not None and temporary_path.exists():
                temporary_path.unlink()
        return CacheEntry(
            source=source,
            key=key,
            payload=payload,
            fetched_at=fetched,
            expires_at=expires,
            stale=False,
        )


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise TypeError("cache timestamp must be a string")
    return _utc(datetime.fromisoformat(value.replace("Z", "+00:00")))


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
