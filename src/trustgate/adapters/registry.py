"""Adapter registration and entry-point discovery."""

from __future__ import annotations

from importlib import metadata as importlib_metadata
from typing import Iterable

from .base import ScannerAdapter


class AdapterRegistry:
    """Resolve adapters without requiring aggregator code changes."""

    ENTRY_POINT_GROUP = "trustgate.adapters"

    def __init__(self) -> None:
        self._adapters: dict[str, type[ScannerAdapter]] = {}
        self.discovery_errors: dict[str, str] = {}

    def register(self, adapter: type[ScannerAdapter]) -> str:
        if not isinstance(adapter, type) or not issubclass(adapter, ScannerAdapter):
            raise TypeError("adapter must be a ScannerAdapter class")
        name = adapter().metadata().name
        if name in self._adapters:
            raise ValueError(f"adapter {name!r} is already registered")
        self._adapters[name] = adapter
        return name

    def get(self, name: str) -> ScannerAdapter:
        try:
            adapter = self._adapters[name]
        except KeyError as error:
            raise KeyError(f"unknown scanner adapter: {name}") from error
        return adapter()

    def names(self) -> tuple[str, ...]:
        return tuple(sorted(self._adapters))

    def discover(self, *, entry_points: Iterable[object] | None = None) -> tuple[str, ...]:
        if entry_points is None:
            entry_points = importlib_metadata.entry_points(
                group=self.ENTRY_POINT_GROUP
            )
        discovered: list[str] = []
        for entry_point in entry_points:
            entry_point_name = str(getattr(entry_point, "name", "unknown"))
            try:
                adapter = entry_point.load()
                discovered.append(self.register(adapter))
            except Exception as error:
                self.discovery_errors[entry_point_name] = (
                    f"{type(error).__name__}: {error}"
                )
        return tuple(sorted(discovered))


__all__ = ["AdapterRegistry"]
