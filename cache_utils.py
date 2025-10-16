"""Simple thread-safe LRU cache utilities for the ISRO-GPT RAG stack."""
from __future__ import annotations

import threading
from collections import OrderedDict
from typing import Generic, MutableMapping, Optional, TypeVar

K = TypeVar("K")
V = TypeVar("V")


class LRUCache(Generic[K, V]):
    """Lightweight LRU cache with coarse locking for cross-thread safety."""

    def __init__(self, capacity: int = 32) -> None:
        if capacity < 0:
            raise ValueError("Capacity must be non-negative")
        self.capacity = capacity
        self._store: MutableMapping[K, V] = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: K) -> Optional[V]:
        if self.capacity == 0:
            return None
        with self._lock:
            if key not in self._store:
                return None
            value = self._store.pop(key)
            self._store[key] = value
            return value

    def set(self, key: K, value: V) -> None:
        if self.capacity == 0:
            return
        with self._lock:
            if key in self._store:
                self._store.pop(key)
            elif len(self._store) >= self.capacity:
                self._store.popitem(last=False)
            self._store[key] = value

    def clear(self) -> None:
        with self._lock:
            self._store.clear()

    def __len__(self) -> int:  # pragma: no cover - trivial
        with self._lock:
            return len(self._store)
