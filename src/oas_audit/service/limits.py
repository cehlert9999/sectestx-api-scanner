"""Ratenbegrenzung im Speicher — IPs nur als Hash mit täglich rotierendem Salz."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import deque


class RateLimiter:
    def __init__(self, *, secret: str, per_hour: int, per_day: int, global_per_day: int) -> None:
        self._secret = secret.encode("utf-8")
        self.per_hour = per_hour
        self.per_day = per_day
        self.global_per_day = global_per_day
        self._lock = threading.Lock()
        self._je_client: dict[str, deque[float]] = {}
        self._global: deque[float] = deque()

    def key(self, ip: str, now: float | None = None) -> str:
        """HMAC(IP, Tagessalz): nicht rückrechenbar, morgen ein anderer Wert."""
        tag = time.strftime("%Y-%m-%d", time.gmtime(now or time.time()))
        return hmac.new(self._secret, f"{tag}|{ip}".encode(), hashlib.sha256).hexdigest()[:24]

    def check(self, ip: str, now: float | None = None) -> tuple[bool, str, int]:
        """(erlaubt, Grund, Sekunden bis zum nächsten Versuch)."""
        now = now or time.time()
        k = self.key(ip, now)
        with self._lock:
            self._aufraeumen(now)
            q = self._je_client.setdefault(k, deque())
            if len(self._global) >= self.global_per_day:
                return False, "Tageskontingent des Dienstes erschöpft.", int(86400 - (now - self._global[0]))
            stunde = sum(1 for t in q if now - t < 3600)
            if stunde >= self.per_hour:
                aeltester = next(t for t in q if now - t < 3600)
                return False, "Zu viele Analysen in dieser Stunde.", int(3600 - (now - aeltester)) + 1
            if len(q) >= self.per_day:
                return False, "Tageskontingent für diese Adresse erschöpft.", int(86400 - (now - q[0])) + 1
            q.append(now)
            self._global.append(now)
            return True, "", 0

    def _aufraeumen(self, now: float) -> None:
        for k in list(self._je_client):
            q = self._je_client[k]
            while q and now - q[0] >= 86400:
                q.popleft()
            if not q:
                del self._je_client[k]
        while self._global and now - self._global[0] >= 86400:
            self._global.popleft()
