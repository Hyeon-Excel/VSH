from __future__ import annotations

import time
from pathlib import Path

from vsh_runtime.engine import VshRuntimeEngine


class ProjectWatcher:
    def __init__(self, target_path: str, debounce_sec: float = 1.0, interval: float = 0.5):
        self.target = Path(target_path)
        self.debounce = debounce_sec
        self.interval = interval
        self.engine = VshRuntimeEngine()
        self._mtimes: dict[str, float] = {}
        self._last_scan: dict[str, float] = {}

    def _iter_files(self):
        if self.target.is_file():
            yield self.target
            return
        for f in self.target.rglob("*"):
            if f.is_file() and f.suffix.lower() in {".py", ".js", ".ts", ".jsx", ".tsx"}:
                yield f

    def poll_once(self) -> list[dict]:
        events = []
        now = time.time()
        for f in self._iter_files():
            mtime = f.stat().st_mtime
            key = str(f)
            prev = self._mtimes.get(key)
            self._mtimes[key] = mtime
            if prev is None or mtime <= prev:
                continue
            if now - self._last_scan.get(key, 0) < self.debounce:
                continue
            self._last_scan[key] = now
            events.append(self.engine.analyze_file(key))
        return events

    def watch_forever(self):
        while True:
            results = self.poll_once()
            for res in results:
                print(res["previews"]["inline"])
            time.sleep(self.interval)
