from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Optional

from vsh_runtime.engine import VshRuntimeEngine


class ProjectWatcher:
    """Thread-safe file system watcher with debouncing and auto-analysis."""
    
    def __init__(self, target_path: str, debounce_sec: float = 1.0, interval: float = 0.5):
        self.target = Path(target_path)
        self.debounce = debounce_sec
        self.interval = interval
        self.engine = VshRuntimeEngine()
        self._mtimes: dict[str, float] = {}
        self._last_scan: dict[str, float] = {}
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()
        self._last_results: list[dict] = []

    def _iter_files(self):
        """Iterate over tracked source files."""
        if self.target.is_file():
            yield self.target
            return
        for f in self.target.rglob("*"):
            if f.is_file() and f.suffix.lower() in {".py", ".js", ".ts", ".jsx", ".tsx"}:
                yield f

    def poll_once(self) -> list[dict]:
        """Poll for changed files and return analysis results."""
        results = []
        now = time.time()
        try:
            for f in self._iter_files():
                try:
                    mtime = f.stat().st_mtime
                except (OSError, FileNotFoundError):
                    continue
                    
                key = str(f)
                prev = self._mtimes.get(key)
                self._mtimes[key] = mtime
                
                # Skip if file hasn't changed or is new (prev is None)
                if prev is None:
                    continue
                if mtime <= prev:
                    continue
                    
                # Check debounce
                last_scan_time = self._last_scan.get(key, 0)
                if now - last_scan_time < self.debounce:
                    continue
                    
                self._last_scan[key] = now
                try:
                    result = self.engine.analyze_file(key)
                    results.append({
                        "path": key,
                        "type": "modified",
                        "analysis": result
                    })
                except Exception as e:
                    print(f"Error analyzing {key}: {e}")
                    results.append({
                        "path": key,
                        "type": "error",
                        "error": str(e)
                    })
        except Exception as e:
            print(f"Error polling files: {e}")
        
        return results

    def _watch_thread_loop(self):
        """Main watch loop running in background thread."""
        while not self._stop_event.is_set():
            try:
                results = self.poll_once()
                if results:
                    with self._lock:
                        self._last_results = results
                    # Optional: log activity
                    print(f"[WATCH] Detected {len(results)} changes")
            except Exception as e:
                print(f"[WATCH ERROR] {e}")
            
            # Sleep in small increments to allow stop event detection
            for _ in range(int(self.interval * 100)):
                if self._stop_event.is_set():
                    break
                time.sleep(0.01)
    
    def start(self) -> bool:
        """Start watching in a background thread. Returns False if already running."""
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return False
            
            self._stop_event.clear()
            self._thread = threading.Thread(target=self._watch_thread_loop, daemon=False)
            self._thread.start()
            return True
    
    def stop(self) -> bool:
        """Stop the watching thread. Returns False if not running."""
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                return False
            self._stop_event.set()
        
        # Wait for thread to finish (with timeout)
        if self._thread:
            self._thread.join(timeout=2.0)
            return not self._thread.is_alive()
        return True
    
    def is_running(self) -> bool:
        """Check if watcher is currently running."""
        with self._lock:
            return self._thread is not None and self._thread.is_alive()
    
    def get_last_results(self) -> list[dict]:
        """Get the last analysis results from file changes."""
        with self._lock:
            return self._last_results.copy()
    
    def watch_forever(self):
        """Blocking watch loop for CLI use. Use start() for background watching."""
        self.start()
        try:
            while self.is_running():
                time.sleep(0.5)
        except KeyboardInterrupt:
            print("\n[WATCH] Stopping...")
        finally:
            self.stop()
