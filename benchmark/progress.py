from __future__ import annotations

import sys
import threading
import time


class Progress:
    """Tiny stderr progress bar for interactive benchmark commands."""

    def __init__(self, label: str, total: int | None = None, enabled: bool | None = None):
        self.label = label
        self.total = total if total and total > 0 else None
        self.enabled = sys.stderr.isatty() if enabled is None else enabled
        self.current = 0
        self._last_render = 0.0
        self._closed = False

    def update(self, current: int, *, total: int | None = None, extra: str = "", force: bool = False) -> None:
        if total and total > 0:
            self.total = total
        self.current = max(0, current)
        if not self.enabled:
            return
        now = time.monotonic()
        if not force and now - self._last_render < 0.1:
            return
        self._last_render = now
        sys.stderr.write("\r" + self._line(extra))
        sys.stderr.flush()

    def advance(self, step: int = 1, *, extra: str = "") -> None:
        self.update(self.current + step, extra=extra)

    def close(self, *, extra: str = "") -> None:
        if self._closed:
            return
        self._closed = True
        if self.enabled:
            self.update(self.current, extra=extra, force=True)
            sys.stderr.write("\n")
            sys.stderr.flush()

    def _line(self, extra: str) -> str:
        width = 28
        if self.total:
            done = min(self.current, self.total)
            frac = done / self.total
            filled = int(width * frac)
            bar = "#" * filled + "-" * (width - filled)
            text = f"{self.label}: [{bar}] {done}/{self.total}"
        else:
            text = f"{self.label}: {self.current}"
        if extra:
            text += f" {extra}"
        return text.ljust(100)


class Spinner:
    """Background heartbeat for progress phases blocked on one network request."""

    def __init__(self, progress: Progress, extra: str, interval: float = 0.2):
        self.progress = progress
        self.extra = extra
        self.interval = interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        if self.progress.enabled:
            self._thread.start()
        return self

    def __exit__(self, *_exc):
        self.stop()
        return False

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=self.interval * 2)

    def _run(self) -> None:
        frames = "|/-\\"
        i = 0
        while not self._stop.wait(self.interval):
            self.progress.update(
                self.progress.current,
                extra=f"{self.extra} {frames[i % len(frames)]}",
                force=True,
            )
            i += 1
