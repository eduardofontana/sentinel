import json
import queue
import threading
from typing import Any, Dict, Optional
from urllib import request, error


class DashboardClient:
    def __init__(
        self,
        base_url: str = "http://127.0.0.1:8000",
        enabled: bool = True,
        queue_size: int = 2000,
        timeout_seconds: float = 1.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.enabled = enabled
        self.timeout_seconds = timeout_seconds
        self._queue: queue.Queue[tuple[str, Dict[str, Any]]] = queue.Queue(maxsize=queue_size)
        self._running = enabled
        self._worker: Optional[threading.Thread] = None
        if enabled:
            self._worker = threading.Thread(target=self._run, daemon=True)
            self._worker.start()

    def _run(self) -> None:
        while self._running or not self._queue.empty():
            try:
                endpoint, payload = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                self._post_json(endpoint, payload)
            finally:
                self._queue.task_done()

    def _post_json(self, endpoint: str, payload: Dict[str, Any]) -> None:
        data = json.dumps(payload).encode("utf-8")
        req = request.Request(
            f"{self.base_url}{endpoint}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(req, timeout=self.timeout_seconds):
                return
        except (error.URLError, TimeoutError, OSError):
            return

    def _enqueue(self, endpoint: str, payload: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        try:
            self._queue.put_nowait((endpoint, payload))
        except queue.Full:
            return

    def send_alert(self, alert_payload: Dict[str, Any]) -> None:
        self._enqueue("/api/alert", alert_payload)

    def send_stats(self, stats_payload: Dict[str, Any]) -> None:
        self._enqueue("/api/stats/update", stats_payload)

    def shutdown(self) -> None:
        if not self.enabled:
            return
        self._running = False
        self._queue.join()
        if self._worker:
            self._worker.join(timeout=2.0)
