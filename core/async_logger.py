import queue
import threading
from typing import Callable, Optional

from core.logger import SentinelLogger
from core.packet_model import Alert, PacketInfo, Severity
from core.state_store import SQLiteMonitoringStore


class AsyncSentinelLogger:
    def __init__(
        self,
        base_logger: Optional[SentinelLogger] = None,
        state_store: Optional[SQLiteMonitoringStore] = None,
        queue_size: int = 10000,
    ):
        self._base_logger = base_logger or SentinelLogger()
        self._state_store = state_store
        self._queue: queue.Queue[Callable[[], None]] = queue.Queue(maxsize=queue_size)
        self._running = True
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    @property
    def logger(self):
        return self._base_logger.logger

    def _run(self) -> None:
        while self._running or not self._queue.empty():
            try:
                task = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue

            try:
                task()
            except Exception as exc:
                self._base_logger.logger.error(f"Async logger task failed: {exc}")
            finally:
                self._queue.task_done()

    def _submit(self, task: Callable[[], None]) -> None:
        try:
            self._queue.put_nowait(task)
        except queue.Full:
            # Fallback synchronous path to avoid data loss under burst traffic.
            task()

    def log_packet(self, packet: PacketInfo, action: str, rule_sid: int = 0, message: str = "") -> None:
        def task() -> None:
            self._base_logger.log_packet(packet, action, rule_sid, message)
            if self._state_store:
                self._state_store.record_packet(packet, action)

        self._submit(task)

    def log_alert(self, alert: Alert) -> None:
        def task() -> None:
            self._base_logger.log_alert(alert)
            if self._state_store:
                self._state_store.record_alert(alert)

        self._submit(task)

    def log_firewall_decision(
        self, packet: PacketInfo, action: str, rule_id: str, description: str
    ) -> None:
        def task() -> None:
            self._base_logger.log_firewall_decision(packet, action, rule_id, description)
            if self._state_store:
                self._state_store.record_firewall_event(packet, action, rule_id, description)

        self._submit(task)

    def log_detector_alert(
        self,
        detector: str,
        source_ip: str,
        message: str,
        severity: Severity,
    ) -> None:
        def task() -> None:
            self._base_logger.log_detector_alert(detector, source_ip, message, severity)
            if self._state_store:
                self._state_store.record_detector_alert(detector, source_ip, message, severity)

        self._submit(task)

    def get_recent_logs(self, count: int = 100):
        return self._base_logger.get_recent_logs(count=count)

    def shutdown(self) -> None:
        if not self._running and not self._worker.is_alive():
            return
        self._running = False
        self._queue.join()
        self._worker.join(timeout=2.0)
