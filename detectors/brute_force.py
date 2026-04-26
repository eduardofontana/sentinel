from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set
from collections import defaultdict
from core.packet_model import PacketInfo, Alert, Severity


class BruteForceDetector:
    SENSITIVE_PORTS = {22, 21, 23, 3389, 3306, 5432, 1433, 8080, 8443}

    def __init__(
        self,
        time_window_seconds: int = 60,
        attempts_threshold: int = 10,
    ):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.threshold = attempts_threshold
        self.attempts_tracker: Dict[str, Dict[int, List[datetime]]] = defaultdict(lambda: defaultdict(list))
        self.alerts: List[Alert] = []

    def check_packet(self, packet: PacketInfo) -> Optional[Alert]:
        source_ip = packet.source_ip
        dest_port = packet.destination_port
        now = datetime.now()

        if dest_port not in self.SENSITIVE_PORTS:
            return None

        self._cleanup_old_attempts(source_ip, dest_port, now)

        self.attempts_tracker[source_ip][dest_port].append(now)

        attempt_count = len(self.attempts_tracker[source_ip][dest_port])

        if attempt_count >= self.threshold:
            alert = Alert(
                timestamp=now,
                severity=Severity.CRITICAL,
                source_ip=source_ip,
                source_port=packet.source_port,
                destination_ip=packet.destination_ip,
                destination_port=dest_port,
                protocol=packet.protocol,
                message=f"Possible brute force attempt: {attempt_count} attempts to port {dest_port} in {self.time_window.total_seconds()}s",
                rule_sid=9000002,
                rule_msg="Brute Force Attempt",
            )
            self.alerts.append(alert)

            self.attempts_tracker[source_ip][dest_port].clear()

            return alert

        return None

    def _cleanup_old_attempts(
        self, source_ip: str, dest_port: int, now: datetime
    ) -> None:
        cutoff = now - self.time_window

        if source_ip in self.attempts_tracker and dest_port in self.attempts_tracker[source_ip]:
            self.attempts_tracker[source_ip][dest_port] = [
                ts for ts in self.attempts_tracker[source_ip][dest_port] if ts >= cutoff
            ]

            if not self.attempts_tracker[source_ip][dest_port]:
                self.attempts_tracker[source_ip][dest_port].pop(dest_port, None)

        if not self.attempts_tracker[source_ip]:
            self.attempts_tracker.pop(source_ip, None)

    def get_alerts(self) -> List[Alert]:
        return self.alerts.copy()

    def reset(self) -> None:
        self.attempts_tracker.clear()
        self.alerts.clear()

    @staticmethod
    def get_sensitive_ports() -> Set[int]:
        return BruteForceDetector.SENSITIVE_PORTS.copy()