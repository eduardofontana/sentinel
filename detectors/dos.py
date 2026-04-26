from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from core.packet_model import PacketInfo, Alert, Severity


class DoSDetector:
    def __init__(
        self,
        time_window_seconds: int = 5,
        packet_threshold: int = 200,
    ):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.threshold = packet_threshold
        self.packet_tracker: Dict[str, List[datetime]] = defaultdict(list)
        self.alerts: List[Alert] = []

    def check_packet(self, packet: PacketInfo) -> Optional[Alert]:
        source_ip = packet.source_ip
        now = datetime.now()

        self._cleanup_old_packets(source_ip, now)

        self.packet_tracker[source_ip].append(now)

        packet_count = len(self.packet_tracker[source_ip])

        if packet_count >= self.threshold:
            alert = Alert(
                timestamp=now,
                severity=Severity.CRITICAL,
                source_ip=source_ip,
                source_port=packet.source_port,
                destination_ip=packet.destination_ip,
                destination_port=packet.destination_port,
                protocol=packet.protocol,
                message=f"Possible DoS attack: {packet_count} packets in {self.time_window.total_seconds()}s from {source_ip}",
                rule_sid=9000003,
                rule_msg="DoS Attack",
            )
            self.alerts.append(alert)

            self.packet_tracker[source_ip].clear()

            return alert

        return None

    def _cleanup_old_packets(self, source_ip: str, now: datetime) -> None:
        cutoff = now - self.time_window

        if source_ip in self.packet_tracker:
            self.packet_tracker[source_ip] = [
                ts for ts in self.packet_tracker[source_ip] if ts >= cutoff
            ]

            if not self.packet_tracker[source_ip]:
                self.packet_tracker.pop(source_ip, None)

    def get_alerts(self) -> List[Alert]:
        return self.alerts.copy()

    def reset(self) -> None:
        self.packet_tracker.clear()
        self.alerts.clear()