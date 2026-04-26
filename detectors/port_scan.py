from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from core.packet_model import PacketInfo, Alert, Severity


class PortScanDetector:
    def __init__(
        self,
        time_window_seconds: int = 10,
        unique_ports_threshold: int = 20,
    ):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.threshold = unique_ports_threshold
        self.connection_tracker: Dict[str, Dict[int, datetime]] = defaultdict(dict)
        self.alerts: List[Alert] = []

    def check_packet(self, packet: PacketInfo) -> Optional[Alert]:
        source_ip = packet.source_ip
        dest_port = packet.destination_port
        now = datetime.now()

        self._cleanup_old_connections(source_ip, now)

        if dest_port > 0:
            self.connection_tracker[source_ip][dest_port] = now

            unique_ports = len(self.connection_tracker[source_ip])
            if unique_ports >= self.threshold:
                for port in list(self.connection_tracker[source_ip].keys())[: self.threshold]:
                    self.connection_tracker[source_ip].pop(port, None)

                alert = Alert(
                    timestamp=now,
                    severity=Severity.HIGH,
                    source_ip=source_ip,
                    source_port=packet.source_port,
                    destination_ip=packet.destination_ip,
                    destination_port=dest_port,
                    protocol=packet.protocol,
                    message=f"Possible port scan detected: {unique_ports} unique ports accessed in {self.time_window.total_seconds()}s",
                    rule_sid=9000001,
                    rule_msg="Port Scan",
                )
                self.alerts.append(alert)
                return alert

        return None

    def _cleanup_old_connections(self, source_ip: str, now: datetime) -> None:
        if source_ip not in self.connection_tracker:
            return

        cutoff = now - self.time_window
        ports_to_remove = []

        for port, timestamp in self.connection_tracker[source_ip].items():
            if timestamp < cutoff:
                ports_to_remove.append(port)

        for port in ports_to_remove:
            self.connection_tracker[source_ip].pop(port, None)

        if not self.connection_tracker[source_ip]:
            self.connection_tracker.pop(source_ip, None)

    def get_alerts(self) -> List[Alert]:
        return self.alerts.copy()

    def reset(self) -> None:
        self.connection_tracker.clear()
        self.alerts.clear()