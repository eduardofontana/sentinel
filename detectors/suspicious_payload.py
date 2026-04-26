from typing import List, Optional
from datetime import datetime
from core.packet_model import PacketInfo, Alert, Severity


class SuspiciousPayloadDetector:
    SUSPICIOUS_PATTERNS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "<script>",
        "<iframe>",
        "../../../",
        "cmd.exe",
        "/bin/sh",
        "/bin/bash",
        "union select",
        "union all select",
        "drop table",
        "drop database",
        "insert into",
        "update set",
        "delete from",
        "exec(",
        "execute(",
        "eval(",
        "passthru(",
        "system(",
        "shell_exec(",
        "<?php",
        "<?=",
        "<%",
        "jndi:",
        "ldap://",
        "${jndi",
        "${env",
    ]

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self.alerts: List[Alert] = []

    def check_packet(self, packet: PacketInfo) -> Optional[Alert]:
        if not self.enabled:
            return None

        if not packet.payload:
            return None

        try:
            payload_str = packet.payload.decode("utf-8", errors="ignore").lower()
        except Exception:
            return None

        for pattern in self.SUSPICIOUS_PATTERNS:
            if pattern.lower() in payload_str:
                alert = Alert(
                    timestamp=datetime.now(),
                    severity=Severity.HIGH,
                    source_ip=packet.source_ip,
                    source_port=packet.source_port,
                    destination_ip=packet.destination_ip,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    message=f"Suspicious payload detected: pattern '{pattern}' found in packet",
                    rule_sid=9000004,
                    rule_msg="Suspicious Payload",
                )
                self.alerts.append(alert)
                return alert

        return None

    def get_alerts(self) -> List[Alert]:
        return self.alerts.copy()

    def reset(self) -> None:
        self.alerts.clear()

    def enable(self) -> None:
        self.enabled = True

    def disable(self) -> None:
        self.enabled = False

    @staticmethod
    def get_patterns() -> List[str]:
        return SuspiciousPayloadDetector.SUSPICIOUS_PATTERNS.copy()