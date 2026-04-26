from typing import List, Optional
from datetime import datetime
from core.packet_model import PacketInfo, Alert, Severity


class SuspiciousPayloadDetector:
    WEB_PATTERNS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "<script>",
        "<iframe>",
        "../../../",
        "union select",
        "union all select",
        "drop table",
        "drop database",
        "insert into",
        "update set",
        "delete from",
        "<?php",
        "<?=",
        "<%",
        "jndi:",
        "ldap://",
        "${jndi",
        "${env",
    ]

    HOST_PATTERNS = [
        "cmd.exe",
        "cmd /c",
        "powershell -enc",
        "powershell.exe -enc",
        "invoke-expression",
        "downloadstring(",
        "mshta http",
        "rundll32 javascript:",
        "regsvr32 /s /u /i:http",
        "certutil -urlcache -f",
        "wmic process call create",
        "mimikatz",
        "net user /add",
        "vssadmin delete shadows",
        "bcdedit /set",
        "/bin/sh",
        "/bin/bash",
        "exec(",
        "execute(",
        "eval(",
        "passthru(",
        "system(",
        "shell_exec(",
    ]

    def __init__(self, enabled: bool = True, profile: str = "home"):
        self.enabled = enabled
        self.profile = profile
        self.alerts: List[Alert] = []

    def _active_patterns(self) -> List[str]:
        normalized = self.profile.lower()
        if normalized == "web":
            return self.WEB_PATTERNS
        if normalized == "mixed":
            return self.HOST_PATTERNS + self.WEB_PATTERNS
        return self.HOST_PATTERNS

    def check_packet(self, packet: PacketInfo) -> Optional[Alert]:
        if not self.enabled:
            return None

        if not packet.payload:
            return None

        try:
            payload_str = packet.payload.decode("utf-8", errors="ignore").lower()
        except Exception:
            return None

        for pattern in self._active_patterns():
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

    def set_profile(self, profile: str) -> None:
        self.profile = profile

    @staticmethod
    def get_patterns(profile: str = "mixed") -> List[str]:
        normalized = profile.lower()
        if normalized == "web":
            return SuspiciousPayloadDetector.WEB_PATTERNS.copy()
        if normalized == "home":
            return SuspiciousPayloadDetector.HOST_PATTERNS.copy()
        return (SuspiciousPayloadDetector.HOST_PATTERNS + SuspiciousPayloadDetector.WEB_PATTERNS).copy()
