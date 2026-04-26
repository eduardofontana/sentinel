import logging
import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
from core.packet_model import PacketInfo, Alert, Severity


class SentinelLogger:
    def __init__(self, log_file: str = "logs/sentinelfw.log", level: str = "INFO"):
        self.log_file = Path(log_file)
        self.log_file.parent.mkdir(parents=True, exist_ok=True)

        self.logger = logging.getLogger("SentinelFW")
        self.logger.setLevel(getattr(logging, level.upper()))

        if not self.logger.handlers:
            file_handler = logging.FileHandler(self.log_file)
            file_handler.setLevel(getattr(logging, level.upper()))

            formatter = logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            )
            file_handler.setFormatter(formatter)
            self.logger.addHandler(file_handler)

            console_handler = logging.StreamHandler()
            console_handler.setLevel(getattr(logging, level.upper()))
            console_handler.setFormatter(formatter)
            self.logger.addHandler(console_handler)

    def log_event(
        self,
        event_type: str,
        source_ip: str,
        source_port: int,
        destination_ip: str,
        destination_port: int,
        protocol: str,
        action: str,
        severity: str,
        message: str,
        rule_sid: int = 0,
    ) -> None:
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "source_ip": source_ip,
            "source_port": source_port,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "protocol": protocol,
            "action": action,
            "severity": severity,
            "message": message,
            "rule_sid": rule_sid,
        }

        log_level = {
            "low": logging.INFO,
            "medium": logging.WARNING,
            "high": logging.ERROR,
            "critical": logging.CRITICAL,
            "warning": logging.WARNING,
            "info": logging.INFO,
        }.get(severity.lower(), logging.INFO)

        self.logger.log(log_level, json.dumps(log_entry))

    def log_packet(self, packet: PacketInfo, action: str, rule_sid: int = 0, message: str = "") -> None:
        self.log_event(
            event_type="packet",
            source_ip=packet.source_ip,
            source_port=packet.source_port,
            destination_ip=packet.destination_ip,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
            action=action,
            severity="info",
            message=message or f"Packet {action}: {packet.protocol} from {packet.source_ip}:{packet.source_port} -> {packet.destination_ip}:{packet.destination_port}",
            rule_sid=rule_sid,
        )

    def log_alert(self, alert: Alert) -> None:
        self.log_event(
            event_type="alert",
            source_ip=alert.source_ip,
            source_port=alert.source_port,
            destination_ip=alert.destination_ip,
            destination_port=alert.destination_port,
            protocol=alert.protocol,
            action="alert",
            severity=alert.severity.value,
            message=alert.message,
            rule_sid=alert.rule_sid,
        )

    def log_firewall_decision(
        self, packet: PacketInfo, action: str, rule_id: str, description: str
    ) -> None:
        self.log_event(
            event_type="firewall",
            source_ip=packet.source_ip,
            source_port=packet.source_port,
            destination_ip=packet.destination_ip,
            destination_port=packet.destination_port,
            protocol=packet.protocol,
            action=action,
            severity="info" if action == "allow" else "warning",
            message=f"Firewall {action.upper()}: {description} (rule: {rule_id})",
            rule_sid=0,
        )

    def log_detector_alert(
        self,
        detector: str,
        source_ip: str,
        message: str,
        severity: Severity,
    ) -> None:
        self.log_event(
            event_type=f"detector_{detector}",
            source_ip=source_ip,
            source_port=0,
            destination_ip="",
            destination_port=0,
            protocol="",
            action="alert",
            severity=severity.value,
            message=message,
            rule_sid=0,
        )

    def get_recent_logs(self, count: int = 100) -> List[Dict[str, Any]]:
        if not self.log_file.exists():
            return []

        logs = []
        try:
            with open(self.log_file, "r") as f:
                lines = f.readlines()
                for line in lines[-count:]:
                    try:
                        logs.append(json.loads(line.split("- ", 1)[1] if "- " in line else line))
                    except (json.JSONDecodeError, IndexError):
                        continue
        except FileNotFoundError:
            pass

        return logs
