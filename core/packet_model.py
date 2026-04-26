from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
from datetime import datetime


class Protocol(Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    ANY = "any"


class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(Enum):
    ALLOW = "allow"
    DENY = "deny"
    ALERT = "alert"
    LOG = "log"
    PASS = "pass"


@dataclass
class PacketInfo:
    timestamp: datetime
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    payload: bytes = b""
    size: int = 0

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "size": self.size,
        }


@dataclass
class FirewallRule:
    id: str
    action: Action
    protocol: Protocol
    source_ip: str
    source_port: str
    destination_ip: str
    destination_port: str
    description: str
    enabled: bool = True

    def matches(self, packet: PacketInfo) -> bool:
        if not self.enabled:
            return False

        if self.protocol != Protocol.ANY and self.protocol.value != packet.protocol.lower():
            return False

        if self.source_ip != "any" and self.source_ip != packet.source_ip:
            return False

        if self.destination_ip != "any" and self.destination_ip != packet.destination_ip:
            return False

        if self.source_port != "any":
            try:
                if int(self.source_port) != packet.source_port:
                    return False
            except ValueError:
                return False

        if self.destination_port != "any":
            try:
                if int(self.destination_port) != packet.destination_port:
                    return False
            except ValueError:
                return False

        return True


@dataclass
class IDSRule:
    action: Action
    protocol: Protocol
    source_ip: str
    source_port: str
    direction: str
    destination_ip: str
    destination_port: str
    msg: str = ""
    content: str = ""
    nocase: bool = False
    sid: int = 0
    rev: int = 1
    classtype: str = "attempted-admin"
    severity: Severity = Severity.MEDIUM

    def matches(self, packet: PacketInfo) -> bool:
        if self.protocol != Protocol.ANY and self.protocol.value != packet.protocol.lower():
            return False

        direct_match = self._matches_endpoints(
            packet.source_ip,
            packet.source_port,
            packet.destination_ip,
            packet.destination_port,
        )

        reverse_match = False
        if self.direction == "<>":
            reverse_match = self._matches_endpoints(
                packet.destination_ip,
                packet.destination_port,
                packet.source_ip,
                packet.source_port,
            )

        if not (direct_match or reverse_match):
            return False

        if self.content:
            payload_str = packet.payload.decode("utf-8", errors="ignore") if packet.payload else ""
            if self.nocase:
                if self.content.lower() not in payload_str.lower():
                    return False
            else:
                if self.content not in payload_str:
                    return False

        return True

    def _matches_endpoints(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
    ) -> bool:
        if self.source_ip != "any" and self.source_ip != src_ip:
            return False
        if self.destination_ip != "any" and self.destination_ip != dst_ip:
            return False
        if not self._matches_port(self.source_port, src_port):
            return False
        if not self._matches_port(self.destination_port, dst_port):
            return False
        return True

    @staticmethod
    def _matches_port(rule_port: Any, packet_port: int) -> bool:
        if str(rule_port).lower() == "any":
            return True
        try:
            return int(rule_port) == packet_port
        except (TypeError, ValueError):
            return False


@dataclass
class Alert:
    timestamp: datetime
    severity: Severity
    source_ip: str
    source_port: int
    destination_ip: str
    destination_port: int
    protocol: str
    message: str
    rule_sid: int = 0
    rule_msg: str = ""

    def to_dict(self) -> dict:
        return {
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity.value,
            "source_ip": self.source_ip,
            "source_port": self.source_port,
            "destination_ip": self.destination_ip,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "message": self.message,
            "rule_sid": self.rule_sid,
            "rule_msg": self.rule_msg,
        }
