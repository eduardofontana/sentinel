from dataclasses import dataclass, field
from typing import Optional, Any
from enum import Enum
from datetime import datetime
import ipaddress


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


HOME_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def _matches_ip_rule(rule_ip: str, packet_ip: str) -> bool:
    normalized = str(rule_ip).strip()
    lowered = normalized.lower()
    if lowered == "any":
        return True

    try:
        ip = ipaddress.ip_address(packet_ip)
    except ValueError:
        return False

    if normalized == "$HOME_NET":
        return any(ip in network for network in HOME_NETWORKS)
    if normalized == "$EXTERNAL_NET":
        return not any(ip in network for network in HOME_NETWORKS)

    try:
        if "/" in normalized:
            return ip in ipaddress.ip_network(normalized, strict=False)
        return ip == ipaddress.ip_address(normalized)
    except ValueError:
        return False


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

        if not _matches_ip_rule(self.source_ip, packet.source_ip):
            return False

        if not _matches_ip_rule(self.destination_ip, packet.destination_ip):
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
        if not _matches_ip_rule(self.source_ip, src_ip):
            return False
        if not _matches_ip_rule(self.destination_ip, dst_ip):
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
