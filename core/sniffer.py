from datetime import datetime
import time
from typing import Callable, Optional, List, Any
from scapy.all import AsyncSniffer, Packet as ScapyPacket, IP, TCP, UDP, ICMP, Raw
from core.packet_model import PacketInfo, Action
from core.firewall import FirewallEngine
from core.ids_engine import IDSEngine
from core.logger import SentinelLogger


class PacketSniffer:
    def __init__(
        self,
        interface: str = "eth0",
        packet_limit: int = 0,
        firewall: Optional[FirewallEngine] = None,
        ids_engine: Optional[IDSEngine] = None,
        logger: Optional[SentinelLogger] = None,
        callback: Optional[Callable] = None,
    ):
        self.interface = interface
        self.packet_limit = packet_limit
        self.firewall = firewall
        self.ids_engine = ids_engine
        self.logger = logger or SentinelLogger()
        self.callback = callback

        self.stats = {
            "packets_captured": 0,
            "packets_allowed": 0,
            "packets_dropped": 0,
            "alerts_generated": 0,
        }

        self._running = False
        self._async_sniffer: Optional[AsyncSniffer] = None
        self._on_start_hooks: list[Callable[[], None]] = []
        self._on_stop_hooks: list[Callable[[], None]] = []

    def register_lifecycle_hook(
        self,
        on_start: Optional[Callable[[], None]] = None,
        on_stop: Optional[Callable[[], None]] = None,
    ) -> None:
        if on_start:
            self._on_start_hooks.append(on_start)
        if on_stop:
            self._on_stop_hooks.append(on_stop)

    def start(self, blocking: bool = True) -> None:
        if self._running:
            return

        self._running = True
        self.logger.logger.info(f"Starting sniffer on interface {self.interface}")
        for hook in self._on_start_hooks:
            hook()

        self._async_sniffer = AsyncSniffer(
            iface=self.interface,
            prn=self._process_packet,
            store=False,
            count=self.packet_limit,
        )
        self._async_sniffer.start()

        if blocking:
            try:
                while self._running and self._async_sniffer.running:
                    time.sleep(0.1)
            finally:
                if self._running:
                    self.stop()

    def stop(self) -> None:
        if not self._running:
            return

        self._running = False
        if self._async_sniffer and self._async_sniffer.running:
            self._async_sniffer.stop()

        if hasattr(self.logger, "shutdown"):
            self.logger.shutdown()

        for hook in self._on_stop_hooks:
            hook()

        self.logger.logger.info(f"Stopping sniffer on interface {self.interface}")

    def _process_packet(self, pkt: ScapyPacket) -> None:
        if not pkt.haslayer(IP):
            return

        packet_info = self._parse_packet(pkt)
        self.stats["packets_captured"] += 1

        if self.firewall:
            action = self.firewall.check_packet(packet_info)
            if action == Action.DENY:
                self.stats["packets_dropped"] += 1
                self.logger.log_firewall_decision(
                    packet_info, "denied", "N/A", "Packet blocked by firewall"
                )
                self.logger.log_packet(packet_info, "denied")
                return
            else:
                self.stats["packets_allowed"] += 1

        if self.ids_engine:
            alerts = self.ids_engine.check_packet(packet_info)
            for alert in alerts:
                self.stats["alerts_generated"] += 1
                self.logger.log_alert(alert)

        self.logger.log_packet(packet_info, "allowed")

        if self.callback:
            self.callback(packet_info)

    def _parse_packet(self, pkt: ScapyPacket) -> PacketInfo:
        ip_layer = pkt.getlayer(IP)

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst

        source_port = 0
        destination_port = 0
        protocol = "other"

        if pkt.haslayer(TCP):
            tcp_layer = pkt.getlayer(TCP)
            source_port = tcp_layer.sport
            destination_port = tcp_layer.dport
            protocol = "tcp"
        elif pkt.haslayer(UDP):
            udp_layer = pkt.getlayer(UDP)
            source_port = udp_layer.sport
            destination_port = udp_layer.dport
            protocol = "udp"
        elif pkt.haslayer(ICMP):
            protocol = "icmp"

        payload = b""
        if pkt.haslayer(Raw):
            payload = bytes(pkt.getlayer(Raw).load)

        return PacketInfo(
            timestamp=datetime.now(),
            source_ip=source_ip,
            source_port=source_port,
            destination_ip=destination_ip,
            destination_port=destination_port,
            protocol=protocol,
            payload=payload[:200] if len(payload) > 200 else payload,
            size=len(pkt),
        )

    def get_stats(self) -> dict:
        stats = self.stats.copy()
        if self.firewall:
            stats["firewall"] = self.firewall.get_stats()
        if self.ids_engine:
            stats["ids"] = self.ids_engine.get_stats()
        return stats

    def is_running(self) -> bool:
        return self._running
