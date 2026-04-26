import tempfile
from datetime import datetime
from pathlib import Path

from scapy.all import IP, TCP, Raw

from core.reporter import Reporter
from core.rule_watcher import RuleFileHandler
from core.sniffer import PacketSniffer


def test_reporter_generate_report_from_logs_uses_real_events():
    reporter = Reporter(output_dir=tempfile.gettempdir())
    logs = [
        {
            "timestamp": datetime.now().isoformat(),
            "event_type": "packet",
            "source_ip": "10.0.0.10",
            "destination_port": 443,
            "protocol": "tcp",
            "severity": "info",
            "message": "Packet allowed",
            "rule_sid": 0,
        },
        {
            "timestamp": datetime.now().isoformat(),
            "event_type": "firewall",
            "source_ip": "10.0.0.10",
            "destination_port": 443,
            "protocol": "tcp",
            "action": "allow",
            "severity": "info",
            "message": "Firewall ALLOW",
            "rule_sid": 0,
        },
        {
            "timestamp": datetime.now().isoformat(),
            "event_type": "firewall",
            "source_ip": "10.0.0.11",
            "destination_port": 23,
            "protocol": "tcp",
            "action": "denied",
            "severity": "warning",
            "message": "Firewall DENY",
            "rule_sid": 0,
        },
        {
            "timestamp": datetime.now().isoformat(),
            "event_type": "alert",
            "source_ip": "10.0.0.11",
            "severity": "high",
            "message": "IDS match",
            "rule_sid": 1001,
        },
        {
            "timestamp": datetime.now().isoformat(),
            "event_type": "detector_port_scan",
            "source_ip": "10.0.0.11",
            "severity": "critical",
            "message": "Port scan",
            "rule_sid": 9000001,
        },
    ]

    report = reporter.generate_report_from_logs(logs)

    assert report["total_packets"] == 3
    assert report["total_alerts"] == 2
    assert report["firewall"]["allowed"] == 1
    assert report["firewall"]["denied"] == 1
    assert report["matched_rules"][1001] == 1
    assert report["alerts_by_severity"]["high"] == 1
    assert report["alerts_by_severity"]["critical"] == 1


def test_rule_file_handler_respects_watch_directory_pattern():
    handler = RuleFileHandler(lambda _: None)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        handler.add_directory_watch(str(temp_path), "*.rules")

        assert handler._should_watch(str(temp_path / "ids.rules")) is True
        assert handler._should_watch(str(temp_path / "firewall.yaml")) is False


def test_sniffer_parse_packet_extracts_only_raw_payload():
    sniffer = PacketSniffer(interface="lo", packet_limit=1, firewall=None, ids_engine=None)

    pkt = IP(src="192.168.1.10", dst="10.0.0.1") / TCP(sport=12345, dport=80) / Raw(load=b"GET / HTTP/1.1")
    parsed = sniffer._parse_packet(pkt)

    assert parsed.protocol == "tcp"
    assert parsed.payload == b"GET / HTTP/1.1"
