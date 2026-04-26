import pytest
from datetime import datetime
from core.packet_model import PacketInfo, Action, Protocol, Severity, IDSRule
from core.ids_engine import IDSEngine


@pytest.fixture
def sample_packet():
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.100",
        source_port=54321,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="tcp",
        payload=b"GET /test.php?id=1' OR '1'='1 HTTP/1.1",
        size=100,
    )


@pytest.fixture
def ids_engine():
    rules = [
        IDSRule(
            action=Action.ALERT,
            protocol=Protocol.TCP,
            source_ip="any",
            source_port="any",
            direction="->",
            destination_ip="any",
            destination_port=80,
            msg="SQL Injection Attempt",
            content="' OR '1'='1",
            nocase=False,
            sid=1000001,
            rev=1,
            classtype="attempted-admin",
            severity=Severity.HIGH,
        ),
    ]
    return IDSEngine(rules)


class TestIDSEngine:
    def test_content_match(self, sample_packet, ids_engine):
        alerts = ids_engine.check_packet(sample_packet)
        assert len(alerts) == 1
        assert alerts[0].rule_sid == 1000001
        assert "SQL Injection" in alerts[0].message

    def test_no_match(self, ids_engine):
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            payload=b"GET /normal/path HTTP/1.1",
            size=100,
        )
        alerts = ids_engine.check_packet(packet)
        assert len(alerts) == 0

    def test_nocase_match(self):
        rules = [
            IDSRule(
                action=Action.ALERT,
                protocol=Protocol.TCP,
                source_ip="any",
                source_port="any",
                direction="->",
                destination_ip="any",
                destination_port=80,
                msg="SQL Injection Detect",
                content="' OR '1'='1",
                nocase=True,
                sid=1000002,
                rev=1,
                severity=Severity.HIGH,
            ),
        ]
        engine = IDSEngine(rules)
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            payload=b"GET /test.php?id=1' OR '1'='1 HTTP/1.1",
            size=100,
        )
        alerts = engine.check_packet(packet)
        assert len(alerts) == 1

    def test_protocol_mismatch(self, ids_engine):
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=53,
            protocol="udp",
            payload=b"GET /test.php?id=1' OR '1'='1",
            size=100,
        )
        alerts = ids_engine.check_packet(packet)
        assert len(alerts) == 0

    def test_stats_tracking(self, ids_engine, sample_packet):
        ids_engine.check_packet(sample_packet)
        ids_engine.check_packet(sample_packet)
        stats = ids_engine.get_stats()
        assert stats["packets_checked"] == 2
        assert stats["alerts_generated"] == 2

    def test_clear_alerts(self, ids_engine, sample_packet):
        ids_engine.check_packet(sample_packet)
        assert len(ids_engine.get_alerts()) == 1
        ids_engine.clear_alerts()
        assert len(ids_engine.get_alerts()) == 0

    def test_source_ip_filter(self):
        rules = [
            IDSRule(
                action=Action.ALERT,
                protocol=Protocol.TCP,
                source_ip="192.168.1.100",
                source_port="any",
                direction="->",
                destination_ip="any",
                destination_port=80,
                msg="Specific Source Alert",
                sid=1000003,
                rev=1,
                severity=Severity.MEDIUM,
            ),
        ]
        engine = IDSEngine(rules)

        matching_packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            payload=b"GET /",
            size=100,
        )
        alerts = engine.check_packet(matching_packet)
        assert len(alerts) == 1

        other_packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.200",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            payload=b"GET /",
            size=100,
        )
        alerts = engine.check_packet(other_packet)
        assert len(alerts) == 0

    def test_destination_port_filter(self):
        rules = [
            IDSRule(
                action=Action.ALERT,
                protocol=Protocol.TCP,
                source_ip="any",
                source_port="any",
                direction="->",
                destination_ip="any",
                destination_port=443,
                msg="HTTPS Alert",
                sid=1000004,
                rev=1,
                severity=Severity.LOW,
            ),
        ]
        engine = IDSEngine(rules)

        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="tcp",
            payload=b"GET /",
            size=100,
        )
        alerts = engine.check_packet(packet)
        assert len(alerts) == 1

    def test_bidirectional_rule_matches_reverse_flow(self):
        rules = [
            IDSRule(
                action=Action.ALERT,
                protocol=Protocol.TCP,
                source_ip="10.0.0.1",
                source_port="80",
                direction="<>",
                destination_ip="192.168.1.100",
                destination_port="12345",
                msg="Bidirectional flow",
                sid=1000005,
                rev=1,
                severity=Severity.MEDIUM,
            ),
        ]
        engine = IDSEngine(rules)

        reverse_packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=12345,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            payload=b"GET /",
            size=100,
        )

        alerts = engine.check_packet(reverse_packet)
        assert len(alerts) == 1
