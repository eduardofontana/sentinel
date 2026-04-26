import pytest
from datetime import datetime
from core.packet_model import PacketInfo, Action, Protocol, FirewallRule, IDSRule, Severity
from core.firewall import FirewallEngine
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
        payload=b"GET / HTTP/1.1",
        size=100,
    )


@pytest.fixture
def firewall_engine():
    rules = [
        FirewallRule(
            id="test_1",
            action=Action.DENY,
            protocol=Protocol.TCP,
            source_ip="any",
            source_port="any",
            destination_ip="any",
            destination_port="80",
            description="Block HTTP",
            enabled=True,
        ),
    ]
    return FirewallEngine(rules, "allow")


class TestFirewallEngine:
    def test_default_allow(self, sample_packet, firewall_engine):
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="tcp",
            payload=b"GET / HTTPS",
            size=100,
        )
        action = firewall_engine.check_packet(packet)
        assert action == Action.ALLOW
        stats = firewall_engine.get_stats()
        assert stats["allowed"] == 1

    def test_block_by_port(self, sample_packet, firewall_engine):
        action = firewall_engine.check_packet(sample_packet)
        assert action == Action.DENY
        stats = firewall_engine.get_stats()
        assert stats["denied"] == 1

    def test_stats_tracking(self, firewall_engine):
        packet1 = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            size=100,
        )
        packet2 = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.101",
            source_port=54322,
            destination_ip="10.0.0.1",
            destination_port=443,
            protocol="tcp",
            size=100,
        )
        firewall_engine.check_packet(packet1)
        firewall_engine.check_packet(packet2)
        stats = firewall_engine.get_stats()
        assert stats["total"] == 2
        assert stats["denied"] == 1
        assert stats["allowed"] == 1

    def test_disabled_rule(self):
        rules = [
            FirewallRule(
                id="test_disabled",
                action=Action.DENY,
                protocol=Protocol.TCP,
                source_ip="any",
                source_port="any",
                destination_ip="any",
                destination_port="80",
                description="Disabled rule",
                enabled=False,
            ),
        ]
        engine = FirewallEngine(rules, "allow")
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            size=100,
        )
        action = engine.check_packet(packet)
        assert action == Action.ALLOW

    def test_add_rule(self, firewall_engine):
        new_rule = FirewallRule(
            id="test_new",
            action=Action.DENY,
            protocol=Protocol.UDP,
            source_ip="any",
            source_port="any",
            destination_ip="any",
            destination_port="53",
            description="Block DNS",
            enabled=True,
        )
        firewall_engine.add_rule(new_rule)
        rules = firewall_engine.get_rules()
        assert len(rules) == 2

    def test_remove_rule(self, firewall_engine):
        result = firewall_engine.remove_rule("test_1")
        assert result is True
        assert len(firewall_engine.get_rules()) == 0

    def test_default_policy_deny(self):
        engine = FirewallEngine([], "deny")
        packet = PacketInfo(
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            source_port=54321,
            destination_ip="10.0.0.1",
            destination_port=80,
            protocol="tcp",
            size=100,
        )
        action = engine.check_packet(packet)
        assert action == Action.DENY