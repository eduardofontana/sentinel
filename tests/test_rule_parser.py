import pytest
import tempfile
import os
import gc
from core.rule_parser import RuleParser
from core.packet_model import Action, Protocol, Severity


class TestRuleParser:
    def test_parse_firewall_rules(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            f.write("""
rules:
  - id: test_1
    action: deny
    protocol: tcp
    source_ip: any
    source_port: any
    destination_ip: any
    destination_port: 23
    description: "Block Telnet"
    enabled: true
  - id: test_2
    action: allow
    protocol: any
    source_ip: 192.168.1.0
    source_port: any
    destination_ip: any
    destination_port: 80
    description: "Allow HTTP"
    enabled: true
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_firewall_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 2
            assert rules[0].id == "test_1"
            assert rules[0].action == Action.DENY
            assert rules[0].destination_port == "23"
            assert rules[0].enabled is True
            assert rules[1].action == Action.ALLOW

    def test_parse_firewall_rules_empty(self):
        rules = RuleParser.parse_firewall_rules("nonexistent.yaml")
        assert len(rules) == 0

    def test_parse_ids_rules_basic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("""
alert tcp any any -> any 80 (msg:"Test HTTP"; content:"test"; sid:1000001; rev:1;)
alert udp any any -> any 53 (msg:"DNS Query"; sid:1000002; rev:1;)
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 2
            assert rules[0].sid == 1000001
            assert rules[0].protocol == Protocol.TCP
            assert rules[0].destination_port == 80
            assert rules[0].msg == "Test HTTP"
            assert rules[0].content == "test"
            assert rules[1].protocol == Protocol.UDP

    def test_parse_ids_rules_with_nocase(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("""
alert tcp any any -> any 80 (msg:"SQL Injection"; content:"' OR '1'='1"; nocase; sid:1000003; rev:1;)
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1
            assert rules[0].nocase is True
            assert rules[0].content == "' OR '1'='1"

    def test_parse_ids_rules_with_multiple_options(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("""
alert tcp any any -> any 80 (msg:"Complex Rule"; content:"test"; nocase; classtype:attempted-admin; sid:1000004; rev:2;)
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1
            assert rules[0].sid == 1000004
            assert rules[0].rev == 2
            assert rules[0].classtype == "attempted-admin"
            assert rules[0].severity == Severity.HIGH

    def test_parse_ids_rules_comments(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("""
# This is a comment
alert tcp any any -> any 80 (msg:"Active Rule"; sid:1000005; rev:1;)
# Another comment
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1

    def test_parse_ids_rules_edge_cases(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("""
# Various rule formats
alert tcp $HOME_NET any -> $EXTERNAL_NET 80 (msg:"Outbound"; sid:1000010; rev:1;)
log tcp any any -> any 443 (msg:"HTTPS Log"; sid:1000011; rev:1;)
pass tcp any any -> any any (msg:"Allow"; sid:1000012; rev:1;)
""")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 3
            assert rules[0].action == Action.ALERT
            assert rules[1].action == Action.LOG
            assert rules[2].action == Action.PASS

    def test_dump_firewall_rules(self):
        from core.packet_model import FirewallRule

        rules = [
            FirewallRule(
                id="fw_1",
                action=Action.ALLOW,
                protocol=Protocol.TCP,
                source_ip="any",
                source_port="any",
                destination_ip="any",
                destination_port="80",
                description="Allow HTTP",
                enabled=True,
            ),
        ]

        dumped = RuleParser.dump_firewall_rules(rules)

        assert "rules" in dumped
        assert len(dumped["rules"]) == 1
        assert dumped["rules"][0]["id"] == "fw_1"
        assert dumped["rules"][0]["action"] == "allow"

    def test_parse_ids_rules_direction(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("alert tcp any any -> 10.0.0.1 80 (msg:\"To Specific IP\"; sid:1000020; rev:1;)")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1
            assert rules[0].destination_ip == "10.0.0.1"
            assert rules[0].direction == "->"

    def test_parse_ids_rules_bidirectional_direction(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("alert tcp any any <> 10.0.0.1 80 (msg:\"Bi-directional\"; sid:1000022; rev:1;)")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1
            assert rules[0].direction == "<>"

    def test_parse_ids_rules_with_any_destination_port(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".rules", delete=False) as f:
            f.write("alert tcp any any -> any any (msg:\"Any port\"; sid:1000021; rev:1;)")
            f.flush()
            filepath = f.name

            rules = RuleParser.parse_ids_rules(filepath)
            try:
                os.unlink(filepath)
            except:
                pass

            assert len(rules) == 1
            assert rules[0].destination_port == "any"
