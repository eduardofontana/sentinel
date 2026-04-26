import yaml
import re
from pathlib import Path
from typing import List, Optional
from core.packet_model import FirewallRule, IDSRule, Protocol, Action, Severity


class RuleParser:
    @staticmethod
    def parse_firewall_rules(file_path: str) -> List[FirewallRule]:
        rules = []
        path = Path(file_path)

        if not path.exists():
            return rules

        with open(path, "r") as f:
            data = yaml.safe_load(f)

        if not data or "rules" not in data:
            return rules

        for idx, rule in enumerate(data["rules"]):
            fw_rule = FirewallRule(
                id=rule.get("id", f"fw_{idx + 1}"),
                action=Action(rule.get("action", "allow").lower()),
                protocol=Protocol(rule.get("protocol", "any").lower()),
                source_ip=rule.get("source_ip", "any"),
                source_port=str(rule.get("source_port", "any")),
                destination_ip=rule.get("destination_ip", "any"),
                destination_port=str(rule.get("destination_port", "any")),
                description=rule.get("description", ""),
                enabled=rule.get("enabled", True),
            )
            rules.append(fw_rule)

        return rules

    @staticmethod
    def parse_ids_rules(file_path: str) -> List[IDSRule]:
        rules = []
        path = Path(file_path)

        if not path.exists():
            return rules

        with open(path, "r") as f:
            lines = f.readlines()

        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            ids_rule = RuleParser._parse_ids_line(line)
            if ids_rule:
                rules.append(ids_rule)

        return rules

    @staticmethod
    def _parse_ids_line(line: str) -> Optional[IDSRule]:
        pattern = r'^(\w+)\s+(\w+)\s+(\S+)\s+(\S+)\s*(->|<>)\s*(\S+)\s+(\S+)(?:\s*\((.*)\))?$'

        match = re.match(pattern, line)
        if not match:
            return None

        action_str, protocol_str, src_ip, src_port, direction, dst_ip, dst_port_str, options_str = match.groups()

        destination_port: str | int
        try:
            destination_port = int(dst_port_str)
        except ValueError:
            destination_port = dst_port_str

        rule = IDSRule(
            action=Action(action_str.lower()),
            protocol=Protocol(protocol_str.lower()),
            source_ip=src_ip,
            source_port=src_port,
            direction=direction,
            destination_ip=dst_ip,
            destination_port=destination_port,
        )

        if options_str:
            rule = RuleParser._parse_options(rule, options_str)

        return rule

    @staticmethod
    def _parse_options(rule: IDSRule, options_str: str) -> IDSRule:
        options_str = options_str.strip().rstrip(";")

        msg_match = re.search(r'msg:"([^"]+)"', options_str)
        if msg_match:
            rule.msg = msg_match.group(1)

        content_match = re.search(r'content:"([^"]+)"', options_str)
        if content_match:
            rule.content = content_match.group(1)

        if "nocase" in options_str:
            rule.nocase = True

        sid_match = re.search(r'sid:(\d+)', options_str)
        if sid_match:
            rule.sid = int(sid_match.group(1))

        rev_match = re.search(r'rev:(\d+)', options_str)
        if rev_match:
            rule.rev = int(rev_match.group(1))

        class_match = re.search(r'classtype:([^;]+)', options_str)
        if class_match:
            rule.classtype = class_match.group(1).strip()

        severity_map = {
            "info": Severity.LOW,
            "attempted-admin": Severity.HIGH,
            "attempted-user": Severity.MEDIUM,
            "attempted-dos": Severity.MEDIUM,
            "successful-dos": Severity.CRITICAL,
            "successful-recon": Severity.LOW,
            "attempted-recon": Severity.LOW,
            "bad-unknown": Severity.MEDIUM,
            "shellcode-detect": Severity.CRITICAL,
            "spam": Severity.LOW,
        }
        rule.severity = severity_map.get(rule.classtype, Severity.MEDIUM)

        threshold_match = re.search(r'threshold:\s*(\w+)', options_str)
        if threshold_match:
            rule.severity = Severity.HIGH

        return rule

    @staticmethod
    def dump_firewall_rules(rules: List[FirewallRule]) -> dict:
        return {
            "rules": [
                {
                    "id": r.id,
                    "action": r.action.value,
                    "protocol": r.protocol.value,
                    "source_ip": r.source_ip,
                    "source_port": r.source_port,
                    "destination_ip": r.destination_ip,
                    "destination_port": r.destination_port,
                    "description": r.description,
                    "enabled": r.enabled,
                }
                for r in rules
            ]
        }
