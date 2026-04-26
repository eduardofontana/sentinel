from typing import List, Optional, Callable
from core.packet_model import PacketInfo, FirewallRule, Action
from core.rule_parser import RuleParser


class FirewallEngine:
    def __init__(self, rules: Optional[List[FirewallRule]] = None, default_policy: str = "allow", rules_file: str = ""):
        self.rules = rules or []
        self.default_policy = Action(default_policy.lower())
        self.rules_file = rules_file
        self.stats = {
            "allowed": 0,
            "denied": 0,
            "total": 0,
        }
        self._reload_callbacks: list[Callable] = []
        self._rule_index: dict[tuple[str, str], list[FirewallRule]] = {}
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        index: dict[tuple[str, str], list[FirewallRule]] = {}
        for rule in self.rules:
            key = (rule.protocol.value, str(rule.destination_port).lower())
            index.setdefault(key, []).append(rule)
        self._rule_index = index

    def _get_candidate_rules(self, packet: PacketInfo) -> list[FirewallRule]:
        protocol = packet.protocol.lower()
        port = str(packet.destination_port)
        candidate_keys = [
            (protocol, port),
            (protocol, "any"),
            ("any", port),
            ("any", "any"),
        ]
        candidates: list[FirewallRule] = []
        seen_ids: set[str] = set()
        for key in candidate_keys:
            for rule in self._rule_index.get(key, []):
                if rule.id in seen_ids:
                    continue
                seen_ids.add(rule.id)
                candidates.append(rule)
        return candidates

    def load_rules(self, rules_file: str) -> None:
        old_count = len(self.rules)
        self.rules_file = rules_file
        self.rules = RuleParser.parse_firewall_rules(rules_file)
        self._rebuild_index()
        new_count = len(self.rules)
        if old_count != new_count:
            for callback in self._reload_callbacks:
                callback(f"Reloaded firewall rules: {old_count} -> {new_count}")

    def register_reload_callback(self, callback: Callable) -> None:
        self._reload_callbacks.append(callback)

    def check_packet(self, packet: PacketInfo) -> Action:
        self.stats["total"] += 1

        candidate_rules = self._get_candidate_rules(packet)
        for rule in candidate_rules:
            if not rule.enabled:
                continue

            if rule.matches(packet):
                if rule.action == Action.DENY:
                    self.stats["denied"] += 1
                else:
                    self.stats["allowed"] += 1
                return rule.action

        if self.default_policy == Action.DENY:
            self.stats["denied"] += 1
        else:
            self.stats["allowed"] += 1

        return self.default_policy

    def get_stats(self) -> dict:
        return self.stats.copy()

    def get_rules(self) -> List[FirewallRule]:
        return self.rules.copy()

    def add_rule(self, rule: FirewallRule) -> None:
        self.rules.append(rule)
        self._rebuild_index()

    def remove_rule(self, rule_id: str) -> bool:
        for i, rule in enumerate(self.rules):
            if rule.id == rule_id:
                self.rules.pop(i)
                self._rebuild_index()
                return True
        return False

    def enable_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = True
                return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        for rule in self.rules:
            if rule.id == rule_id:
                rule.enabled = False
                return True
        return False

    def reload_rules(self, rules_file: str = "") -> None:
        file_to_load = rules_file or self.rules_file
        if file_to_load:
            self.load_rules(file_to_load)

    def get_rules_file(self) -> str:
        return self.rules_file
