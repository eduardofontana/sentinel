from typing import List, Optional, Callable
from datetime import datetime
from core.packet_model import PacketInfo, IDSRule, Alert, Severity, Action
from core.rule_parser import RuleParser


class IDSEngine:
    def __init__(self, rules: Optional[List[IDSRule]] = None, rules_file: str = ""):
        self.rules = rules or []
        self.rules_file = rules_file
        self.stats = {
            "packets_checked": 0,
            "alerts_generated": 0,
            "alerts_suppressed": 0,
            "rules_matched": 0,
        }
        self.alerts: List[Alert] = []
        self._reload_callbacks: list[Callable] = []
        self._rate_limiter = None
        self._rate_limiting_enabled = False
        self._rule_index: dict[tuple[str, str], list[IDSRule]] = {}
        self._rebuild_index()

    def _rebuild_index(self) -> None:
        index: dict[tuple[str, str], list[IDSRule]] = {}
        for rule in self.rules:
            direct_key = (rule.protocol.value, str(rule.destination_port).lower())
            index.setdefault(direct_key, []).append(rule)
            if rule.direction == "<>":
                reverse_key = (rule.protocol.value, str(rule.source_port).lower())
                index.setdefault(reverse_key, []).append(rule)
        self._rule_index = index

    def _get_candidate_rules(self, packet: PacketInfo) -> list[IDSRule]:
        protocol = packet.protocol.lower()
        port = str(packet.destination_port)
        candidate_keys = [
            (protocol, port),
            (protocol, "any"),
            ("any", port),
            ("any", "any"),
        ]
        candidates: list[IDSRule] = []
        seen_keys: set[tuple[int, int]] = set()
        for key in candidate_keys:
            for rule in self._rule_index.get(key, []):
                rule_key = (id(rule), rule.sid)
                if rule_key in seen_keys:
                    continue
                seen_keys.add(rule_key)
                candidates.append(rule)
        return candidates

    def set_rate_limiter(self, limiter) -> None:
        self._rate_limiter = limiter
        self._rate_limiting_enabled = True

    def enable_rate_limiting(
        self,
        max_alerts_per_minute: int = 60,
        max_same_alerts_per_minute: int = 10,
    ) -> None:
        from core.rate_limiter import AlertRateLimiter
        self._rate_limiter = AlertRateLimiter(
            max_alerts_per_minute=max_alerts_per_minute,
            max_same_alerts_per_minute=max_same_alerts_per_minute,
        )
        self._rate_limiting_enabled = True

    def disable_rate_limiting(self) -> None:
        self._rate_limiting_enabled = False
        self._rate_limiter = None

    def load_rules(self, rules_file: str) -> None:
        old_count = len(self.rules)
        self.rules_file = rules_file
        self.rules = RuleParser.parse_ids_rules(rules_file)
        self._rebuild_index()
        new_count = len(self.rules)
        if old_count != new_count:
            for callback in self._reload_callbacks:
                callback(f"Reloaded IDS rules: {old_count} -> {new_count}")

    def register_reload_callback(self, callback: Callable) -> None:
        self._reload_callbacks.append(callback)

    def check_packet(self, packet: PacketInfo) -> List[Alert]:
        self.stats["packets_checked"] += 1
        alerts = []

        for rule in self._get_candidate_rules(packet):
            if rule.matches(packet):
                self.stats["rules_matched"] += 1

                alert = Alert(
                    timestamp=datetime.now(),
                    severity=rule.severity,
                    source_ip=packet.source_ip,
                    source_port=packet.source_port,
                    destination_ip=packet.destination_ip,
                    destination_port=packet.destination_port,
                    protocol=packet.protocol,
                    message=f"[{rule.classtype}] {rule.msg}",
                    rule_sid=rule.sid if rule.sid else 0,
                    rule_msg=rule.msg,
                )

                if self._rate_limiting_enabled and self._rate_limiter:
                    if self._rate_limiter.check_and_record_alert(alert):
                        alerts.append(alert)
                        self.alerts.append(alert)
                        self.stats["alerts_generated"] += 1
                    else:
                        self.stats["alerts_suppressed"] += 1
                else:
                    alerts.append(alert)
                    self.alerts.append(alert)
                    self.stats["alerts_generated"] += 1

        return alerts

    def check_content(self, content: str, packet: PacketInfo) -> List[Alert]:
        if not packet.payload:
            return []

        payload_str = packet.payload.decode("utf-8", errors="ignore")
        alerts = []

        for rule in self._get_candidate_rules(packet):
            if rule.content:
                if rule.nocase:
                    if rule.content.lower() in payload_str.lower():
                        alert = Alert(
                            timestamp=datetime.now(),
                            severity=rule.severity,
                            source_ip=packet.source_ip,
                            source_port=packet.source_port,
                            destination_ip=packet.destination_ip,
                            destination_port=packet.destination_port,
                            protocol=packet.protocol,
                            message=f"[{rule.classtype}] {rule.msg}",
                            rule_sid=rule.sid if rule.sid else 0,
                            rule_msg=rule.msg,
                        )
                        alerts.append(alert)
                        self.alerts.append(alert)
                else:
                    if rule.content in payload_str:
                        alert = Alert(
                            timestamp=datetime.now(),
                            severity=rule.severity,
                            source_ip=packet.source_ip,
                            source_port=packet.source_port,
                            destination_ip=packet.destination_ip,
                            destination_port=packet.destination_port,
                            protocol=packet.protocol,
                            message=f"[{rule.classtype}] {rule.msg}",
                            rule_sid=rule.sid if rule.sid else 0,
                            rule_msg=rule.msg,
                        )
                        alerts.append(alert)
                        self.alerts.append(alert)

        return alerts

    def get_stats(self) -> dict:
        return self.stats.copy()

    def get_alerts(self) -> List[Alert]:
        return self.alerts.copy()

    def get_rules(self) -> List[IDSRule]:
        return self.rules.copy()

    def clear_alerts(self) -> None:
        self.alerts.clear()
        self.stats["alerts_generated"] = 0
        self.stats["rules_matched"] = 0

    def reload_rules(self, rules_file: str = "") -> None:
        file_to_load = rules_file or self.rules_file
        if file_to_load:
            self.load_rules(file_to_load)

    def get_rules_file(self) -> str:
        return self.rules_file
