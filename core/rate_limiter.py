from datetime import datetime, timedelta
from typing import Dict, List, Optional
from collections import defaultdict
from core.packet_model import Alert, Severity


class AlertRateLimiter:
    def __init__(
        self,
        max_alerts_per_minute: int = 60,
        max_same_alerts_per_minute: int = 10,
        suppression_window_seconds: int = 60,
    ):
        self.max_alerts_per_minute = max_alerts_per_minute
        self.max_same_alerts_per_minute = max_same_alerts_per_minute
        self.suppression_window = timedelta(seconds=suppression_window_seconds)

        self.alert_timestamps: List[datetime] = []
        self.similar_alerts: Dict[str, List[datetime]] = defaultdict(list)
        self.suppressed_count = 0

    def check_and_record_alert(self, alert: Alert) -> bool:
        now = datetime.now()

        if not self._check_rate_limit(now):
            self.suppressed_count += 1
            return False

        if not self._check_suppression(alert, now):
            self.suppressed_count += 1
            return False

        self.alert_timestamps.append(now)
        key = self._get_alert_key(alert)
        self.similar_alerts[key].append(now)

        self._cleanup_old_timestamps(now)

        return True

    def _check_rate_limit(self, now: datetime) -> bool:
        cutoff = now - timedelta(minutes=1)

        self.alert_timestamps = [ts for ts in self.alert_timestamps if ts > cutoff]

        return len(self.alert_timestamps) < self.max_alerts_per_minute

    def _check_suppression(self, alert: Alert, now: datetime) -> bool:
        key = self._get_alert_key(alert)
        cutoff = now - self.suppression_window

        self.similar_alerts[key] = [
            ts for ts in self.similar_alerts[key] if ts > cutoff
        ]

        return len(self.similar_alerts[key]) < self.max_same_alerts_per_minute

    def _get_alert_key(self, alert: Alert) -> str:
        return f"{alert.source_ip}:{alert.rule_sid}:{alert.severity.value}"

    def _cleanup_old_timestamps(self, now: datetime) -> None:
        cutoff = now - timedelta(minutes=2)
        self.alert_timestamps = [ts for ts in self.alert_timestamps if ts > cutoff]

    def get_stats(self) -> dict:
        return {
            "alerts_in_window": len(self.alert_timestamps),
            "suppressed_count": self.suppressed_count,
            "active_suppression_keys": len(self.similar_alerts),
        }

    def reset(self) -> None:
        self.alert_timestamps.clear()
        self.similar_alerts.clear()
        self.suppressed_count = 0


class AlertGrouping:
    def __init__(self, time_window_seconds: int = 60):
        self.time_window = timedelta(seconds=time_window_seconds)
        self.grouped_alerts: Dict[str, List[Alert]] = defaultdict(list)

    def add_alert(self, alert: Alert) -> str:
        key = self._get_group_key(alert)
        self.grouped_alerts[key].append(alert)
        return key

    def _get_group_key(self, alert: Alert) -> str:
        return f"{alert.source_ip}:{alert.destination_port}:{alert.protocol}"

    def get_group_summary(self) -> List[dict]:
        summary = []
        now = datetime.now()
        cutoff = now - self.time_window

        for key, alerts in self.grouped_alerts.items():
            recent = [a for a in alerts if a.timestamp > cutoff]
            if recent:
                summary.append({
                    "key": key,
                    "count": len(recent),
                    "first_seen": min(a.timestamp for a in recent),
                    "last_seen": max(a.timestamp for a in recent),
                    "severity": max(a.severity for a in recent),
                    "sample_message": recent[0].message[:50],
                })

            self.grouped_alerts[key] = recent

        return sorted(summary, key=lambda x: x["count"], reverse=True)

    def reset(self) -> None:
        self.grouped_alerts.clear()