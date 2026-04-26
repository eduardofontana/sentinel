import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict, List

from core.packet_model import Alert, PacketInfo, Severity


class SQLiteMonitoringStore:
    def __init__(self, db_path: str = "logs/sentinelfw.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._initialize_schema()

    def _initialize_schema(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS packets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    size INTEGER,
                    action TEXT
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    severity TEXT,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    message TEXT,
                    rule_sid INTEGER,
                    rule_msg TEXT,
                    detector TEXT
                );

                CREATE TABLE IF NOT EXISTS firewall_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT,
                    source_port INTEGER,
                    destination_ip TEXT,
                    destination_port INTEGER,
                    protocol TEXT,
                    action TEXT,
                    rule_id TEXT,
                    description TEXT
                );
                """
            )
            self._conn.commit()

    def record_packet(self, packet: PacketInfo, action: str) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO packets
                    (timestamp, source_ip, source_port, destination_ip, destination_port, protocol, size, action)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.timestamp.isoformat(),
                    packet.source_ip,
                    packet.source_port,
                    packet.destination_ip,
                    packet.destination_port,
                    packet.protocol,
                    packet.size,
                    action,
                ),
            )
            self._conn.commit()

    def record_alert(self, alert: Alert, detector: str = "") -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alerts
                    (timestamp, severity, source_ip, source_port, destination_ip, destination_port, protocol, message, rule_sid, rule_msg, detector)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    alert.timestamp.isoformat(),
                    alert.severity.value,
                    alert.source_ip,
                    alert.source_port,
                    alert.destination_ip,
                    alert.destination_port,
                    alert.protocol,
                    alert.message,
                    alert.rule_sid,
                    alert.rule_msg,
                    detector,
                ),
            )
            self._conn.commit()

    def record_detector_alert(
        self,
        detector: str,
        source_ip: str,
        message: str,
        severity: Severity,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO alerts
                    (timestamp, severity, source_ip, source_port, destination_ip, destination_port, protocol, message, rule_sid, rule_msg, detector)
                VALUES (datetime('now'), ?, ?, 0, '', 0, '', ?, 0, '', ?)
                """,
                (
                    severity.value,
                    source_ip,
                    message,
                    detector,
                ),
            )
            self._conn.commit()

    def record_firewall_event(
        self,
        packet: PacketInfo,
        action: str,
        rule_id: str,
        description: str,
    ) -> None:
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO firewall_events
                    (timestamp, source_ip, source_port, destination_ip, destination_port, protocol, action, rule_id, description)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet.timestamp.isoformat(),
                    packet.source_ip,
                    packet.source_port,
                    packet.destination_ip,
                    packet.destination_port,
                    packet.protocol,
                    action.lower(),
                    rule_id,
                    description,
                ),
            )
            self._conn.commit()

    def fetch_summary(self, timeline_limit: int = 100) -> Dict[str, Any]:
        with self._lock:
            total_packets = self._conn.execute("SELECT COUNT(*) FROM packets").fetchone()[0]
            total_alerts = self._conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]

            top_source_rows = self._conn.execute(
                """
                SELECT source_ip, COUNT(*) as count
                FROM packets
                WHERE source_ip IS NOT NULL AND source_ip != ''
                GROUP BY source_ip
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()

            top_port_rows = self._conn.execute(
                """
                SELECT destination_port, COUNT(*) as count
                FROM packets
                GROUP BY destination_port
                ORDER BY count DESC
                LIMIT 10
                """
            ).fetchall()

            protocol_rows = self._conn.execute(
                """
                SELECT protocol, COUNT(*) as count
                FROM packets
                WHERE protocol IS NOT NULL AND protocol != ''
                GROUP BY protocol
                """
            ).fetchall()

            severity_rows = self._conn.execute(
                """
                SELECT severity, COUNT(*) as count
                FROM alerts
                GROUP BY severity
                """
            ).fetchall()

            rule_rows = self._conn.execute(
                """
                SELECT rule_sid, COUNT(*) as count
                FROM alerts
                WHERE rule_sid > 0
                GROUP BY rule_sid
                """
            ).fetchall()

            timeline_rows = self._conn.execute(
                """
                SELECT timestamp, severity, source_ip, message
                FROM alerts
                ORDER BY id DESC
                LIMIT ?
                """,
                (timeline_limit,),
            ).fetchall()

            firewall_rows = self._conn.execute(
                """
                SELECT action, COUNT(*) as count
                FROM firewall_events
                GROUP BY action
                """
            ).fetchall()

        firewall_allowed = 0
        firewall_denied = 0
        for row in firewall_rows:
            action = str(row["action"]).lower()
            if action == "allow":
                firewall_allowed += row["count"]
            if action in {"deny", "denied"}:
                firewall_denied += row["count"]

        return {
            "total_packets": total_packets,
            "total_alerts": total_alerts,
            "firewall": {
                "total": firewall_allowed + firewall_denied,
                "allowed": firewall_allowed,
                "denied": firewall_denied,
            },
            "top_source_ips": [{"ip": r["source_ip"], "count": r["count"]} for r in top_source_rows],
            "top_destination_ports": [{"port": r["destination_port"], "count": r["count"]} for r in top_port_rows],
            "protocols": {r["protocol"]: r["count"] for r in protocol_rows},
            "alerts_by_severity": {r["severity"]: r["count"] for r in severity_rows},
            "matched_rules": {r["rule_sid"]: r["count"] for r in rule_rows},
            "timeline": [
                {
                    "timestamp": r["timestamp"],
                    "severity": r["severity"],
                    "source_ip": r["source_ip"],
                    "message": r["message"],
                }
                for r in reversed(timeline_rows)
            ],
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()
