from datetime import datetime

from core.packet_model import Alert, PacketInfo, Severity
from core.state_store import SQLiteMonitoringStore


def test_sqlite_monitoring_store_summary(tmp_path):
    db_file = tmp_path / "state.db"
    store = SQLiteMonitoringStore(str(db_file))

    packet = PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.0.10",
        source_port=12345,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="tcp",
        payload=b"GET /",
        size=120,
    )
    store.record_packet(packet, "allowed")
    store.record_firewall_event(packet, "allow", "fw_1", "Allow HTTP")

    alert = Alert(
        timestamp=datetime.now(),
        severity=Severity.HIGH,
        source_ip="192.168.0.10",
        source_port=12345,
        destination_ip="10.0.0.1",
        destination_port=80,
        protocol="tcp",
        message="Test alert",
        rule_sid=1001,
        rule_msg="Rule match",
    )
    store.record_alert(alert)

    summary = store.fetch_summary()
    store.close()

    assert summary["total_packets"] == 1
    assert summary["total_alerts"] == 1
    assert summary["firewall"]["allowed"] == 1
    assert summary["alerts_by_severity"]["high"] == 1
    assert summary["matched_rules"][1001] == 1
