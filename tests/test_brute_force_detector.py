from datetime import datetime, timedelta

from core.packet_model import PacketInfo
from detectors.brute_force import BruteForceDetector


def _packet(dest_port: int = 3389) -> PacketInfo:
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.50",
        source_port=50000,
        destination_ip="192.168.1.1",
        destination_port=dest_port,
        protocol="tcp",
        payload=b"",
        size=60,
    )


def test_cleanup_old_attempts_does_not_raise_and_prunes_empty_tracker():
    detector = BruteForceDetector(time_window_seconds=1, attempts_threshold=10)
    source_ip = "192.168.1.50"
    dest_port = 3389

    detector.attempts_tracker[source_ip][dest_port] = [datetime.now() - timedelta(seconds=5)]

    detector._cleanup_old_attempts(source_ip, dest_port, datetime.now())

    assert source_ip not in detector.attempts_tracker


def test_threshold_generates_alert_after_multiple_attempts():
    detector = BruteForceDetector(time_window_seconds=60, attempts_threshold=3)

    assert detector.check_packet(_packet()) is None
    assert detector.check_packet(_packet()) is None
    alert = detector.check_packet(_packet())

    assert alert is not None
    assert "brute force" in alert.message.lower()
