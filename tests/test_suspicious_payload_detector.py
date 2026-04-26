from datetime import datetime

from core.packet_model import PacketInfo
from detectors.suspicious_payload import SuspiciousPayloadDetector


def _packet(payload: bytes) -> PacketInfo:
    return PacketInfo(
        timestamp=datetime.now(),
        source_ip="192.168.1.10",
        source_port=12345,
        destination_ip="10.0.0.1",
        destination_port=443,
        protocol="tcp",
        payload=payload,
        size=len(payload),
    )


def test_home_profile_detects_host_pattern():
    detector = SuspiciousPayloadDetector(enabled=True, profile="home")
    alert = detector.check_packet(_packet(b"powershell -enc ZQBjAGgAbwA="))
    assert alert is not None


def test_home_profile_ignores_web_only_pattern():
    detector = SuspiciousPayloadDetector(enabled=True, profile="home")
    alert = detector.check_packet(_packet(b"GET /?id=1' OR '1'='1 HTTP/1.1"))
    assert alert is None


def test_web_profile_detects_sqli_pattern():
    detector = SuspiciousPayloadDetector(enabled=True, profile="web")
    alert = detector.check_packet(_packet(b"GET /?id=1' OR '1'='1 HTTP/1.1"))
    assert alert is not None
