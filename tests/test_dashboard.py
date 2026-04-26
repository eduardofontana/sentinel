from fastapi.testclient import TestClient

import dashboard


def test_dashboard_alert_buffer_keeps_recent_alerts():
    dashboard.alerts_data.clear()
    for idx in range(1005):
        dashboard.alerts_data.append({"message": f"alert-{idx}", "source_ip": "192.168.1.10"})

    assert len(dashboard.alerts_data) == 1000
    assert dashboard.alerts_data[0]["message"] == "alert-5"


def test_dashboard_rejects_post_when_token_is_configured(monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_TOKEN", "secret")
    client = TestClient(dashboard.app)

    response = client.post("/api/stats/update", json={"packets_captured": 1})

    assert response.status_code == 401


def test_dashboard_accepts_post_with_token(monkeypatch):
    monkeypatch.setattr(dashboard, "DASHBOARD_TOKEN", "secret")
    client = TestClient(dashboard.app)

    response = client.post(
        "/api/stats/update",
        json={"top_sources": [{"ip": "192.168.1.20", "count": 3}]},
        headers={"X-SentinelFW-Token": "secret"},
    )

    assert response.status_code == 200
    assert "192.168.1.20" in dashboard.device_inventory
