import os
from collections import deque
from fastapi import FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from typing import List, Dict, Any
import json
from datetime import datetime
from pathlib import Path
from core.state_store import SQLiteMonitoringStore

app = FastAPI(title="SentinelFW Dashboard", version="1.0.0")

connections: List[WebSocket] = []
DASHBOARD_TOKEN = os.getenv("SENTINELFW_DASHBOARD_TOKEN", "")
SENSITIVE_PORTS = {21, 22, 23, 135, 137, 138, 139, 445, 3389, 5985, 5986}

stats_data = {
    "packets_captured": 0,
    "alerts_generated": 0,
    "alerts_suppressed": 0,
    "firewall_allowed": 0,
    "firewall_denied": 0,
    "top_sources": [],
    "top_dest_ports": [],
    "alerts_by_severity": {"low": 0, "medium": 0, "high": 0, "critical": 0},
    "uptime_start": datetime.now().isoformat(),
}

alerts_data = deque(maxlen=1000)
device_inventory: Dict[str, Dict[str, Any]] = {}


def _require_dashboard_token(token: str = "") -> None:
    if DASHBOARD_TOKEN and token != DASHBOARD_TOKEN:
        raise HTTPException(status_code=401, detail="invalid dashboard token")


def _remember_device(ip: str, role: str = "talker", alert: Dict[str, Any] | None = None, count: int = 1) -> None:
    if not ip:
        return

    now = datetime.now().isoformat()
    item = device_inventory.setdefault(
        ip,
        {
            "ip": ip,
            "label": f"Casa {len(device_inventory) + 1}",
            "role": role,
            "first_seen": now,
            "last_seen": now,
            "packets": 0,
            "alerts": 0,
            "sensitive_ports": [],
            "severity": "low",
        },
    )
    item["last_seen"] = now
    item["packets"] = int(item.get("packets", 0)) + int(count)
    if alert:
        item["alerts"] = int(item.get("alerts", 0)) + 1
        item["severity"] = alert.get("severity", item.get("severity", "low"))
        port = int(alert.get("destination_port") or 0)
        if port in SENSITIVE_PORTS and port not in item["sensitive_ports"]:
            item["sensitive_ports"].append(port)


def _hydrate_from_state_store() -> None:
    db_path = Path("logs/sentinelfw.db")
    if not db_path.exists():
        return

    store = None
    try:
        store = SQLiteMonitoringStore(str(db_path))
        summary = store.fetch_summary(timeline_limit=200)

        stats_data.update(
            {
                "packets_captured": int(summary.get("total_packets", 0)),
                "alerts_generated": int(summary.get("total_alerts", 0)),
                "firewall_allowed": int(summary.get("firewall", {}).get("allowed", 0)),
                "firewall_denied": int(summary.get("firewall", {}).get("denied", 0)),
                "top_sources": summary.get("top_source_ips", []),
                "top_dest_ports": summary.get("top_destination_ports", []),
                "alerts_by_severity": {
                    "low": int(summary.get("alerts_by_severity", {}).get("low", 0)),
                    "medium": int(summary.get("alerts_by_severity", {}).get("medium", 0)),
                    "high": int(summary.get("alerts_by_severity", {}).get("high", 0)),
                    "critical": int(summary.get("alerts_by_severity", {}).get("critical", 0)),
                },
            }
        )

        timeline = summary.get("timeline", [])
        if timeline:
            alerts_data.clear()
            for item in timeline:
                alert = {
                    "timestamp": item.get("timestamp", datetime.now().isoformat()),
                    "severity": item.get("severity", "low"),
                    "source_ip": item.get("source_ip", ""),
                    "source_port": 0,
                    "destination_ip": "",
                    "destination_port": 0,
                    "protocol": "",
                    "message": item.get("message", ""),
                    "rule_sid": 0,
                    "rule_msg": "",
                }
                alerts_data.append(alert)
                _remember_device(alert["source_ip"], alert=alert)

        for source in stats_data.get("top_sources", []):
            _remember_device(source.get("ip", ""), count=source.get("count", 1))
    except Exception:
        # Fallback is best effort only; dashboard must continue serving.
        return
    finally:
        if store:
            store.close()


_hydrate_from_state_store()


@app.get("/")
async def get_dashboard():
    html = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SentinelFW Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Fira+Code:wght@400;600&display=swap');
        :root {
            --paper: #f3ead7;
            --ink: #162018;
            --pine: #234d34;
            --copper: #b8662c;
            --ember: #d64b2a;
            --night: #101812;
        }
        body {
            font-family: 'Fira Code', monospace;
            background:
                radial-gradient(circle at 20% 10%, rgba(184, 102, 44, .24), transparent 28rem),
                radial-gradient(circle at 90% 0%, rgba(35, 77, 52, .34), transparent 25rem),
                linear-gradient(135deg, #101812 0%, #19251b 46%, #362316 100%);
        }
        .scanline {
            background-image: linear-gradient(rgba(255,255,255,.04) 1px, transparent 1px);
            background-size: 100% 11px;
        }
        .tile {
            background: rgba(243, 234, 215, .09);
            border: 1px solid rgba(243, 234, 215, .18);
            box-shadow: 0 24px 80px rgba(0,0,0,.25);
            backdrop-filter: blur(14px);
        }
        .copper { color: #f0a36d; }
        .home-pill {
            border: 1px solid rgba(240, 163, 109, .45);
            background: rgba(184, 102, 44, .14);
        }
    </style>
</head>
<body class="text-stone-100 scanline min-h-screen">
    <nav class="border-b border-stone-100/10 px-6 py-5">
        <div class="flex items-center justify-between max-w-7xl mx-auto">
            <div>
                <h1 class="text-2xl font-bold copper tracking-tight">SentinelFW</h1>
                <span class="text-xs text-stone-300">posto de vigia da rede domestica</span>
            </div>
            <span class="home-pill rounded-full px-3 py-1 text-xs text-stone-200">tempo real local</span>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto p-6">
        <section class="tile rounded-3xl p-6 mb-6 overflow-hidden relative">
            <div class="absolute -right-10 -top-10 w-48 h-48 rounded-full bg-orange-500/20 blur-3xl"></div>
            <p class="text-xs uppercase tracking-[0.35em] text-stone-400">home map</p>
            <div class="flex flex-col md:flex-row md:items-end md:justify-between gap-4">
                <div>
                    <h2 class="text-3xl md:text-5xl font-black mt-2">A casa esta sendo observada.</h2>
                    <p class="text-stone-300 mt-3 max-w-2xl">Dispositivos, portas sensiveis e alertas recentes ficam aqui sem transformar sua LAN em um SOC corporativo pesado.</p>
                </div>
                <div class="text-right">
                    <div class="text-5xl font-black copper" id="device-count">0</div>
                    <div class="text-xs text-stone-400">dispositivos vistos</div>
                </div>
            </div>
        </section>

        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="tile rounded-2xl p-4">
                <div class="text-stone-400 text-sm">Pacotes Capturados</div>
                <div class="text-2xl font-bold text-blue-400" id="packets">0</div>
            </div>
            <div class="tile rounded-2xl p-4">
                <div class="text-stone-400 text-sm">Alertas Gerados</div>
                <div class="text-2xl font-bold text-yellow-400" id="alerts">0</div>
            </div>
            <div class="tile rounded-2xl p-4">
                <div class="text-stone-400 text-sm">Alertas Suprimidos</div>
                <div class="text-2xl font-bold text-stone-400" id="suppressed">0</div>
            </div>
            <div class="tile rounded-2xl p-4">
                <div class="text-stone-400 text-sm">Pacotes Bloqueados</div>
                <div class="text-2xl font-bold text-red-400" id="blocked">0</div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="tile rounded-2xl p-4 md:col-span-2">
                <h2 class="text-lg font-semibold mb-4">Alertas Recentes</h2>
                <div id="alerts-list" class="space-y-2 max-h-96 overflow-y-auto">
                    <p class="text-stone-500">Nenhum alerta ainda...</p>
                </div>
            </div>
            <div class="tile rounded-2xl p-4">
                <h2 class="text-lg font-semibold mb-4">Por Severidade</h2>
                <div class="space-y-3">
                    <div class="flex items-center justify-between">
                        <span class="text-green-400">Low</span>
                        <span id="severity-low" class="font-bold">0</span>
                    </div>
                    <div class="w-full bg-gray-700 rounded h-2">
                        <div id="bar-low" class="bg-green-400 h-2 rounded" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-yellow-400">Medium</span>
                        <span id="severity-medium" class="font-bold">0</span>
                    </div>
                    <div class="w-full bg-gray-700 rounded h-2">
                        <div id="bar-medium" class="bg-yellow-400 h-2 rounded" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-red-400">High</span>
                        <span id="severity-high" class="font-bold">0</span>
                    </div>
                    <div class="w-full bg-gray-700 rounded h-2">
                        <div id="bar-high" class="bg-red-400 h-2 rounded" style="width: 0%"></div>
                    </div>
                    <div class="flex items-center justify-between">
                        <span class="text-purple-400">Critical</span>
                        <span id="severity-critical" class="font-bold">0</span>
                    </div>
                    <div class="w-full bg-gray-700 rounded h-2">
                        <div id="bar-critical" class="bg-purple-400 h-2 rounded" style="width: 0%"></div>
                    </div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div class="tile rounded-2xl p-4">
                <h2 class="text-lg font-semibold mb-4">Dispositivos da Casa</h2>
                <div id="home-devices" class="space-y-2">
                    <p class="text-stone-500">Nenhum dispositivo visto ainda...</p>
                </div>
            </div>
            <div class="tile rounded-2xl p-4">
                <h2 class="text-lg font-semibold mb-4">Top IPs de Origem</h2>
                <div id="top-sources" class="space-y-2">
                    <p class="text-stone-500">Nenhum dado ainda...</p>
                </div>
            </div>
        </div>
    </main>

    <script>
        const ws = new WebSocket(`ws://${location.host}/ws`);
        let latestAlerts = [];

        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            if (data.type === 'stats') {
                updateDashboard(data);
            } else if (data.type === 'alert') {
                appendAlert(data.data);
            }
        };

        ws.onclose = function() {
            setTimeout(() => window.location.reload(), 3000);
        };

        async function loadInitialData() {
            try {
                const [statsResp, alertsResp, homeResp] = await Promise.all([
                    fetch('/api/stats'),
                    fetch('/api/alerts?limit=20'),
                    fetch('/api/home')
                ]);
                const stats = await statsResp.json();
                const alerts = await alertsResp.json();
                const home = await homeResp.json();
                latestAlerts = Array.isArray(alerts) ? alerts : (alerts.value || []);
                updateDashboard({
                    type: 'stats',
                    stats: stats,
                    recent_alerts: latestAlerts,
                    top_sources: stats.top_sources || [],
                    home: home
                });
            } catch (e) {
                // Keep UI responsive even if bootstrap fetch fails.
            }
        }

        async function pollFallback() {
            try {
                const statsResp = await fetch('/api/stats');
                const stats = await statsResp.json();
                updateDashboard({
                    type: 'stats',
                    stats: stats,
                    recent_alerts: latestAlerts,
                    top_sources: stats.top_sources || []
                });
                const homeResp = await fetch('/api/home');
                updateHome(await homeResp.json());
            } catch (e) {
                // Ignore transient polling failures.
            }
        }

        function updateDashboard(data) {
            document.getElementById('packets').textContent = data.stats.packets_captured || 0;
            document.getElementById('alerts').textContent = data.stats.alerts_generated || 0;
            document.getElementById('suppressed').textContent = data.stats.alerts_suppressed || 0;
            document.getElementById('blocked').textContent = data.stats.firewall_denied || 0;

            const severity = data.stats.alerts_by_severity || {low:0, medium:0, high:0, critical:0};
            const total = severity.low + severity.medium + severity.high + severity.critical || 1;

            document.getElementById('severity-low').textContent = severity.low;
            document.getElementById('severity-medium').textContent = severity.medium;
            document.getElementById('severity-high').textContent = severity.high;
            document.getElementById('severity-critical').textContent = severity.critical;

            document.getElementById('bar-low').style.width = (severity.low / total * 100) + '%';
            document.getElementById('bar-medium').style.width = (severity.medium / total * 100) + '%';
            document.getElementById('bar-high').style.width = (severity.high / total * 100) + '%';
            document.getElementById('bar-critical').style.width = (severity.critical / total * 100) + '%';

            const alertsList = document.getElementById('alerts-list');
            if (data.recent_alerts && data.recent_alerts.length > 0) {
                latestAlerts = data.recent_alerts;
                alertsList.innerHTML = data.recent_alerts.slice(0, 20).map(alert => `
                    <div class="bg-gray-700 rounded p-3 flex justify-between items-center">
                        <div>
                            <span class="text-${getSeverityColor(alert.severity)} font-bold">${alert.severity.toUpperCase()}</span>
                            <span class="text-gray-400 ml-2">${alert.source_ip}</span>
                        </div>
                        <span class="text-gray-500 text-sm">${alert.message.substring(0, 40)}...</span>
                    </div>
                `).join('');
            }

            const sourcesList = document.getElementById('top-sources');
            if (data.top_sources && data.top_sources.length > 0) {
                sourcesList.innerHTML = data.top_sources.slice(0, 5).map((src, i) => `
                    <div class="flex justify-between items-center">
                        <span class="text-stone-400">${i+1}. ${src.ip}</span>
                        <span class="font-bold">${src.count}</span>
                    </div>
                `).join('');
            }

            if (data.home) {
                updateHome(data.home);
            }
        }

        function updateHome(home) {
            const count = home.local_device_count || (home.devices || []).length || 0;
            document.getElementById('device-count').textContent = count;
            const devicesList = document.getElementById('home-devices');
            const devices = home.devices || [];
            if (!devices.length) return;
            devicesList.innerHTML = devices.slice(0, 8).map(device => `
                <div class="rounded-xl border border-stone-100/10 bg-black/20 p-3">
                    <div class="flex items-center justify-between gap-3">
                        <div>
                            <div class="font-bold copper">${device.label || 'Dispositivo'}</div>
                            <div class="text-xs text-stone-400">${device.ip}</div>
                        </div>
                        <div class="text-right text-xs">
                            <div>${device.packets || 0} pacotes</div>
                            <div class="${(device.alerts || 0) > 0 ? 'text-red-300' : 'text-stone-500'}">${device.alerts || 0} alertas</div>
                        </div>
                    </div>
                    <div class="mt-2 text-xs text-stone-400">
                        portas sensiveis: ${(device.sensitive_ports || []).join(', ') || 'nenhuma'}
                    </div>
                </div>
            `).join('');
        }

        function appendAlert(alert) {
            const alertsList = document.getElementById('alerts-list');
            const severityColor = getSeverityColor(alert.severity || 'low');
            const existing = alertsList.innerHTML.includes('Nenhum alerta ainda...');
            const entry = `
                <div class="bg-gray-700 rounded p-3 flex justify-between items-center">
                    <div>
                        <span class="text-${severityColor} font-bold">${(alert.severity || 'low').toUpperCase()}</span>
                        <span class="text-gray-400 ml-2">${alert.source_ip || 'n/a'}</span>
                    </div>
                    <span class="text-gray-500 text-sm">${(alert.message || '').substring(0, 40)}...</span>
                </div>
            `;
            if (existing) {
                alertsList.innerHTML = entry;
            } else {
                alertsList.innerHTML = entry + alertsList.innerHTML;
            }
            latestAlerts = [alert, ...latestAlerts].slice(0, 20);
        }

        function getSeverityColor(severity) {
            const colors = {low: 'green', medium: 'yellow', high: 'red', critical: 'purple'};
            return colors[severity] || 'gray';
        }

        loadInitialData();
        setInterval(pollFallback, 3000);
    </script>
</body>
</html>"""
    return HTMLResponse(html)


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        if websocket in connections:
            connections.remove(websocket)


@app.get("/api/stats")
async def get_stats():
    return stats_data


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    return list(alerts_data)[-limit:]


@app.get("/api/home")
async def get_home_overview():
    devices = sorted(
        device_inventory.values(),
        key=lambda item: (int(item.get("alerts", 0)), int(item.get("packets", 0))),
        reverse=True,
    )
    return {
        "devices": devices[:50],
        "sensitive_ports": sorted(SENSITIVE_PORTS),
        "local_device_count": len(devices),
    }


@app.post("/api/alert")
async def post_alert(alert: Dict[str, Any], x_sentinelfw_token: str = Header(default="")):
    _require_dashboard_token(x_sentinelfw_token)
    alert["timestamp"] = datetime.now().isoformat()
    alerts_data.append(alert)
    _remember_device(alert.get("source_ip", ""), alert=alert)
    _remember_device(alert.get("destination_ip", ""), role="destination")

    await broadcast_alert(alert)
    return {"status": "ok"}


@app.post("/api/stats/update")
async def update_stats(stats: Dict[str, Any], x_sentinelfw_token: str = Header(default="")):
    _require_dashboard_token(x_sentinelfw_token)
    stats_data.update(stats)
    for source in stats.get("top_sources", []):
        _remember_device(source.get("ip", ""), count=source.get("count", 1))
    await broadcast_stats()
    return {"status": "ok"}


async def broadcast_alert(alert: Dict[str, Any]):
    message = json.dumps({"type": "alert", "data": alert})
    for conn in connections:
        try:
            await conn.send_text(message)
        except:
            if conn in connections:
                connections.remove(conn)


async def broadcast_stats():
    message = json.dumps(
        {
            "type": "stats",
            "stats": stats_data,
            "recent_alerts": list(alerts_data)[-20:],
            "home": {
                "devices": list(device_inventory.values())[:20],
                "local_device_count": len(device_inventory),
            },
            "top_sources": stats_data.get("top_sources", []),
        }
    )
    for conn in connections:
        try:
            await conn.send_text(message)
        except:
            if conn in connections:
                connections.remove(conn)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
