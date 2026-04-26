from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
import json
from datetime import datetime
from pathlib import Path

app = FastAPI(title="SentinelFW Dashboard", version="1.0.0")

connections: List[WebSocket] = []

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

alerts_data: List[Dict[str, Any]] = []


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
        body { font-family: 'Fira Code', monospace; }
    </style>
</head>
<body class="bg-gray-900 text-gray-100">
    <nav class="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div class="flex items-center justify-between max-w-7xl mx-auto">
            <h1 class="text-xl font-bold text-blue-400">SentinelFW</h1>
            <span class="text-sm text-gray-400">Dashboard em Tempo Real</span>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto p-6">
        <div class="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Pacotes Capturados</div>
                <div class="text-2xl font-bold text-blue-400" id="packets">0</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Alertas Gerados</div>
                <div class="text-2xl font-bold text-yellow-400" id="alerts">0</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Alertas Suprimidos</div>
                <div class="text-2xl font-bold text-gray-500" id="suppressed">0</div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
                <div class="text-gray-400 text-sm">Pacotes Bloqueados</div>
                <div class="text-2xl font-bold text-red-400" id="blocked">0</div>
            </div>
        </div>

        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700 md:col-span-2">
                <h2 class="text-lg font-semibold mb-4">Alertas Recentes</h2>
                <div id="alerts-list" class="space-y-2 max-h-96 overflow-y-auto">
                    <p class="text-gray-500">Nenhum alerta ainda...</p>
                </div>
            </div>
            <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
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

        <div class="bg-gray-800 rounded-lg p-4 border border-gray-700">
            <h2 class="text-lg font-semibold mb-4">Top IPs de Origem</h2>
            <div id="top-sources" class="space-y-2">
                <p class="text-gray-500">Nenhum dado ainda...</p>
            </div>
        </div>
    </main>

    <script>
        const ws = new WebSocket(`ws://${location.host}/ws`);

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
                        <span class="text-gray-400">${i+1}. ${src.ip}</span>
                        <span class="font-bold">${src.count}</span>
                    </div>
                `).join('');
            }
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
        }

        function getSeverityColor(severity) {
            const colors = {low: 'green', medium: 'yellow', high: 'red', critical: 'purple'};
            return colors[severity] || 'gray';
        }
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
        connections.remove(websocket)


@app.get("/api/stats")
async def get_stats():
    return stats_data


@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    return alerts_data[-limit:]


@app.post("/api/alert")
async def post_alert(alert: Dict[str, Any]):
    alert["timestamp"] = datetime.now().isoformat()
    alerts_data.append(alert)

    if len(alerts_data) > 1000:
        alerts_data.clear()

    await broadcast_alert(alert)
    return {"status": "ok"}


@app.post("/api/stats/update")
async def update_stats(stats: Dict[str, Any]):
    stats_data.update(stats)
    await broadcast_stats()
    return {"status": "ok"}


async def broadcast_alert(alert: Dict[str, Any]):
    message = json.dumps({"type": "alert", "data": alert})
    for conn in connections:
        try:
            await conn.send_text(message)
        except:
            pass


async def broadcast_stats():
    message = json.dumps(
        {
            "type": "stats",
            "stats": stats_data,
            "recent_alerts": alerts_data[-20:],
            "top_sources": stats_data.get("top_sources", []),
        }
    )
    for conn in connections:
        try:
            await conn.send_text(message)
        except:
            pass


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
