import json
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from collections import defaultdict, Counter

from core.packet_model import PacketInfo, Alert, Severity
from core.ids_engine import IDSEngine


class Reporter:
    def __init__(
        self,
        output_dir: str = "reports",
    ):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate_report(
        self,
        packet_info: List[PacketInfo],
        ids_engine: Optional[IDSEngine] = None,
        firewall_stats: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        alerts = ids_engine.get_alerts() if ids_engine else []

        source_ips = [p.source_ip for p in packet_info]
        dest_ports = [p.destination_port for p in packet_info]
        protocols = [p.protocol for p in packet_info]

        source_ip_counts = Counter(source_ips)
        dest_port_counts = Counter(dest_ports)
        protocol_counts = Counter(protocols)

        severity_counts = defaultdict(int)
        matched_rules = defaultdict(int)

        for alert in alerts:
            severity_counts[alert.severity.value] += 1
            if alert.rule_sid:
                matched_rules[alert.rule_sid] += 1

        top_sources = [
            {"ip": ip, "count": count}
            for ip, count in source_ip_counts.most_common(10)
        ]
        top_dest_ports = [
            {"port": port, "count": count}
            for port, count in dest_port_counts.most_common(10)
        ]

        timeline = []
        for alert in alerts:
            timeline.append({
                "timestamp": alert.timestamp.isoformat(),
                "severity": alert.severity.value,
                "source_ip": alert.source_ip,
                "message": alert.message,
            })

        report = {
            "generated_at": datetime.now().isoformat(),
            "total_packets": len(packet_info),
            "total_alerts": len(alerts),
            "firewall": firewall_stats or {},
            "top_source_ips": top_sources,
            "top_destination_ports": top_dest_ports,
            "protocols": dict(protocol_counts),
            "alerts_by_severity": dict(severity_counts),
            "matched_rules": dict(matched_rules),
            "timeline": timeline[:100],
        }

        return report

    def generate_report_from_logs(
        self,
        log_entries: List[Dict[str, Any]],
        firewall_stats: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        traffic_events = []
        alert_events = []

        for entry in log_entries:
            event_type = entry.get("event_type", "")
            if event_type in {"packet", "firewall"}:
                traffic_events.append(entry)
            if event_type == "alert" or event_type.startswith("detector_"):
                alert_events.append(entry)

        source_ip_counts = Counter(
            e.get("source_ip")
            for e in traffic_events
            if e.get("source_ip")
        )
        dest_port_counts = Counter(
            e.get("destination_port")
            for e in traffic_events
            if isinstance(e.get("destination_port"), int)
        )
        protocol_counts = Counter(
            e.get("protocol")
            for e in traffic_events
            if e.get("protocol")
        )

        severity_counts = Counter(
            e.get("severity", "low")
            for e in alert_events
        )
        matched_rules = Counter(
            int(e.get("rule_sid", 0))
            for e in alert_events
            if int(e.get("rule_sid", 0)) > 0
        )

        timeline = [
            {
                "timestamp": e.get("timestamp", ""),
                "severity": e.get("severity", "low"),
                "source_ip": e.get("source_ip", ""),
                "message": e.get("message", ""),
            }
            for e in alert_events[-100:]
        ]

        computed_firewall_stats = firewall_stats
        if computed_firewall_stats is None:
            firewall_events = [e for e in traffic_events if e.get("event_type") == "firewall"]
            denied_count = sum(1 for e in firewall_events if str(e.get("action", "")).lower() in {"deny", "denied"})
            allow_count = sum(1 for e in firewall_events if str(e.get("action", "")).lower() == "allow")
            computed_firewall_stats = {
                "total": len(firewall_events),
                "allowed": allow_count,
                "denied": denied_count,
            }

        return {
            "generated_at": datetime.now().isoformat(),
            "total_packets": len(traffic_events),
            "total_alerts": len(alert_events),
            "firewall": computed_firewall_stats or {},
            "top_source_ips": [
                {"ip": ip, "count": count}
                for ip, count in source_ip_counts.most_common(10)
            ],
            "top_destination_ports": [
                {"port": port, "count": count}
                for port, count in dest_port_counts.most_common(10)
            ],
            "protocols": dict(protocol_counts),
            "alerts_by_severity": dict(severity_counts),
            "matched_rules": dict(matched_rules),
            "timeline": timeline,
        }

    def generate_report_from_summary(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_packets": summary.get("total_packets", 0),
            "total_alerts": summary.get("total_alerts", 0),
            "firewall": summary.get("firewall", {}),
            "top_source_ips": summary.get("top_source_ips", []),
            "top_destination_ports": summary.get("top_destination_ports", []),
            "protocols": summary.get("protocols", {}),
            "alerts_by_severity": summary.get("alerts_by_severity", {}),
            "matched_rules": summary.get("matched_rules", {}),
            "timeline": summary.get("timeline", [])[:100],
        }
        return report

    def save_json_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        output_path = self.output_dir / filename
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        return output_path

    def save_html_report(self, report: Dict[str, Any], filename: Optional[str] = None) -> Path:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

        output_path = self.output_dir / filename

        html = self._generate_html(report)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

        return output_path

    def _generate_html(self, report: Dict[str, Any]) -> str:
        severity_colors = {
            "low": "#4caf50",
            "medium": "#ff9800",
            "high": "#f44336",
            "critical": "#9c27b0",
        }

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatorio SentinelFW</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 20px;
            background: #1a1a2e;
            color: #eee;
        }}
        .header {{
            text-align: center;
            padding: 20px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2.5em;
        }}
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .stat-card {{
            background: #16213e;
            padding: 20px;
            border-radius: 10px;
            text-align: center;
            border: 1px solid #0f3460;
        }}
        .stat-card h3 {{
            margin: 0 0 10px 0;
            color: #667eea;
        }}
        .stat-card .value {{
            font-size: 2em;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #0f3460;
        }}
        th {{
            background: #0f3460;
            color: #667eea;
        }}
        .alert {{
            padding: 10px;
            margin: 5px 0;
            border-radius: 5px;
            border-left: 4px solid;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Relatorio SentinelFW</h1>
        <p>Gerado em: {report['generated_at']}</p>
    </div>

    <div class="stats-grid">
        <div class="stat-card">
            <h3>Pacotes Processados</h3>
            <div class="value">{report['total_packets']}</div>
        </div>
        <div class="stat-card">
            <h3>Total de Alertas</h3>
            <div class="value">{report['total_alerts']}</div>
        </div>
    </div>

    <h2>Top IPs de Origem</h2>
    <table>
        <tr><th>IP</th><th>Quantidade</th></tr>
"""

        for source in report.get("top_source_ips", []):
            html += f"<tr><td>{source['ip']}</td><td>{source['count']}</td></tr>\n"

        html += """
    </table>

    <h2>Top Ports de Destino</h2>
    <table>
        <tr><th>Porta</th><th>Quantidade</th></tr>
"""

        for dest in report.get("top_destination_ports", []):
            html += f"<tr><td>{dest['port']}</td><td>{dest['count']}</td></tr>\n"

        html += """
    </table>

    <h2>Alertas por Severidade</h2>
    <table>
        <tr><th>Severidade</th><th>Quantidade</th></tr>
"""

        for severity, count in report.get("alerts_by_severity", {}).items():
            color = severity_colors.get(severity, "#666")
            html += f'<tr><td style="color: {color}">{severity.upper()}</td><td>{count}</td></tr>\n'

        html += """
    </table>

    <h2>Linha do Tempo de Alertas</h2>
"""

        for event in report.get("timeline", []):
            color = severity_colors.get(event.get("severity", "low"), "#666")
            html += f"""
    <div class="alert" style="border-color: {color}; background: #16213e;">
        <strong>{event.get('timestamp', '')}</strong> -
        <span style="color: {color};">{event.get('severity', '').upper()}</span> -
        {event.get('source_ip', '')}: {event.get('message', '')}
    </div>
"""

        html += """
</body>
</html>"""

        return html
