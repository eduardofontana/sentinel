import sys
import os
import time
import subprocess
import re
import json
from collections import Counter
from pathlib import Path
from typing import Optional, List, Callable

import yaml
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel

from core.packet_model import PacketInfo, Severity
from core.firewall import FirewallEngine
from core.ids_engine import IDSEngine
from core.sniffer import PacketSniffer
from core.rule_parser import RuleParser
from core.reporter import Reporter
from core.logger import SentinelLogger
from core.async_logger import AsyncSentinelLogger
from core.dashboard_client import DashboardClient
from core.state_store import SQLiteMonitoringStore
from detectors.port_scan import PortScanDetector
from detectors.brute_force import BruteForceDetector
from detectors.dos import DoSDetector
from detectors.suspicious_payload import SuspiciousPayloadDetector

console = Console()
app = typer.Typer(help="SentinelFW - Home Firewall + IDS")

CONFIG_FILE = "config/settings.yaml"
FIREWALL_RULES_FILE = "config/firewall_rules.yaml"
IDS_RULES_FILE = "rules/ids.rules"
IDS_HOME_RULES_FILE = "rules/ids_home.rules"
STATE_DB_FILE = "logs/sentinelfw.db"
MONITOR_PID_FILE = "logs/monitor.pid"
MONITOR_OUT_LOG = "logs/monitor.out.log"
MONITOR_ERR_LOG = "logs/monitor.err.log"

loaded_config = {}
sniffer = None


def load_config() -> dict:
    global loaded_config
    config_path = Path(CONFIG_FILE)

    if not config_path.exists():
        loaded_config = {
            "interface": "eth0",
            "default_policy": "allow",
            "log_level": "INFO",
            "packet_limit": 0,
            "ids": {"enabled": True, "rules_file": IDS_HOME_RULES_FILE},
            "firewall": {"enabled": True, "rules_file": FIREWALL_RULES_FILE},
            "dashboard": {"enabled": True, "url": "http://127.0.0.1:8000", "stats_interval_seconds": 1.0},
            "detectors": {
                "port_scan": {"enabled": True, "time_window_seconds": 10, "unique_ports_threshold": 20},
                "brute_force": {"enabled": True, "time_window_seconds": 60, "attempts_threshold": 10},
                "dos": {"enabled": True, "time_window_seconds": 5, "packet_threshold": 200},
                "suspicious_payload": {"enabled": True, "profile": "home"},
            },
        }
    else:
        with open(config_path, "r") as f:
            loaded_config = yaml.safe_load(f)

    return loaded_config


def get_firewall() -> FirewallEngine:
    rules = RuleParser.parse_firewall_rules(loaded_config.get("firewall", {}).get("rules_file", FIREWALL_RULES_FILE))
    default_policy = loaded_config.get("default_policy", "allow")
    return FirewallEngine(rules, default_policy)


def get_ids_engine(rules_file: Optional[str] = None) -> IDSEngine:
    selected_rules_file = rules_file or loaded_config.get("ids", {}).get("rules_file", IDS_HOME_RULES_FILE)
    rules = RuleParser.parse_ids_rules(selected_rules_file)
    return IDSEngine(rules)


def discover_interfaces() -> List[str]:
    try:
        from scapy.all import get_if_list
    except Exception:
        return []

    interfaces: List[str] = []
    seen = set()
    for name in get_if_list():
        if not name or name in seen:
            continue
        seen.add(name)
        interfaces.append(name)
    return interfaces


def _extract_npf_guid(interface_name: str) -> Optional[str]:
    match = re.search(r"\{([0-9A-Fa-f\-]+)\}", interface_name)
    if not match:
        return None
    return match.group(1).upper()


def _windows_adapter_metadata() -> dict[str, dict]:
    if os.name != "nt":
        return {}

    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        (
            "Get-NetAdapter | Select-Object InterfaceGuid,Name,InterfaceDescription,Status | "
            "ConvertTo-Json -Compress"
        ),
    ]
    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=5)
        if result.returncode != 0 or not result.stdout.strip():
            return {}
        parsed = json.loads(result.stdout)
        rows = parsed if isinstance(parsed, list) else [parsed]
        metadata = {}
        for row in rows:
            guid = str(row.get("InterfaceGuid", "")).upper()
            if not guid:
                continue
            metadata[guid] = {
                "name": str(row.get("Name", "")).strip(),
                "description": str(row.get("InterfaceDescription", "")).strip(),
                "status": str(row.get("Status", "")).strip(),
            }
        return metadata
    except Exception:
        return {}


def _display_interface_name(interface_name: str, metadata: dict[str, dict]) -> str:
    guid = _extract_npf_guid(interface_name)
    if not guid or guid not in metadata:
        return interface_name

    item = metadata[guid]
    status = item.get("status", "")
    label = item.get("name") or item.get("description") or interface_name
    if status:
        return f"{label} [{status}] ({interface_name})"
    return f"{label} ({interface_name})"


def _resolve_preferred_interface(preferred: str, interfaces: List[str], metadata: dict[str, dict]) -> Optional[str]:
    if not preferred:
        return None

    preferred_lower = preferred.lower().strip()
    for iface in interfaces:
        if iface.lower() == preferred_lower:
            return iface

    for iface in interfaces:
        guid = _extract_npf_guid(iface)
        if not guid:
            continue
        item = metadata.get(guid, {})
        candidate_names = [
            str(item.get("name", "")).lower(),
            str(item.get("description", "")).lower(),
            _display_interface_name(iface, metadata).lower(),
        ]
        if any(preferred_lower == n for n in candidate_names if n):
            return iface
        if any(preferred_lower in n for n in candidate_names if n):
            return iface

    aliases = {
        "wifi": ["wi-fi", "wifi", "wlan", "wireless"],
        "ethernet": ["ethernet", "eth", "lan"],
    }
    for _, keys in aliases.items():
        if preferred_lower not in keys:
            continue
        for iface in interfaces:
            display = _display_interface_name(iface, metadata).lower()
            if any(k in display for k in keys):
                return iface

    return None


def _pick_interface_from_list(
    interfaces: List[str],
    preferred: Optional[str] = None,
    ask_user: Optional[Callable[[List[str]], str]] = None,
) -> str:
    metadata = _windows_adapter_metadata()
    if preferred:
        resolved = _resolve_preferred_interface(preferred, interfaces, metadata)
        if resolved:
            return resolved
    if not interfaces:
        return "eth0"
    if len(interfaces) == 1:
        return interfaces[0]
    if ask_user:
        return ask_user(interfaces)

    # Non-interactive fallback: prioritize non-loopback interface.
    for name in interfaces:
        lowered = name.lower()
        if "loopback" not in lowered and lowered not in {"lo", "lo0"}:
            return name
    return interfaces[0]


def _is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    if os.name == "nt":
        result = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}"],
            check=False,
            capture_output=True,
            text=True,
        )
        return str(pid) in result.stdout
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _read_monitor_pid() -> Optional[int]:
    pid_path = Path(MONITOR_PID_FILE)
    if not pid_path.exists():
        return None
    pid_text = pid_path.read_text(encoding="utf-8").strip()
    if not pid_text.isdigit():
        return None
    return int(pid_text)


def _start_monitor_background_impl(
    interface: Optional[str],
    rules: Optional[str],
    stop_after: int,
    interactive: bool,
) -> Optional[int]:
    existing_pid = _read_monitor_pid()
    if existing_pid and _is_process_running(existing_pid):
        return existing_pid

    config = load_config()
    detected = discover_interfaces()
    metadata = _windows_adapter_metadata()

    def _prompt_interface(options: List[str]) -> str:
        table = Table(title="Interfaces Disponiveis")
        table.add_column("#", style="cyan")
        table.add_column("Interface", style="green")
        for idx, name in enumerate(options, start=1):
            table.add_row(str(idx), _display_interface_name(name, metadata))
        console.print(table)

        while True:
            choice = typer.prompt("Escolha o numero da interface", default="1")
            try:
                idx = int(choice)
                if 1 <= idx <= len(options):
                    return options[idx - 1]
            except ValueError:
                pass
            console.print("[red]Opcao invalida. Tente novamente.[/red]")

    selected_interface = _pick_interface_from_list(
        interfaces=detected,
        preferred=interface,
        ask_user=_prompt_interface if (interactive and not interface and len(detected) > 1) else None,
    )
    if not selected_interface and config.get("interface"):
        selected_interface = config.get("interface")

    logs_dir = Path("logs")
    logs_dir.mkdir(parents=True, exist_ok=True)

    cmd = [sys.executable, "run.py", "monitor", "--interface", selected_interface]
    if rules:
        cmd.extend(["--rules", rules])
    if stop_after:
        cmd.extend(["--stop-after", str(stop_after)])

    out_fp = open(MONITOR_OUT_LOG, "a", encoding="utf-8")
    err_fp = open(MONITOR_ERR_LOG, "a", encoding="utf-8")

    popen_kwargs = {
        "cwd": str(Path.cwd()),
        "stdout": out_fp,
        "stderr": err_fp,
        "stdin": subprocess.DEVNULL,
    }
    if os.name == "nt":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "CREATE_NO_WINDOW", 0)

    proc = subprocess.Popen(cmd, **popen_kwargs)
    out_fp.close()
    err_fp.close()

    Path(MONITOR_PID_FILE).write_text(str(proc.pid), encoding="utf-8")
    return proc.pid


@app.command()
def monitor(
    interface: str = typer.Option("eth0", help="Network interface to monitor"),
    rules: Optional[str] = typer.Option(None, help="IDS rules file path"),
    stop_after: int = typer.Option(0, help="Stop after N packets (0 = infinite)"),
):
    from cli.banner import print_banner, print_legal_warning
    print_banner()
    print_legal_warning()

    console.print(f"\n[green]Iniciando monitoramento na interface:[/green] {interface}\n")

    config = load_config()
    ids_file = rules or config.get("ids", {}).get("rules_file", IDS_RULES_FILE)

    firewall_engine = get_firewall()
    ids_engine = get_ids_engine(ids_file)

    console.print(f"[cyan]Regras de firewall carregadas:[/cyan] {len(firewall_engine.get_rules())}")
    console.print(f"[cyan]Regras IDS carregadas:[/cyan] {len(ids_engine.get_rules())}")

    port_scan_detector = None
    brute_force_detector = None
    dos_detector = None
    suspicious_payload_detector = None

    if config.get("detectors", {}).get("port_scan", {}).get("enabled", True):
        ps_config = config.get("detectors", {}).get("port_scan", {})
        port_scan_detector = PortScanDetector(
            time_window_seconds=ps_config.get("time_window_seconds", 10),
            unique_ports_threshold=ps_config.get("unique_ports_threshold", 20),
        )
        console.print("[green]Port Scan Detector:[/green] Ativado")

    if config.get("detectors", {}).get("brute_force", {}).get("enabled", True):
        bf_config = config.get("detectors", {}).get("brute_force", {})
        brute_force_detector = BruteForceDetector(
            time_window_seconds=bf_config.get("time_window_seconds", 60),
            attempts_threshold=bf_config.get("attempts_threshold", 10),
        )
        console.print("[green]Brute Force Detector:[/green] Ativado")

    if config.get("detectors", {}).get("dos", {}).get("enabled", True):
        dos_config = config.get("detectors", {}).get("dos", {})
        dos_detector = DoSDetector(
            time_window_seconds=dos_config.get("time_window_seconds", 5),
            packet_threshold=dos_config.get("packet_threshold", 200),
        )
        console.print("[green]DoS Detector:[/green] Ativado")

    sp_config = config.get("detectors", {}).get("suspicious_payload", {})
    suspicious_payload_detector = SuspiciousPayloadDetector(
        enabled=sp_config.get("enabled", True),
        profile=sp_config.get("profile", "home"),
    )
    console.print(
        f"[green]Suspicious Payload Detector:[/green] Ativado (perfil: {suspicious_payload_detector.profile})\n"
    )

    state_store = SQLiteMonitoringStore(STATE_DB_FILE)
    dashboard_cfg = config.get("dashboard", {})
    dashboard_client = DashboardClient(
        base_url=dashboard_cfg.get("url", "http://127.0.0.1:8000"),
        enabled=dashboard_cfg.get("enabled", True),
    )
    stats_interval = float(dashboard_cfg.get("stats_interval_seconds", 1.0))
    logger = AsyncSentinelLogger(
        base_logger=SentinelLogger(level=config.get("log_level", "INFO")),
        state_store=state_store,
        queue_size=config.get("async_queue_size", 10000),
    )

    sniffer = PacketSniffer(
        interface=interface,
        packet_limit=stop_after,
        firewall=firewall_engine,
        ids_engine=ids_engine,
        logger=logger,
    )

    packet_buffer = []
    detected_alerts = []

    severity_counts = Counter({"low": 0, "medium": 0, "high": 0, "critical": 0})
    source_counts = Counter()
    last_stats_push = 0.0

    def push_stats(stats: dict) -> None:
        dashboard_stats = {
            "packets_captured": stats.get("packets_captured", 0),
            "alerts_generated": stats.get("alerts_generated", 0) + len(detected_alerts),
            "alerts_suppressed": stats.get("ids", {}).get("alerts_suppressed", 0),
            "firewall_allowed": stats.get("firewall", {}).get("allowed", 0),
            "firewall_denied": stats.get("firewall", {}).get("denied", 0),
            "alerts_by_severity": {
                "low": severity_counts["low"],
                "medium": severity_counts["medium"],
                "high": severity_counts["high"],
                "critical": severity_counts["critical"],
            },
            "top_sources": [
                {"ip": ip, "count": count}
                for ip, count in source_counts.most_common(5)
            ],
        }
        dashboard_client.send_stats(dashboard_stats)

    def handle_and_publish_alert(alert) -> None:
        severity_counts[alert.severity.value] += 1
        source_counts[alert.source_ip] += 1
        dashboard_client.send_alert(alert.to_dict())

    def packet_callback(packet: PacketInfo, ids_alerts=None):
        nonlocal last_stats_push
        packet_buffer.append(packet)

        if port_scan_detector:
            alert = port_scan_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("port_scan", packet.source_ip, alert.message, alert.severity)
                handle_and_publish_alert(alert)

        if brute_force_detector:
            alert = brute_force_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("brute_force", packet.source_ip, alert.message, alert.severity)
                handle_and_publish_alert(alert)

        if dos_detector:
            alert = dos_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("dos", packet.source_ip, alert.message, alert.severity)
                handle_and_publish_alert(alert)

        if suspicious_payload_detector:
            alert = suspicious_payload_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("suspicious_payload", packet.source_ip, alert.message, alert.severity)
                handle_and_publish_alert(alert)

        for alert in ids_alerts or []:
            handle_and_publish_alert(alert)

        stats = sniffer.get_stats()
        now = time.time()
        if now - last_stats_push >= stats_interval:
            push_stats(stats)
            last_stats_push = now

        console.print(
            f"\r[yellow]Pacotes:[/yellow] {stats['packets_captured']} | "
            f"[yellow]Alertas IDS:[/yellow] {stats['alerts_generated']} | "
            f"[yellow]Alertas Detector:[/yellow] {len(detected_alerts)}     ",
            end="",
        )

    sniffer.callback = packet_callback

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Monitorando trafego de rede...", total=None)
            sniffer.start()
            progress.update(task, completed=True)
    except KeyboardInterrupt:
        if sniffer and sniffer.is_running():
            sniffer.stop()
        console.print("\n\n[red]Monitoramento interrompido pelo usuario[/red]")
    except Exception as e:
        if sniffer and sniffer.is_running():
            sniffer.stop()
        console.print(f"\n\n[red]Erro:[/red] {str(e)}")
    finally:
        logger.shutdown()
        dashboard_client.shutdown()
        state_store.close()

    console.print("\n\n[bold]Estatisticas Finais:[/bold]")
    stats = sniffer.get_stats()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metrica")
    table.add_column("Valor")
    table.add_row("Pacotes Capturados", str(stats.get("packets_captured", 0)))
    table.add_row("Pacotes Permitidos", str(stats.get("packets_allowed", 0)))
    table.add_row("Pacotes Bloqueados", str(stats.get("packets_dropped", 0)))
    table.add_row("Alertas IDS", str(stats.get("alerts_generated", 0)))
    table.add_row("Alertas Detectores", str(len(detected_alerts)))

    console.print(table)

    if detected_alerts or stats.get("alerts_generated", 0) > 0:
        console.print("\n[bold yellow]Alertas Detectados:[/bold yellow]")
        alert_table = Table(show_header=True, header_style="bold red")
        alert_table.add_column("Timestamp")
        alert_table.add_column("Severidade")
        alert_table.add_column("IPOrigem")
        alert_table.add_column("Mensagem")

        all_alerts = detected_alerts + ids_engine.get_alerts()
        for alert in all_alerts[-20:]:
            alert_table.add_row(
                alert.timestamp.strftime("%H:%M:%S"),
                alert.severity.value.upper(),
                alert.source_ip,
                alert.message[:50],
            )

        console.print(alert_table)

        console.print(f"\n[green]Relatorio salvo em:[/green] reports/")


@app.command()
def test_rules(
    rules: Optional[str] = typer.Option(None, help="Rules file to test"),
):
    from cli.banner import print_banner
    print_banner()

    config = load_config()
    ids_file = rules or config.get("ids", {}).get("rules_file", IDS_RULES_FILE)

    console.print(f"[cyan]Testando regras IDS de:[/cyan] {ids_file}\n")

    ids_engine = get_ids_engine(ids_file)
    rules_list = ids_engine.get_rules()

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("SID")
    table.add_column("Acao")
    table.add_column("Protocolo")
    table.add_column("Origem")
    table.add_column("Destino")
    table.add_column("Mensagem")

    for rule in rules_list:
        table.add_row(
            str(rule.sid),
            rule.action.value,
            rule.protocol.value,
            f"{rule.source_ip}:{rule.source_port}",
            f"{rule.destination_ip}:{rule.destination_port}",
            rule.msg[:30],
        )

    console.print(table)
    console.print(f"\n[green]Total de regras:[/green] {len(rules_list)}")


@app.command()
def show_rules(
    firewall: bool = typer.Option(True, help="Show firewall rules"),
    ids: bool = typer.Option(False, help="Show IDS rules"),
):
    from cli.banner import print_banner
    print_banner()

    config = load_config()

    if firewall:
        console.print("\n[bold cyan]Regras de Firewall:[/bold cyan]")
        fw_engine = get_firewall()
        fw_rules = fw_engine.get_rules()

        if not fw_rules:
            console.print("[yellow]Nenhuma regra de firewall carregada[/yellow]")
        else:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("ID")
            table.add_column("Acao")
            table.add_column("Protocolo")
            table.add_column("Origem")
            table.add_column("Destino")
            table.add_column("Descricao")
            table.add_column("Ativa")

            for rule in fw_rules:
                table.add_row(
                    rule.id,
                    rule.action.value,
                    rule.protocol.value,
                    f"{rule.source_ip}:{rule.source_port}",
                    f"{rule.destination_ip}:{rule.destination_port}",
                    rule.description[:30],
                    "Sim" if rule.enabled else "Nao",
                )

            console.print(table)

    if ids:
        console.print("\n[bold cyan]Regras IDS:[/bold cyan]")
        ids_engine = get_ids_engine()
        ids_rules = ids_engine.get_rules()

        if not ids_rules:
            console.print("[yellow]Nenhuma regra IDS carregada[/yellow]")
        else:
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("SID")
            table.add_column("Acao")
            table.add_column("Protocolo")
            table.add_column("Origem")
            table.add_column("Destino")
            table.add_column("Mensagem")

            for rule in ids_rules:
                table.add_row(
                    str(rule.sid),
                    rule.action.value,
                    rule.protocol.value,
                    f"{rule.source_ip}:{rule.source_port}",
                    f"{rule.destination_ip}:{rule.destination_port}",
                    rule.msg[:30],
                )

            console.print(table)
            console.print(f"\n[green]Total de regras IDS:[/green] {len(ids_rules)}")


@app.command()
def report(
    format: str = typer.Option("json", help="Report format: json or html"),
    output: Optional[str] = typer.Option(None, help="Output filename"),
):
    from cli.banner import print_banner
    print_banner()

    config = load_config()
    logger = SentinelLogger(level=config.get("log_level", "INFO"))

    console.print("[cyan]Gerando relatorio...[/cyan]\n")

    reporter = Reporter()
    state_store = SQLiteMonitoringStore(STATE_DB_FILE)
    summary = state_store.fetch_summary()
    state_store.close()

    if summary.get("total_packets", 0) > 0 or summary.get("total_alerts", 0) > 0:
        report_data = reporter.generate_report_from_summary(summary)
    else:
        logs = logger.get_recent_logs(count=10000)
        report_data = reporter.generate_report_from_logs(logs)

    if format == "html":
        output_path = reporter.save_html_report(report_data, output)
        console.print(f"[green]Relatorio HTML salvo em:[/green] {output_path}")
    else:
        output_path = reporter.save_json_report(report_data, output)
        console.print(f"[green]Relatorio JSON salvo em:[/green] {output_path}")

    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Metrica")
    table.add_column("Valor")

    table.add_row("Total Pacotes", str(report_data.get("total_packets", 0)))
    table.add_row("Total Alertas", str(report_data.get("total_alerts", 0)))

    console.print(table)


@app.command()
def status():
    from cli.banner import print_banner
    print_banner()

    config = load_config()

    console.print(Panel(
        "[bold green]Sistema Ativo[/bold green]",
        title="Status do SentinelFW",
        border_style="green",
    ))

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column(" Componente")
    table.add_column("Status")

    interface = config.get("interface", "eth0")
    table.add_row(f"Interface", interface)
    table.add_row(f"Default Policy", config.get("default_policy", "allow"))
    table.add_row(f"Nivel de Log", config.get("log_level", "INFO"))

    console.print(table)

    console.print("\n[bold]Regras Carregadas:[/bold]")

    fw_engine = get_firewall()
    ids_engine = get_ids_engine()

    console.print(f"  - Firewall: {len(fw_engine.get_rules())} regras")
    console.print(f"  - IDS: {len(ids_engine.get_rules())} regras")


@app.command("demo-attack")
def demo_attack(
    target: str = typer.Option("192.168.1.1", help="IP alvo local (roteador/host de laboratorio)"),
    scan_start: int = typer.Option(2000, help="Porta inicial para varredura"),
    scan_end: int = typer.Option(2060, help="Porta final para varredura"),
    rdp_attempts: int = typer.Option(40, help="Numero de tentativas em 3389"),
    udp_burst: int = typer.Option(400, help="Quantidade de pacotes UDP para simular flood"),
    payload_attempts: int = typer.Option(20, help="Quantidade de pacotes com payload suspeito"),
):
    from cli.banner import print_banner
    print_banner()

    console.print("[yellow]Executando demo de ataque controlada para validacao do monitor/dashboard...[/yellow]")
    console.print(f"[cyan]Alvo:[/cyan] {target}")

    try:
        from scapy.all import IP, TCP, UDP, Raw, send
    except Exception:
        console.print("[red]Scapy nao disponivel. Instale as dependencias do projeto.[/red]")
        raise typer.Exit(1)

    sent_total = 0
    try:
        for port in range(scan_start, scan_end):
            send(IP(dst=target) / TCP(sport=44444, dport=port, flags="S"), verbose=0)
            sent_total += 1

        for i in range(rdp_attempts):
            send(IP(dst=target) / TCP(sport=45000 + i, dport=3389, flags="S"), verbose=0)
            sent_total += 1

        for i in range(udp_burst):
            send(
                IP(dst="8.8.8.8") / UDP(sport=50000 + (i % 200), dport=53) / Raw(load=b"AAAAAAAAAAAAAA"),
                verbose=0,
            )
            sent_total += 1

        payload = b"GET /?q=powershell -enc ZQBjAGgAbwA= HTTP/1.1\r\nHost: local\r\n\r\n"
        for i in range(payload_attempts):
            send(IP(dst=target) / TCP(sport=46000 + i, dport=80, flags="PA") / Raw(load=payload), verbose=0)
            sent_total += 1
    except PermissionError:
        console.print("[red]Permissao insuficiente para envio de pacotes. Execute com privilegios elevados.[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Falha na execucao da demo:[/red] {e}")
        raise typer.Exit(1)

    console.print(f"[green]Demo concluida.[/green] Pacotes enviados: {sent_total}")
    console.print("[cyan]Abra o dashboard em:[/cyan] http://127.0.0.1:8000")
    console.print("[cyan]Sugestao:[/cyan] aguarde 2-5 segundos e atualize para ver os alertas.")


@app.command()
def start_dashboard(
    port: int = typer.Option(8000, help="Dashboard port"),
    host: str = typer.Option("0.0.0.0", help="Dashboard host"),
    auto_monitor: bool = typer.Option(True, help="Subir monitor em background automaticamente"),
    monitor_interface: Optional[str] = typer.Option(None, help="Interface do monitor auto"),
    monitor_rules: Optional[str] = typer.Option(None, help="Arquivo de regras IDS para monitor auto"),
    monitor_stop_after: int = typer.Option(0, help="Parar monitor auto apos N pacotes (0 = infinito)"),
    monitor_interactive: bool = typer.Option(True, help="Perguntar interface se houver multiplas"),
):
    from cli.banner import print_banner
    print_banner()

    try:
        import uvicorn
    except ImportError:
        console.print("[red]Erro: FastAPI e Uvicorn nao instalados[/red]")
        console.print("[cyan]Instale com: pip install fastapi uvicorn[/cyan]")
        raise typer.Exit(1)

    from dashboard import app as fastapi_app

    if auto_monitor:
        pid = _start_monitor_background_impl(
            interface=monitor_interface,
            rules=monitor_rules,
            stop_after=monitor_stop_after,
            interactive=monitor_interactive,
        )
        if pid:
            console.print(f"[green]Monitor background ativo[/green] (PID: {pid})")

    console.print(f"[cyan]Iniciando dashboard em:[/cyan] http://{host}:{port}")
    console.print("[yellow]Pressione Ctrl+C para encerrar[/yellow]")

    try:
        uvicorn.run(fastapi_app, host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[red]Dashboard encerrado[/red]")


@app.command("start-monitor-bg")
def start_monitor_background(
    interface: Optional[str] = typer.Option(None, help="Interface de rede. Se omitida, detecta automaticamente."),
    rules: Optional[str] = typer.Option(None, help="Arquivo de regras IDS"),
    stop_after: int = typer.Option(0, help="Parar apos N pacotes (0 = infinito)"),
    interactive: bool = typer.Option(True, help="Permitir escolha interativa da interface quando houver multiplas"),
):
    from cli.banner import print_banner
    print_banner()
    pid = _start_monitor_background_impl(
        interface=interface,
        rules=rules,
        stop_after=stop_after,
        interactive=interactive,
    )
    console.print(f"[green]Monitor em background ativo[/green] (PID: {pid})")
    console.print(f"[cyan]Logs:[/cyan] {MONITOR_OUT_LOG} / {MONITOR_ERR_LOG}")
    console.print("[cyan]Dashboard:[/cyan] http://127.0.0.1:8000")


@app.command("stop-monitor-bg")
def stop_monitor_background():
    from cli.banner import print_banner
    print_banner()

    pid_path = Path(MONITOR_PID_FILE)
    if not pid_path.exists():
        console.print("[yellow]Nenhum PID de monitor encontrado.[/yellow]")
        return

    pid_text = pid_path.read_text(encoding="utf-8").strip()
    if not pid_text.isdigit():
        console.print("[red]Arquivo de PID invalido.[/red]")
        return

    pid = int(pid_text)
    try:
        if os.name == "nt":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"], check=False, capture_output=True, text=True)
        else:
            os.kill(pid, 15)
        console.print(f"[green]Monitor em background encerrado[/green] (PID: {pid})")
    finally:
        if pid_path.exists():
            pid_path.unlink()


@app.command("monitor-bg-status")
def monitor_background_status():
    from cli.banner import print_banner
    print_banner()

    pid_path = Path(MONITOR_PID_FILE)
    if not pid_path.exists():
        console.print("[yellow]Monitor background: PARADO[/yellow]")
        return

    pid_text = pid_path.read_text(encoding="utf-8").strip()
    if not pid_text.isdigit():
        console.print("[red]PID invalido no arquivo de status.[/red]")
        return

    pid = int(pid_text)
    running = _is_process_running(pid)

    if running:
        console.print(f"[green]Monitor background: RODANDO[/green] (PID: {pid})")
        console.print(f"[cyan]Dashboard:[/cyan] http://127.0.0.1:8000")
    else:
        console.print("[yellow]Monitor background: PARADO[/yellow]")
        pid_path.unlink(missing_ok=True)


@app.command()
def stop_dashboard():
    console.print("[yellow]Para encerrar o dashboard:[/yellow]")
    console.print("  - Pressione Ctrl+C no terminal onde ele esta rodando")
    console.print("  - Ou mate o processo: taskkill /PID <pid> /F")


@app.command()
def reload_rules():
    from cli.banner import print_banner
    print_banner()

    config = load_config()
    ids_file = config.get("ids", {}).get("rules_file", IDS_RULES_FILE)
    fw_file = config.get("firewall", {}).get("rules_file", FIREWALL_RULES_FILE)

    console.print("[cyan]Recarregando regras...[/cyan]")

    fw_engine = get_firewall()
    ids_engine = get_ids_engine()

    if fw_file:
        fw_engine.reload_rules(fw_file)
        console.print(f"[green]Firewall:[/green] {len(fw_engine.get_rules())} regras")

    if ids_file:
        ids_engine.reload_rules(ids_file)
        console.print(f"[green]IDS:[/green] {len(ids_engine.get_rules())} regras")

    console.print("[green]Regras recarregadas com sucesso![/green]")


@app.command()
def enable_detector(
    detector: str = typer.Argument(..., help="Detector: port_scan, brute_force, dos, suspicious_payload"),
):
    from cli.banner import print_banner
    print_banner()

    valid = ["port_scan", "brute_force", "dos", "suspicious_payload"]
    if detector not in valid:
        console.print(f"[red]Detector invalido: {detector}[/red]")
        console.print(f"Detectores disponiveis: {', '.join(valid)}")
        raise typer.Exit(1)

    config = load_config()
    if "detectors" not in config:
        config["detectors"] = {}

    if detector not in config["detectors"]:
        config["detectors"][detector] = {"enabled": True}

    config["detectors"][detector] = {"enabled": True}

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f)

    console.print(f"[green]{detector} ATIVADO[/green]")


@app.command()
def disable_detector(
    detector: str = typer.Argument(..., help="Detector: port_scan, brute_force, dos, suspicious_payload"),
):
    from cli.banner import print_banner
    print_banner()

    valid = ["port_scan", "brute_force", "dos", "suspicious_payload"]
    if detector not in valid:
        console.print(f"[red]Detector invalido: {detector}[/red]")
        console.print(f"Detectores disponiveis: {', '.join(valid)}")
        raise typer.Exit(1)

    config = load_config()
    if "detectors" not in config:
        config["detectors"] = {}

    config["detectors"][detector] = {"enabled": False}

    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f)

    console.print(f"[red]{detector} DESATIVADO[/red]")


@app.command()
def list_detectors():
    from cli.banner import print_banner
    print_banner()

    config = load_config()
    detectors = config.get("detectors", {})

    table = Table(title="Detectores")
    table.add_column("Nome", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Configuracao", style="dim")

    all_detectors = {
        "port_scan": "Detecta varredura de portas",
        "brute_force": "Detecta tentativas de brute force",
        "dos": "Detecta ataques DoS",
        "suspicious_payload": "Detecta payloads suspeitos",
    }

    for name, desc in all_detectors.items():
        enabled = detectors.get(name, {}).get("enabled", True)
        status = "[green]ATIVADO[/green]" if enabled else "[red]DESATIVADO[/red]"
        table.add_row(name, status, desc)

    console.print(table)


if __name__ == "__main__":
    app()
