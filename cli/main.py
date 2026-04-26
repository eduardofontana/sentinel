import sys
import os
from pathlib import Path
from datetime import datetime
from typing import Optional

import yaml
import typer
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.panel import Panel
from rich import print as rprint

from core.packet_model import PacketInfo, Severity
from core.firewall import FirewallEngine
from core.ids_engine import IDSEngine
from core.sniffer import PacketSniffer
from core.rule_parser import RuleParser
from core.reporter import Reporter
from core.logger import SentinelLogger
from core.async_logger import AsyncSentinelLogger
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
STATE_DB_FILE = "logs/sentinelfw.db"

loaded_config = {}
loaded_firewall_rules = []
loaded_ids_rules = []
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
            "detectors": {
                "port_scan": {"enabled": True, "time_window_seconds": 10, "unique_ports_threshold": 20},
                "brute_force": {"enabled": True, "time_window_seconds": 60, "attempts_threshold": 10},
                "dos": {"enabled": True, "time_window_seconds": 5, "packet_threshold": 200},
            },
            "ids": {"enabled": True, "rules_file": IDS_RULES_FILE},
            "firewall": {"enabled": True, "rules_file": FIREWALL_RULES_FILE},
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
    selected_rules_file = rules_file or loaded_config.get("ids", {}).get("rules_file", IDS_RULES_FILE)
    rules = RuleParser.parse_ids_rules(selected_rules_file)
    return IDSEngine(rules)


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

    suspicious_payload_detector = SuspiciousPayloadDetector(enabled=True)
    console.print("[green]Suspicious Payload Detector:[/green] Ativado\n")

    state_store = SQLiteMonitoringStore(STATE_DB_FILE)
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

    def packet_callback(packet: PacketInfo):
        packet_buffer.append(packet)

        if port_scan_detector:
            alert = port_scan_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("port_scan", packet.source_ip, alert.message, alert.severity)

        if brute_force_detector:
            alert = brute_force_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("brute_force", packet.source_ip, alert.message, alert.severity)

        if dos_detector:
            alert = dos_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("dos", packet.source_ip, alert.message, alert.severity)

        if suspicious_payload_detector:
            alert = suspicious_payload_detector.check_packet(packet)
            if alert:
                detected_alerts.append(alert)
                logger.log_detector_alert("suspicious_payload", packet.source_ip, alert.message, alert.severity)

        stats = sniffer.get_stats()
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


@app.command()
def start_dashboard(
    port: int = typer.Option(8000, help="Dashboard port"),
    host: str = typer.Option("0.0.0.0", help="Dashboard host"),
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

    console.print(f"[cyan]Iniciando dashboard em:[/cyan] http://{host}:{port}")
    console.print("[yellow]Pressione Ctrl+C para encerrar[/yellow]")

    try:
        uvicorn.run(fastapi_app, host=host, port=port)
    except KeyboardInterrupt:
        console.print("\n[red]Dashboard encerrado[/red]")


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
