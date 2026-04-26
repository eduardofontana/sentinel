# SentinelFW

## Firewall Domestico + Sistema de Deteccao de Intrusao

```text
███████╗███████╗███╗ ██╗████████╗██╗███╗ ██╗███████╗██╗
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║
███████╗█████╗ ██╔██╗ ██║ ██║ ██║██╔██╗ ██║█████╗ ██║
╚════██║██╔══╝ ██║╚██╗██║ ██║ ██║██║╚██╗██║██╔══╝ ██║
███████║███████╗██║ ╚████║ ██║ ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝ ╚═══╝ ╚═╝ ╚═╝╚═╝ ╚═══╝╚══════╝╚══════╝

    Home Firewall + Intrusion Detection
```

Repositorio oficial do app:
- https://github.com/eduardofontana/sentinel

## Visao Geral

SentinelFW combina:
- captura de pacotes com Scapy
- firewall baseado em regras YAML
- IDS estilo Snort
- detectores de comportamento (port scan, brute force, DoS, payload suspeito)
- dashboard web em tempo real (FastAPI + WebSocket)
- persistencia local em SQLite para relatorios

## Arquitetura

```text
CLI (Typer/Rich)
  -> PacketSniffer (Scapy AsyncSniffer)
    -> FirewallEngine
    -> IDSEngine (Snort-like rules)
    -> Detectores (PortScan, BruteForce, DoS, SuspiciousPayload)
    -> Logger/StateStore (SQLite)
    -> DashboardClient (HTTP -> dashboard.py)
```

## Requisitos

- Python 3.10+
- Dependencias de `requirements.txt`
- Windows: Npcap/WinPcap compativel para captura de pacotes

## Instalacao

```bash
git clone https://github.com/eduardofontana/sentinel.git
cd sentinel
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Configuracao

Arquivo: `config/settings.yaml`

Pontos principais:
- `interface`: interface de captura
- `ids.rules_file`: regras IDS (padrao `rules/ids_home.rules`)
- `dashboard.url`: endpoint do dashboard
- `detectors.suspicious_payload.profile`: `home`, `web` ou `mixed`

## Comandos Principais

### Monitor em foreground

```bash
python run.py monitor --interface "\\Device\\NPF_{SEU_GUID}"
```

### Dashboard com monitor automatico

```bash
python run.py start-dashboard --host 127.0.0.1 --port 8000 --auto-monitor --monitor-interface "\\Device\\NPF_{SEU_GUID}" --no-monitor-interactive
```

Link:
- http://127.0.0.1:8000

### Monitor em background

```bash
python run.py start-monitor-bg --interface "\\Device\\NPF_{SEU_GUID}" --no-interactive
python run.py monitor-bg-status
python run.py stop-monitor-bg
```

### Simulacao rapida de trafego/ataque controlado

```bash
python run.py demo-attack --target 192.168.1.1
```

### Utilitarios

```bash
python run.py test-rules --rules rules/ids_home.rules
python run.py show-rules --firewall --ids
python run.py report --format html
python run.py status
```

## Troubleshooting

### `ERR_CONNECTION_REFUSED` no dashboard

1. Confirme se o processo subiu:
```bash
python run.py monitor-bg-status
```
2. Suba dashboard novamente em foreground e mantenha o terminal aberto:
```bash
python run.py start-dashboard --host 127.0.0.1 --port 8000 --auto-monitor
```
3. Teste API:
```bash
curl http://127.0.0.1:8000/api/stats
```

### Alias `python` quebrado no Windows

Se o alias do WindowsApps falhar, execute com caminho completo:

```powershell
& "C:\Users\duhbolado\AppData\Local\Python\pythoncore-3.14-64\python.exe" run.py start-dashboard --host 127.0.0.1 --port 8000 --auto-monitor
```

## Testes

```bash
python -m pytest tests/test_brute_force_detector.py -q
python -m pytest tests/test_suspicious_payload_detector.py -q
```

## Aviso Legal

Uso exclusivo para:
- aprendizado
- laboratorio proprio/autorizado
- defesa de rede domestica

Nao use para atividades ofensivas ou sem autorizacao.

## Autor

Eduardo Fontana
- https://github.com/eduardofontana
