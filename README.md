# SentinelFW

## Firewall Doméstico + Sistema de Detecção de Intrusão

```text
███████╗███████╗███╗ ██╗████████╗██╗███╗ ██╗███████╗██╗
██╔════╝██╔════╝████╗ ██║╚══██╔══╝██║████╗ ██║██╔════╝██║
███████╗█████╗ ██╔██╗ ██║ ██║ ██║██╔██╗ ██║█████╗ ██║
╚════██║██╔══╝ ██║╚██╗██║ ██║ ██║██║╚██╗██║██╔══╝ ██║
███████║███████╗██║ ╚████║ ██║ ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝ ╚═══╝ ╚═╝ ╚═╝╚═╝ ╚═══╝╚══════╝╚══════╝

    Home Firewall + Intrusion Detection
```

## Introdução

Bem-vindo ao **SentinelFW**, uma ferramenta profissional de firewall doméstico e sistema de detecção de intrusão (IDS) inspirada em engines como Snort.

Este projeto foi desenvolvido para:
- Captura e análise de pacotes de rede local
- Aplicação de regras de firewall (allow/deny)
- Detecção de ameaças baseada em regras estilo Snort
- Geração de alertas e logs de eventos
- Relatórios detalhados em JSON/HTML
- Detecção de comportamentos suspeitos (port scan, brute force, DoS)

## Arquitetura

```
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                        ⚡ SentinelFW ⚡                         ┃
┃              Next-Gen CLI Firewall & IDS Framework              ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                 ┃
┃   ┌──────────────┐   ┌──────────────┐   ┌────────────────────┐  ┃
┃   │    CLI UI    │   │   Sniffer    │   │     IDS Engine     │  ┃
┃   │    (Rich)    │   │   (Scapy)    │   │   (Snort Rules)    │  ┃
┃   └──────┬───────┘   └──────┬───────┘   └────────┬───────────┘  ┃
┃          │                  │                    │              ┃
┣━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━━━━━━━┻━━━━━━━━━━━━━━┫
┃                        🔍 Detection Layer                       ┃
┃                                                                 ┃
┃   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐        ┃
┃   │  Port Scan   │   │ Brute Force  │   │     DoS      │        ┃
┃   │   Detector   │   │   Detector   │   │   Detector   │        ┃
┃   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘        ┃
┃          │                  │                  │                ┃
┃          └───────────┬──────┴──────┬───────────┘                ┃
┃                      │             │                            ┃
┃           ┌──────────────┐   ┌──────────────────────┐           ┃
┃           │  Suspicious  │   │  Payload Analyzer    │           ┃
┃           │   Activity   │   │ (Deep Inspection)    │           ┃
┃           └──────────────┘   └──────────────────────┘           ┃
┃                                                                 ┃
┣━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┫
┃                                                                 ┃
┃   ┌──────────────┐         ┌────────────────────────────────┐   ┃
┃   │  Firewall    │         │      Logger & Reporter         │   ┃
┃   │   Engine     │         │   (Logs • Alerts • Reports)    │   ┃
┃   └──────────────┘         └────────────────────────────────┘   ┃
┃                                                                 ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

## Características

### Motor de Firewall
- Regras em formato YAML
- Suporte a protocolos: TCP, UDP, ICMP, any
- Filtro por IP de origem/destino e porta
- Política padrão configurável (allow/deny)
- Estatísticas em tempo real

### Motor IDS (Estilo Snort)
- Parser de regras no formato Snort
- Suporte a opções: `msg`, `content`, `nocase`, `sid`, `rev`, `classtype`
- Detecção de content em payloads
- Matching case-sensitive/insensitive
- Níveis de severidade

### Detectores
- **Port Scan**: Detecta varredura de portas
- **Brute Force**: Detecta tentativas repetidas
- **DoS**: Detecta flood de pacotes
- **Suspicious Payload**: Detecta padrões maliciosos

### Relatórios
- Relatórios em JSON
- Relatórios em HTML
- Estatísticas completas
- Timeline de eventos

## Instalação

```bash
# Clone o repositório
git clone https://github.com/eduardofontana/sentinel.git
cd sentinelfw

# Crie um ambiente virtual (opcional)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale as dependências
pip install -r requirements.txt

# Linux: pode precisar de privilégios de root para captura de pacotes
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
```

## Configuração

Edite `config/settings.yaml` para ajustar as configurações:

```yaml
interface: "eth0"
default_policy: "allow"
log_level: "INFO"
packet_limit: 0

detectors:
  port_scan:
    enabled: true
    time_window_seconds: 10
    unique_ports_threshold: 20
  # ...
```

## Uso

### Monitorar Rede

```bash
python run.py monitor --interface eth0
python run.py monitor --interface wlan0 --rules rules/ids.rules
python run.py monitor --interface eth0 --stop-after 100
```

### Testar Regras

```bash
python run.py test-rules --rules rules/ids.rules
```

### Listar Regras

```bash
python run.py show-rules --firewall
python run.py show-rules --ids
python run.py show-rules --firewall --ids
```

### Gerar Relatório

```bash
python run.py report --format json
python run.py report --format html
```

### Ver Status

```bash
python run.py status
```

## Exemplos de Regras

### Regras de Firewall (YAML)

```yaml
rules:
  - id: fw_1
    action: deny
    protocol: tcp
    source_ip: any
    source_port: any
    destination_ip: any
    destination_port: 23
    description: "Block Telnet"
    enabled: true
```

### Regras IDS (Formato Snort)

```
alert tcp any any -> any 80 (msg:"Possible HTTP SQL Injection"; content:"' OR '1'='1"; sid:1000001; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP Path Traversal"; content:"../"; sid:1000004; rev:1;)
alert tcp any any -> any 80 (msg:"HTTP XSS Script Tag"; content:"<script>"; nocase; sid:1000006; rev:1;)
```

## Roadmap

- [x] Capture de pacotes com Scapy
- [x] Motor de firewall básico
- [x] Parser de regras IDS
- [x] Detectores de anomalias
- [x] Logging estruturado
- [x] Relatórios JSON/HTML
- [ ] Interface gráfica (TBD)
- [ ] Suporte a mais protocolos
- [ ] Integração com bancos de dados
- [ ] Alertas em tempo real (TBD)

## Aviso Legal

**IMPORTANTE**: Esta ferramenta é destinada exclusivamente para:

- Fins educativos e de aprendizado
- Uso em laboratórios de segurança
- Testes autorizados em redes próprias
- Proteção de redes domésticas

**PROIBIDO**:
- Uso em redes sem autorização
- Violação de privacidade de outros
- Ataques offensivos
- Atividades ilegais

O usuário é o único responsável pelo uso adequado desta ferramenta.
Não nos responsabilizamos por qualquer uso indevido ou ilegal.

---

**Autor**: Eduardo Fontana — Web Developer & Pentester

**GitHub**: [github.com/eduardofontana/sentinel](https://github.com/eduardofontana/sentinel)

Licença MIT - Sinta-se livre para usar e contribuir!




