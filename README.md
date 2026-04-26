# SentinelFW

## Firewall DomÃ©stico + Sistema de DetecÃ§Ã£o de IntrusÃ£o

```
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ•—   â–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•—
â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘â•šâ•â•â–ˆâ–ˆâ•”â•â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•â•â•â–ˆâ–ˆâ•‘
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â–ˆâ–ˆâ•— â–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—  â–ˆâ–ˆâ•‘
â•šâ•â•â•â•â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘â•šâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•”â•â•â•  â–ˆâ–ˆâ•‘
â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘   â–ˆâ–ˆâ•‘â–ˆâ–ˆâ•‘ â•šâ–ˆâ–ˆâ–ˆâ–ˆâ•‘â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—â–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ–ˆâ•—
â•šâ•â•â•â•â•â•â•â•šâ•â•â•â•â•â•â•â•šâ•â•  â•šâ•â•â•â•   â•šâ•â•   â•šâ•â•â•šâ•â•  â•šâ•â•â•â•â•šâ•â•â•â•â•â•â•â•šâ•â•â•â•â•â•â•

    Home Firewall + Intrusion Detection
```

## IntroduÃ§Ã£o

Bem-vindo ao **SentinelFW**, uma ferramenta profissional de firewall domÃ©stico e sistema de detecÃ§Ã£o de intrusÃ£o (IDS) inspirada em engines como Snort.

Este projeto foi desenvolvido para:
- Captura e anÃ¡lise de pacotes de rede local
- AplicaÃ§Ã£o de regras de firewall (allow/deny)
- DetecÃ§Ã£o de ameaÃ§asbaseada em regras estilo Snort
- GeraÃ§Ã£o de alertas e logs de eventos
- RelatÃ³rios detalhados em JSON/HTML
- DetecÃ§Ã£o de comportamentos suspeitos (port scan, brute force, DoS)

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

## CaracterÃ­sticas

### Motor de Firewall
- Regras em formato YAML
- Suporte a protocolos: TCP, UDP, ICMP, any
-è¿‡æ»¤ por IP de origem/destino, porta
- PolÃ­tica padrÃ£o configurÃ¡vel (allow/deny)
- EstatÃ­sticas em tempo real

### Motor IDS (Estilo Snort)
- Parser de regras no formato Snort
- Suporte a opÃ§Ãµes: `msg`, `content`, `nocase`, `sid`, `rev`, `classtype`
- DetecÃ§Ã£o de content em payloads
- Matching case-sensitive/insensitive
- NÃ­veis de severidade

### Detectores
- **Port Scan**: Detecta varredura de portas
- **Brute Force**: Detecta tentativas repetidas
- **DoS**: Detecta flood de pacotes
- **Suspicious Payload**: Detecta padrÃµes maliciosos

### RelatÃ³rios
- RelatÃ³rios em JSON
- RelatÃ³rios em HTML
- EstatÃ­sticas completas
- Timeline de eventos

## InstalaÃ§Ã£o

```bash
# Clone o repositÃ³rio
git clone https://github.com/eduardofontana/sentinel.git
cd sentinelfw

# Crie um ambiente virtual (opcional)
python -m venv venv
source venv/bin/activate  # Linux/Mac
# ou
venv\Scripts\activate  # Windows

# Instale as dependÃªncias
pip install -r requirements.txt

# Linux: pode precisar de privilÃ©gios de root para captura de pacotes
sudo setcap cap_net_raw,cap_net_admin=eip $(which python)
```

## ConfiguraÃ§Ã£o

Edite `config/settings.yaml` para ajustar as configuraÃ§Ãµes:

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

### Gerar RelatÃ³rio

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
- [x] Motor de firewall bÃ¡sico
- [x] Parser de regras IDS
- [x] Detectores de anomalias
- [x] Logging estruturado
- [x] RelatÃ³rios JSON/HTML
- [ ] Interface grÃ¡fica (TBD)
- [ ] Suporte a mais protocolos
- [ ] IntegraÃ§Ã£o com bancos de dados
- [ ] Alertas em tempo real (TBD)

## Aviso Legal

**IMPORTANTE**: Esta ferramenta Ã© destinada exclusivamente para:

- Fins educativos e de aprendizado
- Uso em laboratÃ³rios de seguranÃ§a
- Testes autorizados em redes prÃ³prias
- ProteÃ§Ã£o de redes domÃ©sticas

**PROIBIDO**:
- Uso em redes sem autorizaÃ§Ã£o
- ViolaÃ§Ã£o de privacidade de outros
- Ataques offensivos
- Atividades ilegais

O usuÃ¡rio Ã© o Ãºnico responsÃ¡vel pelo uso adequado desta ferramenta.
NÃ£o nos responsabilizamos por qualquer uso indevido ou ilegal.

---

**Autor**: Eduardo Fontana â€” Web Developer & Pentester

**GitHub**: [github.com/eduardofontana/sentinel](https://github.com/eduardofontana/sentinel)

LicenÃ§a MIT - Sinta-se livre para usar e contribuir!

