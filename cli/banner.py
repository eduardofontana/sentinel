import sys
import io


def print_banner():
    BANNER = """███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗
██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║
███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║
╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║
███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝

    Home Firewall + Intrusion Detection"""

    try:
        if sys.stdout.encoding != 'utf-8':
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
        print(BANNER)
    except Exception:
        print("[SentinelFW - Home Firewall + IDS]")


def print_legal_warning():
    print("[AVISO LEGAL]")
    print("Esta ferramenta e destinada exclusivamente para fins educativos,")
    print("defensivos e testes autorizados em laboratorio.")
    print("O usuario e o unico responsavel pelo uso adequado.")