import argparse
import os
import platform
import socket
from datetime import datetime

from network_testes import (
    get_local_ip,
    test_dns,
    test_port,
    test_ssl,
    traceroute_host,
)
from report import generate_report

# (Opcional, mas recomendado)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


def parse_args():
    parser = argparse.ArgumentParser(
        prog="EVO-Diagnostic",
        description="Diagnóstico de conectividade para integrações."
    )

    # Variáveis de ambiente com fallback seguro
    default_host = os.getenv("API_HOST", "api.exemplo.com")
    default_port = int(os.getenv("API_PORT", 443))
    default_timeout = float(os.getenv("API_TIMEOUT", 5.0))

    parser.add_argument(
        "--host",
        default=default_host,
        help="Hostname do endpoint (ou via variável de ambiente API_HOST)"
    )
    parser.add_argument(
        "--port",
        type=int,
        default=default_port,
        help="Porta TCP"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=default_timeout,
        help="Timeout em segundos"
    )
    parser.add_argument(
        "--output",
        default="Relatorio-Diagnostico.txt",
        help="Nome do arquivo de relatório"
    )

    return parser.parse_args()


def get_machine_info():
    return {
        "Data/Hora": datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "Hostname": socket.gethostname(),
        "IP Local": get_local_ip(prefer_ipv4=True),
        "Sistema": platform.system(),
        "Versao": platform.release(),
        "Arquitetura": platform.machine(),
    }


def main():
    args = parse_args()

    target = {
        "host": args.host,
        "port": args.port,
        "timeout": args.timeout
    }

    print("Iniciando diagnóstico...\n")
    print(f"Alvo: {target['host']}:{target['port']} (timeout {target['timeout']}s)\n")

    machine = get_machine_info()
    dns_result = test_dns(target["host"])

    if dns_result.get("ok"):
        port_result = test_port(
            target["host"],
            target["port"],
            timeout=target["timeout"]
        )
        ssl_result = test_ssl(
            target["host"],
            target["port"],
            timeout=target["timeout"]
        )
    else:
        port_result = {
            "ok": False,
            "status": "FALHA",
            "message": "Nao testado (DNS falhou)"
        }
        ssl_result = {
            "ok": False,
            "status": "FALHA",
            "tls": "N/A",
            "cipher": "N/A",
            "message": "Nao testado (DNS falhou)",
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "san": "",
            "inspection_hint": "",
        }

    trace_result = traceroute_host(
        target["host"],
        max_hops=8,
        timeout_sec=5
    )

    out_path = os.path.join(os.getcwd(), args.output)

    filename = generate_report(
        machine=machine,
        target={"host": target["host"], "port": target["port"]},
        dns=dns_result,
        port=port_result,
        ssl=ssl_result,
        trace=trace_result,
        fallback=None,
        output_path=out_path,
    )

    print(f"\nRelatório salvo em: {filename}")
    print("\nDiagnóstico finalizado.")


if __name__ == "__main__":
    main()