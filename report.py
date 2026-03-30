def generate_report(
    machine: dict,
    target: dict,
    dns: dict,
    port: dict,
    ssl: dict,
    trace: dict,
    fallback=None,
    output_path: str = "Relatorio-Diagnostico-EVO.txt"
) -> str:
    filename = output_path

    def w(f, s=""):
        f.write(s + "\n")

    with open(filename, "w", encoding="utf-8") as f:
        w(f, "=====================================")
        w(f, "DIAGNOSTICO DE INTEGRACAO - EVO")
        w(f, "=====================================")
        w(f)
        w(f, f"Servidor testado: {target['host']}")
        w(f, f"Porta: {target['port']}")
        w(f, f"Data/Hora: {machine.get('Data/Hora', 'N/A')}")
        w(f)
        w(f, f"Hostname: {machine.get('Hostname', 'N/A')}")
        w(f, f"IP Local (saida): {machine.get('IP Local', 'N/A')}")
        w(f, f"Sistema: {machine.get('Sistema', 'N/A')} {machine.get('Versao', '')}".strip())
        w(f, f"Arquitetura: {machine.get('Arquitetura', 'N/A')}")
        w(f)

        w(f, "-------------------------------------")
        w(f, "[DNS]")
        w(f, f"Status: {dns.get('status', 'N/A')}")
        if dns.get("ips"):
            w(f, "IPs resolvidos: " + ", ".join(dns["ips"]))
        w(f, f"Mensagem: {dns.get('message', '')}")
        w(f)

        w(f, "[PORTA]")
        w(f, f"Status: {port.get('status', 'N/A')}")
        w(f, f"Mensagem: {port.get('message', '')}")
        w(f)

        w(f, "[SSL/TLS]")
        w(f, f"Status: {ssl.get('status', 'N/A')}")
        w(f, f"TLS Negociado: {ssl.get('tls', 'N/A')}")
        w(f, f"Cipher: {ssl.get('cipher', 'N/A')}")
        w(f, f"Mensagem: {ssl.get('message', '')}")

        if ssl.get("subject"):
            w(f, f"Subject: {ssl.get('subject')}")
        if ssl.get("issuer"):
            w(f, f"Issuer: {ssl.get('issuer')}")
        if ssl.get("not_before"):
            w(f, f"Valido a partir de: {ssl.get('not_before')}")
        if ssl.get("not_after"):
            w(f, f"Valido ate: {ssl.get('not_after')}")
        if ssl.get("san"):
            w(f, f"SAN: {ssl.get('san')}")
        if ssl.get("inspection_hint"):
            w(f, f"Diagnostico SSL: {ssl.get('inspection_hint')}")
        w(f)

        w(f, "[TRACEROUTE]")
        w(f, f"Status: {trace.get('status', 'N/A')}")
        w(f, f"Mensagem: {trace.get('message', '')}")
        if trace.get("hops"):
            for idx, hop in enumerate(trace["hops"], start=1):
                w(f, f"{idx}. {hop}")
        w(f)

        if fallback:
            w(f, "-------------------------------------")
            w(f, "[FALLBACK POR IP]")
            w(f, f"IP usado: {fallback.get('ip', 'N/A')}")
            port_ip = fallback.get("port", {})
            ssl_ip = fallback.get("ssl", {})
            w(f, f"Porta por IP: {port_ip.get('status', 'N/A')} - {port_ip.get('message', '')}")
            w(f, f"SSL por IP: {ssl_ip.get('status', 'N/A')} - {ssl_ip.get('message', '')}")
            w(f)

        w(f, "-------------------------------------")
        w(f, "Acoes recomendadas (se houver falha):")
        if not dns.get("ok", False):
            w(f, "- Verificar DNS configurado na maquina/rede e regras de firewall para resolucao.")
        if dns.get("ok", False) and not port.get("ok", False):
            w(f, f"- Liberar saida TCP {target['port']} para {target['host']}.")
        if port.get("ok", False) and not ssl.get("ok", False):
            w(f, "- Possivel inspecao SSL/proxy. Verificar politica de interceptacao e certificados confiaveis.")
        if dns.get("ok", False) and port.get("ok", False) and ssl.get("ok", False):
            w(f, "- Nenhuma. Conectividade OK.")

    return filename