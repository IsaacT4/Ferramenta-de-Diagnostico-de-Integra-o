import platform
import re
import subprocess


def get_configured_dns_servers() -> list[str]:
    """
    Tenta descobrir os DNS configurados.
    - Windows: usa ipconfig /all
    - Linux: tenta resolv.conf (via comando 'cat' para compatibilidade), e fallback.
    """
    system = platform.system().lower()

    if "windows" in system:
        try:
            out = subprocess.check_output(["ipconfig", "/all"], text=True, errors="ignore")
            # Captura linhas de "DNS Servers" e as linhas subsequentes indentadas
            servers = []
            lines = out.splitlines()
            for i, line in enumerate(lines):
                if "DNS Servers" in line:
                    # pega o que vem após ':'
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        first = parts[1].strip()
                        if first:
                            servers.append(first)
                    # pega linhas seguintes que começam com espaço (continuação)
                    j = i + 1
                    while j < len(lines) and (lines[j].startswith(" ") or lines[j].startswith("\t")):
                        cand = lines[j].strip()
                        if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", cand) or ":" in cand:
                            servers.append(cand)
                        j += 1
            # remove duplicados preservando ordem
            seen = set()
            uniq = []
            for s in servers:
                if s not in seen:
                    seen.add(s)
                    uniq.append(s)
            return uniq
        except Exception:
            return []

    # Linux / macOS
    try:
        # preferir ler /etc/resolv.conf diretamente sem shell
        with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as f:
            servers = []
            for line in f:
                line = line.strip()
                if line.startswith("nameserver"):
                    parts = line.split()
                    if len(parts) >= 2:
                        servers.append(parts[1])
            # remove duplicados
            seen = set()
            uniq = []
            for s in servers:
                if s not in seen:
                    seen.add(s)
                    uniq.append(s)
            return uniq
    except Exception:
        return []