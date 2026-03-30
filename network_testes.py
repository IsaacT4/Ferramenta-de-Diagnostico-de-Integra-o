import os
import re
import ssl
import socket
import subprocess
from dataclasses import dataclass
from typing import List, Dict, Any


def get_local_ip(prefer_ipv4: bool = True) -> str:
    targets = [("8.8.8.8", 80), ("1.1.1.1", 80)]

    families = [socket.AF_INET] if prefer_ipv4 else [socket.AF_INET6, socket.AF_INET]

    for family in families:
        for host, port in targets:
            s = None
            try:
                s = socket.socket(family, socket.SOCK_DGRAM)
                s.connect((host, port))
                ip = s.getsockname()[0]
                if ip:
                    return ip
            except Exception:
                pass
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass

    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "N/A"


def resolve_host(host: str) -> Dict[str, Any]:
    try:
        infos = socket.getaddrinfo(host, None)
        ips = sorted({info[4][0] for info in infos})
        return {"ok": True, "ips": ips, "error": ""}
    except Exception as e:
        return {"ok": False, "ips": [], "error": str(e)}


def test_dns(host: str) -> Dict[str, Any]:
    res = resolve_host(host)
    if res["ok"]:
        return {"ok": True, "status": "OK", "ips": res["ips"], "message": "DNS resolvido"}
    return {"ok": False, "status": "FALHA", "ips": [], "message": res["error"]}


def test_port(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {"ok": True, "status": "OK", "message": f"Porta {port} aberta"}
    except Exception as e:
        return {"ok": False, "status": "FALHA", "message": str(e)}


def _format_cert_name(x509_name) -> str:
    parts = []
    try:
        for rdn in x509_name:
            for item in rdn:
                if len(item) == 2:
                    k, v = item
                    parts.append(f"{k}={v}")
    except Exception:
        return ""
    return ", ".join(parts)


def _extract_san(peer_cert: dict) -> str:
    try:
        san = peer_cert.get("subjectAltName", [])
        dns_names = [v for (t, v) in san if t == "DNS"]
        return ", ".join(dns_names[:20])
    except Exception:
        return ""


def test_ssl(host: str, port: int, timeout: float = 5.0) -> Dict[str, Any]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                peer = ssock.getpeercert()
                tls = ssock.version() or "N/A"
                cipher = ssock.cipher()[0] if ssock.cipher() else "N/A"

                return {
                    "ok": True,
                    "status": "OK",
                    "tls": tls,
                    "cipher": cipher,
                    "message": "Handshake SSL bem-sucedido",
                    "subject": _format_cert_name(peer.get("subject", ())),
                    "issuer": _format_cert_name(peer.get("issuer", ())),
                    "not_before": peer.get("notBefore", ""),
                    "not_after": peer.get("notAfter", ""),
                    "san": _extract_san(peer),
                    "inspection_hint": "",
                }

    except ssl.SSLCertVerificationError as e:
        verify_error = str(e)

        details = {
            "ok": False,
            "status": "FALHA",
            "tls": "N/A",
            "cipher": "N/A",
            "message": verify_error,
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "san": "",
            "inspection_hint": "",
        }

        try:
            insecure_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            insecure_context.check_hostname = False
            insecure_context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=timeout) as sock:
                with insecure_context.wrap_socket(sock, server_hostname=host) as ssock:
                    peer = ssock.getpeercert()
                    details["tls"] = ssock.version() or "N/A"
                    details["cipher"] = ssock.cipher()[0] if ssock.cipher() else "N/A"
                    details["subject"] = _format_cert_name(peer.get("subject", ()))
                    details["issuer"] = _format_cert_name(peer.get("issuer", ()))
                    details["not_before"] = peer.get("notBefore", "")
                    details["not_after"] = peer.get("notAfter", "")
                    details["san"] = _extract_san(peer)

                    haystack = (details["issuer"] + " " + details["subject"]).lower()
                    keywords = [
                        "fortinet", "fortigate", "zscaler", "blue coat", "symantec",
                        "palo alto", "netskope", "checkpoint", "proxy", "ssl inspection",
                        "inspection", "websense", "squid"
                    ]
                    hits = [k for k in keywords if k in haystack]

                    if hits:
                        details["inspection_hint"] = (
                            "Possível inspeção SSL/proxy detectada: " + ", ".join(hits)
                        )
                    else:
                        details["inspection_hint"] = (
                            "Possível inspeção SSL/proxy ou cadeia de certificado não confiável."
                        )
        except Exception:
            pass

        return details

    except Exception as e:
        return {
            "ok": False,
            "status": "FALHA",
            "tls": "N/A",
            "cipher": "N/A",
            "message": str(e),
            "subject": "",
            "issuer": "",
            "not_before": "",
            "not_after": "",
            "san": "",
            "inspection_hint": "",
        }


def traceroute_host(host: str, max_hops: int = 15, timeout_sec: int = 2) -> Dict[str, Any]:
    is_windows = os.name == "nt"

    try:
        if is_windows:
            cmd = ["tracert", "-d", "-h", str(max_hops), "-w", str(timeout_sec * 1000), host]
        else:
            cmd = ["traceroute", "-n", "-m", str(max_hops), "-w", str(timeout_sec), host]

        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=(max_hops * timeout_sec * 3)
        )

        raw = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        hops: List[str] = []

        for line in (proc.stdout or "").splitlines():
            line = line.strip()
            if not line:
                continue

            if is_windows:
                match = re.search(r"^\d+\s+.*\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$", line)
                if match:
                    hops.append(match.group(1))
                elif "*" in line and re.match(r"^\d+\s+", line):
                    hops.append("*")
            else:
                match = re.search(r"^\d+\s+(\d{1,3}(?:\.\d{1,3}){3})\b", line)
                if match:
                    hops.append(match.group(1))
                elif "*" in line and re.match(r"^\d+\s+", line):
                    hops.append("*")

        return {
            "ok": True,
            "status": "OK",
            "hops": hops,
            "raw": raw,
            "message": "Traceroute executado com sucesso"
        }

    except FileNotFoundError:
        return {
            "ok": False,
            "status": "FALHA",
            "hops": [],
            "raw": "",
            "message": "Comando tracert/traceroute não encontrado"
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "status": "FALHA",
            "hops": [],
            "raw": "",
            "message": "Timeout executando traceroute"
        }
    except Exception as e:
        return {
            "ok": False,
            "status": "FALHA",
            "hops": [],
            "raw": "",
            "message": str(e)
        }