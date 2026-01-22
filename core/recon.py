import nmap
import json
import requests

def run_nmap_scan(target: str):
    scanner = nmap.PortScanner()

    print(f"[+] Running nmap scan against {target}")
    scanner.scan(
        hosts=target,
        arguments="-sS -sV -Pn --open"
    )

    results = []

    if target not in scanner.all_hosts():
        print("[-] Host appears down or blocked")
        return results

    for proto in scanner[target].all_protocols():
        ports = scanner[target][proto].keys()
        for port in ports:
            service = scanner[target][proto][port]
            results.append({
                "port": port,
                "protocol": proto,
                "service": service.get("name"),
                "version": service.get("version"),
                "product": service.get("product")
            })

    return results

def detect_http_services(recon_results, target):
    web_services = []

    for entry in recon_results:
        if entry["service"] in ["http", "https"]:
            port = entry["port"]
            url = f"http://{target}:{port}"

            try:
                r = requests.get(url, timeout=5)
                web_services.append({
                    "port": port,
                    "url": url,
                    "status_code": r.status_code,
                    "server": r.headers.get("Server"),
                    "x_powered_by": r.headers.get("X-Powered-By")
                })
            except requests.RequestException:
                continue

    return web_services
