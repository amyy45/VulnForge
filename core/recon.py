import nmap
import json

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
