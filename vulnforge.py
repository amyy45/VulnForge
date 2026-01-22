import argparse
from colorama import Fore, Style

from core.recon import run_nmap_scan, detect_http_services
from core.config import validate_target


def main():
    parser = argparse.ArgumentParser(
        description="VulnForge — Automated Attack Chain Discovery Framework"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address (lab only)"
    )

    args = parser.parse_args()
    target = args.target

    # Scope / target validation
    if not validate_target(target):
        print(Fore.RED + "[-] Invalid target. Only IP addresses allowed." + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"[+] Target validated: {target}" + Style.RESET_ALL)

    # -----------------------
    # Recon Phase
    # -----------------------
    recon_results = run_nmap_scan(target)

    if not recon_results:
        print(Fore.YELLOW + "[!] No open services discovered" + Style.RESET_ALL)
        return

    print(Fore.CYAN + "\n[+] Recon Results:" + Style.RESET_ALL)
    for r in recon_results:
        print(
            f"  - {r['protocol'].upper()} {r['port']} | "
            f"{r['service']} {r.get('product','')} {r.get('version','')}"
        )

    # -----------------------
    # Web Surface Detection
    # -----------------------
    web_results = detect_http_services(recon_results, target)

    if web_results:
        print(Fore.CYAN + "\n[+] Web Services Detected:" + Style.RESET_ALL)
        for w in web_results:
            print(
                f"  - {w['url']} | "
                f"Status: {w['status_code']} | "
                f"Server: {w.get('server')} | "
                f"X-Powered-By: {w.get('x_powered_by')}"
            )
    else:
        print(Fore.YELLOW + "\n[!] No web services detected" + Style.RESET_ALL)


if __name__ == "__main__":
    main()
