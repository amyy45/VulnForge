import argparse
from core.recon import run_nmap_scan
from core.config import validate_target
from colorama import Fore, Style

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

    if not validate_target(target):
        print(Fore.RED + "[-] Invalid target. Only IP addresses allowed." + Style.RESET_ALL)
        return

    print(Fore.GREEN + f"[+] Target validated: {target}" + Style.RESET_ALL)

    recon_results = run_nmap_scan(target)

    if not recon_results:
        print(Fore.YELLOW + "[!] No open services discovered" + Style.RESET_ALL)
        return

    print(Fore.CYAN + "\n[+] Recon Results:" + Style.RESET_ALL)
    for r in recon_results:
        print(
            f"  - {r['protocol'].upper()} {r['port']} | "
            f"{r['service']} {r['product']} {r['version']}"
        )

if __name__ == "__main__":
    main()
