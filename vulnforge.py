import argparse
from colorama import Fore, Style

from core.recon import run_nmap_scan, detect_http_services
from core.config import validate_target
from core.chain_builder import build_attack_chain

from exploits.weak_creds import spray_ftp
from exploits.ftp_access import validate_ftp_access
from exploits.bindshell_rce import exploit_bindshell
from exploits.distccd_rce import exploit_distccd

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

    # -----------------------
    # Recon Phase
    # -----------------------
    recon_results = run_nmap_scan(target)

    if not recon_results:
        print(Fore.YELLOW + "[!] No open services discovered" + Style.RESET_ALL)
        return

    print(Fore.CYAN + "\n[+] Recon Results:" + Style.RESET_ALL)
    for r in recon_results:
        print(Style.DIM + f"  - {r['protocol'].upper()} {r['port']} | "
            f"{r['service']} {r.get('product','')} {r.get('version','')}" 
            + Style.RESET_ALL)

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

    # -----------------------
    # Credential Attack Phase
    # -----------------------
    creds = spray_ftp(target)

    if creds:
        print(
            Fore.GREEN +
            f"\n[+] AUTHENTICATED ACCESS CONFIRMED → "
            f"{creds['service']} | {creds['username']}:{creds['password']}"
            + Style.RESET_ALL
        )
    else:
        print(Fore.RED + "\n[!] No valid credentials found" + Style.RESET_ALL)
    
    # -----------------------
    # Exploit Validation Phase
    # -----------------------
    if creds and creds["service"] == "ftp":
        access = validate_ftp_access(
            target,
            creds["username"],
            creds["password"]
        )

        if access:
            print(
                Fore.GREEN +
                "\n[+] FTP ACCESS CONFIRMED — FILE SYSTEM LISTING:" +
                Style.RESET_ALL
            )
            for f in access["files"]:
                print(f"  - {f}")
    
    # -----------------------
    # Controlled RCE Phase
    # -----------------------
    rce_output = exploit_bindshell(target)

    if rce_output:
        print(
            Fore.GREEN +
            "\n[!!!] REMOTE COMMAND EXECUTION CONFIRMED (ROOT)" +
            Style.RESET_ALL
        )
        print(f"[RCE OUTPUT] {rce_output}")
    else:
        print(Fore.RED + "\n[!] RCE attempt unsuccessful" + Style.RESET_ALL)

    # -----------------------
    # Alternate RCE Path 
    # -----------------------
    distccd_output = exploit_distccd(target)

    if distccd_output:
        print(
            Fore.RED +
            "\n[!!!] ALTERNATE RCE CONFIRMED (DISTCCD)" +
            Style.RESET_ALL
        )
        print(f"[RCE OUTPUT] {distccd_output}")
    else:
        print(
            Fore.YELLOW +
            "\n[!] distccd RCE assessed — command output not returned by service" +
            Style.RESET_ALL
        )

    # -----------------------
    # Attack Chain Summary
    # -----------------------
    chain = build_attack_chain()

    print(Fore.CYAN + "\n[+] ATTACK CHAIN SUMMARY:" + Style.RESET_ALL)
    for step in chain:
        print(f" - {step}")


if __name__ == "__main__":
    main()
