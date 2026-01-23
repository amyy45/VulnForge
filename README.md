# VulnForge — Automated Attack Chain Discovery Framework

VulnForge is a **CLI-based penetration testing framework** built to identify exposed services, validate real exploitability, and chain findings into a complete attack narrative with evidence and impact.

The project emphasizes **practical exploitation, restraint, and reporting discipline** over automated scanning noise or UI-heavy tooling.

---

## Project Objectives

- Discover exposed network services
- Identify realistic initial access vectors
- Validate exploitation with proof, not assumptions
- Chain multiple findings into a single attack path
- Produce clear, professional pentest-style evidence

All testing was performed **exclusively in authorized lab environments**.

---

## Scope & Legal Notice

⚠️ **Important**

VulnForge is intended **only for educational use in controlled lab environments** (e.g., Metasploitable, DVWA).

Do **not** run this tool against systems you do not own or do not have explicit permission to test.

---

## Target Environment

- **Lab:** Metasploitable 2
- **Methodology:** Black-box, non-destructive
- **Execution Style:** CLI-first (no Metasploit automation)

---

## Key Capabilities

- Network and service reconnaissance
- Web service fingerprinting
- Weak credential detection (password spraying)
- Authenticated access validation
- Remote command execution confirmation
- Alternate exploitation path assessment
- Attack chain summarization
- Evidence-driven reporting

---

## High-Level Workflow

```text
Reconnaissance
↓
Credential Discovery
↓
Authenticated Access
↓
Post-Auth Enumeration
↓
Privilege / RCE Validation
↓
Alternate Path Assessment
↓
Attack Chain Summary
```

---

## Confirmed Attack Chain (Metasploitable 2)

1. **Reconnaissance**
   - Multiple exposed and legacy services identified

2. **Initial Access**
   - Weak FTP credentials discovered (`msfadmin:msfadmin`)

3. **Authenticated Access**
   - FTP login validated
   - File system access confirmed

4. **Pivot**
   - Exposed bind shell identified on port `1524`

5. **Impact**
   - Root-level remote command execution confirmed

6. **Alternate Path (Assessed)**
   - Unauthenticated `distccd` command execution tested
   - Command output not returned by service (documented behavior)

---

## Evidence

Screenshots are stored in `reports/screenshots/` and follow a strict, chronological naming convention:

```text
00_full_attack_chain.png
01_recon_services.png
02_credential_discovery.png
03_authenticated_access.png
04_root_rce.png
05_distccd_rce_assessed.png
```

Each screenshot maps directly to a stage in the documented attack chain.

---

## Project Structure

```yaml
vulnforge/
├── core/
│ ├── recon.py
│ ├── scanner.py
│ ├── validator.py
│ ├── chain_builder.py
│ └── config.py
│
├── exploits/
│ ├── weak_creds.py
│ ├── bind_shell.py
│ ├── unrealircd_rce.py
│ └── distccd_rce.py
│
├── reports/
│ ├── markdown/
│ │ └── metasploitable_attack_chain.md
│ ├── html/
│ └── screenshots/
│
├── targets/
│ └── .keep
│
├── vulnforge.py
├── requirements.txt
└── README.md
```

### Note on `targets/`
The `targets/` directory is intentionally kept empty and contains only a `.keep` file.  
Targets are supplied at runtime via the CLI to avoid committing sensitive scope data and to keep the framework reusable across engagements.

---

## How to Run

### 1. Set up environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```
### 2. Execute against lab target
```bash
sudo python3 vulnforge.py --target 192.168.64.3
```

Root privileges are required for certain network operations.

---

## Sample Output (Excerpt)
```yaml
[!!!] VALID CREDENTIAL FOUND → msfadmin:msfadmin
[!!!] REMOTE COMMAND EXECUTION CONFIRMED (ROOT)
[RCE OUTPUT] root@metasploitable:/#

[!] distccd RCE assessed — command output not returned by service

[+] ATTACK CHAIN SUMMARY:
- Recon: Multiple exposed services identified
- Initial Access: Weak FTP credentials discovered
- Post-Auth: Authenticated FTP file system access
- Pivot: Exposed bind shell on port 1524
- Impact: Root-level remote command execution
- Alternate Path: distccd RCE assessed
```

---

## Reporting Philosophy

- No CVE dumping
- No blind exploitation
- No Metasploit automation
- Evidence over assumptions
- Honest documentation of limitations

If command output is not returned, it is documented, not forced.

---

## Why This Attack Succeeded

- Excessive exposed services increased the attack surface
- Default and weak credentials enabled trivial initial access
- Lack of service isolation and monitoring
- Legacy services exposed without hardening

---

## Remediation Summary

- Disable or firewall unused services
- Remove default and weak credentials
- Enforce service hardening and monitoring
- Restrict administrative interfaces
- Apply network segmentation where possible

---

## Author Notes

This project was built to demonstrate practical pentesting capability, not tool memorization.

The emphasis is on:
- Thinking in attack paths
- Knowing when to stop exploiting
- Reporting findings responsibly