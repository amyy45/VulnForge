# VulnForge Pentest Report — Metasploitable 2

## Executive Summary
A full system compromise was achieved on the target host through a chained attack involving weak FTP credentials and an exposed bind shell, ultimately resulting in root-level remote command execution and complete administrative control.

## Scope
- Target: 192.168.64.3
- Environment: Authorized lab (Metasploitable 2)
- Methodology: Black-box, non-destructive

## Attack Chain
1. Service discovery identified multiple exposed services including FTP and a bind shell.
2. Password spraying against FTP revealed valid credentials (msfadmin:msfadmin).
3. Authenticated FTP access confirmed file system visibility.
4. Initial vsftpd backdoor exploitation was attempted and ruled out (port 6200 not listening).
5. Pivoted to an exposed bind shell on port 1524.
6. Executed a benign command through the bind shell to confirm root-level remote command execution.

## Proof of Compromise
- Authenticated FTP access was validated via successful login and directory enumeration.
- Root-level remote command execution was confirmed through an exposed bind shell on port 1524.

## Impact
- Complete system compromise
- Full administrative control
- Potential data exfiltration and persistence
- This level of access would allow an attacker to fully control the host and use it as a pivot point within the network.

## Why This Attack Succeeded

- Multiple unnecessary services were exposed, significantly increasing the attack surface.
- Default and weak credentials enabled trivial initial access.
- No network segmentation or service isolation was enforced.
- Critical services lacked monitoring, detection, and hardening controls.
- Known vulnerable services were exposed without compensating controls.

## Remediation
- Disable or firewall unused services (FTP, bind shell).
- Enforce strong credential policies.
- Restrict administrative access.
- Apply system hardening and monitoring.
- Remove or restrict legacy services and ensure no hardcoded or default credentials remain in production environments.

## Notes
All actions were performed safely without destructive commands.
