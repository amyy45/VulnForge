def build_attack_chain():
    return [
        "Recon: Multiple exposed services identified",
        "Initial Access: Weak FTP credentials discovered",
        "Post-Auth: Authenticated FTP file system access",
        "Pivot: Exposed bind shell on port 1524",
        "Impact: Root-level remote command execution",
        "Alternate Path: distccd command execution assessed"
    ]
