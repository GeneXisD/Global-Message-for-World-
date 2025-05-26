
#!/usr/bin/env python3

import os
import subprocess
import json
import time
from pathlib import Path

WATCHLIST = "metal-cert-chain.txt"
CERT_DIR = "/etc/ssl/certs"  # Change as needed
LOG_FILE = "/var/log/ritual_certscan.log"  # Log output location
INTERVAL = 3600  # Run every hour

def get_fingerprints(cert_path):
    try:
        sha256 = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-noout", "-fingerprint", "-sha256"]
        ).decode().strip().split('=')[-1].replace(":", "")
        return sha256
    except Exception:
        return None

def check_policy_oid(cert_path):
    try:
        output = subprocess.check_output(
            ["openssl", "x509", "-in", cert_path, "-noout", "-text"]
        ).decode()
        return "2.23.140.1.2.1" in output
    except Exception:
        return False

def load_watchlist():
    with open(WATCHLIST, 'r') as f:
        lines = f.readlines()
    return [line.strip() for line in lines if "SHA-256" in line]

def scan_certs(cert_dir):
    results = []
    watch_fingerprints = load_watchlist()
    for cert_file in Path(cert_dir).glob("*.pem"):
        sha256 = get_fingerprints(str(cert_file))
        if not sha256:
            continue
        match = any(sha256.lower() in fp.lower() for fp in watch_fingerprints)
        oid_present = check_policy_oid(str(cert_file))
        if match or oid_present:
            results.append({
                "certificate": str(cert_file),
                "sha256": sha256,
                "match_in_watchlist": match,
                "dv_policy_oid_detected": oid_present
            })
    return results

def write_log(entries):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a") as log:
        log.write(f"[{timestamp}] Cert Scan Results:\n")
        log.write(json.dumps(entries, indent=2))
        log.write("\n\n")

def main():
    while True:
        findings = scan_certs(CERT_DIR)
        if findings:
            write_log(findings)
        time.sleep(INTERVAL)

if __name__ == "__main__":
    main()
