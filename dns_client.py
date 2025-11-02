#!/usr/bin/env python3
"""
Simple helper that encodes a payload, appends `.com`, and issues a DNS query
using the `dig` command against the provided DNS server IP.
"""

import base64
import subprocess
import sys


def build_domain_from_payload(payload: str) -> str:
    """Return the base64-encoded payload followed by .com."""
    encoded = base64.b64encode(payload.encode("utf-8")).decode("utf-8")
    return f"{encoded}.com"


def run_dig(server_ip: str, domain: str) -> int:
    """Invoke dig for the domain against the specified server."""
    command = ["dig", f"@{server_ip}", domain, "+noall", "+answer"]
    print(f"Running: {' '.join(command)}")
    result = subprocess.run(command)
    return result.returncode


def main() -> int:
    if len(sys.argv) < 3:
        print("Usage: dns_client.py <server_ip> <payload>")
        return 1

    server_ip = sys.argv[1]
    payload = " ".join(sys.argv[2:])
    domain = build_domain_from_payload(payload)
    return run_dig(server_ip, domain)


if __name__ == "__main__":
    raise SystemExit(main())
