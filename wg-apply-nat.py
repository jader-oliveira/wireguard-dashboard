#!/usr/bin/env python3
"""
Privileged helper — apply nftables masquerade NAT rules for WireGuard traffic.

Called by vpn-portal as:
    sudo /usr/bin/python3 /opt/vpn-portal/wg-apply-nat.py /tmp/wg-nat-XXXX.json

Payload: {"subnet": "10.200.20.0/24", "out_iface": "ens34"}
Stdout:  {"ok": true} or {"ok": true, "note": "..."}
Stderr:  {"error": "..."} on failure (+ non-zero exit)

Rules applied (equivalent to):
    nft add table ip nat
    nft 'add chain ip nat postrouting { type nat hook postrouting priority 100; }'
    nft add rule ip nat postrouting ip saddr <subnet> oifname "<out_iface>" masquerade
"""
import json
import os
import re
import subprocess
import sys

IFACE_RE  = re.compile(r'^[a-zA-Z0-9_.@:-]{1,20}$')
SUBNET_RE = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')


def die(msg):
    print(json.dumps({'error': msg}), file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        die('Usage: wg-apply-nat.py <json_file>')

    json_path = sys.argv[1]
    if not json_path.startswith('/tmp/'):
        die('json_file must be under /tmp/')

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception as e:
        die(f'Cannot read payload: {e}')

    subnet    = str(data.get('subnet', '')).strip()
    out_iface = str(data.get('out_iface', '')).strip()

    if not SUBNET_RE.match(subnet):
        die('Invalid subnet format')
    if not IFACE_RE.match(out_iface):
        die('Invalid outbound interface name')

    # Feed all three nft statements via stdin — no shell, no injection risk.
    # 'nft -f -' reads a script from stdin.
    # add table and add chain are idempotent on nft 0.9.3+ (Ubuntu 22.04+).
    nft_script = (
        'add table ip nat\n'
        'add chain ip nat postrouting { type nat hook postrouting priority 100; }\n'
        f'add rule ip nat postrouting ip saddr {subnet} oifname "{out_iface}" masquerade\n'
    )

    result = subprocess.run(
        ['nft', '-f', '-'],
        input=nft_script.encode(),
        capture_output=True
    )

    if result.returncode != 0:
        stderr = result.stderr.decode().strip()
        # "already exists" on table/chain is acceptable — rule was still applied
        if 'already exists' in stderr or 'File exists' in stderr:
            print(json.dumps({'ok': True, 'note': 'Table or chain already existed; masquerade rule was added.'}))
            return
        die(f'nft error: {stderr}')

    print(json.dumps({'ok': True}))


if __name__ == '__main__':
    main()
