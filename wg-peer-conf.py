#!/usr/bin/env python3
"""
Privileged helper — read a VPN peer client .conf by matching its public key.

Called by vpn-portal as:
    sudo /usr/bin/python3 /opt/vpn-portal/wg-peer-conf.py /tmp/wg-peerconf-XXXX.json

Payload: {"pubkey": "<44-char base64 WireGuard key>"}
Stdout:  {"conf": "<file contents>", "name": "<basename>"}
Stderr:  {"error": "<message>"} on failure (+ non-zero exit)
"""
import json
import os
import re
import sys

KEY_RE   = re.compile(r'^[A-Za-z0-9+/]{43}=$')
DEV_BASE = '/opt/vpn-devices'


def die(msg):
    print(json.dumps({'error': msg}), file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 2:
        die('Usage: wg-peer-conf.py <json_file>')

    json_path = sys.argv[1]
    if not json_path.startswith('/tmp/'):
        die('json_file must be under /tmp/')

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception as e:
        die(f'Cannot read payload: {e}')

    pubkey = str(data.get('pubkey', '')).strip()
    if not KEY_RE.match(pubkey):
        die('Invalid public key format')

    if not os.path.isdir(DEV_BASE):
        die(f'{DEV_BASE} does not exist')

    for device_dir in sorted(os.listdir(DEV_BASE)):
        full_dir = os.path.join(DEV_BASE, device_dir)
        if not os.path.isdir(full_dir):
            continue
        for fname in sorted(os.listdir(full_dir)):
            if not fname.endswith('.pub'):
                continue
            pub_path = os.path.join(full_dir, fname)
            try:
                with open(pub_path) as fh:
                    if fh.read().strip() == pubkey:
                        base_name = fname[:-4]  # strip .pub
                        conf_path = os.path.join(full_dir, f'{base_name}.conf')
                        if not os.path.isfile(conf_path):
                            die(f'Client config not found: {conf_path}')
                        with open(conf_path) as cf:
                            conf_content = cf.read()
                        print(json.dumps({'conf': conf_content, 'name': base_name}))
                        return
            except OSError:
                continue

    die('No device folder found matching this public key')


if __name__ == '__main__':
    main()
