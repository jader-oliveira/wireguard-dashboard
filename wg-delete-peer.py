#!/usr/bin/env python3
"""
Privileged helper — delete a WireGuard peer.

Called by vpn-portal as:
    sudo /usr/bin/python3 /opt/vpn-portal/wg-delete-peer.py /tmp/wg-delpeer-XXXX.json

Payload: {"iface": "wg0", "pubkey": "<44-char base64 key>"}

Actions:
  1. Remove peer from /etc/wireguard/<iface>.conf
  2. Apply live removal: wg set <iface> peer <pubkey> remove
  3. Delete /opt/vpn-devices/<folder>/ whose <name>.pub matches the pubkey

Stdout:  {"ok": true}
Stderr:  {"error": "..."} on failure (+ non-zero exit)
"""
import json
import os
import re
import shutil
import subprocess
import sys

IFACE_RE = re.compile(r'^[a-zA-Z0-9_-]{1,16}$')
KEY_RE   = re.compile(r'^[A-Za-z0-9+/]{43}=$')
WG_BASE  = '/etc/wireguard'
DEV_BASE = '/opt/vpn-devices'


def die(msg):
    print(json.dumps({'error': msg}), file=sys.stderr)
    sys.exit(1)


def rewrite_conf_without_peer(conf_path, pubkey):
    """Remove the [Peer] block matching pubkey from the conf file."""
    with open(conf_path, 'r') as fh:
        lines = fh.readlines()

    output   = []
    in_peer  = False
    peer_key = None
    block    = []

    def flush_block():
        if in_peer and peer_key == pubkey:
            # Drop one leading blank line that separates this block
            if output and output[-1].strip() == '':
                output.pop()
        else:
            output.extend(block)

    for line in lines:
        stripped = line.strip()
        if stripped == '[Peer]':
            flush_block()
            in_peer  = True
            peer_key = None
            block    = [line]
        elif stripped.startswith('[') and stripped != '[Peer]':
            flush_block()
            in_peer  = False
            peer_key = None
            block    = [line]
            output.append(line)
            block = []
        elif in_peer:
            block.append(line)
            if stripped.startswith('PublicKey'):
                _, _, v = stripped.partition('=')
                peer_key = v.strip()
        else:
            output.append(line)

    flush_block()

    # Strip trailing blank lines then ensure single newline at end
    while output and output[-1].strip() == '':
        output.pop()
    output.append('\n')

    with open(conf_path, 'w') as fh:
        fh.writelines(output)


def find_device_dir(pubkey):
    """Return the device folder path whose <name>.pub contains pubkey, or None."""
    if not os.path.isdir(DEV_BASE):
        return None
    for entry in sorted(os.listdir(DEV_BASE)):
        full = os.path.join(DEV_BASE, entry)
        if not os.path.isdir(full):
            continue
        for fname in os.listdir(full):
            if not fname.endswith('.pub'):
                continue
            try:
                with open(os.path.join(full, fname)) as fh:
                    if fh.read().strip() == pubkey:
                        return full
            except OSError:
                pass
    return None


def main():
    if len(sys.argv) != 2:
        die('Usage: wg-delete-peer.py <json_file>')

    json_path = sys.argv[1]
    if not json_path.startswith('/tmp/'):
        die('json_file must be under /tmp/')

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception as e:
        die(f'Cannot read payload: {e}')

    iface  = str(data.get('iface',  '')).strip()
    pubkey = str(data.get('pubkey', '')).strip()

    if not IFACE_RE.match(iface):
        die('Invalid interface name')
    if not KEY_RE.match(pubkey):
        die('Invalid public key format')

    conf_path = os.path.join(WG_BASE, f'{iface}.conf')
    if not os.path.isfile(conf_path):
        die(f'Interface config not found: {conf_path}')

    # 1. Rewrite conf without this peer
    try:
        rewrite_conf_without_peer(conf_path, pubkey)
    except Exception as e:
        die(f'Failed to update conf: {e}')

    # 2. Remove live (best-effort — interface might not be up)
    subprocess.run(['wg', 'set', iface, 'peer', pubkey, 'remove'],
                   capture_output=True)

    # 3. Remove device directory
    device_dir = find_device_dir(pubkey)
    if device_dir:
        try:
            shutil.rmtree(device_dir)
        except Exception as e:
            # Conf already updated — warn but don't fail
            print(json.dumps({'ok': True, 'warning': f'Could not remove {device_dir}: {e}'}))
            return

    print(json.dumps({'ok': True}))


if __name__ == '__main__':
    main()
