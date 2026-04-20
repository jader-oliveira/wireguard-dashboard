#!/usr/bin/env python3
"""
Privileged helper — create a new WireGuard peer.

Called by vpn-portal as:
    sudo /usr/bin/python3 /opt/vpn-portal/wg-add-peer.py /tmp/wg-addpeer-XXXX.json

The JSON payload is written by the portal, this script does all operations
that require root (mkdir, write key files, append wg0.conf, wg addconf).

Exits 0 on success and prints {"ok": true} on stdout.
Exits non-zero on error and prints {"error": "..."} on stderr.
"""
import json
import os
import re
import subprocess
import sys

# ── Validation ────────────────────────────────────────────────────────────────
IFACE_RE  = re.compile(r'^[a-zA-Z0-9_-]{1,16}$')
NAME_RE   = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$')
IP_RE     = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$')
KEY_RE    = re.compile(r'^[A-Za-z0-9+/]{43}=$')          # 44-char base64 WG key
ENDPT_RE  = re.compile(r'^[a-zA-Z0-9._:-]{1,100}$')
DNS_RE    = re.compile(r'^[a-zA-Z0-9.,: ]{1,200}$')

WG_BASE   = '/etc/wireguard'
DEV_BASE  = '/opt/vpn-devices'


def die(msg):
    print(json.dumps({'error': msg}), file=sys.stderr)
    sys.exit(1)


def validate(data):
    if not IFACE_RE.match(data.get('iface', '')):
        die('Invalid interface name')
    if not NAME_RE.match(data.get('peer_name', '')):
        die('Invalid peer name')
    for ip in data.get('peer_ip', '').split(','):
        if not IP_RE.match(ip.strip()):
            die(f'Invalid peer IP: {ip.strip()}')
    for key_field in ('pubkey', 'psk', 'privkey', 'server_pub'):
        if not KEY_RE.match(data.get(key_field, '')):
            die(f'Invalid key field: {key_field}')
    dns = data.get('dns', '')
    if dns and not DNS_RE.match(dns):
        die('Invalid DNS')
    ep = data.get('endpoint', '')
    if ep and not ENDPT_RE.match(ep):
        die('Invalid endpoint')


def main():
    if len(sys.argv) != 2:
        die('Usage: wg-add-peer.py <json_file>')

    json_path = sys.argv[1]
    # Only allow files in /tmp
    if not json_path.startswith('/tmp/'):
        die('json_file must be under /tmp/')

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception as e:
        die(f'Cannot read payload: {e}')

    validate(data)

    iface       = data['iface']
    peer_name   = data['peer_name']
    peer_ip     = data['peer_ip']
    pubkey      = data['pubkey']
    psk         = data['psk']
    privkey     = data['privkey']
    server_pub  = data['server_pub']
    dns         = data.get('dns', '192.168.0.1').strip()
    endpoint    = data.get('endpoint', '').strip()
    routes      = data.get('routes', '192.168.0.0/24, 10.200.20.0/24').strip()
    keepalive   = int(data.get('keepalive', 25))

    device_dir = os.path.join(DEV_BASE, peer_name)
    conf_path  = os.path.join(WG_BASE, f'{iface}.conf')

    if not os.path.isfile(conf_path):
        die(f'Interface config not found: {conf_path}')

    if os.path.exists(device_dir):
        die(f'Device folder already exists: {device_dir}')

    # ── Create device directory ───────────────────────────────────────────────
    os.makedirs(device_dir, mode=0o700, exist_ok=False)

    # ── Write key files ───────────────────────────────────────────────────────
    for fname, content in [
        (f'{peer_name}.key', privkey + '\n'),
        (f'{peer_name}.pub', pubkey  + '\n'),
        (f'{peer_name}.psk', psk     + '\n'),
    ]:
        fpath = os.path.join(device_dir, fname)
        with open(fpath, 'w') as fh:
            fh.write(content)
        os.chmod(fpath, 0o600)

    # ── Write client config ───────────────────────────────────────────────────
    ka_line = f'PersistentKeepalive = {keepalive}\n' if keepalive > 0 else ''
    ep_line = f'Endpoint = {endpoint}\n' if endpoint else ''
    dns_line = f'DNS = {dns}\n' if dns else ''

    client_conf = (
        '[Interface]\n'
        f'Address = {peer_ip}\n'
        f'PrivateKey = {privkey}\n'
        f'{dns_line}'
        '\n'
        '[Peer]\n'
        f'PublicKey = {server_pub}\n'
        f'PresharedKey = {psk}\n'
        f'{ep_line}'
        f'AllowedIPs = {routes}\n'
        f'{ka_line}'
    )
    cpath = os.path.join(device_dir, f'{peer_name}.conf')
    with open(cpath, 'w') as fh:
        fh.write(client_conf)
    os.chmod(cpath, 0o600)

    # ── Append [Peer] block to interface conf ─────────────────────────────────
    server_peer_block = (
        '\n'
        '[Peer]\n'
        f'# {peer_name}\n'
        f'PublicKey = {pubkey}\n'
        f'PresharedKey = {psk}\n'
        f'AllowedIPs = {peer_ip}\n'
    )
    if keepalive > 0:
        server_peer_block += f'PersistentKeepalive = {keepalive}\n'

    with open(conf_path, 'a') as fh:
        fh.write(server_peer_block)

    # ── Apply peer live via wg addconf ────────────────────────────────────────
    live_block = (
        '[Peer]\n'
        f'PublicKey = {pubkey}\n'
        f'PresharedKey = {psk}\n'
        f'AllowedIPs = {peer_ip}\n'
    )
    if keepalive > 0:
        live_block += f'PersistentKeepalive = {keepalive}\n'

    tmpf = f'/tmp/wg-live-{peer_name}.conf'
    try:
        with open(tmpf, 'w') as fh:
            fh.write(live_block)
        os.chmod(tmpf, 0o600)
        subprocess.run(['wg', 'addconf', iface, tmpf], check=True)
    except subprocess.CalledProcessError as e:
        # Peer was added to conf but live apply failed — not fatal, will work after next restart
        print(json.dumps({'ok': True, 'warning': f'wg addconf failed (will apply on restart): {e}'}))
        return
    finally:
        try:
            os.unlink(tmpf)
        except OSError:
            pass

    print(json.dumps({'ok': True}))


if __name__ == '__main__':
    main()
