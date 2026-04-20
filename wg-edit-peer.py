#!/usr/bin/env python3
"""
Privileged helper — edit a WireGuard peer (name, AllowedIPs, PersistentKeepalive).

Called by vpn-portal as:
    sudo /usr/bin/python3 /opt/vpn-portal/wg-edit-peer.py /tmp/wg-editpeer-XXXX.json

Payload:
  {
    "iface":      "wg0",
    "pubkey":     "<44-char base64 key>",
    "new_name":   "laptop-work",         # optional — renames device folder + files
    "allowed_ips": "10.200.20.3/32",     # optional — updates AllowedIPs
    "keepalive":  25                     # optional — 0 means disable
  }

Actions:
  1. Patch /etc/wireguard/<iface>.conf in-place
  2. Apply live changes via wg set
  3. Rename device folder/files if name changed

Stdout:  {"ok": true}
Stderr:  {"error": "..."} on failure (+ non-zero exit)
"""
import json
import os
import re
import subprocess
import sys

IFACE_RE = re.compile(r'^[a-zA-Z0-9_-]{1,16}$')
KEY_RE   = re.compile(r'^[A-Za-z0-9+/]{43}=$')
NAME_RE  = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$')
IP_RE    = re.compile(r'^(\d{1,3}\.){3}\d{1,3}/\d{1,2}(,\s*(\d{1,3}\.){3}\d{1,3}/\d{1,2})*$')
WG_BASE  = '/etc/wireguard'
DEV_BASE = '/opt/vpn-devices'


def die(msg):
    print(json.dumps({'error': msg}), file=sys.stderr)
    sys.exit(1)


def patch_conf(conf_path, pubkey, new_name, allowed_ips, keepalive):
    """Rewrite the [Peer] block matching pubkey with updated fields."""
    with open(conf_path, 'r') as fh:
        lines = fh.readlines()

    output      = []
    in_peer     = False
    peer_key    = None
    block       = []
    name_patched = False

    def build_patched_block(blk, upd_name, upd_ips, upd_ka):
        """Return lines with updated fields; preserve existing order."""
        result    = []
        has_ka    = False
        has_name  = False
        for ln in blk:
            s = ln.strip()
            if s.startswith('#') and not has_name and not any(
                    x.strip().startswith('PublicKey') for x in blk[:blk.index(ln)]):
                # First comment inside peer = name line
                if upd_name is not None:
                    result.append(f'# {upd_name}\n')
                    has_name = True
                else:
                    result.append(ln)
                    has_name = True
                continue
            if s.startswith('AllowedIPs') and upd_ips is not None:
                result.append(f'AllowedIPs = {upd_ips}\n')
                continue
            if s.startswith('PersistentKeepalive'):
                has_ka = True
                if upd_ka is not None and upd_ka > 0:
                    result.append(f'PersistentKeepalive = {upd_ka}\n')
                # if upd_ka == 0 → drop the line (disabling keepalive)
                continue
            result.append(ln)

        # Name comment not yet encountered (wasn't in original block)
        if upd_name is not None and not has_name:
            # Insert after [Peer] line
            insert_pos = next(
                (i + 1 for i, ln in enumerate(result) if ln.strip() == '[Peer]'), 1
            )
            result.insert(insert_pos, f'# {upd_name}\n')

        # Add keepalive if didn't exist and we want one
        if upd_ka is not None and upd_ka > 0 and not has_ka:
            result.append(f'PersistentKeepalive = {upd_ka}\n')

        return result

    i = 0
    while i < len(lines):
        line    = lines[i]
        stripped = line.strip()
        if stripped == '[Peer]':
            in_peer  = True
            peer_key = None
            block    = [line]
        elif in_peer:
            if stripped.startswith('[') and stripped != '[Peer]':
                # End of peer block — flush
                if peer_key == pubkey:
                    output.extend(build_patched_block(
                        block, new_name, allowed_ips, keepalive))
                    name_patched = True
                else:
                    output.extend(block)
                in_peer  = False
                peer_key = None
                block    = []
                output.append(line)
            else:
                block.append(line)
                if stripped.startswith('PublicKey'):
                    _, _, v = stripped.partition('=')
                    peer_key = v.strip()
        else:
            output.append(line)
        i += 1

    # Flush last peer block
    if in_peer and block:
        if peer_key == pubkey:
            output.extend(build_patched_block(block, new_name, allowed_ips, keepalive))
            name_patched = True
        else:
            output.extend(block)

    if not name_patched:
        die(f'Peer {pubkey[:16]}… not found in {conf_path}')

    with open(conf_path, 'w') as fh:
        fh.writelines(output)


def find_device_dir(pubkey):
    """Return (dir_path, base_name) for the device folder matching pubkey."""
    if not os.path.isdir(DEV_BASE):
        return None, None
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
                        return full, fname[:-4]   # strip .pub
            except OSError:
                pass
    return None, None


def main():
    if len(sys.argv) != 2:
        die('Usage: wg-edit-peer.py <json_file>')

    json_path = sys.argv[1]
    if not json_path.startswith('/tmp/'):
        die('json_file must be under /tmp/')

    try:
        with open(json_path) as fh:
            data = json.load(fh)
    except Exception as e:
        die(f'Cannot read payload: {e}')

    iface       = str(data.get('iface',  '')).strip()
    pubkey      = str(data.get('pubkey', '')).strip()
    new_name    = data.get('new_name')
    allowed_ips = data.get('allowed_ips')
    keepalive   = data.get('keepalive')   # None = don't change

    if not IFACE_RE.match(iface):
        die('Invalid interface name')
    if not KEY_RE.match(pubkey):
        die('Invalid public key format')
    if new_name is not None:
        new_name = str(new_name).strip()
        if not NAME_RE.match(new_name):
            die('Invalid peer name')
    if allowed_ips is not None:
        allowed_ips = str(allowed_ips).strip()
        if not IP_RE.match(allowed_ips.replace(' ', '')):
            die('Invalid AllowedIPs')
    if keepalive is not None:
        try:
            keepalive = int(keepalive)
            if not (0 <= keepalive <= 3600):
                raise ValueError
        except (ValueError, TypeError):
            die('keepalive must be 0–3600')

    conf_path = os.path.join(WG_BASE, f'{iface}.conf')
    if not os.path.isfile(conf_path):
        die(f'Interface config not found: {conf_path}')

    # 1. Patch conf
    try:
        patch_conf(conf_path, pubkey, new_name, allowed_ips, keepalive)
    except SystemExit:
        raise
    except Exception as e:
        die(f'Failed to patch conf: {e}')

    # 2. Apply live via wg set
    wg_args = ['wg', 'set', iface, 'peer', pubkey]
    if allowed_ips is not None:
        wg_args += ['allowed-ips', allowed_ips.replace(' ', '')]
    if keepalive is not None:
        wg_args += ['persistent-keepalive', str(keepalive)]
    if len(wg_args) > 5:
        subprocess.run(wg_args, capture_output=True)   # best-effort

    # 3. Rename device folder if name changed
    if new_name is not None:
        device_dir, base_name = find_device_dir(pubkey)
        if device_dir and base_name and base_name != new_name:
            new_dir = os.path.join(DEV_BASE, new_name)
            if os.path.exists(new_dir):
                die(f'Target device folder already exists: {new_dir}')
            os.rename(device_dir, new_dir)
            # Rename individual files inside
            for fname in os.listdir(new_dir):
                if fname.startswith(base_name + '.'):
                    ext = fname[len(base_name):]
                    src = os.path.join(new_dir, fname)
                    dst = os.path.join(new_dir, new_name + ext)
                    os.rename(src, dst)

    print(json.dumps({'ok': True}))


if __name__ == '__main__':
    main()
