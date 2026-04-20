# WireGuard VPN Portal

A self-hosted Flask web portal for managing WireGuard VPN peers, protected by AWS Cognito MFA (TOTP). Built for a specific server configuration — read every constraint below before deploying elsewhere.

---

## Table of Contents

1. [What It Does](#what-it-does)  
2. [Architecture](#architecture)  
3. [Hard Requirements](#hard-requirements)  
4. [Directory & File Layout](#directory--file-layout)  
5. [AWS Cognito Setup](#aws-cognito-setup)  
6. [Server Setup — Step by Step](#server-setup--step-by-step)  
7. [Environment Variables](#environment-variables)  
8. [sudoers Configuration](#sudoers-configuration)  
9. [WireGuard Configuration Conventions](#wireguard-configuration-conventions)  
10. [Systemd Service](#systemd-service)  
11. [Running Locally (Dev)](#running-locally-dev)  
12. [Feature Reference](#feature-reference)  
13. [Constraints & Assumptions](#constraints--assumptions)  
14. [Adapting to a New Environment](#adapting-to-a-new-environment)  

---

## What It Does

- Login via **username or email + password + TOTP MFA** (backed by AWS Cognito)
- **Password reset** flow: self-service (forgot password with username or email) and admin-initiated (Cognito console)
- **Dashboard** with live stats: interfaces, peers, active connections, generated keys
- **Interfaces page**: list/manage WireGuard interfaces and their peers
- Per-peer actions: view details, show QR code (client config), edit, delete
- Add peer with auto-suggested next available IP
- Apply NAT/masquerade rules via `nftables`
- Idle session timeout (10 min) + server-side session polling
- Full CSRF protection (Double Submit Cookie pattern)

---

## Architecture

```
Browser ──HTTPS──► Flask (web-portal.py) ──► AWS Cognito (auth)
                        │
                        ├── reads /etc/wireguard/*.conf  (as wg-portal group)
                        ├── sudo ──► /opt/vpn-portal/*.py helpers  (root)
                        └── /opt/vpn-devices/<name>/              (root-owned)
```

**Privilege separation model:**  
The Flask app runs as `manager:wg-portal`. Any operation that requires root (writing WireGuard conf, calling `wg set`, managing nftables) is done through locked Python helper scripts in `/opt/vpn-portal/`, called via a tightly scoped sudoers file — one rule per script, argument wildcard fixed to `/tmp/wg-<prefix>-*.json`.

---

## Hard Requirements

| Requirement | Value |
|---|---|
| **OS** | Ubuntu 24.04 LTS (uses `nftables`, `systemd`, `wg-quick`) |
| **Python** | 3.11+ |
| **WireGuard tools** | `wireguard-tools` package (`wg`, `wg-quick`) |
| **nftables** | `nftables` package (for NAT feature) |
| **AWS account** | Cognito User Pool required — no alternative auth supported |
| **AWS region** | Configurable via `AWS_REGION` env var (default: `us-east-1`) |
| **IAM** | The server needs `cognito-idp:*` permissions (or scoped to `InitiateAuth`, `RespondToAuthChallenge`, `AssociateSoftwareToken`, `VerifySoftwareToken`, `GlobalSignOut`, `ForgotPassword`, `ConfirmForgotPassword`) |

---

## Directory & File Layout

```
/app/                          ← Flask app root (WorkingDirectory in systemd)
├── web-portal.py              ← Main Flask app
├── env.conf                   ← Environment variables (EnvironmentFile in service)
├── .venv/                     ← Python virtual environment
├── static/
│   ├── login.html
│   ├── app.js
│   ├── home.html
│   ├── home.js
│   ├── interfaces.html
│   ├── interfaces.js
│   └── favicon.svg

/opt/vpn-portal/               ← Root-owned helper scripts (chmod 750, chown root:root)
├── wg-add-peer.py             ← Adds a new peer to wg conf + creates /opt/vpn-devices/ folder
├── wg-delete-peer.py          ← Removes peer from conf + deletes device folder
├── wg-edit-peer.py            ← Patches peer in conf (name, AllowedIPs, keepalive)
├── wg-peer-conf.py            ← Reads client .conf by matching public key
└── wg-apply-nat.py            ← Applies nftables masquerade rules

/opt/vpn-devices/              ← Root-owned peer key storage
└── <peer-name>/
    ├── <peer-name>.key        ← Client private key
    ├── <peer-name>.pub        ← Client public key
    ├── <peer-name>.psk        ← Pre-shared key
    └── <peer-name>.conf       ← Complete client WireGuard config (for QR code)

/etc/wireguard/
└── wg0.conf                   ← WireGuard server config (root:wg-portal, 640)

/etc/sudoers.d/vpn-portal      ← Locked sudo rules for the helper scripts
```

---

## AWS Cognito Setup

1. **Create a User Pool** (AWS Console → Cognito → Create user pool)
   - Sign-in options: **User name** + **Email** (both must be checked)
   - User name case sensitivity: **Not case sensitive**
   - MFA: **Authenticator apps (TOTP)** — set to **Required**
   - Password policy: minimum 12 chars, require uppercase/lowercase/numbers/symbols
   - Self-service reset: **Enabled** (sends code via email)

2. **Create an App Client** (within the User Pool)
   - App type: **Other** (not Cognito Hosted UI)
   - Auth flows to **enable**: `ALLOW_USER_PASSWORD_AUTH`, `ALLOW_REFRESH_TOKEN_AUTH`
   - Auth flows to **disable**: `ALLOW_USER_SRP_AUTH`, `ALLOW_CUSTOM_AUTH`, `ALLOW_ADMIN_USER_PASSWORD_AUTH` — not used, unnecessary attack surface
   - **Generate a client secret** — required by this app (used for SECRET_HASH)
   - Token expiration: Access token 10 min, Refresh token your preference

3. **Note down:**
   - User Pool ID: `eu-west-1_XXXXXXXXX`
   - App Client ID
   - App Client Secret

4. **Create users manually** (Users tab → Create user)
   - Set a temporary password — user will be forced to change on first login
   - After first login + password change, they'll be prompted to set up TOTP

---

## Server Setup — Step by Step

### 1. System packages

```bash
sudo apt update && sudo apt install -y \
  python3.11 python3.11-venv \
  wireguard wireguard-tools \
  nftables
```

### 2. Users and groups

```bash
# Create the group WireGuard conf will be readable by
sudo groupadd wg-portal

# Create the portal user (or use existing 'manager')
sudo useradd -m -s /bin/bash manager
sudo usermod -aG wg-portal manager
```

### 3. App directory

```bash
sudo mkdir -p /app
sudo chown manager:manager /app
cd /app

# Copy all files from this repo into /app
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 4. Environment file

```bash
sudo nano /app/env.conf
```

See [Environment Variables](#environment-variables) section. File must be `chmod 600` and owned by `manager`.

```bash
sudo chmod 600 /app/env.conf
sudo chown manager:manager /app/env.conf
```

### 5. Helper scripts

```bash
sudo mkdir -p /opt/vpn-portal
sudo cp wg-add-peer.py wg-delete-peer.py wg-edit-peer.py wg-peer-conf.py wg-apply-nat.py /opt/vpn-portal/
sudo chown root:root /opt/vpn-portal/*.py
sudo chmod 750 /opt/vpn-portal/*.py
```

### 6. Peer device directory

```bash
sudo mkdir -p /opt/vpn-devices
sudo chown root:root /opt/vpn-devices
sudo chmod 755 /opt/vpn-devices
```

### 7. WireGuard config permissions

The app reads `/etc/wireguard/wg0.conf` as the `wg-portal` group:

```bash
sudo chown root:wg-portal /etc/wireguard/wg0.conf
sudo chmod 640 /etc/wireguard/wg0.conf
```

### 8. sudoers

```bash
sudo cp /path/to/repo/sudoers-vpn-portal /etc/sudoers.d/vpn-portal
sudo chmod 440 /etc/sudoers.d/vpn-portal
sudo visudo -c   # validate — fix any errors before proceeding
```

See [sudoers Configuration](#sudoers-configuration) for exact contents.

### 9. Systemd service

```bash
sudo cp vpn-portal.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now vpn-portal.service
sudo systemctl status vpn-portal.service
```

---

## Environment Variables

All variables go in `/app/env.conf`. Format: `KEY=value` (no `export`, no quotes unless value has spaces).

| Variable | Required | Description |
|---|---|---|
| `SECRET_KEY` | ✅ | Flask secret key — generate with `openssl rand -hex 32` |
| `COGNITO_USER_POOL_ID` | ✅ | e.g. `eu-west-1_s4kMLXc1j` |
| `COGNITO_CLIENT_ID` | ✅ | App client ID from Cognito |
| `COGNITO_CLIENT_SECRET` | ✅ | App client secret from Cognito |
| `AWS_REGION` | optional | Defaults to `us-east-1` |
| `APP_ENV` | optional | Set to `production` to enable HTTPS-only cookies and HSTS |

Example `/app/env.conf`:
```
SECRET_KEY=your-64-char-hex-string-here
COGNITO_USER_POOL_ID=eu-west-1_xxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxx
COGNITO_CLIENT_SECRET=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
AWS_REGION=eu-west-1
APP_ENV=production
```

> ⚠️ Never commit this file to version control. It contains secrets.

---

## sudoers Configuration

File: `/etc/sudoers.d/vpn-portal`  
Permissions: `root:root 440`

```
manager ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpn-portal/wg-add-peer.py /tmp/wg-addpeer-*.json
manager ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpn-portal/wg-peer-conf.py *
manager ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpn-portal/wg-apply-nat.py /tmp/wg-nat-*.json
manager ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpn-portal/wg-delete-peer.py /tmp/wg-delpeer-*.json
manager ALL=(root) NOPASSWD: /usr/bin/python3 /opt/vpn-portal/wg-edit-peer.py /tmp/wg-editpeer-*.json
```

Additionally, `wg show` and `systemctl` reads are called directly with sudo:

```
manager ALL=(root) NOPASSWD: /usr/bin/wg show * dump
manager ALL=(root) NOPASSWD: /usr/bin/systemctl is-active wg-quick@*
```

> Validate with `sudo visudo -c` every time you edit this file.

---

## WireGuard Configuration Conventions

The app parses `/etc/wireguard/*.conf` and expects this specific format for named peers:

```ini
[Interface]
Address    = 10.200.20.1/24
ListenPort = 51820
PrivateKey = <server-private-key>

[Peer]
# my-laptop           ← peer name: comment on the line immediately after [Peer]
PublicKey    = <client-public-key>
PresharedKey = <psk>
AllowedIPs   = 10.200.20.2/32
PersistentKeepalive = 25
```

**Critical:** The `# name` comment must be on the **first line after `[Peer]`**, before `PublicKey`. If missing, the portal uses a truncated public key as the display name. No other comment placement is supported.

Peer device files in `/opt/vpn-devices/<name>/` must be named `<name>.key`, `<name>.pub`, `<name>.psk`, `<name>.conf` — matching the comment name exactly.

---

## Systemd Service

File: `/etc/systemd/system/vpn-portal.service`

```ini
[Unit]
Description=VPN Portal Flask App
After=network.target

[Service]
Type=simple
User=manager
Group=wg-portal
WorkingDirectory=/app
EnvironmentFile=/app/env.conf
ExecStart=/app/.venv/bin/python3 /app/web-portal.py
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Useful commands:
```bash
sudo systemctl status vpn-portal.service
sudo journalctl -u vpn-portal.service -f
sudo systemctl restart vpn-portal.service
```

---

## Running Locally (Dev)

```bash
cd wireguard-portal
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

export SECRET_KEY=$(openssl rand -hex 32)
export COGNITO_USER_POOL_ID=eu-west-1_XXXXXXXX
export COGNITO_CLIENT_ID=your-client-id
export COGNITO_CLIENT_SECRET=your-client-secret
export AWS_REGION=eu-west-1

python3 web-portal.py
```

The app listens on `http://0.0.0.0:8078`.

> Without a real server WireGuard setup, the Interfaces page will show errors — that's expected in dev. Auth and dashboard will work normally against Cognito.

---

## Feature Reference

| Feature | Route | Notes |
|---|---|---|
| Login | `GET /` | Username or email + password + TOTP |
| Forgot password | `POST /api/auth/forgot-password` | Accepts username or email — Cognito sends code to registered email |
| Confirm reset | `POST /api/auth/confirm-forgot-password` | Username or email + code + new password |
| Admin reset | (automatic) | Cognito console → portal auto-routes to confirm step |
| Dashboard | `GET /home` | Stats: interfaces, peers, active, keys |
| Interface list | `GET /interfaces` | All WG interfaces |
| Interface detail | `GET /api/wireguard/interface/<name>` | Config + live peer status |
| Add peer | `POST /api/wireguard/interface/<name>/peer` | Auto IP, writes conf |
| Edit peer | `PATCH /api/wireguard/interface/<name>/peer/<pubkey>` | Name, IPs, keepalive |
| Delete peer | `DELETE /api/wireguard/interface/<name>/peer/<pubkey>` | Removes from conf + filesystem |
| QR code | `GET /api/wireguard/peer/qrcode?pubkey=…` | PNG of client config |
| Apply NAT | `POST /api/wireguard/interface/<name>/apply-nat` | nftables masquerade |
| Dashboard stats | `GET /api/dashboard/stats` | JSON stats for home page |
| Logout | `POST /api/auth/logout` | Revokes Cognito tokens, clears session |

---

## Constraints & Assumptions

These are **not** configuration options — they are baked into the code. Changing them requires code edits.

| Constraint | Detail |
|---|---|
| **OS** | Ubuntu 24.04 only. Uses `nftables` (not `iptables`), `wg-quick@` systemd unit naming, `/etc/wireguard/` path. |
| **Python path** | Helpers called as `/usr/bin/python3` — must exist at that exact path on the server. |
| **App path** | Hardcoded to `/app/` in the systemd service. |
| **Helpers path** | Hardcoded to `/opt/vpn-portal/` in `web-portal.py` subprocess calls. |
| **Devices path** | Hardcoded to `/opt/vpn-devices/` in helpers and `api_dashboard_stats`. |
| **WG config dir** | Hardcoded to `/etc/wireguard/` via `WIREGUARD_CONFIG_DIR` constant in `web-portal.py`. |
| **Run user** | `manager` — must match the `User=` in the service file AND every sudoers entry. |
| **Group** | `wg-portal` — must be the group that owns `/etc/wireguard/*.conf` (640). |
| **Single Cognito pool** | One User Pool only. Multi-tenant not supported. |
| **Session store** | In-memory dictionary in `web-portal.py`. Restarts clear all sessions. Use Redis for production HA. |
| **Rate limiter** | In-memory (flask-limiter default). Use Redis URI for multi-process/HA. |
| **Interface name length** | Max 16 chars, alphanumeric + underscore + hyphen only. |
| **Peer name** | Max 63 chars, must start with alphanumeric, allows `.`, `_`, `-`. |
| **TOTP only** | No SMS MFA. Cognito pool must have TOTP enabled and set as required. |
| **App Client Secret** | Required. The `SECRET_HASH` HMAC is always computed. Client without secret will fail. |
| **Port** | Default Flask dev port `5000`. For production use gunicorn behind nginx or a reverse proxy. |

---

## Adapting to a New Environment

If you want to deploy this on a different server (different IP, different user, different paths), here is every place you must change:

### Change the run user (from `manager` to something else)

1. `vpn-portal.service` → `User=` and `Group=`
2. Every line in `/etc/sudoers.d/vpn-portal`
3. File ownership: `/app/`, `/app/env.conf`, all static files

### Change `/app` to another path

1. `vpn-portal.service` → `WorkingDirectory=` and `ExecStart=`
2. `vpn-portal.service` → `EnvironmentFile=`
3. Rebuild `.venv` in the new location

### Change `/opt/vpn-portal` (helper scripts path)

1. All `subprocess.run(...)` calls in `web-portal.py` — search for `/opt/vpn-portal/`
2. All lines in `/etc/sudoers.d/vpn-portal`

### Change `/opt/vpn-devices` (peer key storage path)

1. `wg-add-peer.py` — `DEVICES_DIR` constant
2. `wg-delete-peer.py` — `DEVICES_DIR` constant
3. `wg-edit-peer.py` — `DEVICES_DIR` constant
4. `wg-peer-conf.py` — `DEVICES_DIR` constant
5. `web-portal.py` → `api_dashboard_stats()` — `vpn_devices_dir` variable

### Change `/etc/wireguard` (WireGuard config path)

1. `web-portal.py` → `WIREGUARD_CONFIG_DIR` constant (line ~21)
2. `wg-add-peer.py` — conf path references
3. `wg-delete-peer.py` — conf path references
4. `wg-edit-peer.py` — conf path references

### Change Cognito region / pool

1. `/app/env.conf` → update all `COGNITO_*` and `AWS_REGION` variables
2. No code changes needed — all read from environment
