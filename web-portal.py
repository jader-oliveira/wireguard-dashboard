from flask import Flask, request, jsonify, make_response, send_from_directory, redirect, url_for
from flask_talisman import Talisman  # Security headers (Helmet equivalent)
from flask_limiter import Limiter   # Rate limiting
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from functools import wraps
import boto3
import qrcode
import io
import base64
import os
import secrets
import re
import hmac
import hashlib
import subprocess
import glob
import time
import json
import ipaddress
import tempfile
from datetime import datetime, timedelta, timezone
from werkzeug.exceptions import HTTPException
from email_validator import validate_email, EmailNotValidError

WIREGUARD_CONFIG_DIR = '/etc/wireguard'

app = Flask(__name__, static_folder='static', static_url_path='')

# Validate required environment variables at startup
_REQUIRED_ENV = ['SECRET_KEY', 'COGNITO_USER_POOL_ID', 'COGNITO_CLIENT_ID', 'COGNITO_CLIENT_SECRET']
for _var in _REQUIRED_ENV:
    if not os.environ.get(_var):
        raise RuntimeError(f"Required environment variable '{_var}' is not set")

# Security Configuration (NIST 800-63B)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY'),
    SESSION_PERMANENT=False,
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=10),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.environ.get('APP_ENV') == 'production',
    SESSION_COOKIE_SAMESITE='Strict',
    # Disable Flask-WTF session-based CSRF — we use Double Submit Cookie instead
    WTF_CSRF_CHECK_DEFAULT=False,
)

# Initialize Extensions
_is_production = os.environ.get('APP_ENV') == 'production'
Talisman(app,
    force_https=_is_production,
    strict_transport_security=_is_production,
    strict_transport_security_max_age=31536000,
    content_security_policy={
        'default-src': "'self'",
        'script-src': "'self' https://cdn.jsdelivr.net",
        'style-src': "'self' https://cdn.jsdelivr.net 'unsafe-inline'",
        'img-src': "'self' data:",
        'font-src': "'self' https://cdn.jsdelivr.net",
        'connect-src': "'self' https://*.amazoncognito.com",
        'frame-ancestors': "'none'",
    },
    referrer_policy='strict-origin-when-cross-origin',
    feature_policy={
        'accelerometer': "'none'",
        'camera': "'none'",
        'geolocation': "'none'",
        'microphone': "'none'",
    }
)

csrf = CSRFProtect(app)

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["100 per 15 minute"],
    storage_uri="memory://",  # Use Redis in production: "redis://localhost:6379"
    headers_enabled=True,
)

# Stricter limit for login
login_limit = limiter.shared_limit("5 per 15 minute", scope="login")

# AWS Cognito Client
cognito = boto3.client('cognito-idp', region_name=os.environ.get('AWS_REGION', 'us-east-1'))
USER_POOL_ID = os.environ.get('COGNITO_USER_POOL_ID')
CLIENT_ID = os.environ.get('COGNITO_CLIENT_ID')
CLIENT_SECRET = os.environ.get('COGNITO_CLIENT_SECRET')

def compute_secret_hash(username: str) -> str:
    """Compute SECRET_HASH required when App Client has a client secret."""
    message = username + CLIENT_ID
    dig = hmac.new(CLIENT_SECRET.encode('utf-8'), msg=message.encode('utf-8'), digestmod=hashlib.sha256).digest()
    return base64.b64encode(dig).decode()

# Session store (replace with Redis in production)
session_store = {}

# ── Auth decorator ──────────────────────────────────────────────
# touch=False: background API calls (WireGuard data, auto-refresh) do NOT
# reset the idle timer — only explicit user-driven requests do.
def require_session(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get('_vpn_session')
        if not validate_session(session_id, touch=False):
            return jsonify({'error': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated

# ── WireGuard helpers ────────────────────────────────────────────
_PEER_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$')

def _valid_iface(name):
    """Strictly validate interface names to prevent path traversal."""
    return bool(re.match(r'^[a-zA-Z0-9_-]{1,16}$', name))

def _next_available_ip(iface_conf, peers_conf):
    """Return the next free /32 host IP in the interface subnet."""
    iface_addr = iface_conf.get('Address', '')
    if not iface_addr or '/' not in iface_addr:
        return None
    used = {iface_addr.split('/')[0]}
    for pc in peers_conf:
        for ip_cidr in pc.get('AllowedIPs', '').split(','):
            ip = ip_cidr.strip().split('/')[0]
            if ip:
                used.add(ip)
    try:
        network = ipaddress.IPv4Network(iface_addr, strict=False)
    except ValueError:
        return None
    for addr in network.hosts():
        if str(addr) not in used:
            return f'{addr}/32'
    return None

def _format_bytes(b):
    for unit in ['B', 'KiB', 'MiB', 'GiB', 'TiB']:
        if b < 1024:
            return f'{b:.1f} {unit}'
        b /= 1024
    return f'{b:.1f} PiB'

def _parse_wg_conf(conf_path):
    """Parse WireGuard .conf — never returns private keys or preshared keys.

    Peer names are read from comments in two common formats:
      # Name            <- comment immediately before [Peer]
      [Peer]
      # Name            <- comment immediately after [Peer] (wg-quick style)
      PublicKey = ...
    """
    iface, peers = {}, []
    section, current_peer, pending_comment = None, {}, None
    with open(conf_path, 'r') as fh:
        for raw in fh:
            line = raw.strip()
            if not line:
                # Only reset pending_comment between sections, not inside a peer block
                if section != 'peer':
                    pending_comment = None
                continue
            if line.startswith('#'):
                comment_val = line[1:].strip()
                if section == 'peer' and current_peer and not current_peer.get('_name'):
                    # Comment inside a peer block → use as name directly
                    current_peer['_name'] = comment_val
                else:
                    pending_comment = comment_val
                continue
            if line == '[Interface]':
                section = 'interface'
                pending_comment = None
                continue
            if line == '[Peer]':
                if section == 'peer' and current_peer:
                    peers.append(current_peer)
                section = 'peer'
                current_peer = {'_name': pending_comment or ''}
                pending_comment = None
                continue
            if '=' in line:
                k, _, v = line.partition('=')
                k, v = k.strip(), v.strip()
                if section == 'interface':
                    if k in ('PrivateKey',):  # never expose
                        continue
                    iface[k] = v
                elif section == 'peer':
                    if k in ('PresharedKey',):  # never expose
                        continue
                    current_peer[k] = v
    if section == 'peer' and current_peer:
        peers.append(current_peer)
    return iface, peers

def _wg_show_dump(iface_name):
    """Run `sudo wg show <iface> dump` and return (iface_status, peers_status_dict)."""
    try:
        r = subprocess.run(
            ['sudo', 'wg', 'show', iface_name, 'dump'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode != 0:
            return None, {}
        lines = [l for l in r.stdout.strip().split('\n') if l]
    except (FileNotFoundError, PermissionError, subprocess.TimeoutExpired):
        return None, {}

    iface_status = {}
    peers_status = {}
    for i, line in enumerate(lines):
        parts = line.split('\t')
        if i == 0:  # interface line: privkey pubkey listenport fwmark
            iface_status = {
                'public_key':   parts[1] if len(parts) > 1 else '',
                'listen_port':  parts[2] if len(parts) > 2 else '',
            }
        else:  # peer line: pubkey presharedkey endpoint allowedips latesthandshake rx tx keepalive
            if len(parts) < 8:
                continue
            pub = parts[0]
            peers_status[pub] = {
                'endpoint':          parts[2] if parts[2] not in ('(none)', '') else '',
                'latest_handshake':  int(parts[4]) if parts[4].isdigit() else 0,
                'rx_bytes':          int(parts[5]) if parts[5].isdigit() else 0,
                'tx_bytes':          int(parts[6]) if parts[6].isdigit() else 0,
                'keepalive':         parts[7] if parts[7] != 'off' else '0',
            }
    return iface_status, peers_status

def _service_status(iface_name):
    try:
        r = subprocess.run(
            ['sudo', 'systemctl', 'is-active', f'wg-quick@{iface_name}'],
            capture_output=True, text=True, timeout=5
        )
        return r.stdout.strip()  # 'active', 'inactive', 'failed'
    except Exception:
        return 'unknown'

def create_session(username, tokens):
    """Create secure session (NIST 800-63B)"""
    session_id = secrets.token_hex(32)
    session_data = {
        'username': username,
        'access_token': tokens.get('AccessToken'),
        'id_token': tokens.get('IdToken'),
        'refresh_token': tokens.get('RefreshToken'),
        'created_at': datetime.now(timezone.utc).isoformat(),
        'last_activity': datetime.now(timezone.utc),
        'ip': request.remote_addr,
        'user_agent': request.user_agent.string
    }
    session_store[session_id] = session_data
    return session_id

def validate_session(session_id, touch=True):
    """Validate session. touch=True updates last_activity (user-driven); touch=False for background polls."""
    if not session_id or session_id not in session_store:
        return None
    
    session = session_store[session_id]
    last_activity = session['last_activity']
    
    # Check 10-minute idle timeout (NIST 800-63B)
    if datetime.now(timezone.utc) - last_activity > timedelta(minutes=10):
        session_store.pop(session_id, None)
        return None
    
    # Only update last_activity for explicit user-driven requests
    if touch:
        session['last_activity'] = datetime.now(timezone.utc)
    return session

def sanitize_input(value):
    """XSS prevention"""
    if not value:
        return value
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', '', str(value))
    return clean.strip()

# Routes

# ── Double Submit Cookie CSRF ────────────────────────────────────────────────
# The token is stored in a plain readable cookie AND returned in JSON.
# On state-changing requests the client sends the token back in the
# X-CSRF-Token header.  We compare header vs cookie value.
# This is secure because SameSite=Strict prevents the cookie from being
# sent on cross-site requests, so an attacker can never forge a matching pair.

def _check_csrf():
    """Raise 400 if the CSRF Double Submit check fails."""
    cookie_token  = request.cookies.get('csrf_token', '')
    header_token  = (
        request.headers.get('X-CSRF-Token') or
        request.headers.get('X-CSRFToken') or
        ''
    )
    if not cookie_token or not header_token:
        from flask import abort
        abort(400, 'CSRF token missing')
    if not hmac.compare_digest(cookie_token, header_token):
        from flask import abort
        abort(400, 'CSRF token mismatch')

@app.route('/api/auth/csrf', methods=['GET'])
def get_csrf():
    """Issue a fresh CSRF token as a readable cookie + JSON."""
    token = secrets.token_hex(32)
    resp = jsonify({'csrf_token': token})
    resp.set_cookie(
        'csrf_token', token,
        httponly=False,          # JS must be able to read it (sent in header)
        samesite='Strict',
        secure=_is_production,
        max_age=3600,
        path='/'
    )
    return resp

@app.route('/api/auth/login', methods=['POST'])
@login_limit
def login():
    """Login endpoint (NIST 800-63B)"""
    _check_csrf()
    try:
        data = request.get_json()
        
        # Input validation (ISO 27002 A.9.2.1)
        username = sanitize_input(data.get('username', '')).strip().lower()
        password = data.get('password', '')
        
        # Accept username or email (Cognito resolves either)
        if not username or len(username) > 128:
            return jsonify({'error': 'Invalid credentials format'}), 400
        
        if not password or len(password) < 8 or len(password) > 256:
            return jsonify({'error': 'Invalid credentials format'}), 400
        
        # AWS Cognito Authentication
        try:
            response = cognito.initiate_auth(
                ClientId=CLIENT_ID,
                AuthFlow='USER_PASSWORD_AUTH',
                AuthParameters={
                    'USERNAME': username,
                    'PASSWORD': password,
                    'SECRET_HASH': compute_secret_hash(username)
                }
            )
            
            # Handle challenges
            if 'ChallengeName' in response:
                return jsonify({
                    'challengeName': response['ChallengeName'],
                    'session': response['Session'],
                    'userAttributes': response.get('ChallengeParameters', {}).get('userAttributes', {})
                }), 200
            
            # Direct authentication (rare with MFA)
            if 'AuthenticationResult' in response:
                session_id = create_session(username, response['AuthenticationResult'])
                
                resp = make_response(jsonify({
                    'success': True,
                    'tokens': {
                        'AccessToken': response['AuthenticationResult']['AccessToken'],
                        'IdToken': response['AuthenticationResult']['IdToken']
                    }
                }))
                
                # Set secure cookie (ISO 27002 A.12.3)
                resp.set_cookie(
                    '_vpn_session',
                    session_id,
                    httponly=True,
                    secure=os.environ.get('APP_ENV') == 'production',
                    samesite='Strict',
                    max_age=600,  # 10 minutes
                    path='/'
                )
                return resp
                
        except cognito.exceptions.NotAuthorizedException as e:
            app.logger.warning(f"[SECURITY] Failed login attempt for {username}: {e}")
            return jsonify({'error': 'Authentication failed'}), 401
        except cognito.exceptions.UserNotFoundException as e:
            app.logger.warning(f"[SECURITY] User not found for {username}: {e}")
            # Generic error to prevent user enumeration (NIST 800-63B)
            return jsonify({'error': 'Authentication failed'}), 401
        except cognito.exceptions.PasswordResetRequiredException:
            # Admin triggered a password reset — code already emailed to user
            app.logger.info(f"[SECURITY] Password reset required for {username}")
            return jsonify({'challengeName': 'PASSWORD_RESET_REQUIRED'}), 200
            
    except Exception as e:
        app.logger.error(f"[SECURITY] Login error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 401

@app.route('/api/auth/respond-to-challenge', methods=['POST'])
def respond_to_challenge():
    """Handle password change and TOTP verification"""
    _check_csrf()
    try:
        data = request.get_json()
        challenge_name = data.get('challengeName')
        username = sanitize_input(data.get('username', ''))
        session = data.get('session')
        
        challenge_responses = {'USERNAME': username}
        
        if challenge_name == 'NEW_PASSWORD_REQUIRED':
            new_password = data.get('newPassword', '')
            # Password policy check (NIST 800-63B)
            if len(new_password) < 12:
                return jsonify({'error': 'Password does not meet requirements'}), 400
            
            challenge_responses['NEW_PASSWORD'] = new_password
            
            # Add user attributes if provided (Cognito returns them as a JSON string)
            user_attrs = data.get('userAttributes', {})
            if isinstance(user_attrs, str):
                import json as _json
                try:
                    user_attrs = _json.loads(user_attrs)
                except Exception:
                    user_attrs = {}
            if isinstance(user_attrs, dict):
                for key, value in user_attrs.items():
                    challenge_responses[key] = value
                
        elif challenge_name == 'SOFTWARE_TOKEN_MFA':
            totp_code = sanitize_input(data.get('totpCode', ''))
            if not re.match(r'^\d{6}$', totp_code):
                return jsonify({'error': 'Invalid code format'}), 400
            challenge_responses['SOFTWARE_TOKEN_MFA_CODE'] = totp_code
        
        challenge_responses['SECRET_HASH'] = compute_secret_hash(username)
        response = cognito.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName=challenge_name,
            ChallengeResponses=challenge_responses,
            Session=session
        )
        
        # Check for more challenges
        if 'ChallengeName' in response:
            return jsonify({
                'challengeName': response['ChallengeName'],
                'session': response['Session']
            }), 200
        
        # Authentication complete
        if 'AuthenticationResult' in response:
            session_id = create_session(username, response['AuthenticationResult'])
            
            resp = make_response(jsonify({
                'success': True,
                'tokens': {
                    'AccessToken': response['AuthenticationResult']['AccessToken'],
                    'IdToken': response['AuthenticationResult']['IdToken']
                }
            }))
            
            resp.set_cookie(
                '_vpn_session',
                session_id,
                httponly=True,
                secure=os.environ.get('APP_ENV') == 'production',
                samesite='Strict',
                max_age=600,  # 10 minutes
                path='/'
            )
            return resp
            
    except Exception as e:
        app.logger.error(f"[SECURITY] Challenge error: {str(e)}")
        return jsonify({'error': 'Authentication failed'}), 401

@app.route('/api/auth/associate-mfa', methods=['POST'])
def associate_mfa():
    """Generate QR code for MFA setup using Cognito associate_software_token"""
    _check_csrf()
    try:
        data = request.get_json()
        session = data.get('session')
        username = sanitize_input(data.get('username', ''))

        # Request TOTP secret from Cognito using the MFA_SETUP challenge session
        assoc_response = cognito.associate_software_token(Session=session)
        secret_code = assoc_response['SecretCode']
        new_session = assoc_response['Session']

        # Build TOTP URI and generate QR code
        qr_url = f"otpauth://totp/VPN:{username}?secret={secret_code}&issuer=SecureVPN"

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(qr_url)
        qr.make(fit=True)

        img_buffer = io.BytesIO()
        qr.make_image(fill_color="black", back_color="white").save(img_buffer, format='PNG')
        img_buffer.seek(0)
        qr_b64 = base64.b64encode(img_buffer.getvalue()).decode()

        return jsonify({
            'qrCode': f'data:image/png;base64,{qr_b64}',
            'secretCode': secret_code,
            'session': new_session  # Updated session required for verify step
        }), 200

    except Exception as e:
        app.logger.error(f"[SECURITY] MFA setup error: {str(e)}")
        return jsonify({'error': 'Failed to setup MFA'}), 400

@app.route('/api/auth/verify-mfa-setup', methods=['POST'])
def verify_mfa_setup():
    """Verify TOTP setup and complete authentication"""
    _check_csrf()
    try:
        data = request.get_json()
        session = data.get('session')
        username = sanitize_input(data.get('username', ''))
        totp_code = sanitize_input(data.get('totpCode', ''))

        if not re.match(r'^\d{6}$', totp_code):
            return jsonify({'error': 'Invalid code format'}), 400

        # Verify TOTP code with Cognito
        verify_response = cognito.verify_software_token(
            Session=session,
            UserCode=totp_code,
            FriendlyDeviceName='Authenticator'
        )

        if verify_response.get('Status') != 'SUCCESS':
            return jsonify({'error': 'Invalid verification code'}), 400

        # Complete the MFA_SETUP challenge to obtain auth tokens
        auth_response = cognito.respond_to_auth_challenge(
            ClientId=CLIENT_ID,
            ChallengeName='MFA_SETUP',
            Session=verify_response['Session'],
            ChallengeResponses={
                'USERNAME': username,
                'SECRET_HASH': compute_secret_hash(username)
            }
        )

        if 'AuthenticationResult' not in auth_response:
            return jsonify({'error': 'Authentication failed after MFA setup'}), 401

        session_id = create_session(username, auth_response['AuthenticationResult'])

        resp = make_response(jsonify({
            'success': True,
            'tokens': {
                'AccessToken': auth_response['AuthenticationResult']['AccessToken'],
                'IdToken': auth_response['AuthenticationResult']['IdToken']
            }
        }))
        resp.set_cookie(
            '_vpn_session',
            session_id,
            httponly=True,
            secure=os.environ.get('APP_ENV') == 'production',
            samesite='Strict',
            max_age=600,  # 10 minutes
            path='/'
        )
        return resp

    except Exception as e:
        app.logger.error(f"[SECURITY] MFA verification error: {str(e)}")
        return jsonify({'error': 'Invalid verification code'}), 400

@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    """Initiate password reset — always returns success to prevent user enumeration"""
    _check_csrf()
    try:
        data = request.get_json()
        username = sanitize_input(data.get('username', '').strip()).lower()
        if not username or len(username) > 128:
            return jsonify({'success': True}), 200  # Don't reveal invalid input

        try:
            cognito.forgot_password(
                ClientId=CLIENT_ID,
                Username=username,
                SecretHash=compute_secret_hash(username)
            )
        except cognito.exceptions.UserNotFoundException:
            pass  # Don't reveal if user exists (NIST 800-63B)
        except cognito.exceptions.InvalidParameterException:
            pass  # User not confirmed — silently ignore
        except Exception as e:
            app.logger.warning(f"[SECURITY] Forgot password warning for {username}: {e}")

        return jsonify({'success': True}), 200

    except Exception as e:
        app.logger.error(f"[SECURITY] Forgot password error: {str(e)}")
        return jsonify({'success': True}), 200  # Always succeed (anti-enumeration)

@app.route('/api/auth/confirm-forgot-password', methods=['POST'])
def confirm_forgot_password():
    """Complete password reset with code from email"""
    _check_csrf()
    try:
        data = request.get_json()
        username = sanitize_input(data.get('username', '').strip()).lower()
        if not username or len(username) > 128:
            return jsonify({'error': 'Invalid input'}), 400

        code = sanitize_input(data.get('code', '').strip())
        new_password = data.get('newPassword', '')

        if not re.match(r'^\d{6}$', code):
            return jsonify({'error': 'Invalid code format'}), 400

        if len(new_password) < 12:
            return jsonify({'error': 'Password does not meet requirements'}), 400

        cognito.confirm_forgot_password(
            ClientId=CLIENT_ID,
            Username=username,
            ConfirmationCode=code,
            Password=new_password,
            SecretHash=compute_secret_hash(username)
        )

        return jsonify({'success': True}), 200

    except cognito.exceptions.CodeMismatchException:
        return jsonify({'error': 'Invalid or expired reset code'}), 400
    except cognito.exceptions.ExpiredCodeException:
        return jsonify({'error': 'Reset code has expired, please request a new one'}), 400
    except cognito.exceptions.InvalidPasswordException:
        return jsonify({'error': 'Password does not meet complexity requirements'}), 400
    except Exception as e:
        app.logger.error(f"[SECURITY] Confirm forgot password error: {str(e)}")
        return jsonify({'error': 'Failed to reset password. Please try again.'}), 400

@app.route('/api/user/profile', methods=['GET'])
def get_profile():
    """Protected route"""
    session_id = request.cookies.get('_vpn_session')
    session = validate_session(session_id)
    
    if not session:
        return jsonify({'error': 'Session expired'}), 401
    
    return jsonify({
        'username': session['username'],
        'authenticated': True
    }), 200

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    """Secure logout - revokes Cognito tokens and clears local session"""
    _check_csrf()
    session_id = request.cookies.get('_vpn_session')
    if session_id and session_id in session_store:
        access_token = session_store[session_id].get('access_token')
        if access_token:
            try:
                cognito.global_sign_out(AccessToken=access_token)
            except Exception as e:
                app.logger.warning(f"[SECURITY] Failed to revoke Cognito tokens: {e}")
        session_store.pop(session_id, None)

    resp = make_response(jsonify({'success': True}))
    resp.delete_cookie('_vpn_session')
    resp.delete_cookie('csrf_token')
    return resp

@app.route('/', methods=['GET', 'POST'])
def index():
    """Serve login page"""
    return send_from_directory('static', 'login.html')

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/home')
def home():
    """Protected dashboard - requires valid session"""
    session_id = request.cookies.get('_vpn_session')
    user_session = validate_session(session_id)
    if not user_session:
        return redirect(url_for('index'))
    return send_from_directory('static', 'home.html')

@app.route('/interfaces')
def interfaces_page():
    """Interface administration page"""
    session_id = request.cookies.get('_vpn_session')
    if not validate_session(session_id):
        return redirect(url_for('index'))
    return send_from_directory('static', 'interfaces.html')

@app.route('/api/wireguard/interfaces', methods=['GET'])
@require_session
def api_list_interfaces():
    """List available WireGuard interfaces from config dir."""
    try:
        confs = glob.glob(os.path.join(WIREGUARD_CONFIG_DIR, '*.conf'))
        names = sorted(os.path.basename(c).replace('.conf', '') for c in confs)
        return jsonify({'interfaces': names})
    except Exception as e:
        app.logger.error(f'[WG] list interfaces: {e}')
        return jsonify({'error': 'Failed to list interfaces'}), 500

@app.route('/api/dashboard/stats', methods=['GET'])
@require_session
def api_dashboard_stats():
    """Aggregated stats for the home dashboard overview."""
    try:
        now = time.time()
        confs = sorted(glob.glob(os.path.join(WIREGUARD_CONFIG_DIR, '*.conf')))
        iface_names = [os.path.basename(c).replace('.conf', '') for c in confs]

        total_ifaces   = len(iface_names)
        total_peers    = 0
        active_peers   = 0
        active_services = 0

        for name in iface_names:
            # Count service status
            svc = _service_status(name)
            if svc == 'active':
                active_services += 1

            # Parse conf for peer count
            conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
            try:
                _, peers_conf = _parse_wg_conf(conf_path)
                total_peers += len(peers_conf)
            except Exception:
                pass

            # Live handshake data for active peers
            _, peers_status = _wg_show_dump(name)
            for ps in peers_status.values():
                hs = ps.get('latest_handshake', 0)
                if hs > 0 and (now - hs) < 180:
                    active_peers += 1

        # Keys = folders under /opt/vpn-devices/
        keys_count = 0
        vpn_devices_dir = '/opt/vpn-devices'
        try:
            if os.path.isdir(vpn_devices_dir):
                keys_count = sum(
                    1 for e in os.scandir(vpn_devices_dir) if e.is_dir()
                )
        except PermissionError:
            app.logger.warning('[DASH] Cannot read /opt/vpn-devices — check permissions for manager user')

        return jsonify({
            'interfaces':      total_ifaces,
            'active_services': active_services,
            'total_peers':     total_peers,
            'active_peers':    active_peers,
            'keys_generated':  keys_count,
            'service_running': active_services > 0,
        }), 200

    except Exception as e:
        app.logger.error(f'[DASH] stats error: {e}')
        return jsonify({'error': 'Failed to load stats'}), 500

@app.route('/api/wireguard/interface/<name>', methods=['GET'])
@require_session
def api_get_interface(name):
    """Return interface config + live peer status."""
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400

    conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
    if not os.path.isfile(conf_path):
        return jsonify({'error': 'Interface not found'}), 404

    try:
        iface_conf, peers_conf = _parse_wg_conf(conf_path)
    except PermissionError:
        return jsonify({'error': 'Permission denied reading config. Run portal as root or add to wireguard group.'}), 403
    except Exception as e:
        app.logger.error(f'[WG] parse conf {name}: {e}')
        return jsonify({'error': 'Failed to read config'}), 500

    iface_status, peers_status = _wg_show_dump(name)
    svc = _service_status(name)
    now = time.time()

    # Merge conf + live status per peer
    peers_out = []
    for pc in peers_conf:
        pub = pc.get('PublicKey', '')
        ps  = peers_status.get(pub, {})
        hs  = ps.get('latest_handshake', 0)
        connected = hs > 0 and (now - hs) < 180  # handshake within 3 min = connected
        rx = ps.get('rx_bytes', 0)
        tx = ps.get('tx_bytes', 0)
        raw_ips = pc.get('AllowedIPs', '')
        ips = [ip.strip() for ip in raw_ips.split(',') if ip.strip()]
        peer_name = pc.get('_name') or (pub[:16] + '...' if pub else '—')
        peers_out.append({
            'name':             peer_name,
            'public_key':       pub,
            'public_key_short': pub[:20] + '…' if len(pub) > 20 else pub,
            'allowed_ips':      ips,
            'endpoint':         ps.get('endpoint', ''),
            'connected':        connected,
            'latest_handshake': hs,
            'rx':               _format_bytes(rx),
            'tx':               _format_bytes(tx),
            'keepalive':        pc.get('PersistentKeepalive', '—'),
        })

    pub_key = (iface_status or {}).get('public_key') or iface_conf.get('PublicKey', '—')
    listen_port = (iface_status or {}).get('listen_port') or iface_conf.get('ListenPort', '—')

    return jsonify({
        'name':            name,
        'service_status':  svc,
        'interface': {
            'public_key':   pub_key,
            'address':      iface_conf.get('Address', '—'),
            'listen_port':  listen_port,
            'dns':          iface_conf.get('DNS', '—'),
            'mtu':          iface_conf.get('MTU', '1420'),
            'post_up':      iface_conf.get('PostUp', ''),
            'post_down':    iface_conf.get('PostDown', ''),
        },
        'stats': {
            'total':     len(peers_out),
            'enabled':   len(peers_out),  # all conf peers are enabled by definition
            'connected': sum(1 for p in peers_out if p['connected']),
        },
        'peers': peers_out,
    })

# ── GET next available peer IP ───────────────────────────────────
@app.route('/api/wireguard/interface/<name>/next-ip', methods=['GET'])
@require_session
def api_next_peer_ip(name):
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400
    conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
    if not os.path.isfile(conf_path):
        return jsonify({'error': 'Interface not found'}), 404
    try:
        iface_conf, peers_conf = _parse_wg_conf(conf_path)
    except Exception as e:
        return jsonify({'error': 'Failed to read config'}), 500
    nxt = _next_available_ip(iface_conf, peers_conf)
    if nxt is None:
        return jsonify({'error': 'No IPs available in this subnet'}), 409
    return jsonify({'ip': nxt})


# ── GET peer QR code ─────────────────────────────────────────────────────────
@app.route('/api/wireguard/peer/qrcode', methods=['GET'])
@require_session
def api_peer_qrcode():
    """Return a base64 PNG QR code of the peer's client config file."""
    pubkey = request.args.get('pubkey', '').strip()
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', pubkey):
        return jsonify({'error': 'Invalid public key'}), 400

    payload  = {'pubkey': pubkey}
    tf_path  = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='wg-peerconf-', suffix='.json', dir='/tmp', delete=False
        ) as tf:
            json.dump(payload, tf)
            tf_path = tf.name
        os.chmod(tf_path, 0o600)

        result = subprocess.run(
            ['sudo', '/usr/bin/python3', '/opt/vpn-portal/wg-peer-conf.py', tf_path],
            capture_output=True, timeout=10
        )
        if result.returncode != 0:
            raw = result.stderr.decode().strip()
            try:
                msg = json.loads(raw).get('error', raw)
            except Exception:
                msg = raw or 'Config not found'
            return jsonify({'error': msg}), 404

        out_data   = json.loads(result.stdout.decode())
        conf_text  = out_data.get('conf', '')
        peer_label = out_data.get('name', 'peer')
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timed out reading peer config'}), 500
    except Exception as e:
        app.logger.error(f'[WG] qrcode: {e}')
        return jsonify({'error': 'Failed to read peer config'}), 500
    finally:
        if tf_path:
            try: os.unlink(tf_path)
            except OSError: pass

    try:
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=6,
            border=4,
        )
        qr.add_data(conf_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        b64 = base64.b64encode(buf.getvalue()).decode()
        return jsonify({'qr': f'data:image/png;base64,{b64}', 'name': peer_label})
    except Exception as e:
        app.logger.error(f'[WG] qrcode generate: {e}')
        return jsonify({'error': 'Failed to generate QR code'}), 500


# ── GET server network interfaces ─────────────────────────────────────────────
@app.route('/api/system/interfaces', methods=['GET'])
@require_session
def api_system_interfaces():
    """Return non-loopback, non-WireGuard interfaces on the server."""
    try:
        result = subprocess.run(
            ['ip', '-o', 'link', 'show'],
            capture_output=True, check=True, timeout=5
        )
        ifaces = []
        for line in result.stdout.decode().splitlines():
            parts = line.split(':', 2)
            if len(parts) < 2:
                continue
            name = parts[1].strip().split('@')[0]  # strip VLAN @parent
            if name and name != 'lo' and not name.startswith('wg'):
                ifaces.append(name)
        return jsonify({'interfaces': ifaces})
    except Exception as e:
        app.logger.error(f'[SYS] list interfaces: {e}')
        return jsonify({'error': 'Failed to list network interfaces'}), 500


# ── POST apply NAT masquerade ─────────────────────────────────────────────────
@app.route('/api/wireguard/interface/<name>/apply-nat', methods=['POST'])
@require_session
def api_apply_nat(name):
    """Apply nftables masquerade rules so VPN clients can reach the LAN."""
    _check_csrf()
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400

    data      = request.get_json(silent=True) or {}
    out_iface = str(data.get('out_iface', '')).strip()
    subnet    = str(data.get('subnet', '')).strip()

    if not re.match(r'^[a-zA-Z0-9_.@:-]{1,20}$', out_iface):
        return jsonify({'error': 'Invalid outbound interface name'}), 400
    try:
        ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return jsonify({'error': 'Invalid subnet'}), 400

    payload = {'subnet': subnet, 'out_iface': out_iface}
    tf_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='wg-nat-', suffix='.json', dir='/tmp', delete=False
        ) as tf:
            json.dump(payload, tf)
            tf_path = tf.name
        os.chmod(tf_path, 0o600)

        result = subprocess.run(
            ['sudo', '/usr/bin/python3', '/opt/vpn-portal/wg-apply-nat.py', tf_path],
            capture_output=True, timeout=15
        )
        if result.returncode != 0:
            raw = result.stderr.decode().strip()
            try:
                msg = json.loads(raw).get('error', raw)
            except Exception:
                msg = raw or 'Helper failed'
            return jsonify({'error': msg}), 500

        return jsonify(json.loads(result.stdout.decode()))
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timed out applying NAT rules'}), 500
    except Exception as e:
        app.logger.error(f'[NAT] apply: {e}')
        return jsonify({'error': 'Unexpected error applying NAT rules'}), 500
    finally:
        if tf_path:
            try: os.unlink(tf_path)
            except OSError: pass


# ── POST add peer ─────────────────────────────────────────────────
@app.route('/api/wireguard/interface/<name>/peer', methods=['POST'])
@require_session
def api_add_peer(name):
    _check_csrf()
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400

    data        = request.get_json(silent=True) or {}
    peer_name   = str(data.get('peer_name', '')).strip()
    allowed_ip  = str(data.get('allowed_ips', '')).strip()
    dns         = str(data.get('dns', '192.168.0.1')).strip()
    endpoint    = str(data.get('endpoint', '')).strip()
    routes      = str(data.get('routes', '192.168.0.0/24, 10.200.20.0/24')).strip()
    keepalive   = data.get('keepalive', 25)

    # Validate inputs
    if not _PEER_NAME_RE.match(peer_name):
        return jsonify({'error': 'Invalid peer name (alphanumeric, dash, dot, underscore; 1-63 chars)'}), 400
    try:
        ipaddress.IPv4Network(allowed_ip, strict=False)
    except ValueError:
        return jsonify({'error': f'Invalid AllowedIPs: {allowed_ip}'}), 400
    try:
        keepalive = int(keepalive)
        if not (0 <= keepalive <= 3600):
            raise ValueError
    except (ValueError, TypeError):
        return jsonify({'error': 'keepalive must be 0-3600'}), 400

    conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
    if not os.path.isfile(conf_path):
        return jsonify({'error': 'Interface not found'}), 404

    try:
        iface_conf, peers_conf = _parse_wg_conf(conf_path)
    except Exception:
        return jsonify({'error': 'Failed to read interface config'}), 500

    # Check IP not already in use
    used_ips = set()
    for pc in peers_conf:
        for ip_cidr in pc.get('AllowedIPs', '').split(','):
            used_ips.add(ip_cidr.strip().split('/')[0])
    if allowed_ip.split('/')[0] in used_ips:
        return jsonify({'error': f'IP {allowed_ip} is already assigned to another peer'}), 409

    # Check folder doesn't already exist
    device_dir = os.path.join('/opt/vpn-devices', peer_name)
    existing_check = subprocess.run(
        ['test', '-d', device_dir], capture_output=True
    )
    if existing_check.returncode == 0:
        return jsonify({'error': f'Peer "{peer_name}" already exists'}), 409

    # Get server public key
    iface_status, _ = _wg_show_dump(name)
    server_pub = (iface_status or {}).get('public_key', '')
    if not server_pub:
        return jsonify({'error': 'Cannot determine server public key'}), 500

    # Generate keys (no sudo needed — wg genkey/pubkey/genpsk are unprivileged)
    try:
        priv_res = subprocess.run(['wg', 'genkey'], capture_output=True, check=True)
        privkey  = priv_res.stdout.decode().strip()
        pub_res  = subprocess.run(['wg', 'pubkey'], input=priv_res.stdout, capture_output=True, check=True)
        pubkey   = pub_res.stdout.decode().strip()
        psk_res  = subprocess.run(['wg', 'genpsk'], capture_output=True, check=True)
        psk      = psk_res.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        app.logger.error(f'[WG] key generation failed: {e}')
        return jsonify({'error': 'Key generation failed'}), 500

    # Write payload JSON for helper
    payload = {
        'iface':      name,
        'peer_name':  peer_name,
        'peer_ip':    allowed_ip,
        'pubkey':     pubkey,
        'psk':        psk,
        'privkey':    privkey,
        'server_pub': server_pub,
        'dns':        dns,
        'endpoint':   endpoint,
        'routes':     routes,
        'keepalive':  keepalive,
    }

    tf_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='wg-addpeer-', suffix='.json',
            dir='/tmp', delete=False
        ) as tf:
            json.dump(payload, tf)
            tf_path = tf.name
        os.chmod(tf_path, 0o600)

        result = subprocess.run(
            ['sudo', '/usr/bin/python3', '/opt/vpn-portal/wg-add-peer.py', tf_path],
            capture_output=True, timeout=20
        )
        if result.returncode != 0:
            raw_err = result.stderr.decode().strip()
            app.logger.error(f'[WG] add-peer helper error: {raw_err}')
            try:
                err_msg = json.loads(raw_err).get('error', raw_err)
            except Exception:
                err_msg = raw_err or 'Helper failed'
            return jsonify({'error': err_msg}), 500
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Peer creation timed out'}), 500
    except Exception as e:
        app.logger.error(f'[WG] add-peer unexpected: {e}')
        return jsonify({'error': 'Unexpected error during peer creation'}), 500
    finally:
        if tf_path:
            try:
                os.unlink(tf_path)
            except OSError:
                pass

    return jsonify({
        'ok':         True,
        'peer_name':  peer_name,
        'public_key': pubkey,
        'allowed_ips': allowed_ip,
    })


# ── DELETE peer ───────────────────────────────────────────────────────────────
@app.route('/api/wireguard/interface/<name>/peer/<path:pubkey>', methods=['DELETE'])
@require_session
def api_delete_peer(name, pubkey):
    _check_csrf()
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400
    pubkey = pubkey.strip()
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', pubkey):
        return jsonify({'error': 'Invalid public key'}), 400

    conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
    if not os.path.isfile(conf_path):
        return jsonify({'error': 'Interface not found'}), 404

    payload = {'iface': name, 'pubkey': pubkey}
    tf_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='wg-delpeer-', suffix='.json', dir='/tmp', delete=False
        ) as tf:
            json.dump(payload, tf)
            tf_path = tf.name
        os.chmod(tf_path, 0o600)

        result = subprocess.run(
            ['sudo', '/usr/bin/python3', '/opt/vpn-portal/wg-delete-peer.py', tf_path],
            capture_output=True, timeout=15
        )
        if result.returncode != 0:
            raw = result.stderr.decode().strip()
            try:
                msg = json.loads(raw).get('error', raw)
            except Exception:
                msg = raw or 'Helper failed'
            return jsonify({'error': msg}), 500

        return jsonify(json.loads(result.stdout.decode()))
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timed out deleting peer'}), 500
    except Exception as e:
        app.logger.error(f'[WG] delete-peer: {e}')
        return jsonify({'error': 'Unexpected error deleting peer'}), 500
    finally:
        if tf_path:
            try: os.unlink(tf_path)
            except OSError: pass


# ── PATCH peer (edit name / AllowedIPs / keepalive) ──────────────────────────
@app.route('/api/wireguard/interface/<name>/peer/<path:pubkey>', methods=['PATCH'])
@require_session
def api_edit_peer(name, pubkey):
    _check_csrf()
    if not _valid_iface(name):
        return jsonify({'error': 'Invalid interface name'}), 400
    pubkey = pubkey.strip()
    if not re.match(r'^[A-Za-z0-9+/]{43}=$', pubkey):
        return jsonify({'error': 'Invalid public key'}), 400

    data        = request.get_json(silent=True) or {}
    new_name    = data.get('new_name')
    allowed_ips = data.get('allowed_ips')
    keepalive   = data.get('keepalive')

    if new_name is not None:
        new_name = str(new_name).strip()
        if not _PEER_NAME_RE.match(new_name):
            return jsonify({'error': 'Invalid peer name'}), 400
    if allowed_ips is not None:
        allowed_ips = str(allowed_ips).strip()
        try:
            for cidr in allowed_ips.split(','):
                ipaddress.IPv4Network(cidr.strip(), strict=False)
        except ValueError:
            return jsonify({'error': f'Invalid AllowedIPs: {allowed_ips}'}), 400
    if keepalive is not None:
        try:
            keepalive = int(keepalive)
            if not (0 <= keepalive <= 3600):
                raise ValueError
        except (ValueError, TypeError):
            return jsonify({'error': 'keepalive must be 0–3600'}), 400

    if new_name is None and allowed_ips is None and keepalive is None:
        return jsonify({'error': 'Nothing to update'}), 400

    conf_path = os.path.join(WIREGUARD_CONFIG_DIR, f'{name}.conf')
    if not os.path.isfile(conf_path):
        return jsonify({'error': 'Interface not found'}), 404

    payload = {'iface': name, 'pubkey': pubkey}
    if new_name    is not None: payload['new_name']    = new_name
    if allowed_ips is not None: payload['allowed_ips'] = allowed_ips
    if keepalive   is not None: payload['keepalive']   = keepalive

    tf_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', prefix='wg-editpeer-', suffix='.json', dir='/tmp', delete=False
        ) as tf:
            json.dump(payload, tf)
            tf_path = tf.name
        os.chmod(tf_path, 0o600)

        result = subprocess.run(
            ['sudo', '/usr/bin/python3', '/opt/vpn-portal/wg-edit-peer.py', tf_path],
            capture_output=True, timeout=15
        )
        if result.returncode != 0:
            raw = result.stderr.decode().strip()
            try:
                msg = json.loads(raw).get('error', raw)
            except Exception:
                msg = raw or 'Helper failed'
            return jsonify({'error': msg}), 500

        return jsonify(json.loads(result.stdout.decode()))
    except subprocess.TimeoutExpired:
        return jsonify({'error': 'Timed out editing peer'}), 500
    except Exception as e:
        app.logger.error(f'[WG] edit-peer: {e}')
        return jsonify({'error': 'Unexpected error editing peer'}), 500
    finally:
        if tf_path:
            try: os.unlink(tf_path)
            except OSError: pass


@app.errorhandler(Exception)
def handle_error(e):
    """Don't leak stack traces"""
    app.logger.error(f"[ERROR] {str(e)}")
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # WARNING: Don't use debug=True in production (RCE risk)
    # Use Gunicorn in production: gunicorn -w 4 -b 0.0.0.0:8078 app:app
    app.run(host='0.0.0.0', port=8078, debug=False)  # TLS terminated by nginx