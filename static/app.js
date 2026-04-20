// Security Configuration
const CONFIG = {
    API_BASE_URL: '/api/auth', // Same-origin to avoid CORS issues
    SESSION_TIMEOUT: 900000, // 15 minutes (NIST 800-63B)
    MAX_RETRIES: 3,
    RETRY_WINDOW: 300000 // 5 minutes
};

// State Management (in-memory only, no localStorage for sensitive data per OWASP)
let sessionState = {
    username: null,
    session: null,
    userAttributes: null,
    retryCount: 0,
    lastRetry: 0,
    resetUsername: null
};

// CSRF Token Management
let csrfToken = null;

// Initialize CSRF token on load
async function initializeCSRF() {
    try {
        const response = await fetch('/api/auth/csrf', {
            credentials: 'same-origin'
        });
        const data = await response.json();
        csrfToken = data.csrf_token;
    } catch (e) {
        console.error('Failed to initialize CSRF protection');
    }
}

// Utility: Sanitize input (XSS prevention)
function sanitizeInput(input) {
    const div = document.createElement('div');
    div.textContent = input;
    return div.innerHTML;
}

// Utility: Show/Hide steps
function showStep(stepId) {
    document.querySelectorAll('.form-step').forEach(step => {
        step.classList.remove('active');
    });
    document.getElementById(stepId).classList.add('active');
}

// Utility: Show error (generic messages to prevent user enumeration)
function showError(elementId, message) {
    const el = document.getElementById(elementId);
    const genericMessage = 'Authentication failed. Please check your credentials and try again.';
    el.textContent = message || genericMessage;
    el.style.display = 'block';
    setTimeout(() => {
        el.style.display = 'none';
    }, 5000);
}

// Utility: Toggle password visibility
function togglePassword(fieldId) {
    const field = document.getElementById(fieldId);
    const toggle = field.nextElementSibling;
    if (field.type === 'password') {
        field.type = 'text';
        toggle.textContent = 'Hide';
    } else {
        field.type = 'password';
        toggle.textContent = 'Show';
    }
}

// Utility: Set loading state
function setLoading(buttonId, loading) {
    const btn = document.getElementById(buttonId);
    if (loading) {
        btn.disabled = true;
        btn.classList.add('loading');
    } else {
        btn.disabled = false;
        btn.classList.remove('loading');
    }
}

// Wire up password visibility toggle (replaces inline onclick blocked by CSP)
document.querySelectorAll('.password-toggle[data-toggle]').forEach(btn => {
    btn.addEventListener('click', () => togglePassword(btn.dataset.toggle));
});

// Step 1: Login Handler
document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    // Rate limiting check (client-side)
    const now = Date.now();
    if (sessionState.retryCount >= CONFIG.MAX_RETRIES &&
        now - sessionState.lastRetry < CONFIG.RETRY_WINDOW) {
        showError('loginError', 'Too many attempts. Please try again in 5 minutes.');
        return;
    }

    const username = sanitizeInput(document.getElementById('username').value.trim().toLowerCase());
    const password = document.getElementById('password').value;

    // Client-side validation (defense in depth)
    if (!username || !password || password.length < 8) {
        showError('loginError', 'Invalid input format');
        return;
    }

    setLoading('loginBtn', true);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/login`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({ username, password })
        });

        const data = await response.json();

        if (!response.ok) {
            sessionState.retryCount++;
            sessionState.lastRetry = now;
            throw new Error(data.error || 'Authentication failed');
        }

        // Reset retry count on success
        sessionState.retryCount = 0;
        sessionState.username = username;
        sessionState.session = data.session;
        sessionState.userAttributes = data.userAttributes;

        // Route based on challenge
        if (data.challengeName === 'NEW_PASSWORD_REQUIRED') {
            showStep('step-new-password');
        } else if (data.challengeName === 'MFA_SETUP') {
            showStep('step-mfa-setup');
            fetchQRCode(data.session);
        } else if (data.challengeName === 'SOFTWARE_TOKEN_MFA') {
            showStep('step-totp');
            document.getElementById('totpCode').focus();
        } else if (data.challengeName === 'PASSWORD_RESET_REQUIRED') {
            // Admin triggered a reset — code was already sent to user's email
            sessionState.resetUsername = username;
            const infoEl = document.getElementById('forgotConfirmError');
            infoEl.style.background = 'rgba(59, 130, 246, 0.12)';
            infoEl.style.borderColor = 'rgba(59, 130, 246, 0.5)';
            infoEl.style.color = '#93c5fd';
            infoEl.textContent = 'Your password has been reset by an administrator. A reset code has been sent to your email.';
            infoEl.style.display = 'block';
            showStep('step-forgot-confirm');
        } else if (data.tokens) {
            window.location.href = '/home';
        }

    } catch (error) {
        showError('loginError', error.message);
        setLoading('loginBtn', false);
    }
});

// Step 2: New Password Handler
document.getElementById('newPasswordForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const newPassword = document.getElementById('newPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    if (newPassword.length < 12) {
        showError('passwordError', 'Password must be at least 12 characters');
        return;
    }
    if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) ||
        !/[0-9]/.test(newPassword) || !/[!@#$%^&*]/.test(newPassword)) {
        showError('passwordError', 'Password must include uppercase, lowercase, number, and symbol');
        return;
    }
    if (newPassword !== confirmPassword) {
        showError('passwordError', 'Passwords do not match');
        return;
    }

    setLoading('passwordBtn', true);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/respond-to-challenge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                challengeName: 'NEW_PASSWORD_REQUIRED',
                username: sessionState.username,
                session: sessionState.session,
                newPassword: newPassword,
                userAttributes: sessionState.userAttributes
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Password update failed');
        }

        if (data.challengeName === 'MFA_SETUP') {
            sessionState.session = data.session;
            showStep('step-mfa-setup');
            fetchQRCode(data.session);
        }

    } catch (error) {
        showError('passwordError', error.message);
        setLoading('passwordBtn', false);
    }
});

// Fetch QR Code for MFA Setup
async function fetchQRCode(session) {
    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/associate-mfa`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                username: sessionState.username,
                session: session
            })
        });

        const data = await response.json();

        if (data.qrCode) {
            document.getElementById('qrCode').src = data.qrCode;
            document.getElementById('secretKey').textContent = data.secretCode;
            // Update session — Cognito returns a new session after associate_software_token
            sessionState.session = data.session;
        }
    } catch (error) {
        showError('mfaSetupError', 'Failed to generate QR code. Please refresh.');
    }
}

// Step 3: MFA Setup Verification
document.getElementById('mfaSetupForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const totpCode = document.getElementById('setupTotpCode').value;

    if (!/^\d{6}$/.test(totpCode)) {
        showError('mfaSetupError', 'Please enter a valid 6-digit code');
        return;
    }

    setLoading('setupMfaBtn', true);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/verify-mfa-setup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                username: sessionState.username,
                session: sessionState.session,
                totpCode: totpCode
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Invalid verification code');
        }

        window.location.href = '/home';

    } catch (error) {
        showError('mfaSetupError', error.message);
        setLoading('setupMfaBtn', false);
    }
});

// Step 4: TOTP Verification
document.getElementById('totpForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const totpCode = document.getElementById('totpCode').value;

    if (!/^\d{6}$/.test(totpCode)) {
        showError('totpError', 'Please enter a valid 6-digit code');
        return;
    }

    setLoading('totpBtn', true);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/respond-to-challenge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRF-Token': csrfToken
            },
            credentials: 'same-origin',
            body: JSON.stringify({
                challengeName: 'SOFTWARE_TOKEN_MFA',
                username: sessionState.username,
                session: sessionState.session,
                totpCode: totpCode
            })
        });

        const data = await response.json();

        if (!response.ok) {
            sessionState.retryCount++;
            throw new Error(data.error || 'Invalid authentication code');
        }

        window.location.href = '/home';

    } catch (error) {
        showError('totpError', error.message);
        setLoading('totpBtn', false);
    }
});

// ── Forgot Password link ─────────────────────────────────────────────────────
document.getElementById('forgotPasswordLink').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('forgotRequestError').style.display = 'none';
    document.getElementById('forgotRequestSuccess').style.display = 'none';
    showStep('step-forgot-request');
});

document.getElementById('backToLoginFromForgot').addEventListener('click', (e) => {
    e.preventDefault();
    showStep('step-login');
});

document.getElementById('backToForgotRequest').addEventListener('click', (e) => {
    e.preventDefault();
    document.getElementById('forgotConfirmError').style.display = 'none';
    showStep('step-forgot-request');
});

// ── Forgot Password — Step 1: Request Code ────────────────────────────────────
document.getElementById('forgotRequestForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const email = sanitizeInput(document.getElementById('forgotEmail').value.trim().toLowerCase());
    if (!email) {
        showError('forgotRequestError', 'Please enter your username or email');
        return;
    }

    setLoading('forgotRequestBtn', true);

    try {
        await fetch(`${CONFIG.API_BASE_URL}/forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            credentials: 'same-origin',
            body: JSON.stringify({ username: email })
        });

        // Always show success regardless of server response (anti-enumeration)
        sessionState.resetUsername = email;
        const successEl = document.getElementById('forgotRequestSuccess');
        successEl.textContent = 'If that account is registered, a reset code has been sent to your email. Check your inbox (and spam folder).';
        successEl.style.display = 'block';

        setTimeout(() => {
            successEl.style.display = 'none';
            showStep('step-forgot-confirm');
        }, 3000);

    } catch (err) {
        showError('forgotRequestError', 'Failed to send reset code. Please try again.');
    } finally {
        setLoading('forgotRequestBtn', false);
    }
});

// ── Forgot Password — Step 2: Confirm Code + New Password ────────────────────
document.getElementById('forgotConfirmForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const code            = document.getElementById('resetCode').value.trim();
    const newPassword     = document.getElementById('resetPassword').value;
    const confirmPassword = document.getElementById('resetPasswordConfirm').value;

    if (!/^\d{6}$/.test(code)) {
        showError('forgotConfirmError', 'Please enter the 6-digit code from your email');
        return;
    }
    if (newPassword.length < 12) {
        showError('forgotConfirmError', 'Password must be at least 12 characters');
        return;
    }
    if (!/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) ||
        !/[0-9]/.test(newPassword) || !/[!@#$%^&*]/.test(newPassword)) {
        showError('forgotConfirmError', 'Password must include uppercase, lowercase, number, and symbol');
        return;
    }
    if (newPassword !== confirmPassword) {
        showError('forgotConfirmError', 'Passwords do not match');
        return;
    }

    setLoading('forgotConfirmBtn', true);

    try {
        const response = await fetch(`${CONFIG.API_BASE_URL}/confirm-forgot-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken },
            credentials: 'same-origin',
            body: JSON.stringify({
                username: sessionState.resetUsername,
                code: code,
                newPassword: newPassword
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || 'Failed to reset password');
        }

        // Success — full page redirect clears all JS state (OWASP: credential change must
        // invalidate existing session context; prevents back-button replay)
        sessionState.resetUsername = null;
        try { sessionStorage.setItem('_vpn_pwreset', '1'); } catch (_) {}
        window.location.replace('/');
        return; // keep spinner until navigation completes

    } catch (err) {
        showError('forgotConfirmError', err.message);
        setLoading('forgotConfirmBtn', false);
    }
});

// Session timeout warning (NIST 800-63B)
let sessionTimer;
function resetSessionTimer() {
    clearTimeout(sessionTimer);
    sessionTimer = setTimeout(() => {
        document.getElementById('timeoutWarning').style.display = 'block';
        setTimeout(() => {
            window.location.href = '/logout';
        }, 60000); // 1 minute warning
    }, CONFIG.SESSION_TIMEOUT);
}

// Monitor user activity
['mousedown', 'keydown', 'touchstart', 'scroll'].forEach(event => {
    document.addEventListener(event, resetSessionTimer, true);
});

// Initialize
initializeCSRF();
resetSessionTimer();

// Show post-reset success banner (set before redirect in confirm flow)
(function () {
    try {
        if (!sessionStorage.getItem('_vpn_pwreset')) return;
        sessionStorage.removeItem('_vpn_pwreset');
        const el = document.getElementById('loginError');
        el.style.background    = 'rgba(46, 204, 113, 0.15)';
        el.style.borderColor   = 'rgba(46, 204, 113, 0.5)';
        el.style.color         = '#9fffbf';
        el.textContent = 'Password reset successfully. Please sign in with your new password.';
        el.style.display = 'block';
        setTimeout(() => { el.style.display = 'none'; el.removeAttribute('style'); }, 8000);
    } catch (_) {}
})();

// Prevent back button after logout (MITRE ATT&CK T1539 mitigation)
if (window.history && window.history.pushState) {
    window.history.pushState(null, null, window.location.href);
    window.onpopstate = function () {
        window.history.pushState(null, null, window.location.href);
    };
}
