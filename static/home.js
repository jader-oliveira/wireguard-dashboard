// home.js — Dashboard logic

// ── CONFIG — easy to change ──────────────────────────────────────
const IDLE_TIMEOUT_MS   = 10 * 60 * 1000;  // 10 minutes: auto-logout after inactivity
const IDLE_WARNING_SEC  = 60;               // show warning this many seconds before logout
const SESSION_POLL_MS   = 60 * 1000;        // check server session every 60 seconds

// ── State ────────────────────────────────────────────────────────
let idleTimer        = null;
let warningTimer     = null;
let countdownTimer   = null;
let warningActive    = false;

// ── Load user info ───────────────────────────────────────────────
(async function loadUser() {
    try {
        const r = await fetch('/api/user/profile', { credentials: 'same-origin' });
        if (!r.ok) { hardLogout(); return; }
        const data = await r.json();
        const email = data.username || '';
        document.getElementById('userEmail').textContent = email;
        const initials = email.split('@')[0].slice(0, 2).toUpperCase();
        document.getElementById('userAvatar').textContent = initials;
    } catch {
        hardLogout();
    }
})();

// ── Logout ───────────────────────────────────────────────────────
document.getElementById('logoutBtn').addEventListener('click', () => performLogout('manual'));

async function performLogout(reason) {
    clearAllTimers();

    // Show toast
    const toastEl = document.getElementById('logoutToast');
    if (toastEl) {
        const msg = reason === 'idle'
            ? '<i class="bi bi-clock me-2 text-warning"></i>Session expired — logging out…'
            : '<i class="bi bi-box-arrow-right me-2 text-danger"></i>Signing you out…';
        toastEl.querySelector('.toast-body').innerHTML = msg;
        new bootstrap.Toast(toastEl, { autohide: false }).show();
    }

    try {
        // Get fresh CSRF token
        const csrfResp = await fetch('/api/auth/csrf', { credentials: 'same-origin' });
        const csrfData = await csrfResp.json();
        const csrfToken = csrfData.csrf_token;

        // Call logout — server: global_sign_out (revokes Cognito tokens) + clears session cookie
        await fetch('/api/auth/logout', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'X-CSRF-Token': csrfToken }
        });
    } catch { /* always redirect even if request fails */ }

    // Clear any remaining client-side state
    hardLogout();
}

function hardLogout() {
    clearAllTimers();
    // Belt-and-suspenders: try to clear any storage (should be none per OWASP but cover all bases)
    try { sessionStorage.clear(); } catch {}
    try { localStorage.clear();   } catch {}
    // Replace history so back button doesn't return to dashboard
    window.location.replace('/');
}

// ── Idle Timeout ─────────────────────────────────────────────────
function resetIdleTimer() {
    if (warningActive) return;  // don't reset while warning is showing — user must click "Stay"
    clearAllTimers();
    // Schedule warning IDLE_WARNING_SEC before the timeout
    warningTimer = setTimeout(showIdleWarning, IDLE_TIMEOUT_MS - (IDLE_WARNING_SEC * 1000));
    idleTimer    = setTimeout(() => performLogout('idle'), IDLE_TIMEOUT_MS);
}

function showIdleWarning() {
    warningActive = true;
    let remaining = IDLE_WARNING_SEC;
    document.getElementById('idleCountdown').textContent = remaining;
    document.getElementById('idleOverlay').style.display = 'flex';

    countdownTimer = setInterval(() => {
        remaining--;
        const el = document.getElementById('idleCountdown');
        if (el) el.textContent = remaining;
        if (remaining <= 0) clearInterval(countdownTimer);
    }, 1000);
}

document.getElementById('idleStayBtn').addEventListener('click', () => {
    warningActive = false;
    clearInterval(countdownTimer);
    document.getElementById('idleOverlay').style.display = 'none';
    // Ping server to confirm session still valid
    fetch('/api/user/profile', { credentials: 'same-origin' })
        .then(r => { if (!r.ok) hardLogout(); else resetIdleTimer(); })
        .catch(hardLogout);
});

// Activity events that reset the idle clock
['mousedown', 'mousemove', 'keydown', 'touchstart', 'scroll', 'click'].forEach(evt =>
    document.addEventListener(evt, resetIdleTimer, { passive: true })
);

// ── Server-side session polling ───────────────────────────────────
setInterval(async () => {
    // Never poll while idle overlay is showing — let the countdown run
    if (document.getElementById('idleOverlay').style.display === 'flex') return;
    try {
        const r = await fetch('/api/user/profile', { credentials: 'same-origin' });
        if (!r.ok) performLogout('idle');
    } catch {
        performLogout('idle');
    }
}, SESSION_POLL_MS);

// ── Prevent back-button return after logout ───────────────────────
history.pushState(null, '', location.href);
window.addEventListener('popstate', () => history.pushState(null, '', location.href));

// ── Helpers ───────────────────────────────────────────────────────
function clearAllTimers() {
    clearTimeout(idleTimer);
    clearTimeout(warningTimer);
    clearInterval(countdownTimer);
}

// ── Dashboard stats ───────────────────────────────────────────────
async function loadDashboardStats() {
    try {
        const r = await fetch('/api/dashboard/stats', { credentials: 'same-origin' });
        if (!r.ok) return;
        const d = await r.json();

        // Status pill
        const pill    = document.getElementById('statusPill');
        const dot     = document.getElementById('statusDot');
        const pillTxt = document.getElementById('statusPillText');
        if (d.service_running) {
            pill.style.background   = 'rgba(46,204,113,0.12)';
            pill.style.borderColor  = 'rgba(46,204,113,0.3)';
            pill.style.color        = '#2ecc71';
            dot.style.background    = '#2ecc71';
            pillTxt.textContent     = `Service Running (${d.active_services} active)`;
        } else {
            pill.style.background   = 'rgba(231,76,60,0.12)';
            pill.style.borderColor  = 'rgba(231,76,60,0.3)';
            pill.style.color        = '#e74c3c';
            dot.style.background    = '#e74c3c';
            dot.style.animation     = 'none';
            pillTxt.textContent     = 'No WireGuard Service Active';
        }

        // Stat cards
        document.getElementById('statActivePeers').textContent = d.active_peers  ?? '—';
        document.getElementById('statInterfaces').textContent  = d.interfaces    ?? '—';
        document.getElementById('statTotalPeers').textContent  = d.total_peers   ?? '—';
        document.getElementById('statKeys').textContent        = d.keys_generated ?? '—';
    } catch { /* non-fatal — leave placeholders */ }
}

loadDashboardStats();

// Start idle tracking on load
resetIdleTimer();

