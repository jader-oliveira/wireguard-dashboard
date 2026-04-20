/**
 * interfaces.js — WireGuard Interface Administration Page
 * CSP-compliant: no inline handlers. All events via addEventListener.
 */
(function () {
    'use strict';

    // ── Config ──────────────────────────────────────────────────────
    const AUTO_REFRESH_MS  = 30_000;   // 30 s live refresh
    const IDLE_TIMEOUT_MS  = 10 * 60 * 1000;
    const IDLE_WARNING_SEC = 60;
    const SESSION_POLL_MS  = 60_000;

    // ── State ────────────────────────────────────────────────────────
    let allPeers       = [];
    let filteredPeers  = [];
    let currentPage    = 1;
    let perPage        = 10;
    let currentIfaceData = null;
    let autoRefreshTimer = null;
    let idleTimer        = null;
    let idleCountInterval= null;

    // ── DOM refs ─────────────────────────────────────────────────────
    const ifaceSelector     = document.getElementById('ifaceSelector');
    const refreshBtn        = document.getElementById('refreshBtn');
    const loadingState      = document.getElementById('loadingState');
    const errorState        = document.getElementById('errorState');
    const errorMsg          = document.getElementById('errorMsg');
    const noIfacesState     = document.getElementById('noIfacesState');
    const ifaceCard         = document.getElementById('ifaceCard');
    const ifaceCardTitle    = document.getElementById('ifaceCardTitle');
    const ifaceInfoGrid     = document.getElementById('ifaceInfoGrid');
    const totalPeersBadge   = document.getElementById('totalPeersBadge');
    const connectedPeersBadge = document.getElementById('connectedPeersBadge');
    const peersCard         = document.getElementById('peersCard');
    const peersTableBody    = document.getElementById('peersTableBody');
    const peerSearch        = document.getElementById('peerSearch');
    const paginationInfo    = document.getElementById('paginationInfo');
    const paginationBtns    = document.getElementById('paginationBtns');
    const perPageSelect     = document.getElementById('perPageSelect');
    const serviceBadgeWrap  = document.getElementById('serviceBadgeWrap');
    const lastUpdated       = document.getElementById('lastUpdated');
    const selectAll         = document.getElementById('selectAll');
    const logoutBtn         = document.getElementById('logoutBtn');
    const idleOverlay       = document.getElementById('idleOverlay');
    const idleCountdown     = document.getElementById('idleCountdown');
    const idleStayBtn       = document.getElementById('idleStayBtn');
    const userAvatar        = document.getElementById('userAvatar');
    const userEmail         = document.getElementById('userEmail');
    const addPeerBtn        = document.getElementById('addPeerBtn');
    const applyNatBtn       = document.getElementById('applyNatBtn');

    // ── Add Peer modal element refs (resolved on demand) ─────────────
    const getApEl = id => document.getElementById(id);

    // ── Helpers ──────────────────────────────────────────────────────
    function escHtml(str) {
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;');
    }

    function showOnly(el) {
        [loadingState, errorState, noIfacesState].forEach(e => {
            if (e) e.style.display = 'none';
        });
        if (el) el.style.display = '';
    }

    function setLoading(on) {
        if (on) {
            ifaceCard.style.display  = 'none';
            peersCard.style.display  = 'none';
            loadingState.style.removeProperty('display');
        } else {
            loadingState.style.display = 'none';
        }
    }

    function formatHandshake(epoch) {
        if (!epoch) return '—';
        const diff = Math.floor(Date.now() / 1000) - epoch;
        if (diff < 10)    return 'just now';
        if (diff < 60)    return `${diff}s ago`;
        if (diff < 3600)  return `${Math.floor(diff/60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff/3600)}h ago`;
        return `${Math.floor(diff/86400)}d ago`;
    }

    // Convert interface address (e.g. 10.200.20.1/24) to network (10.200.20.0/24)
    function ipToNetwork(cidr) {
        if (!cidr || !cidr.includes('/')) return cidr || '';
        const [ip, bits] = cidr.split('/');
        const prefix = parseInt(bits, 10);
        const parts  = ip.split('.').map(Number);
        const ipInt  = ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
        const mask   = prefix === 0 ? 0 : (0xFFFFFFFF << (32 - prefix)) >>> 0;
        const netInt = (ipInt & mask) >>> 0;
        const net    = [(netInt >>> 24) & 0xFF, (netInt >>> 16) & 0xFF,
                        (netInt >>> 8)  & 0xFF, netInt & 0xFF].join('.');
        return `${net}/${prefix}`;
    }

    // ── CSRF ─────────────────────────────────────────────────────────
    let csrfToken = null;
    async function fetchCsrf() {
        try {
            const r = await fetch('/api/auth/csrf');
            const d = await r.json();
            csrfToken = d.csrf_token;
        } catch (_) { /* ignore */ }
    }

    // ── User profile ─────────────────────────────────────────────────
    async function loadUser() {
        try {
            const r = await fetch('/api/user/profile', { credentials: 'same-origin' });
            if (r.status === 401) { window.location.replace('/'); return; }
            const d = await r.json();
            const email = d.email || d.username || 'user';
            if (userEmail) userEmail.textContent = email;
            if (userAvatar) userAvatar.textContent = email[0].toUpperCase();
        } catch (_) { /* non-critical */ }
    }

    // ── Interface list ────────────────────────────────────────────────
    async function loadInterfaces() {
        try {
            const r = await fetch('/api/wireguard/interfaces', { credentials: 'same-origin' });
            if (r.status === 401) { window.location.replace('/'); return; }
            const d = await r.json();

            if (!d.interfaces || d.interfaces.length === 0) {
                ifaceCard.style.display = 'none';
                peersCard.style.display = 'none';
                showOnly(noIfacesState);
                return;
            }

            ifaceSelector.innerHTML = d.interfaces
                .map(n => `<option value="${escHtml(n)}">${escHtml(n)}</option>`)
                .join('');

            // Load first interface automatically
            await loadInterface(d.interfaces[0]);
        } catch (e) {
            showError('Failed to contact the API. Check server logs.');
        }
    }

    // ── Interface detail ──────────────────────────────────────────────
    async function loadInterface(name) {
        if (!name) return;
        setLoading(true);

        try {
            const r = await fetch(`/api/wireguard/interface/${encodeURIComponent(name)}`, {
                credentials: 'same-origin'
            });

            if (r.status === 401) { window.location.replace('/'); return; }
            if (r.status === 403) {
                showError('Permission denied. The portal needs root or wireguard group access to read configs.');
                return;
            }
            if (!r.ok) {
                const d = await r.json().catch(() => ({}));
                showError(d.error || `Server error (${r.status}).`);
                return;
            }

            const data = await r.json();
            setLoading(false);
            renderInterface(data);
            lastUpdated.textContent = 'Updated ' + new Date().toLocaleTimeString();
        } catch (e) {
            showError('Network error loading interface data.');
        }
    }

    function showError(msg) {
        setLoading(false);
        ifaceCard.style.display = 'none';
        peersCard.style.display = 'none';
        errorMsg.textContent = msg;
        showOnly(errorState);
    }

    // ── Render interface status card ──────────────────────────────────
    function renderInterface(data) {
        errorState.style.display = 'none';

        // Service badge
        const svcClass = data.service_status === 'active'   ? 'svc-active'
                       : data.service_status === 'inactive' ? 'svc-inactive'
                       : 'svc-unknown';
        const svcLabel = data.service_status || 'unknown';
        serviceBadgeWrap.innerHTML =
            `<span class="svc-badge ${escHtml(svcClass)}">
                <span class="dot"></span>
                wg-quick@${escHtml(data.name)} &mdash; ${escHtml(svcLabel)}
             </span>`;

        // Card title
        ifaceCardTitle.textContent = data.name;

        // Stats badges
        const stats = data.stats || {};
        totalPeersBadge.textContent     = `${stats.total || 0} peer${stats.total !== 1 ? 's' : ''}`;
        connectedPeersBadge.textContent = `${stats.connected || 0} connected`;
        connectedPeersBadge.className   = `stat-pill ${(stats.connected > 0) ? 'stat-pill-green' : 'stat-pill-muted'}`;

        // Info grid
        const ifc = data.interface || {};
        const items = [
            { label: 'Public Key',      value: ifc.public_key   || '—', mono: true },
            { label: 'IP Address',      value: ifc.address       || '—', mono: true },
            { label: 'Listening Port',  value: ifc.listen_port   || '—', mono: true },
            { label: 'DNS Servers',     value: ifc.dns           || '—', mono: true },
            { label: 'MTU',             value: ifc.mtu           || '—', mono: true },
            { label: 'Total Peers',
              value: `${stats.total || 0} &nbsp;<span class="stat-pill stat-pill-muted">${stats.enabled || 0} enabled</span>` },
        ];

        ifaceInfoGrid.innerHTML = items.map(item =>
            `<div class="info-item">
                <div class="info-label">${escHtml(item.label)}</div>
                <div class="info-value${item.mono ? ' monospace' : ''}">${item.value}</div>
             </div>`
        ).join('');

        ifaceCard.style.display = '';

        // Peers
        allPeers      = data.peers || [];
        filteredPeers = allPeers;
        currentPage   = 1;
        currentIfaceData = data;
        applySearch();
    }

    // ── Peers table ───────────────────────────────────────────────────
    function applySearch() {
        const q = peerSearch.value.trim().toLowerCase();
        filteredPeers = q
            ? allPeers.filter(p =>
                p.name.toLowerCase().includes(q) ||
                p.public_key.toLowerCase().includes(q) ||
                (p.allowed_ips || []).some(ip => ip.toLowerCase().includes(q)) ||
                (p.endpoint || '').toLowerCase().includes(q)
              )
            : allPeers;
        currentPage = 1;
        renderPeersPage();
    }

    function renderPeersPage() {
        const total = filteredPeers.length;
        const start = (currentPage - 1) * perPage;
        const slice = filteredPeers.slice(start, start + perPage);

        if (total === 0) {
            peersTableBody.innerHTML =
                `<tr><td colspan="8">
                    <div class="empty-state" style="padding:2.5rem 1rem;">
                        <i class="bi bi-people" style="font-size:2rem; opacity:0.3;"></i>
                        <p class="mt-2" style="font-size:0.85rem; color:var(--brand-muted);">
                            ${allPeers.length === 0 ? 'No peers configured.' : 'No peers match your search.'}
                        </p>
                    </div>
                 </td></tr>`;
        } else {
            peersTableBody.innerHTML = slice.map(peer => renderPeerRow(peer)).join('');
        }

        // Pagination info
        paginationInfo.textContent = total === 0
            ? '0 peers'
            : `${start + 1}–${Math.min(start + perPage, total)} of ${total} peer${total !== 1 ? 's' : ''}`;

        // Pagination buttons
        const pages = Math.ceil(total / perPage);
        let btns = '';
        btns += `<button class="pg-btn" id="pgPrev" ${currentPage <= 1 ? 'disabled' : ''}>
                    <i class="bi bi-chevron-left"></i></button>`;
        for (let p = 1; p <= pages; p++) {
            if (pages > 7 && Math.abs(p - currentPage) > 2 && p !== 1 && p !== pages) {
                if (p === 2 || p === pages - 1) btns += '<span style="color:var(--brand-muted);padding:0 4px;">…</span>';
                continue;
            }
            btns += `<button class="pg-btn ${p === currentPage ? 'active' : ''}" data-page="${p}">${p}</button>`;
        }
        btns += `<button class="pg-btn" id="pgNext" ${currentPage >= pages ? 'disabled' : ''}>
                    <i class="bi bi-chevron-right"></i></button>`;
        paginationBtns.innerHTML = btns;

        // Bind pagination button events
        paginationBtns.querySelectorAll('.pg-btn[data-page]').forEach(btn => {
            btn.addEventListener('click', () => {
                currentPage = parseInt(btn.dataset.page, 10);
                renderPeersPage();
            });
        });
        const prevBtn = document.getElementById('pgPrev');
        const nextBtn = document.getElementById('pgNext');
        if (prevBtn) prevBtn.addEventListener('click', () => { currentPage--; renderPeersPage(); });
        if (nextBtn) nextBtn.addEventListener('click', () => { currentPage++; renderPeersPage(); });

        peersCard.style.display = '';
    }

    function renderPeerRow(peer) {
        const statusHtml = peer.connected
            ? `<span class="status-connected"><span class="dot"></span>Connected</span>`
            : `<span class="status-disconnected"><span class="dot"></span>Offline</span>`;

        const ipsHtml = (peer.allowed_ips || [])
            .map(ip => `<span class="ip-badge">${escHtml(ip)}</span>`)
            .join('');

        const endpoint = peer.endpoint
            ? `<span style="font-family:monospace;font-size:0.78rem;">${escHtml(peer.endpoint)}</span>`
            : '<span style="color:var(--brand-muted);">—</span>';

        const keepalive = peer.keepalive && peer.keepalive !== '—' && peer.keepalive !== '0'
            ? `${escHtml(peer.keepalive)}s`
            : '<span style="color:var(--brand-muted);">off</span>';

        const handshakeTitle = peer.latest_handshake
            ? `title="Last handshake: ${formatHandshake(peer.latest_handshake)}"` : '';

        return `
        <tr>
            <td><input type="checkbox" class="peer-check" style="accent-color:var(--brand-primary);"></td>
            <td>
                <div class="peer-name">${escHtml(peer.name)}</div>
            </td>
            <td>${ipsHtml || '<span style="color:var(--brand-muted);">—</span>'}</td>
            <td>${endpoint}</td>
            <td ${handshakeTitle}>${statusHtml}</td>
            <td>
                <div class="rxtx">
                    <span class="rx">↓ ${escHtml(peer.rx || '0 B')}</span>
                    <span class="sep">/</span>
                    <span class="tx">↑ ${escHtml(peer.tx || '0 B')}</span>
                </div>
            </td>
            <td>${keepalive}</td>
            <td>
                <button class="action-btn" title="View details" data-action="detail" data-key="${escHtml(peer.public_key)}">
                    <i class="bi bi-eye"></i>
                </button>
                <button class="action-btn" title="QR Code" data-action="qr" data-key="${escHtml(peer.public_key)}" data-peer-name="${escHtml(peer.name)}">
                    <i class="bi bi-qr-code"></i>
                </button>
                <button class="action-btn" title="Edit peer" data-action="edit" data-key="${escHtml(peer.public_key)}" data-peer-name="${escHtml(peer.name)}" data-peer-ips="${escHtml((peer.allowed_ips||[]).join(', '))}" data-peer-ka="${escHtml(peer.keepalive||'0')}">
                    <i class="bi bi-pencil"></i>
                </button>
                <button class="action-btn" title="Delete peer" data-action="delete" data-key="${escHtml(peer.public_key)}" data-peer-name="${escHtml(peer.name)}" style="color:#e74c3c;border-color:rgba(231,76,60,0.3);">
                    <i class="bi bi-trash"></i>
                </button>
            </td>
        </tr>`;
    }

    // ── Events ────────────────────────────────────────────────────────
    ifaceSelector.addEventListener('change', () => {
        const name = ifaceSelector.value;
        if (name) loadInterface(name);
    });

    refreshBtn.addEventListener('click', () => {
        const name = ifaceSelector.value;
        if (!name) return;
        refreshBtn.classList.add('spinning');
        loadInterface(name).finally(() => refreshBtn.classList.remove('spinning'));
    });

    peerSearch.addEventListener('input', applySearch);

    perPageSelect.addEventListener('change', () => {
        perPage = parseInt(perPageSelect.value, 10);
        currentPage = 1;
        renderPeersPage();
    });

    selectAll.addEventListener('change', () => {
        document.querySelectorAll('.peer-check')
            .forEach(cb => { cb.checked = selectAll.checked; });
    });

    // Action buttons (delegated) — detail view + QR code
    peersTableBody.addEventListener('click', e => {
        const btn = e.target.closest('.action-btn');
        if (!btn) return;
        const action = btn.dataset.action;
        const key    = btn.dataset.key;
        if (!key) return;
        if (action === 'detail') {
            const peer = allPeers.find(p => p.public_key === key);
            if (peer) showPeerDetail(peer);
        } else if (action === 'qr') {
            showPeerQr(key, btn.dataset.peerName || '');
        } else if (action === 'edit') {
            showEditPeer(key, btn.dataset.peerName || '', btn.dataset.peerIps || '', btn.dataset.peerKa || '0');
        } else if (action === 'delete') {
            showDeletePeer(key, btn.dataset.peerName || '');
        }
    });

    // ── Apply NAT modal ───────────────────────────────────────────────
    let natModal = null;

    function buildNatCmds(subnet, outIface) {
        if (!subnet || !outIface) return '';
        return [
            'nft add table ip nat',
            `nft 'add chain ip nat postrouting { type nat hook postrouting priority 100; }'`,
            `nft add rule ip nat postrouting ip saddr ${subnet} oifname "${outIface}" masquerade`,
        ].join('\n');
    }

    function updateNatPreview() {
        const subnet  = document.getElementById('natSubnet').value;
        const iface   = document.getElementById('natIfaceSelect').value;
        document.getElementById('natCmdPreview').textContent = buildNatCmds(subnet, iface);
    }

    if (applyNatBtn) {
        applyNatBtn.addEventListener('click', async () => {
            const wgIface = ifaceSelector.value;
            if (!wgIface) return;

            // Derive subnet from interface address
            const address = currentIfaceData && currentIfaceData.interface
                ? currentIfaceData.interface.address : '';
            const subnet = ipToNetwork(address);

            // Reset modal
            document.getElementById('natError').style.display = 'none';
            document.getElementById('natSubnet').value = subnet;
            document.getElementById('natIfaceSelect').innerHTML =
                '<option value="">Loading…</option>';
            document.getElementById('natCmdPreview').textContent = '';
            document.getElementById('natApplyBtn').disabled = false;
            document.getElementById('natApplyBtn').innerHTML =
                '<i class="bi bi-lightning-charge me-1"></i>Apply Rules';

            if (!natModal) natModal = new bootstrap.Modal(document.getElementById('natModal'));
            natModal.show();

            // Fetch server interfaces
            try {
                const r = await fetch('/api/system/interfaces', { credentials: 'same-origin' });
                const d = await r.json();
                const ifaces = d.interfaces || [];
                const sel = document.getElementById('natIfaceSelect');
                sel.innerHTML = ifaces.length
                    ? ifaces.map(n => `<option value="${escHtml(n)}">${escHtml(n)}</option>`).join('')
                    : '<option value="">No interfaces found</option>';
                updateNatPreview();
            } catch (_) {
                document.getElementById('natIfaceSelect').innerHTML =
                    '<option value="">Failed to load interfaces</option>';
            }
        });
    }

    document.getElementById('natIfaceSelect').addEventListener('change', updateNatPreview);

    document.getElementById('natCopyBtn').addEventListener('click', () => {
        const text = document.getElementById('natCmdPreview').textContent;
        if (!text) return;
        navigator.clipboard.writeText(text).then(() => {
            const btn = document.getElementById('natCopyBtn');
            btn.innerHTML = '<i class="bi bi-check me-1"></i>Copied!';
            setTimeout(() => {
                btn.innerHTML = '<i class="bi bi-clipboard me-1"></i>Copy Commands';
            }, 2000);
        }).catch(() => {});
    });

    document.getElementById('natApplyBtn').addEventListener('click', async () => {
        const wgIface = ifaceSelector.value;
        const subnet  = document.getElementById('natSubnet').value;
        const outIface = document.getElementById('natIfaceSelect').value;

        const errEl = document.getElementById('natError');
        errEl.style.display = 'none';

        if (!outIface) {
            errEl.textContent = 'Please select an outbound interface.';
            errEl.style.display = '';
            return;
        }

        const btn = document.getElementById('natApplyBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Applying…';

        try {
            if (!csrfToken) await fetchCsrf();
            const r = await fetch(`/api/wireguard/interface/${encodeURIComponent(wgIface)}/apply-nat`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
                body: JSON.stringify({ subnet, out_iface: outIface }),
            });
            const d = await r.json();

            if (!r.ok || d.error) {
                errEl.textContent = d.error || `Server error ${r.status}`;
                errEl.style.display = '';
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-lightning-charge me-1"></i>Apply Rules';
                return;
            }

            // Success
            btn.innerHTML = '<i class="bi bi-check-circle me-1"></i>Applied!';
            if (d.note) {
                errEl.className = 'alert py-2 mt-3';
                errEl.style.background = 'rgba(46,204,113,0.1)';
                errEl.style.border = '1px solid rgba(46,204,113,0.3)';
                errEl.style.color = '#2ecc71';
                errEl.textContent = d.note;
                errEl.style.display = '';
            }
            setTimeout(() => { if (natModal) natModal.hide(); }, 2000);
        } catch (err) {
            errEl.textContent = 'Network error: ' + err.message;
            errEl.style.display = '';
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-lightning-charge me-1"></i>Apply Rules';
        }
    });

    document.getElementById('natModal').addEventListener('hidden.bs.modal', () => {
        const errEl = document.getElementById('natError');
        errEl.style.display = 'none';
        errEl.className = 'alert alert-danger py-2 mt-3';
        errEl.style.background = '';
        errEl.style.border     = '';
        errEl.style.color      = '';
        const btn = document.getElementById('natApplyBtn');
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-lightning-charge me-1"></i>Apply Rules';
    });
    // ── Add Peer modal ────────────────────────────────────────────────
    let addPeerModal = null;

    if (addPeerBtn) {
        addPeerBtn.addEventListener('click', async () => {
            const iface = ifaceSelector.value;
            if (!iface) return;

            // Reset form
            getApEl('addPeerForm').reset();
            getApEl('addPeerError').style.display = 'none';
            getApEl('addPeerSubmitBtn').disabled = false;

            if (!addPeerModal) {
                addPeerModal = new bootstrap.Modal(document.getElementById('addPeerModal'));
            }
            addPeerModal.show();

            // Auto-suggest next IP
            try {
                const r = await fetch(`/api/wireguard/interface/${encodeURIComponent(iface)}/next-ip`, { credentials: 'same-origin' });
                if (r.ok) {
                    const d = await r.json();
                    getApEl('apIp').value = d.ip || '';
                }
            } catch (_) { /* non-fatal */ }
        });
    }

    // "Magic" next-IP button inside the modal
    document.addEventListener('click', async e => {
        if (!e.target.closest('#apNextIpBtn')) return;
        const iface = ifaceSelector.value;
        if (!iface) return;
        try {
            const r = await fetch(`/api/wireguard/interface/${encodeURIComponent(iface)}/next-ip`, { credentials: 'same-origin' });
            if (r.ok) {
                const d = await r.json();
                getApEl('apIp').value = d.ip || '';
            }
        } catch (_) { /* ignore */ }
    });

    // Submit the Add Peer form
    document.addEventListener('click', async e => {
        if (!e.target.closest('#addPeerSubmitBtn')) return;
        const iface = ifaceSelector.value;
        if (!iface) return;

        const errorBox = getApEl('addPeerError');
        const submitBtn = getApEl('addPeerSubmitBtn');
        errorBox.style.display = 'none';

        const name      = (getApEl('apName').value || '').trim();
        const ip        = (getApEl('apIp').value || '').trim();
        const endpoint  = (getApEl('apEndpoint').value || '').trim();
        const keepalive = parseInt(getApEl('apKeepalive').value || '25', 10);
        const dns       = (getApEl('apDns').value || '').trim();
        const routes    = (getApEl('apRoutes').value || '').trim();

        if (!name || !ip) {
            errorBox.textContent = 'Peer Name and VPN IP are required.';
            errorBox.style.display = '';
            return;
        }

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Creating…';

        try {
            if (!csrfToken) await fetchCsrf();
            const r = await fetch(`/api/wireguard/interface/${encodeURIComponent(iface)}/peer`, {
                method: 'POST',
                credentials: 'same-origin',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRF-Token': csrfToken || '',
                },
                body: JSON.stringify({ peer_name: name, allowed_ips: ip, endpoint, keepalive, dns, routes }),
            });
            const data = await r.json();
            if (!r.ok || data.error) {
                errorBox.textContent = data.error || `Server error ${r.status}`;
                errorBox.style.display = '';
                submitBtn.disabled = false;
                submitBtn.innerHTML = '<i class="bi bi-plus-circle me-1"></i>Create Peer';
                return;
            }
            // Success
            addPeerModal.hide();
            await loadInterface(iface);
        } catch (err) {
            errorBox.textContent = 'Network error: ' + err.message;
            errorBox.style.display = '';
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="bi bi-plus-circle me-1"></i>Create Peer';
        }
    });

    // Reset submit button text when modal is hidden
    document.getElementById('addPeerModal').addEventListener('hidden.bs.modal', () => {
        const btn = getApEl('addPeerSubmitBtn');
        if (btn) { btn.disabled = false; btn.innerHTML = '<i class="bi bi-plus-circle me-1"></i>Create Peer'; }
        getApEl('addPeerError').style.display = 'none';
    });

    // ── Peer QR code modal ───────────────────────────────────────────────
    let peerQrModal = null;

    async function showPeerQr(pubkey, peerName) {
        if (!peerQrModal) peerQrModal = new bootstrap.Modal(document.getElementById('peerQrModal'));

        // Reset state
        document.getElementById('peerQrTitle').textContent  = peerName ? `QR Code — ${peerName}` : 'Peer QR Code';
        document.getElementById('peerQrLoading').style.display = '';
        document.getElementById('peerQrError').style.display   = 'none';
        document.getElementById('peerQrImage').style.display   = 'none';
        document.getElementById('peerQrHint').style.display    = 'none';
        peerQrModal.show();

        try {
            const r = await fetch(`/api/wireguard/peer/qrcode?pubkey=${encodeURIComponent(pubkey)}`, {
                credentials: 'same-origin'
            });
            const d = await r.json();

            document.getElementById('peerQrLoading').style.display = 'none';

            if (!r.ok || d.error) {
                const errEl = document.getElementById('peerQrError');
                errEl.textContent  = d.error || `Server error ${r.status}`;
                errEl.style.display = '';
                return;
            }

            const img = document.getElementById('peerQrImage');
            img.src = d.qr;
            img.style.display = '';
            document.getElementById('peerQrHint').style.display = '';
        } catch (err) {
            document.getElementById('peerQrLoading').style.display = 'none';
            const errEl = document.getElementById('peerQrError');
            errEl.textContent  = 'Network error: ' + err.message;
            errEl.style.display = '';
        }
    }

    // ── Edit peer modal ──────────────────────────────────────────────────────
    let editPeerModal = null;

    function showEditPeer(pubkey, name, ips, ka) {
        if (!editPeerModal) editPeerModal = new bootstrap.Modal(document.getElementById('editPeerModal'));
        document.getElementById('editPeerError').style.display = 'none';
        document.getElementById('epName').value      = name;
        document.getElementById('epIps').value       = ips;
        document.getElementById('epKeepalive').value = ka === '—' ? '0' : (ka || '0');
        document.getElementById('epPubkey').value    = pubkey;
        const btn = document.getElementById('editPeerSaveBtn');
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-floppy me-1"></i>Save Changes';
        editPeerModal.show();
    }

    document.getElementById('editPeerSaveBtn').addEventListener('click', async () => {
        const iface  = ifaceSelector.value;
        const pubkey = document.getElementById('epPubkey').value;
        const errEl  = document.getElementById('editPeerError');
        errEl.style.display = 'none';

        const newName    = document.getElementById('epName').value.trim();
        const newIps     = document.getElementById('epIps').value.trim();
        const newKa      = document.getElementById('epKeepalive').value.trim();

        const payload = {};
        const origPeer = allPeers.find(p => p.public_key === pubkey);
        if (newName && newName !== (origPeer?.name || ''))   payload.new_name    = newName;
        if (newIps  && newIps  !== (origPeer?.allowed_ips || []).join(', ')) payload.allowed_ips = newIps;
        if (newKa   !== '')  payload.keepalive = parseInt(newKa, 10);

        if (!Object.keys(payload).length) {
            editPeerModal.hide();
            return;
        }

        const btn = document.getElementById('editPeerSaveBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving…';

        try {
            if (!csrfToken) await fetchCsrf();
            const r = await fetch(
                `/api/wireguard/interface/${encodeURIComponent(iface)}/peer/${encodeURIComponent(pubkey)}`,
                {
                    method: 'PATCH',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrfToken || '' },
                    body: JSON.stringify(payload),
                }
            );
            const d = await r.json();
            if (!r.ok || d.error) {
                errEl.textContent = d.error || `Server error ${r.status}`;
                errEl.style.display = '';
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-floppy me-1"></i>Save Changes';
                return;
            }
            editPeerModal.hide();
            await loadInterface(iface);
        } catch (err) {
            errEl.textContent = 'Network error: ' + err.message;
            errEl.style.display = '';
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-floppy me-1"></i>Save Changes';
        }
    });

    document.getElementById('editPeerModal').addEventListener('hidden.bs.modal', () => {
        document.getElementById('editPeerError').style.display = 'none';
    });

    // ── Delete peer modal ────────────────────────────────────────────────────
    let deletePeerModal = null;

    function showDeletePeer(pubkey, name) {
        if (!deletePeerModal) deletePeerModal = new bootstrap.Modal(document.getElementById('deletePeerModal'));
        document.getElementById('deletePeerError').style.display = 'none';
        document.getElementById('deletePeerName').textContent   = name || pubkey.slice(0, 16) + '…';
        document.getElementById('deletePeerPubkey').value       = pubkey;
        const btn = document.getElementById('deletePeerConfirmBtn');
        btn.disabled = false;
        btn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete Permanently';
        deletePeerModal.show();
    }

    document.getElementById('deletePeerConfirmBtn').addEventListener('click', async () => {
        const iface  = ifaceSelector.value;
        const pubkey = document.getElementById('deletePeerPubkey').value;
        const errEl  = document.getElementById('deletePeerError');
        errEl.style.display = 'none';

        const btn = document.getElementById('deletePeerConfirmBtn');
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Deleting…';

        try {
            if (!csrfToken) await fetchCsrf();
            const r = await fetch(
                `/api/wireguard/interface/${encodeURIComponent(iface)}/peer/${encodeURIComponent(pubkey)}`,
                {
                    method: 'DELETE',
                    credentials: 'same-origin',
                    headers: { 'X-CSRF-Token': csrfToken || '' },
                }
            );
            const d = await r.json();
            if (!r.ok || d.error) {
                errEl.textContent = d.error || `Server error ${r.status}`;
                errEl.style.display = '';
                btn.disabled = false;
                btn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete Permanently';
                return;
            }
            deletePeerModal.hide();
            await loadInterface(iface);
        } catch (err) {
            errEl.textContent = 'Network error: ' + err.message;
            errEl.style.display = '';
            btn.disabled = false;
            btn.innerHTML = '<i class="bi bi-trash me-1"></i>Delete Permanently';
        }
    });

    document.getElementById('deletePeerModal').addEventListener('hidden.bs.modal', () => {
        document.getElementById('deletePeerError').style.display = 'none';
    });

    // ── Peer detail popover ───────────────────────────────────────────
    function showPeerDetail(peer) {
        // Simple Bootstrap modal created on the fly
        const existing = document.getElementById('peerDetailModal');
        if (existing) existing.remove();

        const ips = (peer.allowed_ips || []).join(', ') || '—';
        const hs  = peer.latest_handshake ? formatHandshake(peer.latest_handshake) : 'Never';

        const html = `
        <div class="modal fade" id="peerDetailModal" tabindex="-1">
          <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content" style="background:var(--brand-surface);border:1px solid var(--brand-border);color:var(--brand-text);">
              <div class="modal-header" style="border-color:var(--brand-border);">
                <h5 class="modal-title" style="font-size:0.85rem;letter-spacing:2px;text-transform:uppercase;">
                  <i class="bi bi-person-badge me-2" style="color:var(--brand-primary);"></i>
                  Peer Details
                </h5>
                <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal"></button>
              </div>
              <div class="modal-body" style="font-size:0.85rem;">
                <table style="width:100%;border-collapse:collapse;">
                  ${[
                    ['Name',            escHtml(peer.name)],
                    ['Public Key',      `<code style="font-size:0.78rem;word-break:break-all;">${escHtml(peer.public_key)}</code>`],
                    ['Allowed IPs',     escHtml(ips)],
                    ['Endpoint',        escHtml(peer.endpoint || '—')],
                    ['Status',          peer.connected ? '<span style="color:#2ecc71;">Connected</span>' : '<span style="color:var(--brand-muted);">Offline</span>'],
                    ['Last Handshake',  escHtml(hs)],
                    ['RX',              escHtml(peer.rx || '0 B')],
                    ['TX',              escHtml(peer.tx || '0 B')],
                    ['Keepalive',       escHtml(peer.keepalive && peer.keepalive !== '0' ? peer.keepalive + 's' : 'off')],
                  ].map(([k,v]) => `
                    <tr>
                      <td style="padding:5px 0;color:var(--brand-muted);font-size:0.72rem;letter-spacing:1px;text-transform:uppercase;width:38%;vertical-align:top;">${k}</td>
                      <td style="padding:5px 0;">${v}</td>
                    </tr>`).join('')}
                </table>
              </div>
            </div>
          </div>
        </div>`;
        document.body.insertAdjacentHTML('beforeend', html);
        const modal = new bootstrap.Modal(document.getElementById('peerDetailModal'));
        modal.show();
    }

    // ── Auto-refresh ──────────────────────────────────────────────────
    // Only runs while the user is NOT idle (overlay not showing).
    function startAutoRefresh() {
        stopAutoRefresh();
        autoRefreshTimer = setInterval(() => {
            // Do not refresh while the idle warning overlay is visible —
            // the request would not reset the server-side timer anyway
            // (require_session uses touch=False), but we also don't want
            // background network activity confusing the UX.
            if (idleOverlay.classList.contains('show')) return;
            const name = ifaceSelector.value;
            if (name) loadInterface(name);
        }, AUTO_REFRESH_MS);
    }

    function stopAutoRefresh() {
        if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    }

    // ── Logout ────────────────────────────────────────────────────────
    async function doLogout() {
        stopAutoRefresh();
        try {
            const csrfResp = await fetch('/api/auth/csrf');
            const csrfData = await csrfResp.json();
            const token    = csrfData.csrf_token || '';
            await fetch('/api/auth/logout', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'X-CSRFToken': token },
                credentials: 'same-origin',
                body: JSON.stringify({})
            });
        } catch (_) { /* proceed regardless */ }
        sessionStorage.clear();
        localStorage.clear();
        window.location.replace('/');
    }

    logoutBtn.addEventListener('click', doLogout);

    // ── Idle timeout ──────────────────────────────────────────────────
    function resetIdleTimer() {
        clearTimeout(idleTimer);
        idleOverlay.classList.remove('show');
        idleTimer = setTimeout(showIdleWarning, IDLE_TIMEOUT_MS - IDLE_WARNING_SEC * 1000);
    }

    function showIdleWarning() {
        let remaining = IDLE_WARNING_SEC;
        idleCountdown.textContent = remaining;
        idleOverlay.classList.add('show');
        clearInterval(idleCountInterval);
        idleCountInterval = setInterval(() => {
            remaining--;
            idleCountdown.textContent = remaining;
            if (remaining <= 0) {
                clearInterval(idleCountInterval);
                doLogout();
            }
        }, 1000);
    }

    ['mousemove','keydown','click','touchstart','scroll'].forEach(ev =>
        document.addEventListener(ev, resetIdleTimer, { passive: true })
    );

    idleStayBtn.addEventListener('click', async () => {
        clearInterval(idleCountInterval);
        idleOverlay.classList.remove('show');
        try {
            const r = await fetch('/api/user/profile', { credentials: 'same-origin' });
            if (r.status === 401) { doLogout(); return; }
        } catch (_) { /* ignore */ }
        resetIdleTimer();
    });

    setInterval(async () => {
        // Never poll while idle overlay is showing — let the countdown run
        if (idleOverlay.classList.contains('show')) return;
        try {
            const r = await fetch('/api/user/profile', { credentials: 'same-origin' });
            if (r.status === 401) doLogout();
        } catch (_) { /* ignore */ }
    }, SESSION_POLL_MS);

    // Back-button prevention
    history.pushState(null, '', window.location.href);
    window.addEventListener('popstate', () => {
        history.pushState(null, '', window.location.href);
    });

    // ── Init ──────────────────────────────────────────────────────────
    async function init() {
        await Promise.all([fetchCsrf(), loadUser()]);
        await loadInterfaces();
        startAutoRefresh();
        resetIdleTimer();
    }

    init();
})();
