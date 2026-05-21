// ── WebSocket connection ──
const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${protocol}//${location.host}/ws`;
let ws = null;
let selectedRequestId = null;
let captureEnabled = false;
let currentSessionId = null;

function connect() {
    ws = new WebSocket(wsUrl);
    ws.onopen = () => {
        document.getElementById('connection-status').className = 'connected';
        document.getElementById('connection-status').textContent = 'Connected';
    };
    ws.onclose = () => {
        document.getElementById('connection-status').className = 'disconnected';
        document.getElementById('connection-status').textContent = 'Disconnected';
        setTimeout(connect, 2000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            handleMessage(msg);
        } catch (e) {
            console.error('Failed to parse WS message:', e);
        }
    };
}

function handleMessage(msg) {
    switch (msg.type) {
        case 'History':
            renderRequestTable(msg.payload.requests);
            updateRequestCount();
            break;
        case 'NewRequest':
        case 'RequestUpdated':
            upsertRequestRow(msg.payload);
            addToTimeline(msg.payload);
            if (msg.payload.id === selectedRequestId) {
                showRequestDetail(msg.payload);
            }
            updateRequestCount();
            break;
        case 'SseEvent':
            if (msg.payload.request_id === selectedRequestId) {
                appendSseEvent(msg.payload.event);
            }
            break;
        case 'HookHistory':
            renderHookTable(msg.payload.events);
            break;
        case 'NewHook':
            addHookRow(msg.payload);
            addToTimeline(msg.payload);
            break;
        case 'McpHistory':
            renderMcpTable(msg.payload.requests);
            break;
        case 'NewMcp':
            addMcpRow(msg.payload);
            addToTimeline(msg.payload);
            break;
        case 'Cleared':
            clearAllTables();
            updateRequestCount();
            break;
        case 'McpCleared':
            document.getElementById('mcp-tbody').innerHTML = '';
            break;
        case 'McpConfigChanged':
            if (msg.payload.destination_url) {
                document.getElementById('mcp-destination').value = msg.payload.destination_url;
            }
            break;
        case 'SessionStarted':
            addSessionCard(msg.payload);
            break;
        case 'SessionStopped':
            updateSessionCard(msg.payload);
            break;
        case 'UpstreamChanged':
            populateUpstreamDropdown(msg.payload.upstreams, msg.payload.active_url);
            break;
        case 'TeeStatusChanged':
            captureEnabled = msg.payload.enabled;
            updateCaptureButton();
            break;
    }
}

// ── Navigation ──
document.querySelectorAll('nav a').forEach(link => {
    link.addEventListener('click', (e) => {
        e.preventDefault();
        const view = link.dataset.view;
        document.querySelectorAll('nav a').forEach(a => a.classList.remove('active'));
        link.classList.add('active');
        document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
        document.getElementById(`view-${view}`).classList.add('active');
    });
});

// ── Request table ──
const requestRows = new Map();

function upsertRequestRow(req) {
    const existing = requestRows.get(req.id);
    if (existing) {
        requestRows.set(req.id, req);
        updateRequestRow(req);
    } else {
        requestRows.set(req.id, req);
        prependRequestRow(req);
    }
    updateFilterOptions();
}

function prependRequestRow(req) {
    const tbody = document.getElementById('requests-tbody');
    const tr = document.createElement('tr');
    tr.id = `req-${req.id}`;
    tr.innerHTML = buildRequestRowHTML(req);
    tr.addEventListener('click', () => showRequestDetail(req));
    tbody.prepend(tr);
    // Keep max 200 rows in view
    while (tbody.children.length > 200) tbody.lastChild.remove();
}

function updateRequestRow(req) {
    const row = document.getElementById(`req-${req.id}`);
    if (row) {
        row.innerHTML = buildRequestRowHTML(req);
    }
}

function buildRequestRowHTML(req) {
    let statusClass = '';
    if (req.status_code) {
        if (req.status_code < 400) statusClass = 'status-200';
        else if (req.status_code < 500) statusClass = 'status-4xx';
        else statusClass = 'status-5xx';
    }
    return `
        <td>${formatTime(req.timestamp)}</td>
        <td>${esc(req.method)}</td>
        <td>${esc(req.path)}</td>
        <td class="${statusClass}">${req.status_code || '—'}</td>
        <td>${esc(req.model || '—')}</td>
        <td>${req.is_streaming ? '✓' : '—'}</td>
        <td>${req.input_tokens || '—'}</td>
        <td>${req.output_tokens || '—'}</td>
        <td>${req.duration_ms != null ? req.duration_ms + 'ms' : '—'}</td>
        <td>${req.time_to_first_token_ms != null ? req.time_to_first_token_ms + 'ms' : '—'}</td>
    `;
}

function renderRequestTable(requests) {
    requestRows.clear();
    const tbody = document.getElementById('requests-tbody');
    tbody.innerHTML = '';
    requests.forEach(req => {
        requestRows.set(req.id, req);
        const tr = document.createElement('tr');
        tr.id = `req-${req.id}`;
        tr.innerHTML = buildRequestRowHTML(req);
        tr.addEventListener('click', () => showRequestDetail(req));
        tbody.appendChild(tr);
    });
    updateFilterOptions();
    updateRequestCount();
}

function showRequestDetail(req) {
    selectedRequestId = req.id;
    const content = document.getElementById('detail-content');
    delete content.dataset.streamStarted;
    document.getElementById('request-detail').classList.remove('hidden');
    document.getElementById('detail-title').textContent = `${req.method} ${req.path}`;

    // Highlight selected row
    document.querySelectorAll('#requests-tbody tr').forEach(r => r.classList.remove('selected'));
    const row = document.getElementById(`req-${req.id}`);
    if (row) row.classList.add('selected');

    updateDetailView(req);
}

function updateDetailView(req) {
    const activeTab = document.querySelector('.detail-tabs .tab.active')?.dataset.tab || 'request';
    showDetailTab(activeTab, req);
}

function showDetailTab(tab, req) {
    const content = document.getElementById('detail-content');
    switch (tab) {
        case 'request':
            content.innerHTML = renderDetailBody(formatHeaders(req.request_headers), req.request_body);
            break;
        case 'response':
            content.innerHTML = renderDetailBody(formatHeaders(req.response_headers), req.response_body);
            break;
        case 'sse':
            content.textContent = formatSseContent(req);
            break;
    }
}

function renderDetailBody(headers, body) {
    const parts = [];
    if (headers) {
        parts.push(`<pre class="detail-headers">${esc(headers)}</pre>`);
    }
    if (body) {
        const parsed = tryParseJson(body);
        if (parsed) {
            parts.push(`<div class="json-tree">${jsonTreeHTML(parsed, 0)}</div>`);
        } else {
            parts.push(`<pre class="detail-plain">${esc(body)}</pre>`);
        }
    }
    return parts.join('');
}

function formatSseContent(req) {
    const parts = [];
    // Show merged content text first if available
    if (req.content_text) {
        parts.push('=== Response Content ===');
        parts.push(req.content_text);
    }
    // Show structured events (filter out noisy delta events)
    const structured = req.sse_events.filter(e => {
        if (!e.data) return false;
        try {
            const d = JSON.parse(e.data);
            const t = d.type;
            return t === 'message_start' || t === 'message_delta' || t === 'message_stop'
                || t === 'content_block_start' || t === 'content_block_stop'
                || (t !== 'content_block_delta' && t !== 'ping');
        } catch { return true; }
    });
    if (structured.length > 0) {
        if (parts.length > 0) parts.push('');
        parts.push('=== Events ===');
        structured.forEach(e => {
            parts.push(`event: ${e.event_type || '—'}\ndata: ${e.data || '—'}\n`);
        });
    }
    return parts.join('\n');
}

function appendSseEvent(event) {
    const activeTab = document.querySelector('.detail-tabs .tab.active')?.dataset.tab;
    if (activeTab === 'sse') {
        // Show streaming progress — will be replaced by merged content on RequestUpdated
        const content = document.getElementById('detail-content');
        if (!content.dataset.streamStarted) {
            content.dataset.streamStarted = '1';
            content.textContent = '(streaming…)\n\n';
        }
        content.textContent += `event: ${event.event_type || '—'}\ndata: ${event.data || '—'}\n\n`;
        content.scrollTop = content.scrollHeight;
    }
}

document.querySelectorAll('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.tab').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const req = requestRows.get(selectedRequestId);
        if (req) showDetailTab(btn.dataset.tab, req);
    });
});

document.getElementById('btn-close-detail').addEventListener('click', () => {
    document.getElementById('request-detail').classList.add('hidden');
    selectedRequestId = null;
    document.querySelectorAll('#requests-tbody tr').forEach(r => r.classList.remove('selected'));
});

// ── Timeline ──
function addToTimeline(item) {
    const timeline = document.getElementById('conversation-timeline');
    const div = document.createElement('div');
    div.className = 'timeline-item';

    if (item.hook_event_name) {
        div.classList.add('hook');
        div.innerHTML = `
            <div class="timeline-header">
                <span>Hook: ${esc(item.hook_event_name)}</span>
                <span>${formatTime(item.timestamp)}</span>
            </div>
            <div class="timeline-body">${JSON.stringify(item.hook_input, null, 2)}</div>
        `;
    } else if (item.model && item.model.includes('mcp')) {
        div.classList.add('mcp');
        div.innerHTML = `
            <div class="timeline-header">
                <span>MCP: ${esc(item.model)}</span>
                <span>${formatTime(item.timestamp)}</span>
            </div>
            <div class="timeline-body">${item.response_body || item.request_body || ''}</div>
        `;
    } else {
        div.innerHTML = `
            <div class="timeline-header">
                <span>${esc(item.method)} ${esc(item.path)} — ${item.status_code || '...'}</span>
                <span>${formatTime(item.timestamp)} | ${item.duration_ms || 0}ms</span>
            </div>
            <div class="timeline-body">${item.response_body || item.request_body || ''}</div>
        `;
    }
    timeline.prepend(div);
    while (timeline.children.length > 100) timeline.lastChild.remove();
}

// ── MCP table ──
function addMcpRow(req) {
    const tbody = document.getElementById('mcp-tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${formatTime(req.timestamp)}</td>
        <td>${esc(req.model || '—')}</td>
        <td>${req.status_code || '—'}</td>
        <td>${esc(truncate(req.request_body, 100))}</td>
        <td>${esc(truncate(req.response_body, 100))}</td>
    `;
    tbody.prepend(tr);
    while (tbody.children.length > 100) tbody.lastChild.remove();
}

function renderMcpTable(requests) {
    const tbody = document.getElementById('mcp-tbody');
    tbody.innerHTML = '';
    requests.forEach(req => addMcpRow(req));
}

// ── Hook table ──
function addHookRow(event) {
    const tbody = document.getElementById('hooks-tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `
        <td>${formatTime(event.timestamp)}</td>
        <td>${esc(event.hook_event_name)}</td>
        <td>${esc(event.session_id)}</td>
        <td>${esc(event.cwd)}</td>
        <td>${event.exit_code}</td>
    `;
    tbody.prepend(tr);
    while (tbody.children.length > 200) tbody.lastChild.remove();
}

function renderHookTable(events) {
    const tbody = document.getElementById('hooks-tbody');
    tbody.innerHTML = '';
    events.forEach(e => addHookRow(e));
}

// ── Upstream targets ──

let upstreamEditMode = null; // 'add' | 'edit' (null = hidden)
let upstreamList = []; // cached list for editing model_map

function populateUpstreamDropdown(list, activeUrl) {
    const select = document.getElementById('upstream-select');
    const display = document.getElementById('upstream-url-display');
    const delBtn = document.getElementById('btn-upstream-delete');
    select.innerHTML = '';
    upstreamList = list || [];

    if (!list || list.length === 0) {
        select.innerHTML = '<option value="">— none —</option>';
        display.textContent = '';
        delBtn.disabled = true;
        return;
    }

    let activeName = '';
    list.forEach((u, i) => {
        const opt = document.createElement('option');
        opt.value = u.name;
        opt.textContent = u.name + (u.has_token ? ' \uD83D\uDD11' : '')
            + (u.model_map && Object.keys(u.model_map).length > 0 ? ' \uD83D\uDD04' : '');
        if (u.active) {
            opt.selected = true;
            activeName = u.name;
            display.textContent = u.url + (u.has_token ? ' (has token)' : '')
                + (u.model_map && Object.keys(u.model_map).length > 0 ? ' (has model map)' : '');
        }
        select.appendChild(opt);
    });

    delBtn.disabled = list.length <= 1;
}

// ── Model map helpers ──

function modelMapToText(map) {
    if (!map || typeof map !== 'object') return '';
    return Object.entries(map).map(([k, v]) => `${k} = ${v}`).join('\n');
}

function textToModelMap(text) {
    const map = {};
    text.split('\n').forEach(line => {
        const idx = line.indexOf('=');
        if (idx > 0) {
            const key = line.substring(0, idx).trim();
            const val = line.substring(idx + 1).trim();
            if (key && val) map[key] = val;
        }
    });
    return map;
}

// Dropdown change → activate
document.getElementById('upstream-select').addEventListener('change', async () => {
    const name = document.getElementById('upstream-select').value;
    if (!name) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}/activate`, { method: 'POST' });
});

// Add button → show inline form
document.getElementById('btn-upstream-add').addEventListener('click', () => {
    upstreamEditMode = 'add';
    document.getElementById('upstream-edit-name').value = '';
    document.getElementById('upstream-edit-url').value = '';
    document.getElementById('upstream-edit-token').value = '';
    document.getElementById('upstream-edit-modelmap').value = '';
    document.getElementById('upstream-edit-name').disabled = false;
    document.getElementById('upstream-edit-form').classList.remove('hidden');
    document.getElementById('upstream-edit-name').focus();
});

// Edit button → show inline form pre-filled
document.getElementById('btn-upstream-edit').addEventListener('click', () => {
    const select = document.getElementById('upstream-select');
    const name = select.value;
    if (!name) return;
    const display = document.getElementById('upstream-url-display');
    upstreamEditMode = 'edit';
    document.getElementById('upstream-edit-name').value = name;
    // display.textContent may include " (has token)(has model map)" suffixes — strip them
    document.getElementById('upstream-edit-url').value = display.textContent.replace(/ \(has token\)| \(has model map\)/g, '');
    document.getElementById('upstream-edit-token').value = '';
    document.getElementById('upstream-edit-token').placeholder = 'Token (unchanged if empty)';

    // Pre-fill model_map from cached upstream list
    const u = upstreamList.find(u => u.name === name);
    document.getElementById('upstream-edit-modelmap').value = u ? modelMapToText(u.model_map) : '';

    document.getElementById('upstream-edit-name').disabled = true;
    document.getElementById('upstream-edit-form').classList.remove('hidden');
    document.getElementById('upstream-edit-url').focus();
});

// Save button
document.getElementById('btn-upstream-save').addEventListener('click', async () => {
    const nameInput = document.getElementById('upstream-edit-name');
    const urlInput = document.getElementById('upstream-edit-url');
    const tokenInput = document.getElementById('upstream-edit-token');
    const name = nameInput.value.trim();
    const url = urlInput.value.trim();
    const token = tokenInput.value.trim();
    const modelMapText = document.getElementById('upstream-edit-modelmap').value.trim();
    const modelMap = modelMapText ? textToModelMap(modelMapText) : {};
    if (!name || !url) return;

    let resp;
    if (upstreamEditMode === 'add') {
        resp = await fetch('/api/upstreams', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, url, token: token || undefined, model_map: modelMap })
        });
    } else {
        const body = { url, model_map: modelMap };
        if (token) body.token = token;
        resp = await fetch(`/api/upstreams/${encodeURIComponent(name)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });
    }
    if (resp.ok) {
        hideUpstreamForm();
    } else {
        const err = await resp.json();
        alert(err.error || 'Failed to save upstream');
    }
});

// Cancel button
document.getElementById('btn-upstream-cancel').addEventListener('click', hideUpstreamForm);

function hideUpstreamForm() {
    upstreamEditMode = null;
    document.getElementById('upstream-edit-form').classList.add('hidden');
}

// Delete button
document.getElementById('btn-upstream-delete').addEventListener('click', async () => {
    const name = document.getElementById('upstream-select').value;
    if (!name) return;
    if (!confirm(`Delete upstream "${name}"?`)) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}`, { method: 'DELETE' });
    // UI updates via WS UpstreamChanged
});

// Initial load
fetch('/api/upstreams')
    .then(r => r.json())
    .then(data => {
        populateUpstreamDropdown(data.upstreams, data.activeUrl);
    });

// ── MCP destination ──
document.getElementById('btn-set-mcp').addEventListener('click', async () => {
    const url = document.getElementById('mcp-destination').value.trim();
    await fetch('/api/mcp-destination', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ destinationUrl: url || null })
    });
});

// ── Clear ──
document.getElementById('btn-clear').addEventListener('click', () => {
    ws.send(JSON.stringify({ action: 'clear' }));
    fetch('/api/clear', { method: 'POST' });
});

document.getElementById('btn-clear-mcp').addEventListener('click', () => {
    ws.send(JSON.stringify({ action: 'clear_mcp' }));
    fetch('/api/clear-mcp', { method: 'POST' });
});

document.getElementById('btn-clear-mcp-view').addEventListener('click', () => {
    fetch('/api/clear-mcp', { method: 'POST' });
});

document.getElementById('btn-clear-hooks').addEventListener('click', () => {
    fetch('/api/clear', { method: 'POST' });
});

// ── Capture toggle ──
document.getElementById('btn-toggle-capture').addEventListener('click', async () => {
    captureEnabled = !captureEnabled;
    await fetch('/api/capture', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: captureEnabled })
    });
    updateCaptureButton();
});

function updateCaptureButton() {
    const btn = document.getElementById('btn-toggle-capture');
    btn.textContent = captureEnabled ? 'Stop Capture' : 'Start Capture';
    btn.style.background = captureEnabled ? 'var(--accent)' : '';
    document.getElementById('capture-status').textContent = captureEnabled ? 'Capturing' : '';
}

// ── Sessions ──
document.getElementById('btn-start-session').addEventListener('click', async () => {
    const label = document.getElementById('session-label').value.trim();
    const resp = await fetch('/api/session/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ label: label || null })
    });
    const session = await resp.json();
    currentSessionId = session.id;
    addSessionCard(session);
});

function addSessionCard(session) {
    const container = document.getElementById('sessions-list');
    const card = document.createElement('div');
    card.className = 'session-card';
    card.id = `session-${session.id}`;
    const status = session.status === 'Recording'
        ? '<span style="color:var(--success)">● Recording</span>'
        : '<span style="color:var(--text-muted)">■ Stopped</span>';
    card.innerHTML = `
        <h3>Session: ${esc(session.id)}</h3>
        <div class="meta">
            ${status} |
            Label: ${esc(session.label || '—')} |
            Started: ${formatTime(session.started_at)} |
            Requests: ${session.request_ids.length}
        </div>
        <div class="actions">
            ${session.status === 'Recording'
                ? `<button onclick="stopSession('${session.id}')">Stop</button>`
                : ''}
            <button onclick="selectExportSession('${session.id}')">Export</button>
        </div>
    `;
    container.prepend(card);
}

function updateSessionCard(session) {
    const card = document.getElementById(`session-${session.id}`);
    if (card) {
        card.remove();
        addSessionCard(session);
    }
}

async function stopSession(id) {
    await fetch(`/api/session/${id}/stop`, { method: 'POST' });
    // UI will update via WS SessionStopped message
}

function selectExportSession(id) {
    const panel = document.getElementById('session-export');
    panel.classList.remove('hidden');
    panel.dataset.sessionId = id;
    document.querySelectorAll('#session-export .export-btn').forEach(btn => {
        btn.onclick = () => {
            window.open(`/api/session/${id}/export?format=${btn.dataset.format}`, '_blank');
        };
    });
}

// ── Filter ──
function updateFilterOptions() {
    const models = new Set();
    requestRows.forEach(r => { if (r.model) models.add(r.model); });
    const select = document.getElementById('filter-model');
    const current = select.value;
    select.innerHTML = '<option value="">All Models</option>';
    models.forEach(m => {
        select.innerHTML += `<option value="${esc(m)}">${esc(m)}</option>`;
    });
    select.value = current;
}

document.getElementById('filter-model').addEventListener('change', () => {
    const model = document.getElementById('filter-model').value;
    document.querySelectorAll('#requests-tbody tr').forEach(tr => {
        const req = requestRows.get(tr.id.replace('req-', ''));
        if (!model || (req && req.model === model)) {
            tr.style.display = '';
        } else {
            tr.style.display = 'none';
        }
    });
});

// ── Utilities ──
function formatTime(ts) {
    if (!ts) return '—';
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
}

function formatHeaders(headers) {
    if (!headers) return '';
    return Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
}

// ── JSON Tree Viewer ──
const IMPORTANT_KEYS = ['role', 'type', 'name', 'id', 'model', 'status', 'stop_reason', 'index', 'tool_use_id'];

function tryParseJson(str) {
    if (!str || typeof str !== 'string') return null;
    const trimmed = str.trim();
    if ((trimmed.startsWith('{') || trimmed.startsWith('['))) {
        try { return JSON.parse(trimmed); } catch (e) { return null; }
    }
    return null;
}

function jsonTreeHTML(value, depth) {
    if (value === null) return '<span class="jt-null">null</span>';
    if (typeof value === 'boolean') return `<span class="jt-bool">${value}</span>`;
    if (typeof value === 'number') return `<span class="jt-number">${value}</span>`;
    if (typeof value === 'string') return `<span class="jt-string">"${esc(value)}"</span>`;

    if (Array.isArray(value)) {
        if (value.length === 0) return '<span class="jt-bracket">[]</span>';
        const collapsed = depth >= 2;
        const preview = `[${value.length} item${value.length > 1 ? 's' : ''}]`;
        const children = value.map((item, i) => {
            const v = jsonTreeHTML(item, depth + 1);
            return `<div class="jt-item"><span class="jt-index">${i}: </span>${v}</div>`;
        }).join('');

        return `<span class="jt-node jt-array">`
            + `<span class="jt-toggle ${collapsed ? '' : 'expanded'}" data-depth="${depth}">${collapsed ? '+' : '-'}</span>`
            + `<span class="jt-bracket">[</span>`
            + `<span class="jt-preview ${collapsed ? '' : 'hidden'}">${esc(preview)}</span>`
            + `<span class="jt-children ${collapsed ? 'hidden' : ''}">${children}</span>`
            + `<span class="jt-bracket">]</span>`
            + `</span>`;
    }

    if (typeof value === 'object') {
        const keys = Object.keys(value);
        if (keys.length === 0) return '<span class="jt-bracket">{}</span>';
        const collapsed = depth >= 2;

        // Build preview from important keys
        const previewParts = [];
        for (const k of IMPORTANT_KEYS) {
            if (k in value) {
                const v = value[k];
                if (typeof v === 'string') {
                    previewParts.push(`${k}: "${esc(truncate(v, 40))}"`);
                } else if (typeof v === 'number' || typeof v === 'boolean') {
                    previewParts.push(`${k}: ${v}`);
                } else if (Array.isArray(v)) {
                    previewParts.push(`${k}: [${v.length} item${v.length !== 1 ? 's' : ''}]`);
                } else if (v === null) {
                    previewParts.push(`${k}: null`);
                } else if (typeof v === 'object') {
                    previewParts.push(`${k}: {...}`);
                }
            }
        }
        const remaining = keys.filter(k => !IMPORTANT_KEYS.includes(k)).length;
        const preview = previewParts.length > 0
            ? previewParts.join(', ') + (remaining > 0 ? ` +${remaining}` : '')
            : `${keys.length} key${keys.length > 1 ? 's' : ''}`;

        const children = keys.map(k => {
            const v = jsonTreeHTML(value[k], depth + 1);
            return `<div class="jt-pair"><span class="jt-key">"${esc(k)}": </span>${v}</div>`;
        }).join('');

        return `<span class="jt-node jt-object">`
            + `<span class="jt-toggle ${collapsed ? '' : 'expanded'}" data-depth="${depth}">${collapsed ? '+' : '-'}</span>`
            + `<span class="jt-bracket">{</span>`
            + `<span class="jt-preview ${collapsed ? '' : 'hidden'}">${preview}</span>`
            + `<span class="jt-children ${collapsed ? 'hidden' : ''}">${children}</span>`
            + `<span class="jt-bracket">}</span>`
            + `</span>`;
    }

    return String(value);
}

// Global click handler for JSON tree toggles (event delegation)
document.addEventListener('click', function(e) {
    const toggle = e.target.closest('.jt-toggle');
    if (!toggle) return;

    const node = toggle.parentElement;
    if (!node || !node.classList.contains('jt-node')) return;

    // Find direct children of this node
    const children = node.querySelector('.jt-children');
    const preview = node.querySelector('.jt-preview');
    if (!children) return;

    const isExpanding = toggle.textContent === '+';

    if (isExpanding) {
        // Expand this node AND all descendants
        expandAll(node);
    } else {
        // Collapse this node
        children.classList.add('hidden');
        if (preview) preview.classList.remove('hidden');
        toggle.textContent = '+';
        toggle.classList.remove('expanded');
    }
});

function expandAll(node) {
    // Expand all nested toggles within this node
    const allToggles = node.querySelectorAll('.jt-toggle');
    allToggles.forEach(t => {
        t.textContent = '-';
        t.classList.add('expanded');
    });
    const allChildren = node.querySelectorAll('.jt-children');
    allChildren.forEach(c => c.classList.remove('hidden'));
    const allPreviews = node.querySelectorAll('.jt-preview');
    allPreviews.forEach(p => p.classList.add('hidden'));
}

function esc(str) {
    if (!str) return '—';
    const s = String(str);
    const div = document.createElement('div');
    div.textContent = s;
    return div.innerHTML;
}

function truncate(str, maxLen) {
    if (!str) return '—';
    if (str.length <= maxLen) return str;
    return str.substring(0, maxLen) + '…';
}

function updateRequestCount() {
    document.getElementById('request-count').textContent = `${requestRows.size} requests`;
}

function clearAllTables() {
    requestRows.clear();
    document.getElementById('requests-tbody').innerHTML = '';
    document.getElementById('hooks-tbody').innerHTML = '';
    document.getElementById('conversation-timeline').innerHTML = '';
}

// ── Init ──
connect();
// Fetch MCP destination on load
fetch('/api/mcp-destination')
    .then(r => r.json())
    .then(data => {
        if (data.destinationUrl) {
            document.getElementById('mcp-destination').value = data.destinationUrl;
        }
    });
