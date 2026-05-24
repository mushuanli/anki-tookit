// ── WebSocket connection ──
const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
const wsUrl = `${protocol}//${location.host}/ws`;
let ws = null;
let selectedRequestId = null;
let captureEnabled = false;

// ── Pagination & filter state ──
let currentPage = 1;
let pageSize = 50;
let filterModel = '';
let filterSession = '';
let filterTimeFrom = '';
let filterTimeTo = '';

// ── Selection state ──
const selectedIds = new Set();

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

// ── Request table (paginated + filtered) ──
const requestRows = new Map();

function getFilteredRequests() {
    let result = [];
    for (const req of requestRows.values()) {
        if (filterModel && req.model !== filterModel) continue;
        if (filterSession && req.session_id !== filterSession) continue;
        if (filterTimeFrom && new Date(req.timestamp) < new Date(filterTimeFrom)) continue;
        if (filterTimeTo && new Date(req.timestamp) > new Date(filterTimeTo)) continue;
        result.push(req);
    }
    result.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
    return result;
}

function renderPage() {
    const filtered = getFilteredRequests();
    const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const start = (currentPage - 1) * pageSize;
    const pageItems = filtered.slice(start, start + pageSize);

    const tbody = document.getElementById('requests-tbody');
    tbody.innerHTML = '';
    pageItems.forEach(req => {
        const tr = document.createElement('tr');
        tr.id = `req-${req.id}`;
        tr.innerHTML = buildRequestRowHTML(req);
        tr.addEventListener('click', () => showRequestDetail(req));
        tbody.appendChild(tr);
    });

    if (selectedRequestId) {
        const row = document.getElementById(`req-${selectedRequestId}`);
        if (row) row.classList.add('selected');
    }

    updatePagination(filtered.length, totalPages);
    updateSelectionUI();
}

function updatePagination(total, totalPages) {
    document.getElementById('page-info').textContent = `${total} requests`;
    document.getElementById('page-num').textContent = `Page ${currentPage} / ${totalPages}`;
    document.getElementById('btn-page-prev').disabled = currentPage <= 1;
    document.getElementById('btn-page-next').disabled = currentPage >= totalPages;
}

function upsertRequestRow(req) {
    const isNew = !requestRows.has(req.id);
    requestRows.set(req.id, req);
    if (isNew || req.id === selectedRequestId) {
        renderPage();
    } else {
        const row = document.getElementById(`req-${req.id}`);
        if (row) {
            row.innerHTML = buildRequestRowHTML(req);
        }
    }
    updateFilterOptions();
}

function renderRequestTable(requests) {
    requestRows.clear();
    requests.forEach(req => requestRows.set(req.id, req));
    currentPage = 1;
    renderPage();
    updateFilterOptions();
}

function buildRequestRowHTML(req) {
    let statusClass = '';
    if (req.status_code) {
        if (req.status_code < 400) statusClass = 'status-200';
        else if (req.status_code < 500) statusClass = 'status-4xx';
        else statusClass = 'status-5xx';
    }
    const checked = selectedIds.has(req.id) ? 'checked' : '';
    return `
        <td class="col-chk"><input type="checkbox" class="row-chk" data-id="${req.id}" ${checked}></td>
        <td>${formatTime(req.timestamp)}</td>
        <td>${esc(req.method)}</td>
        <td>${esc(req.path)}</td>
        <td class="${statusClass}">${req.status_code || '—'}</td>
        <td>${esc(req.model || '—')}</td>
        <td>${esc(req.session_id?.substring(0, 8) || '—')}</td>
        <td>${req.input_tokens || '—'}</td>
        <td>${req.output_tokens || '—'}</td>
        <td>${req.duration_ms != null ? req.duration_ms + 'ms' : '—'}</td>
        <td>${req.time_to_first_token_ms != null ? req.time_to_first_token_ms + 'ms' : '—'}</td>
        <td class="row-actions"><button class="btn-delete-row" data-id="${req.id}" title="Delete">×</button></td>
    `;
}

function showRequestDetail(req) {
    selectedRequestId = req.id;
    const content = document.getElementById('detail-content');
    delete content.dataset.streamStarted;
    document.getElementById('request-detail').classList.remove('hidden');
    document.getElementById('detail-title').textContent = `${req.method} ${req.path}`;

    const filtered = getFilteredRequests();
    const idx = filtered.findIndex(r => r.id === req.id);
    if (idx >= 0) {
        const targetPage = Math.floor(idx / pageSize) + 1;
        if (targetPage !== currentPage) {
            currentPage = targetPage;
        }
    }
    renderPage();

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
    if (req.content_text) {
        parts.push('=== Response Content ===');
        parts.push(req.content_text);
    }
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
let upstreamEditMode = null;
let upstreamList = [];

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

    list.forEach((u, i) => {
        const opt = document.createElement('option');
        opt.value = u.name;
        opt.textContent = u.name + (u.has_token ? ' \uD83D\uDD11' : '')
            + (u.model_map && Object.keys(u.model_map).length > 0 ? ' \uD83D\uDD04' : '');
        if (u.active) {
            opt.selected = true;
            display.textContent = u.url + (u.has_token ? ' (has token)' : '')
                + (u.model_map && Object.keys(u.model_map).length > 0 ? ' (has model map)' : '');
        }
        select.appendChild(opt);
    });

    delBtn.disabled = list.length <= 1;
}

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

document.getElementById('upstream-select').addEventListener('change', async () => {
    const name = document.getElementById('upstream-select').value;
    if (!name) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}/activate`, { method: 'POST' });
});

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

document.getElementById('btn-upstream-edit').addEventListener('click', () => {
    const select = document.getElementById('upstream-select');
    const name = select.value;
    if (!name) return;
    const display = document.getElementById('upstream-url-display');
    upstreamEditMode = 'edit';
    document.getElementById('upstream-edit-name').value = name;
    document.getElementById('upstream-edit-url').value = display.textContent.replace(/ \(has token\)| \(has model map\)/g, '');
    document.getElementById('upstream-edit-token').value = '';
    document.getElementById('upstream-edit-token').placeholder = 'Token (unchanged if empty)';
    const u = upstreamList.find(u => u.name === name);
    document.getElementById('upstream-edit-modelmap').value = u ? modelMapToText(u.model_map) : '';
    document.getElementById('upstream-edit-name').disabled = true;
    document.getElementById('upstream-edit-form').classList.remove('hidden');
    document.getElementById('upstream-edit-url').focus();
});

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

document.getElementById('btn-upstream-cancel').addEventListener('click', hideUpstreamForm);

function hideUpstreamForm() {
    upstreamEditMode = null;
    document.getElementById('upstream-edit-form').classList.add('hidden');
}

document.getElementById('btn-upstream-delete').addEventListener('click', async () => {
    const name = document.getElementById('upstream-select').value;
    if (!name) return;
    if (!confirm(`Delete upstream "${name}"?`)) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}`, { method: 'DELETE' });
});

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
    btn.textContent = captureEnabled ? 'Dumping...' : 'Dump Raw';
    btn.style.background = captureEnabled ? 'var(--accent)' : '';
    document.getElementById('capture-status').textContent = captureEnabled ? 'Dumping' : '';
}

// ── Session actions (appear when a session filter is selected) ──

async function refreshSessionActions() {
    const sid = filterSession;
    const exportBtn = document.getElementById('btn-session-export');
    const renameBtn = document.getElementById('btn-session-rename');
    const deleteBtn = document.getElementById('btn-session-delete');

    if (!sid) {
        exportBtn.classList.add('hidden');
        renameBtn.classList.add('hidden');
        deleteBtn.classList.add('hidden');
        return;
    }

    // Fetch session details to get current label
    let session = null;
    try {
        const resp = await fetch(`/api/session/${encodeURIComponent(sid)}`);
        const data = await resp.json();
        session = data.session;
    } catch (e) { /* ignore */ }

    exportBtn.classList.remove('hidden');
    renameBtn.classList.remove('hidden');
    deleteBtn.classList.remove('hidden');

    // Export: open links in new tabs
    exportBtn.onclick = () => {
        window.open(`/api/session/${encodeURIComponent(sid)}/export?format=json`, '_blank');
    };

    // Rename
    renameBtn.onclick = () => {
        const current = session?.label || sid.substring(0, 8);
        const label = prompt('New name:', current);
        if (label === null || label.trim() === '' || label.trim() === current) return;
        fetch(`/api/session/${encodeURIComponent(sid)}`, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ label: label.trim() })
        }).then(() => updateFilterOptions());
    };

    // Delete
    deleteBtn.onclick = () => {
        const name = session?.label || sid.substring(0, 8);
        if (!confirm(`Delete session "${name}" and all its requests?`)) return;
        fetch(`/api/session/${encodeURIComponent(sid)}`, { method: 'DELETE' }).then(() => {
            filterSession = '';
            document.getElementById('filter-session').value = '';
            refreshSessionActions();
            applyFiltersAndRender();
            updateFilterOptions();
        });
    };
}

// ── Filters ──
let sessionCache = {}; // session_id → label mapping

function updateFilterOptions() {
    // Model filter
    const models = new Set();
    requestRows.forEach(r => { if (r.model) models.add(r.model); });
    const modelSelect = document.getElementById('filter-model');
    const currentModel = modelSelect.value;
    modelSelect.innerHTML = '<option value="">All Models</option>';
    models.forEach(m => {
        modelSelect.innerHTML += `<option value="${esc(m)}">${esc(m)}</option>`;
    });
    modelSelect.value = currentModel;

    // Session filter — fetch labels from API for display names
    const sessionsInData = new Set();
    requestRows.forEach(r => { if (r.session_id) sessionsInData.add(r.session_id); });

    Promise.all(
        Array.from(sessionsInData).map(sid =>
            fetch(`/api/session/${encodeURIComponent(sid)}`)
                .then(r => r.json())
                .then(data => { sessionCache[sid] = data.session?.label || sid.substring(0, 8); })
                .catch(() => { sessionCache[sid] = sid.substring(0, 8); })
        )
    ).then(() => {
        const sessionSelect = document.getElementById('filter-session');
        const currentSession = sessionSelect.value;
        sessionSelect.innerHTML = '<option value="">All Sessions</option>';
        sessionsInData.forEach(s => {
            const label = esc(sessionCache[s] || s.substring(0, 8));
            sessionSelect.innerHTML += `<option value="${esc(s)}">${label} (${esc(s.substring(0, 8))})</option>`;
        });
        sessionSelect.value = currentSession;
    });
}

function applyFiltersAndRender() {
    currentPage = 1;
    renderPage();
}

document.getElementById('filter-model').addEventListener('change', () => {
    filterModel = document.getElementById('filter-model').value;
    applyFiltersAndRender();
});

document.getElementById('filter-session').addEventListener('change', () => {
    filterSession = document.getElementById('filter-session').value;
    refreshSessionActions();
    applyFiltersAndRender();
});

document.getElementById('filter-time-from').addEventListener('change', () => {
    filterTimeFrom = document.getElementById('filter-time-from').value;
    if (filterTimeFrom) filterTimeFrom += ':00';
    applyFiltersAndRender();
});

document.getElementById('filter-time-to').addEventListener('change', () => {
    filterTimeTo = document.getElementById('filter-time-to').value;
    if (filterTimeTo) filterTimeTo += ':00';
    applyFiltersAndRender();
});

// ── Pagination controls ──
document.getElementById('page-size').addEventListener('change', () => {
    pageSize = parseInt(document.getElementById('page-size').value);
    currentPage = 1;
    renderPage();
});

document.getElementById('btn-page-prev').addEventListener('click', () => {
    if (currentPage > 1) {
        currentPage--;
        renderPage();
    }
});

document.getElementById('btn-page-next').addEventListener('click', () => {
    const totalPages = Math.max(1, Math.ceil(getFilteredRequests().length / pageSize));
    if (currentPage < totalPages) {
        currentPage++;
        renderPage();
    }
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

document.addEventListener('click', function(e) {
    const toggle = e.target.closest('.jt-toggle');
    if (!toggle) return;
    const node = toggle.parentElement;
    if (!node || !node.classList.contains('jt-node')) return;
    const children = node.querySelector('.jt-children');
    const preview = node.querySelector('.jt-preview');
    if (!children) return;
    const isExpanding = toggle.textContent === '+';
    if (isExpanding) {
        expandAll(node);
    } else {
        children.classList.add('hidden');
        if (preview) preview.classList.remove('hidden');
        toggle.textContent = '+';
        toggle.classList.remove('expanded');
    }
});

function expandAll(node) {
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

// ── Selection & delete (event delegation) ──
document.addEventListener('change', (e) => {
    if (e.target.classList.contains('row-chk')) {
        const id = e.target.dataset.id;
        if (e.target.checked) {
            selectedIds.add(id);
        } else {
            selectedIds.delete(id);
        }
        updateSelectionUI();
    }
});

document.addEventListener('change', (e) => {
    if (e.target.id === 'select-all') {
        const checked = e.target.checked;
        document.querySelectorAll('.row-chk').forEach(cb => {
            cb.checked = checked;
            const id = cb.dataset.id;
            if (checked) {
                selectedIds.add(id);
            } else {
                selectedIds.delete(id);
            }
        });
        updateSelectionUI();
    }
});

document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.btn-delete-row');
    if (!btn) return;
    e.stopPropagation();
    const id = btn.dataset.id;
    if (!confirm(`Delete request ${id.substring(0, 8)}?`)) return;
    const resp = await fetch(`/api/request/${encodeURIComponent(id)}`, { method: 'DELETE' });
    if (resp.ok) {
        requestRows.delete(id);
        selectedIds.delete(id);
        if (selectedRequestId === id) {
            selectedRequestId = null;
            document.getElementById('request-detail').classList.add('hidden');
        }
        renderPage();
        updateFilterOptions();
        updateRequestCount();
    }
});

document.getElementById('btn-delete-selected').addEventListener('click', async () => {
    if (selectedIds.size === 0) return;
    if (!confirm(`Delete ${selectedIds.size} selected request(s)?`)) return;
    const ids = Array.from(selectedIds);
    const resp = await fetch('/api/requests', {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids })
    });
    if (resp.ok) {
        ids.forEach(id => requestRows.delete(id));
        selectedIds.clear();
        document.getElementById('select-all').checked = false;
        if (selectedRequestId && ids.includes(selectedRequestId)) {
            selectedRequestId = null;
            document.getElementById('request-detail').classList.add('hidden');
        }
        renderPage();
        updateFilterOptions();
        updateRequestCount();
    }
});

function updateSelectionUI() {
    const count = selectedIds.size;
    document.getElementById('selected-count').textContent = count;
    const btn = document.getElementById('btn-delete-selected');
    if (count > 0) {
        btn.classList.remove('hidden');
    } else {
        btn.classList.add('hidden');
    }
    const totalVisible = document.querySelectorAll('.row-chk').length;
    const selectAll = document.getElementById('select-all');
    if (count === 0) {
        selectAll.checked = false;
        selectAll.indeterminate = false;
    } else if (count >= totalVisible) {
        selectAll.checked = true;
        selectAll.indeterminate = false;
    } else {
        selectAll.checked = false;
        selectAll.indeterminate = true;
    }
}

function clearAllTables() {
    requestRows.clear();
    currentPage = 1;
    filterModel = '';
    filterSession = '';
    filterTimeFrom = '';
    filterTimeTo = '';
    document.getElementById('filter-model').value = '';
    document.getElementById('filter-session').innerHTML = '<option value="">All Sessions</option>';
    document.getElementById('filter-time-from').value = '';
    document.getElementById('filter-time-to').value = '';
    document.getElementById('requests-tbody').innerHTML = '';
    document.getElementById('hooks-tbody').innerHTML = '';
    document.getElementById('conversation-timeline').innerHTML = '';
    updatePagination(0, 1);
    updateRequestCount();
    refreshSessionActions();
}

// ── Init ──
connect();
fetch('/api/mcp-destination')
    .then(r => r.json())
    .then(data => {
        if (data.destinationUrl) {
            document.getElementById('mcp-destination').value = data.destinationUrl;
        }
    });
fetch('/api/capture/status')
    .then(r => r.json())
    .then(data => {
        captureEnabled = data.enabled;
        updateCaptureButton();
    });
