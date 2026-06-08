// ── WebSocket ──
const protocol = location.protocol === 'https:' ? 'wss:' : 'ws:';
let ws = null;
let selectedRequestId = null;
let captureEnabled = false;

// Reconnection with exponential backoff: 1s → 2s → 4s → … → 30s max
let _reconnectDelay = 1000;
const _RECONNECT_MAX = 30000;
let _lastMsgTime = Date.now();
let _silentTimer = null;

// ── Pagination & filter state ──
let currentPage = 1;
let pageSize = 50;
let filterModel = '';
let filterSession = '';
let filterTimeFrom = '';
let filterTimeTo = '';

// ── Selection state ──
const selectedIds = new Set();

// ── Session folding state ──
const expandedSessions = new Set();  // session IDs currently expanded
let sessionFoldEnabled = true;  // global toggle for session folding

// ── Provider / upstream state ──
let providerList = [];  // ProviderInfo[]
let upstreamList = [];  // UpstreamInfo[]
let activeUpstream = '';
let activeEffort = 'auto';
const EFFORT_LEVELS = ['auto', 'low', 'medium', 'high', 'xhigh', 'max', 'ultracode'];

function connect() {
    ws = new WebSocket(`${protocol}//${location.host}/ws`);

    ws.onopen = () => {
        _reconnectDelay = 1000;
        _lastMsgTime = Date.now();
        const el = document.getElementById('connection-status');
        el.className = 'connected';
        el.textContent = 'Connected';
        console.debug('[ws] connected at', new Date().toISOString());
        startSilentCheck();
    };

    ws.onclose = (ev) => {
        clearInterval(_silentTimer);
        clearTimeout(_updateFilterTimer);
        clearTimeout(_renderPageTimer);
        const el = document.getElementById('connection-status');
        el.className = 'disconnected';
        const label = ev.code === 1000 ? 'Disconnected'
                    : ev.code === 1005 ? 'Disconnected (timeout)'
                    : `Disconnected (${ev.code})`;
        el.textContent = label;
        console.warn(`[ws] closed at ${new Date().toISOString()} — code=${ev.code} reason="${ev.reason}" clean=${ev.wasClean}, retry in ${_reconnectDelay}ms`);
        setTimeout(connect, _reconnectDelay);
        _reconnectDelay = Math.min(_reconnectDelay * 2, _RECONNECT_MAX);
    };

    ws.onerror = (e) => {
        console.error('[ws] error', e);
        ws.close(); // triggers onclose → retry
    };

    ws.onmessage = (event) => {
        try { handleMessage(JSON.parse(event.data)); }
        catch (e) { console.error('Failed to parse WS message:', e); }
    };
}

function handleMessage(msg) {
    _lastMsgTime = Date.now();
    console.debug('[ws] msg type=' + msg.type);
    switch (msg.type) {
        case 'History':
            // Requests are loaded via REST GET /api/requests — this WS branch is kept
            // for backward compatibility but the server no longer sends it on connect.
            break;
        case 'NewRequest':
        case 'RequestUpdated':
            upsertRequestRow(msg.payload);
            addToTimeline(msg.payload);
            if (msg.payload.id === selectedRequestId) showRequestDetail(msg.payload);
            updateRequestCount();
            break;
        case 'SseEvent':
            if (msg.payload.request_id === selectedRequestId) appendSseEvent(msg.payload.event);
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
            if (msg.payload.destination_url) document.getElementById('mcp-destination').value = msg.payload.destination_url;
            break;
        case 'UpstreamChanged':
            applyUpstreamState(msg.payload.active_upstream, msg.payload.upstreams, msg.payload.providers, msg.payload.active_effort);
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
        if (view === 'cost' && !document.getElementById('cost-from').value) {
            const { from, to } = COST_PRESETS.today();
            document.getElementById('cost-from').value = from;
            document.getElementById('cost-to').value = to;
            loadCosts();
        }
    });
});

// ── Request table ──
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

function formatCostNum(req) {
    const price = lookupProviderPrice(req.model);
    if (!price) return 0;
    const inTotal = req.total_input_tokens ?? req.input_tokens ?? 0;
    const outTotal = req.total_output_tokens ?? req.output_tokens ?? 0;
    return inTotal * price.in / 1_000_000 + outTotal * price.out / 1_000_000;
}

function getSessionGroups() {
    const filtered = getFilteredRequests();
    const groupsMap = new Map();
    for (const req of filtered) {
        const sid = req.session_id || '__no_session__';
        if (!groupsMap.has(sid)) {
            groupsMap.set(sid, {
                session_id: sid,
                label: sessionCache[sid] || sid.substring(0, 8),
                requests: [],
                totalIn: 0,
                totalOut: 0,
                totalCost: 0,
                firstTime: req.timestamp,
                lastTime: req.timestamp,
                models: new Set(),
            });
        }
        const g = groupsMap.get(sid);
        g.requests.push(req);
        if (req.model) g.models.add(req.model);
        if (new Date(req.timestamp) < new Date(g.firstTime)) g.firstTime = req.timestamp;
        if (new Date(req.timestamp) > new Date(g.lastTime)) g.lastTime = req.timestamp;
    }
    const result = Array.from(groupsMap.values());
    result.forEach(g => {
        g.requests.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
        // The request with the largest timestamp carries cumulative total_* token counts,
        // so we take its values as the session-level totals rather than summing across requests.
        const latest = g.requests[0];
        g.totalIn = latest.total_input_tokens || 0;
        g.totalOut = latest.total_output_tokens || 0;
        g.totalCost = formatCostNum(latest);
        g.models = Array.from(g.models);
    });
    result.sort((a, b) => new Date(b.lastTime) - new Date(a.lastTime));
    return result;
}

function buildSessionHeaderHTML(group, isExpanded) {
    const reqCount = group.requests.length;
    const timeRange = formatTime(group.lastTime);
    const tokens = group.totalIn > 0 || group.totalOut > 0 ? `${group.totalIn}/${group.totalOut}` : '—';
    const cost = group.totalCost > 0 ? `¥${group.totalCost.toFixed(4)}` : '—';
    const models = group.models.join(', ');
    return `<td colspan="13">
        <div class="session-header-inner">
            <span class="session-expand-icon${isExpanded ? ' expanded' : ''}">▶</span>
            <span class="session-label">${esc(group.label)}</span>
            <span class="session-summary">
                <span class="session-summary-item">${reqCount} req${reqCount > 1 ? 's' : ''}</span>
                ${models ? `<span class="session-summary-item">${esc(models)}</span>` : ''}
                <span class="session-summary-item">${timeRange}</span>
                <span class="session-summary-item">${tokens}t</span>
                <span class="session-summary-item cost">${cost}</span>
            </span>
        </div>
    </td>`;
}

function toggleSession(sessionId) {
    if (expandedSessions.has(sessionId)) {
        expandedSessions.delete(sessionId);
    } else {
        expandedSessions.add(sessionId);
    }
    renderPage();
}

function expandAllSessions() {
    const groups = getSessionGroups();
    groups.forEach(g => expandedSessions.add(g.session_id));
    renderPage();
}

function collapseAllSessions() {
    expandedSessions.clear();
    renderPage();
}

function renderPage() {
    const groups = getSessionGroups();
    const totalPages = Math.max(1, Math.ceil(groups.length / pageSize));
    if (currentPage > totalPages) currentPage = totalPages;
    const start = (currentPage - 1) * pageSize;
    const tbody = document.getElementById('requests-tbody');
    tbody.innerHTML = '';

    const pageGroups = groups.slice(start, start + pageSize);
    pageGroups.forEach((group, idx) => {
        // Requests without a session ID are rendered as plain rows (no folding)
        if (group.session_id === '__no_session__') {
            group.requests.forEach(req => {
                const tr = document.createElement('tr');
                tr.id = `req-${req.id}`;
                tr.innerHTML = buildRequestRowHTML(req);
                tr.addEventListener('click', (e) => {
                    if (e.target.closest('.row-chk') || e.target.closest('.btn-delete-row')) return;
                    showRequestDetail(req);
                });
                tbody.appendChild(tr);
            });
        } else {
            const isExpanded = expandedSessions.has(group.session_id);

            // Session header row
            const headerTr = document.createElement('tr');
            headerTr.className = 'session-header';
            headerTr.dataset.session = group.session_id;
            headerTr.innerHTML = buildSessionHeaderHTML(group, isExpanded);
            headerTr.addEventListener('click', (e) => {
                if (e.target.closest('.row-chk')) return;
                toggleSession(group.session_id);
            });
            tbody.appendChild(headerTr);

            // Child request rows
            group.requests.forEach(req => {
                const tr = document.createElement('tr');
                tr.id = `req-${req.id}`;
                tr.className = 'session-child' + (isExpanded ? '' : ' collapsed');
                tr.dataset.session = group.session_id;
                tr.innerHTML = buildRequestRowHTML(req);
                tr.addEventListener('click', (e) => {
                    if (e.target.closest('.row-chk') || e.target.closest('.btn-delete-row')) return;
                    showRequestDetail(req);
                });
                tbody.appendChild(tr);
            });
        }

        // Spacer between groups
        if (idx < pageGroups.length - 1) {
            const spacerTr = document.createElement('tr');
            spacerTr.className = 'session-group-spacer';
            spacerTr.innerHTML = '<td colspan="13"></td>';
            tbody.appendChild(spacerTr);
        }
    });

    // Highlight selected row
    if (selectedRequestId) {
        const row = document.getElementById(`req-${selectedRequestId}`);
        if (row) row.classList.add('selected');
    }

    updatePagination(groups.length, totalPages);
    updateSelectionUI();
}

function updatePagination(total, totalPages) {
    document.getElementById('page-info').textContent = `${total} sessions · ${requestRows.size} requests`;
    document.getElementById('page-num').textContent = `Page ${currentPage} / ${totalPages}`;
    document.getElementById('btn-page-prev').disabled = currentPage <= 1;
    document.getElementById('btn-page-next').disabled = currentPage >= totalPages;
}

function upsertRequestRow(req) {
    const isNew = !requestRows.has(req.id);
    requestRows.set(req.id, req);
    // Always re-render when session folding is on — new requests may affect group layout
    if (isNew || req.id === selectedRequestId || sessionFoldEnabled) {
        if (!_renderPageTimer) {
            _renderPageTimer = setTimeout(() => {
                renderPage();
                _renderPageTimer = null;
            }, 200);
        }
    } else {
        const row = document.getElementById(`req-${req.id}`);
        if (row) row.innerHTML = buildRequestRowHTML(req);
    }
    // Debounce filter updates — streaming can fire 10-20x/sec
    clearTimeout(_updateFilterTimer);
    _updateFilterTimer = setTimeout(updateFilterOptions, 500);
}

function buildRequestRowHTML(req) {
    let statusClass = '';
    if (req.status_code) {
        if (req.status_code < 400) statusClass = 'status-200';
        else if (req.status_code < 500) statusClass = 'status-4xx';
        else statusClass = 'status-5xx';
    }
    const checked = selectedIds.has(req.id) ? 'checked' : '';

    const inOut = (req.input_tokens != null || req.output_tokens != null)
        ? `${req.input_tokens ?? 0}/${req.output_tokens ?? 0}`
        : '—';
    const totalInOut = (req.total_input_tokens != null || req.total_output_tokens != null)
        ? `${req.total_input_tokens ?? 0}/${req.total_output_tokens ?? 0}`
        : '—';
    const costStr = formatCost(req);

    return `
        <td class="col-chk"><input type="checkbox" class="row-chk" data-id="${req.id}" ${checked}></td>
        <td>${formatTime(req.timestamp)}</td>
        <td>${esc(req.method)}</td>
        <td>${esc(req.path)}</td>
        <td class="${statusClass}">${req.status_code || '—'}</td>
        <td>${esc(req.model || '—')}</td>
        <td>${esc(req.session_id?.substring(0, 8) || '—')}</td>
        <td>${inOut}</td>
        <td>${totalInOut}</td>
        <td class="col-cost">${costStr}</td>
        <td>${req.duration_ms != null ? req.duration_ms + 'ms' : '—'}</td>
        <td>${req.time_to_first_token_ms != null ? req.time_to_first_token_ms + 'ms' : '—'}</td>
        <td class="row-actions"><button class="btn-delete-row" data-id="${req.id}" title="Delete">×</button></td>
    `;
}

function lookupProviderPrice(model) {
    if (!model) return null;
    for (const p of providerList) {
        if (p.models && Array.isArray(p.models)) {
            const match = p.models.find(m => m.id === model);
            if (match) {
                return {
                    in: match.price_per_million_input ?? 5,
                    out: match.price_per_million_output ?? 25,
                };
            }
        }
    }
    return null;
}

function formatCost(req) {
    const price = lookupProviderPrice(req.model);
    if (!price) return '—';
    const inTotal = req.total_input_tokens ?? req.input_tokens ?? 0;
    const outTotal = req.total_output_tokens ?? req.output_tokens ?? 0;
    const inCost = inTotal * price.in / 1_000_000;
    const outCost = outTotal * price.out / 1_000_000;
    const total = inCost + outCost;
    if (total === 0) return '¥0.00';
    if (total < 0.001) return `¥${total.toFixed(5)}`;
    return `¥${total.toFixed(4)}`;
}

// ── Request detail ──

function showRequestDetail(req) {
    selectedRequestId = req.id;
    // Auto-expand the session containing this request
    if (req.session_id) expandedSessions.add(req.session_id);

    const content = document.getElementById('detail-content');
    delete content.dataset.streamStarted;
    document.getElementById('request-detail').classList.remove('hidden');
    document.getElementById('view-inspector').classList.add('detail-open');
    document.getElementById('detail-title').textContent = `${req.method} ${req.path}`;

    // Find page containing this request's session group
    const groups = getSessionGroups();
    const groupIdx = groups.findIndex(g => g.session_id === (req.session_id || '__no_session__'));
    if (groupIdx >= 0) {
        const targetPage = Math.floor(groupIdx / pageSize) + 1;
        if (targetPage !== currentPage) currentPage = targetPage;
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
        const lines = headers.split('\n');
        parts.push(`<details class="foldable-section"><summary>Headers (${lines.length} lines)</summary><pre class="detail-headers">${esc(headers)}</pre></details>`);
    }
    if (body) {
        const parsed = tryParseJson(body);
        if (parsed) parts.push(`<div class="json-tree">${jsonTreeHTML(parsed, 0)}</div>`);
        else parts.push(`<pre class="detail-plain">${esc(body)}</pre>`);
    }
    return parts.join('');
}

function formatSseContent(req) {
    const parts = [];
    if (req.content_text) {
        parts.push('=== Response Content ===');
        parts.push(req.content_text);
    }
    const structured = (req.sse_events || []).filter(e => {
        if (!e.data) return false;
        try {
            const d = JSON.parse(e.data);
            return d.type !== 'content_block_delta' && d.type !== 'ping';
        } catch { return true; }
    });
    if (structured.length > 0) {
        if (parts.length > 0) parts.push('');
        parts.push('=== Events ===');
        structured.forEach(e => parts.push(`event: ${e.event_type || '—'}\ndata: ${e.data || '—'}\n`));
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
    document.getElementById('view-inspector').classList.remove('detail-open');
    selectedRequestId = null;
    document.querySelectorAll('#requests-tbody tr').forEach(r => r.classList.remove('selected'));
});

// ── Fullscreen ──

let fullscreenReqId = null;

document.getElementById('btn-fullscreen-close').addEventListener('click', () => {
    document.getElementById('fullscreen-overlay').classList.add('hidden');
    fullscreenReqId = null;
});

document.getElementById('btn-fullscreen-detail').addEventListener('click', () => {
    const req = requestRows.get(selectedRequestId);
    if (!req) return;
    fullscreenReqId = req.id;
    const activeTab = document.querySelector('.detail-tabs .tab.active')?.dataset.tab || 'request';
    renderDetailFullscreen(req, activeTab);
});

function renderDetailFullscreen(req, activeTab) {
    document.getElementById('fullscreen-title').textContent = `${req.method} ${req.path}`;
    const content = document.getElementById('fullscreen-content');
    content.innerHTML = `
        <div class="detail-tabs fs-detail-tabs" style="padding:0 16px;border-bottom:1px solid var(--border);background:var(--bg-panel);">
            <button class="tab${activeTab==='request'?' active':''}" data-tab="request">Request</button>
            <button class="tab${activeTab==='response'?' active':''}" data-tab="response">Response</button>
            <button class="tab${activeTab==='sse'?' active':''}" data-tab="sse">SSE Events</button>
        </div>
        <div id="fs-detail-body" class="detail-body" style="max-height:none;flex:1;overflow-y:auto;"></div>
    `;
    renderFullscreenTab(activeTab, req);
}

function renderFullscreenTab(tab, req) {
    const body = document.getElementById('fs-detail-body');
    if (!body) return;
    switch (tab) {
        case 'request': body.innerHTML = renderDetailBody(formatHeaders(req.request_headers), req.request_body); break;
        case 'response': body.innerHTML = renderDetailBody(formatHeaders(req.response_headers), req.response_body); break;
        case 'sse': body.textContent = formatSseContent(req); break;
    }
}

document.getElementById('fullscreen-content').addEventListener('click', (e) => {
    const btn = e.target.closest('.fs-detail-tabs .tab');
    if (!btn) return;
    const req = requestRows.get(fullscreenReqId);
    if (!req) return;
    document.querySelectorAll('.fs-detail-tabs .tab').forEach(t => t.classList.remove('active'));
    btn.classList.add('active');
    renderFullscreenTab(btn.dataset.tab, req);
});

document.getElementById('btn-fullscreen-conv').addEventListener('click', () => {
    document.getElementById('fullscreen-title').textContent = 'Conversation';
    const content = document.getElementById('fullscreen-content');
    content.innerHTML = document.getElementById('conversation-timeline').innerHTML;
    document.getElementById('fullscreen-overlay').classList.remove('hidden');
});

// ── Timeline ──
const convSessions = new Set();

function addToTimeline(item) {
    const timeline = document.getElementById('conversation-timeline');
    const div = document.createElement('div');
    div.className = 'timeline-item';
    if (item.session_id) {
        div.dataset.session = item.session_id;
        if (!convSessions.has(item.session_id)) {
            convSessions.add(item.session_id);
            updateConvFilter();
        }
    }
    if (item.hook_event_name) {
        div.classList.add('hook');
        div.innerHTML = `
            <div class="timeline-header"><span>Hook: ${esc(item.hook_event_name)}</span><span>${formatTime(item.timestamp)}</span></div>
            <div class="timeline-body">${esc(JSON.stringify(item.hook_input, null, 2))}</div>`;
    } else {
        const model = item.model || '—';
        const tokens = item.input_tokens != null ? `${item.input_tokens}→${item.output_tokens || 0}t` : '';
        const content = item.content_text || item.response_body || item.request_body || '';
        const formatted = esc(content)
            .replace(/\[Thinking\]/g, '<span class="tl-thinking">[Thinking]</span>')
            .replace(/\[Tool Use\]/g, '<span class="tl-tool">[Tool Use]</span>');
        div.innerHTML = `
            <div class="timeline-header">
                <span>${esc(item.method)} ${esc(item.path)} — ${item.status_code || '...'} | ${esc(model)} | ${tokens} | ${esc(item.session_id?.substring(0, 8) || '—')}</span>
                <span>${formatTime(item.timestamp)} | ${item.duration_ms || 0}ms</span>
            </div>
            <div class="timeline-body">${formatted}</div>`;
    }
    timeline.prepend(div);
    while (timeline.children.length > 100) timeline.lastChild.remove();
}

function updateConvFilter() {
    const select = document.getElementById('conv-filter');
    const current = select.value;
    select.innerHTML = '<option value="">All</option>';
    convSessions.forEach(s => {
        select.innerHTML += `<option value="${esc(s)}">${esc(s.substring(0, 8))}</option>`;
    });
    select.value = current;
    applyConvFilter();
}

function applyConvFilter() {
    const sid = document.getElementById('conv-filter').value;
    document.querySelectorAll('#conversation-timeline .timeline-item').forEach(el => {
        el.style.display = (!sid || el.dataset.session === sid) ? '' : 'none';
    });
}
document.getElementById('conv-filter').addEventListener('change', applyConvFilter);

// ── MCP table ──
function addMcpRow(req) {
    const tbody = document.getElementById('mcp-tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${formatTime(req.timestamp)}</td><td>${esc(req.model || '—')}</td><td>${req.status_code || '—'}</td><td>${esc(truncate(req.request_body, 100))}</td><td>${esc(truncate(req.response_body, 100))}</td>`;
    tbody.prepend(tr);
    while (tbody.children.length > 100) tbody.lastChild.remove();
}
function renderMcpTable(requests) {
    document.getElementById('mcp-tbody').innerHTML = '';
    requests.forEach(req => addMcpRow(req));
}

// ── Hook table ──
function addHookRow(event) {
    const tbody = document.getElementById('hooks-tbody');
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${formatTime(event.timestamp)}</td><td>${esc(event.hook_event_name)}</td><td>${esc(event.session_id)}</td><td>${esc(event.cwd)}</td><td>${event.exit_code}</td>`;
    tbody.prepend(tr);
    while (tbody.children.length > 200) tbody.lastChild.remove();
}
function renderHookTable(events) {
    document.getElementById('hooks-tbody').innerHTML = '';
    events.forEach(e => addHookRow(e));
}

// ── Upstream select (Inspector toolbar) ──

document.getElementById('upstream-select').addEventListener('change', async () => {
    const name = document.getElementById('upstream-select').value;
    if (!name) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}/activate`, { method: 'POST' });
});

// ── Effort select (Inspector toolbar) ──

function populateEffortSelect(active) {
    const select = document.getElementById('effort-select');
    select.innerHTML = '';
    EFFORT_LEVELS.forEach(level => {
        const opt = document.createElement('option');
        opt.value = level;
        opt.textContent = level === 'auto' ? 'auto (passthrough)' : level;
        if (level === active) opt.selected = true;
        select.appendChild(opt);
    });
}

document.getElementById('effort-select').addEventListener('change', async () => {
    const effort = document.getElementById('effort-select').value;
    if (!effort) return;
    await fetch('/api/effort', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ effort }),
    });
});

function populateUpstreamSelect(upstreams, active) {
    const select = document.getElementById('upstream-select');
    select.innerHTML = '';
    if (!upstreams || upstreams.length === 0) {
        select.innerHTML = '<option value="">— no upstreams —</option>';
        return;
    }
    upstreams.forEach(u => {
        const opt = document.createElement('option');
        opt.value = u.name;
        opt.textContent = u.name + (u.active ? ' ✓' : '');
        if (u.name === active || u.active) opt.selected = true;
        select.appendChild(opt);
    });
}

// ── Settings: shared state update ──

function applyUpstreamState(active, upstreams, providers, effort) {
    activeUpstream = active;
    upstreamList = upstreams || [];
    providerList = providers || [];
    if (effort !== undefined) { activeEffort = effort; }
    populateUpstreamSelect(upstreams, active);
    populateEffortSelect(activeEffort);
    renderProviderList();
    renderUpstreamList();
    refreshProviderSelects();
}

// ── Settings: Providers ──

let providerEditMode = null;  // 'add' | 'edit'
let providerEditModels = [];  // model IDs being edited

function renderProviderList() {
    const container = document.getElementById('provider-list');
    if (providerList.length === 0) {
        container.innerHTML = '<div class="item-empty">No providers configured</div>';
        return;
    }
    container.innerHTML = providerList.map(p => {
        const modelPricing = (p.models || []).map(m => {
            const pIn = m.price_per_million_input ?? 5;
            const pOut = m.price_per_million_output ?? 25;
            return `${m.id}:￥${pIn}/${pOut}`;
        }).join(', ');
        return `
        <div class="item-row">
            <div class="item-row-info">
                <div class="item-row-name">${esc(p.name)}</div>
                <div class="item-row-meta">${esc(p.url)}${p.has_token ? ' · 🔑' : ''}${p.models && p.models.length ? ` · ${p.models.length} model${p.models.length !== 1 ? 's' : ''}` : ''}${modelPricing ? ` · ${modelPricing}` : ''}</div>
            </div>
            <div class="item-row-actions">
                <button class="btn-sm" onclick="openProviderEdit('${esc(p.name)}')">Edit</button>
                <button class="btn-sm btn-danger" onclick="deleteProvider('${esc(p.name)}')">×</button>
            </div>
        </div>
    `}).join('');
}

function openProviderEdit(name) {
    const p = name ? providerList.find(p => p.name === name) : null;
    providerEditMode = p ? 'edit' : 'add';
    providerEditModels = p ? (p.models || []).map(m => ({
        id: m.id,
        price_per_million_input: m.price_per_million_input ?? null,
        price_per_million_output: m.price_per_million_output ?? null,
    })) : [];

    document.getElementById('pe-name').value = p ? p.name : '';
    document.getElementById('pe-name').disabled = !!p;
    document.getElementById('pe-url').value = p ? p.url : '';
    document.getElementById('pe-token').value = '';
    document.getElementById('pe-token').placeholder = p ? 'Token (leave empty to keep current)' : 'sk-...';

    renderProviderModelList();
    document.getElementById('provider-edit').classList.remove('hidden');
    document.getElementById('pe-url').focus();
}

function renderProviderModelList() {
    const container = document.getElementById('pe-models-list');
    if (providerEditModels.length === 0) {
        container.innerHTML = '<div class="model-empty">No models added yet</div>';
        return;
    }
    container.innerHTML = providerEditModels.map((m, i) => {
        const pin = m.price_per_million_input != null ? m.price_per_million_input : '';
        const pout = m.price_per_million_output != null ? m.price_per_million_output : '';
        return `
        <div class="model-edit-row">
            <span class="model-edit-id">${esc(m.id)}</span>
            <input type="number" class="model-price-in" placeholder="in=5" min="0" step="0.01"
                   value="${pin}" onchange="providerEditModels[${i}].price_per_million_input = this.value ? parseFloat(this.value) : null">
            <input type="number" class="model-price-out" placeholder="out=25" min="0" step="0.01"
                   value="${pout}" onchange="providerEditModels[${i}].price_per_million_output = this.value ? parseFloat(this.value) : null">
            <button class="model-tag-del" onclick="removeProviderModel(${i})">×</button>
        </div>
    `}).join('');
}

function removeProviderModel(i) {
    providerEditModels.splice(i, 1);
    renderProviderModelList();
}

document.getElementById('pe-model-add-btn').addEventListener('click', () => {
    const input = document.getElementById('pe-model-input');
    const val = input.value.trim();
    if (val && !providerEditModels.some(m => m.id === val)) {
        providerEditModels.push({ id: val, price_per_million_input: null, price_per_million_output: null });
        renderProviderModelList();
    }
    input.value = '';
    input.focus();
});

document.getElementById('pe-model-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        e.preventDefault();
        document.getElementById('pe-model-add-btn').click();
    }
});

document.getElementById('btn-provider-add').addEventListener('click', () => {
    closeProviderEdit();
    openProviderEdit(null);
});

document.getElementById('btn-provider-save').addEventListener('click', async () => {
    const name = document.getElementById('pe-name').value.trim();
    const url = document.getElementById('pe-url').value.trim();
    const token = document.getElementById('pe-token').value.trim();
    if (!name || !url) { alert('Name and URL are required'); return; }

    const body = { name, url, models: providerEditModels };
    if (token) body.token = token;

    let resp;
    if (providerEditMode === 'add') {
        resp = await fetch('/api/providers', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
        resp = await fetch(`/api/providers/${encodeURIComponent(name)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    }
    if (resp.ok) {
        closeProviderEdit();
    } else {
        const err = await resp.json();
        alert(err.error || 'Failed to save provider');
    }
});

document.getElementById('btn-provider-cancel').addEventListener('click', closeProviderEdit);

function closeProviderEdit() {
    document.getElementById('provider-edit').classList.add('hidden');
    providerEditMode = null;
    providerEditModels = [];
}

async function deleteProvider(name) {
    if (!confirm(`Delete provider "${name}"?`)) return;
    await fetch(`/api/providers/${encodeURIComponent(name)}`, { method: 'DELETE' });
}

// ── Settings: Upstreams ──

let upstreamEditMode = null;  // 'add' | 'edit'
let upstreamEditName = null;  // name being edited

const TIER_IDS = ['high', 'mid', 'low', 'default'];

function renderUpstreamList() {
    const container = document.getElementById('upstream-list');
    if (upstreamList.length === 0) {
        container.innerHTML = '<div class="item-empty">No upstreams configured</div>';
        return;
    }
    container.innerHTML = upstreamList.map(u => {
        const tiers = [
            u.high && `H: ${u.high.provider}/${u.high.model}`,
            u.mid && `M: ${u.mid.provider}/${u.mid.model}`,
            u.low && `L: ${u.low.provider}/${u.low.model}`,
        ].filter(Boolean).join(' · ');
        const activeTag = u.active ? '<span class="active-badge">active</span>' : '';
        return `
            <div class="item-row${u.active ? ' item-active' : ''}">
                <div class="item-row-info">
                    <div class="item-row-name">${esc(u.name)} ${activeTag}</div>
                    <div class="item-row-meta">${esc(tiers || 'No tiers configured')}</div>
                </div>
                <div class="item-row-actions">
                    ${!u.active ? `<button class="btn-sm" onclick="activateUpstream('${esc(u.name)}')">Activate</button>` : ''}
                    <button class="btn-sm" onclick="openUpstreamEdit('${esc(u.name)}')">Edit</button>
                    <button class="btn-sm btn-danger" onclick="deleteUpstream('${esc(u.name)}')">×</button>
                </div>
            </div>`;
    }).join('');
}

function openUpstreamEdit(name) {
    const u = name ? upstreamList.find(u => u.name === name) : null;
    upstreamEditMode = u ? 'edit' : 'add';
    upstreamEditName = u ? u.name : null;

    document.getElementById('ue-name').value = u ? u.name : '';
    document.getElementById('ue-name').disabled = !!u;

    // Fill tiers
    const defaults = u ? {} : { high: 'opus', mid: 'sonnet', low: 'haiku' };
    fillTierForm('high', u?.high, defaults.high);
    fillTierForm('mid', u?.mid, defaults.mid);
    fillTierForm('low', u?.low, defaults.low);

    // Default
    document.getElementById('ue-default-provider').value = u?.default_provider || '';
    document.getElementById('ue-default-model').value = u?.default_model || '';
    refreshProviderSelects();
    updateModelDatalist('ue-default-provider', 'dl-default');

    document.getElementById('upstream-edit').classList.remove('hidden');
    document.getElementById('ue-name').focus();
}

function fillTierForm(tier, rule, defaultKw) {
    document.getElementById(`ue-${tier}-kw`).value = rule ? rule.keywords.join(', ') : (defaultKw || '');
    document.getElementById(`ue-${tier}-provider`).value = rule ? rule.provider : '';
    document.getElementById(`ue-${tier}-model`).value = rule ? rule.model : '';
}

function getTierPayload(tier) {
    const kw = document.getElementById(`ue-${tier}-kw`).value.trim();
    const provider = document.getElementById(`ue-${tier}-provider`).value;
    const model = document.getElementById(`ue-${tier}-model`).value.trim();
    if (!provider && !model) return null;
    return {
        keywords: kw ? kw.split(',').map(s => s.trim()).filter(Boolean) : [],
        provider,
        model,
    };
}

document.getElementById('btn-upstream-add').addEventListener('click', () => {
    closeUpstreamEdit();
    openUpstreamEdit(null);
});

document.getElementById('btn-upstream-save').addEventListener('click', async () => {
    const name = document.getElementById('ue-name').value.trim();
    if (!name) { alert('Name is required'); return; }

    const body = {
        name,
        high: getTierPayload('high'),
        mid: getTierPayload('mid'),
        low: getTierPayload('low'),
        default_provider: document.getElementById('ue-default-provider').value,
        default_model: document.getElementById('ue-default-model').value.trim(),
    };

    let resp;
    if (upstreamEditMode === 'add') {
        resp = await fetch('/api/upstreams', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    } else {
        resp = await fetch(`/api/upstreams/${encodeURIComponent(name)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    }
    if (resp.ok) {
        closeUpstreamEdit();
    } else {
        const err = await resp.json();
        alert(err.error || 'Failed to save upstream');
    }
});

document.getElementById('btn-upstream-cancel').addEventListener('click', closeUpstreamEdit);

function closeUpstreamEdit() {
    document.getElementById('upstream-edit').classList.add('hidden');
    upstreamEditMode = null;
    upstreamEditName = null;
}

async function activateUpstream(name) {
    await fetch(`/api/upstreams/${encodeURIComponent(name)}/activate`, { method: 'POST' });
}

async function deleteUpstream(name) {
    if (!confirm(`Delete upstream "${name}"?`)) return;
    await fetch(`/api/upstreams/${encodeURIComponent(name)}`, { method: 'DELETE' });
}

// ── Provider selects & model datalists ──

function refreshProviderSelects() {
    const opts = '<option value="">— none —</option>' +
        providerList.map(p => `<option value="${esc(p.name)}">${esc(p.name)}</option>`).join('');

    ['ue-high-provider', 'ue-mid-provider', 'ue-low-provider', 'ue-default-provider'].forEach(id => {
        const sel = document.getElementById(id);
        if (!sel) return;
        const current = sel.value;
        sel.innerHTML = opts;
        sel.value = current;
    });
}

function updateModelDatalist(selectId, datalistId) {
    const providerName = document.getElementById(selectId)?.value;
    const dl = document.getElementById(datalistId);
    if (!dl) return;
    const p = providerList.find(p => p.name === providerName);
    dl.innerHTML = (p?.models || []).map(m => `<option value="${esc(m)}">`).join('');
}

// Attach provider-select → datalist update listeners
document.getElementById('ue-high-provider').addEventListener('change', () => updateModelDatalist('ue-high-provider', 'dl-high'));
document.getElementById('ue-mid-provider').addEventListener('change', () => updateModelDatalist('ue-mid-provider', 'dl-mid'));
document.getElementById('ue-low-provider').addEventListener('change', () => updateModelDatalist('ue-low-provider', 'dl-low'));
document.getElementById('ue-default-provider').addEventListener('change', () => updateModelDatalist('ue-default-provider', 'dl-default'));

// ── MCP destination ──
document.getElementById('btn-set-mcp').addEventListener('click', async () => {
    const url = document.getElementById('mcp-destination').value.trim();
    await fetch('/api/mcp-destination', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ destinationUrl: url || null }) });
});

// ── Clear ──
document.getElementById('btn-clear-mcp-view').addEventListener('click', () => fetch('/api/clear-mcp', { method: 'POST' }));
document.getElementById('btn-clear-hooks').addEventListener('click', () => fetch('/api/clear', { method: 'POST' }));

// ── Session expand/collapse all ──
document.getElementById('btn-expand-all').addEventListener('click', expandAllSessions);
document.getElementById('btn-collapse-all').addEventListener('click', collapseAllSessions);

// ── Capture ──
document.getElementById('btn-toggle-capture').addEventListener('click', async () => {
    captureEnabled = !captureEnabled;
    await fetch('/api/capture', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ enabled: captureEnabled }) });
    updateCaptureButton();
});

function updateCaptureButton() {
    const btn = document.getElementById('btn-toggle-capture');
    btn.textContent = captureEnabled ? 'Dumping...' : 'Dump Raw';
    btn.style.background = captureEnabled ? 'var(--accent)' : '';
    document.getElementById('capture-status').textContent = captureEnabled ? 'Dumping' : '';
}

// ── Session actions ──

async function refreshSessionActions() {
    const sid = filterSession;
    const exportBtn = document.getElementById('btn-session-export');
    const renameBtn = document.getElementById('btn-session-rename');
    const deleteBtn = document.getElementById('btn-session-delete');
    if (!sid) {
        [exportBtn, renameBtn, deleteBtn].forEach(b => b.classList.add('hidden'));
        return;
    }
    let session = null;
    try {
        const resp = await fetch(`/api/session/${encodeURIComponent(sid)}`);
        session = (await resp.json()).session;
    } catch { /* ignore */ }
    [exportBtn, renameBtn, deleteBtn].forEach(b => b.classList.remove('hidden'));
    exportBtn.onclick = () => window.open(`/api/session/${encodeURIComponent(sid)}/export?format=json`, '_blank');
    renameBtn.onclick = () => {
        const current = session?.label || sid.substring(0, 8);
        const label = prompt('New name:', current);
        if (!label || label.trim() === current) return;
        fetch(`/api/session/${encodeURIComponent(sid)}`, { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ label: label.trim() }) }).then(() => updateFilterOptions());
    };
    deleteBtn.onclick = () => {
        if (!confirm(`Delete session "${session?.label || sid.substring(0, 8)}"?`)) return;
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
let sessionCache = {};
let pendingSessionFetches = new Set();
let _updateFilterTimer = null;
let _renderPageTimer = null;

function updateFilterOptions() {
    const models = new Set();
    requestRows.forEach(r => { if (r.model) models.add(r.model); });
    const modelSelect = document.getElementById('filter-model');
    const currentModel = modelSelect.value;
    modelSelect.innerHTML = '<option value="">All Models</option>';
    models.forEach(m => { modelSelect.innerHTML += `<option value="${esc(m)}">${esc(m)}</option>`; });
    modelSelect.value = currentModel;

    const sessionsInData = new Set();
    requestRows.forEach(r => { if (r.session_id) sessionsInData.add(r.session_id); });

    // Immediately render from cache + fallback (no fetch delay)
    renderSessionSelect(sessionsInData);

    // Only fetch uncached sessions that aren't already in-flight
    const toFetch = Array.from(sessionsInData).filter(
        sid => !sessionCache[sid] && !pendingSessionFetches.has(sid)
    );
    if (toFetch.length === 0) return;

    toFetch.forEach(sid => pendingSessionFetches.add(sid));

    // Fetch in batches of 5 to avoid flooding the server
    (async function fetchInBatches() {
        const BATCH_SIZE = 5;
        for (let i = 0; i < toFetch.length; i += BATCH_SIZE) {
            const batch = toFetch.slice(i, i + BATCH_SIZE);
            await Promise.all(batch.map(sid =>
                fetch(`/api/session/${encodeURIComponent(sid)}`)
                    .then(r => r.json())
                    .then(data => { sessionCache[sid] = data.session?.label || sid.substring(0, 8); })
                    .catch(() => { sessionCache[sid] = sid.substring(0, 8); })
                    .finally(() => { pendingSessionFetches.delete(sid); })
            ));
        }
        renderSessionSelect(sessionsInData);
    })();
}

function renderSessionSelect(sessionsInData) {
    const sessionSelect = document.getElementById('filter-session');
    const current = sessionSelect.value;
    sessionSelect.innerHTML = '<option value="">All Sessions</option>';
    sessionsInData.forEach(s => {
        const label = sessionCache[s] || s.substring(0, 8);
        sessionSelect.innerHTML += `<option value="${esc(s)}">${esc(label)} (${esc(s.substring(0, 8))})</option>`;
    });
    sessionSelect.value = current;
}

function applyFiltersAndRender() {
    currentPage = 1;
    renderPage();
}

document.getElementById('filter-model').addEventListener('change', () => { filterModel = document.getElementById('filter-model').value; applyFiltersAndRender(); });
document.getElementById('filter-session').addEventListener('change', () => {
    filterSession = document.getElementById('filter-session').value;
    expandedSessions.clear();
    if (filterSession) {
        // Auto-expand the selected session
        expandedSessions.add(filterSession);
    } else {
        // "All Sessions" — expand latest only
        const groups = getSessionGroups();
        if (groups.length > 0) expandedSessions.add(groups[0].session_id);
    }
    refreshSessionActions();
    applyFiltersAndRender();
});
document.getElementById('filter-time-from').addEventListener('change', () => { filterTimeFrom = document.getElementById('filter-time-from').value; if (filterTimeFrom) filterTimeFrom += ':00'; applyFiltersAndRender(); });
document.getElementById('filter-time-to').addEventListener('change', () => { filterTimeTo = document.getElementById('filter-time-to').value; if (filterTimeTo) filterTimeTo += ':00'; applyFiltersAndRender(); });

// ── Pagination ──
document.getElementById('page-size').addEventListener('change', () => { pageSize = parseInt(document.getElementById('page-size').value); currentPage = 1; renderPage(); });
document.getElementById('btn-page-prev').addEventListener('click', () => { if (currentPage > 1) { currentPage--; renderPage(); } });
document.getElementById('btn-page-next').addEventListener('click', () => { const tp = Math.max(1, Math.ceil(getSessionGroups().length / pageSize)); if (currentPage < tp) { currentPage++; renderPage(); } });

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
const IMPORTANT_KEYS = ['role', 'type', 'name', 'id', 'model', 'status', 'stop_reason', 'index'];

function tryParseJson(str) {
    if (!str || typeof str !== 'string') return null;
    const t = str.trim();
    if (t.startsWith('{') || t.startsWith('[')) {
        try { return JSON.parse(t); } catch { return null; }
    }
    return null;
}

const COLLAPSED_KEYS = new Set(['tools', 'request_headers', 'response_headers']);

function jsonTreeHTML(value, depth, key) {
    if (value === null) return '<span class="jt-null">null</span>';
    if (typeof value === 'boolean') return `<span class="jt-bool">${value}</span>`;
    if (typeof value === 'number') return `<span class="jt-number">${value}</span>`;
    if (typeof value === 'string') return `<span class="jt-string">"${esc(value)}"</span>`;
    const shouldCollapse = COLLAPSED_KEYS.has(key);
    if (Array.isArray(value)) {
        if (value.length === 0) return '<span class="jt-bracket">[]</span>';
        const collapsed = depth >= 2 || shouldCollapse;
        const preview = `[${value.length} item${value.length > 1 ? 's' : ''}]`;
        const children = value.map((item, i) => `<div class="jt-item"><span class="jt-index">${i}: </span>${jsonTreeHTML(item, depth + 1)}</div>`).join('');
        return `<span class="jt-node jt-array"><span class="jt-toggle ${collapsed ? '' : 'expanded'}">${collapsed ? '+' : '-'}</span><span class="jt-bracket">[</span><span class="jt-preview ${collapsed ? '' : 'hidden'}">${esc(preview)}</span><span class="jt-children ${collapsed ? 'hidden' : ''}">${children}</span><span class="jt-bracket">]</span></span>`;
    }
    if (typeof value === 'object') {
        const keys = Object.keys(value);
        if (keys.length === 0) return '<span class="jt-bracket">{}</span>';
        const collapsed = depth >= 2 || shouldCollapse;
        const previewParts = IMPORTANT_KEYS.filter(k => k in value).map(k => {
            const v = value[k];
            if (typeof v === 'string') return `${k}: "${esc(truncate(v, 40))}"`;
            if (typeof v === 'number' || typeof v === 'boolean') return `${k}: ${v}`;
            if (Array.isArray(v)) return `${k}: [${v.length}]`;
            if (v === null) return `${k}: null`;
            return `${k}: {...}`;
        });
        // For message objects, show a snippet of the last meaningful content
        if (value.role !== undefined) {
            // Case 1: content is a plain string (e.g. user message)
            if (typeof value.content === 'string' && value.content.trim()) {
                const clean = value.content.replace(/\s+/g, ' ').trim();
                previewParts.push(`"${esc(truncate(clean, 80))}"`);
            }
            // Case 2: content is an array of blocks (e.g. assistant message)
            else if (Array.isArray(value.content) && value.content.length > 0) {
            const lastBlock = value.content[value.content.length - 1];
            const lastText = lastBlock && (
                (typeof lastBlock.text === 'string' && lastBlock.text.trim()) ||
                (typeof lastBlock.content === 'string' && lastBlock.content.trim())
            );

            if (lastText) {
                // Last block has text or content (e.g. tool_result) — show it directly
                const text = (typeof lastBlock.text === 'string' && lastBlock.text.trim())
                    || (typeof lastBlock.content === 'string' && lastBlock.content.trim());
                const clean = text.replace(/\s+/g, ' ').trim();
                previewParts.push(`"${esc(truncate(clean, 80))}"`);
            } else if (lastBlock) {
                // Last block is not text (tool_use / thinking / etc.) — show action label first
                const actionLabel = typeof lastBlock.name === 'string' ? `[tool:${lastBlock.name}]`
                    : typeof lastBlock.type === 'string' ? `[${lastBlock.type}]`
                    : null;
                if (actionLabel) previewParts.push(actionLabel);

                // Then look backwards for context: text → content → tool_use → thinking
                let textTarget = null;
                // 1. Prefer text blocks
                for (let i = value.content.length - 2; i >= 0; i--) {
                    const b = value.content[i];
                    if (b && typeof b.text === 'string' && b.text.trim()) {
                        textTarget = b;
                        break;
                    }
                }
                // 2. Fallback: blocks with "content" field (e.g. tool_result)
                if (!textTarget) {
                    for (let i = value.content.length - 2; i >= 0; i--) {
                        const b = value.content[i];
                        if (b && typeof b.content === 'string' && b.content.trim()) {
                            textTarget = b;
                            break;
                        }
                    }
                }
                // 3. Fallback: tool_use blocks — show parameters
                if (!textTarget) {
                    for (let i = value.content.length - 2; i >= 0; i--) {
                        const b = value.content[i];
                        if (b && b.type === 'tool_use' && b.input && typeof b.input === 'object') {
                            textTarget = b;
                            break;
                        }
                    }
                }
                // 4. Last resort: thinking blocks
                if (!textTarget) {
                    for (let i = value.content.length - 2; i >= 0; i--) {
                        const b = value.content[i];
                        if (b && typeof b.thinking === 'string' && b.thinking.trim()) {
                            textTarget = b;
                            break;
                        }
                    }
                }

                if (textTarget) {
                    let snippet;
                    if (typeof textTarget.text === 'string') {
                        snippet = textTarget.text.trim();
                    } else if (typeof textTarget.content === 'string') {
                        snippet = textTarget.content.trim();
                    } else if (textTarget.type === 'tool_use' && textTarget.input) {
                        snippet = JSON.stringify(textTarget.input);
                    } else if (typeof textTarget.thinking === 'string') {
                        snippet = textTarget.thinking.trim();
                    }
                    if (snippet) {
                        const clean = snippet.replace(/\s+/g, ' ').trim();
                        previewParts.push(`"${esc(truncate(clean, 80))}"`);
                    }
                }
            }
        }
    }
        const remaining = keys.filter(k => !IMPORTANT_KEYS.includes(k)).length;
        const preview = previewParts.length > 0 ? previewParts.join(', ') + (remaining > 0 ? ` +${remaining}` : '') : `${keys.length} key${keys.length > 1 ? 's' : ''}`;
        const children = keys.map(k => `<div class="jt-pair"><span class="jt-key">"${esc(k)}": </span>${jsonTreeHTML(value[k], depth + 1, k)}</div>`).join('');
        return `<span class="jt-node jt-object"><span class="jt-toggle ${collapsed ? '' : 'expanded'}">${collapsed ? '+' : '-'}</span><span class="jt-bracket">{</span><span class="jt-preview ${collapsed ? '' : 'hidden'}">${preview}</span><span class="jt-children ${collapsed ? 'hidden' : ''}">${children}</span><span class="jt-bracket">}</span></span>`;
    }
    return String(value);
}

document.addEventListener('click', function(e) {
    const toggle = e.target.closest('.jt-toggle');
    if (!toggle) return;
    const node = toggle.parentElement;
    if (!node?.classList.contains('jt-node')) return;
    const children = node.querySelector('.jt-children');
    const preview = node.querySelector('.jt-preview');
    if (!children) return;
    if (toggle.textContent === '+') {
        node.querySelectorAll('.jt-toggle').forEach(t => { t.textContent = '-'; t.classList.add('expanded'); });
        node.querySelectorAll('.jt-children').forEach(c => c.classList.remove('hidden'));
        node.querySelectorAll('.jt-preview').forEach(p => p.classList.add('hidden'));
    } else {
        children.classList.add('hidden');
        if (preview) preview.classList.remove('hidden');
        toggle.textContent = '+';
        toggle.classList.remove('expanded');
    }
});

function esc(str) {
    if (!str) return '—';
    const div = document.createElement('div');
    div.textContent = String(str);
    return div.innerHTML;
}
function truncate(str, maxLen) {
    if (!str) return '—';
    return str.length <= maxLen ? str : str.substring(0, maxLen) + '…';
}
function updateRequestCount() {
    document.getElementById('request-count').textContent = `${requestRows.size} requests`;
}

// ── Selection & delete ──
document.addEventListener('change', (e) => {
    if (e.target.classList.contains('row-chk')) {
        const id = e.target.dataset.id;
        if (e.target.checked) selectedIds.add(id); else selectedIds.delete(id);
        updateSelectionUI();
    }
    if (e.target.id === 'select-all') {
        document.querySelectorAll('.row-chk').forEach(cb => {
            cb.checked = e.target.checked;
            if (e.target.checked) selectedIds.add(cb.dataset.id); else selectedIds.delete(cb.dataset.id);
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
        if (selectedRequestId === id) { selectedRequestId = null; document.getElementById('request-detail').classList.add('hidden'); document.getElementById('view-inspector').classList.remove('detail-open'); }
        renderPage(); updateFilterOptions(); updateRequestCount();
    }
});

document.getElementById('btn-delete-selected').addEventListener('click', async () => {
    if (selectedIds.size === 0) return;
    if (!confirm(`Delete ${selectedIds.size} selected request(s)?`)) return;
    const ids = Array.from(selectedIds);
    const resp = await fetch('/api/requests', { method: 'DELETE', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ids }) });
    if (resp.ok) {
        ids.forEach(id => requestRows.delete(id));
        selectedIds.clear();
        document.getElementById('select-all').checked = false;
        if (selectedRequestId && ids.includes(selectedRequestId)) {
            selectedRequestId = null;
            document.getElementById('request-detail').classList.add('hidden');
            document.getElementById('view-inspector').classList.remove('detail-open');
        }
        renderPage(); updateFilterOptions(); updateRequestCount();
    }
});

function updateSelectionUI() {
    const count = selectedIds.size;
    document.getElementById('selected-count').textContent = count;
    document.getElementById('btn-delete-selected').classList.toggle('hidden', count === 0);
    const total = document.querySelectorAll('.row-chk').length;
    const selectAll = document.getElementById('select-all');
    if (count === 0) { selectAll.checked = false; selectAll.indeterminate = false; }
    else if (count >= total) { selectAll.checked = true; selectAll.indeterminate = false; }
    else { selectAll.checked = false; selectAll.indeterminate = true; }
}

function clearAllTables() {
    requestRows.clear();
    expandedSessions.clear();
    currentPage = 1;
    filterModel = ''; filterSession = ''; filterTimeFrom = ''; filterTimeTo = '';
    document.getElementById('filter-model').value = '';
    document.getElementById('filter-session').innerHTML = '<option value="">All Sessions</option>';
    document.getElementById('filter-time-from').value = '';
    document.getElementById('filter-time-to').value = '';
    document.getElementById('requests-tbody').innerHTML = '';
    document.getElementById('hooks-tbody').innerHTML = '';
    updatePagination(0, 1);
    updateRequestCount();
    refreshSessionActions();
}

// ── Silent check ──
function startSilentCheck() {
    clearInterval(_silentTimer);
    _silentTimer = setInterval(() => {
        const elapsed = Math.floor((Date.now() - _lastMsgTime) / 1000);
        const el = document.getElementById('connection-status');
        if (elapsed > 180) {
            el.textContent = `Connected (silent ${elapsed}s)`;
            el.className = 'connected silent';
            if (elapsed % 30 === 0) {
                console.warn(`[ws] silent for ${elapsed}s — no messages received`);
            }
        } else {
            el.textContent = 'Connected';
            el.className = 'connected';
        }
    }, 5000);
}

// ── Init ──
connect();

fetch('/api/upstreams')
    .then(r => r.json())
    .then(data => applyUpstreamState(data.active_upstream, data.upstreams, data.providers, data.active_effort));

// Pre-fill session cache in one call to avoid N individual fetches
fetch('/api/sessions')
    .then(r => r.json())
    .then(sessions => {
        sessions.forEach(s => { sessionCache[s.id] = s.label || s.id.substring(0, 8); });
    })
    .catch(() => {});

fetch('/api/requests?limit=2000')
    .then(r => r.json())
    .then(requests => {
        if (requests.length > 0) {
            requestRows.clear();
            requests.forEach(req => requestRows.set(req.id, req));
            // Expand latest session only on initial load
            const groups = getSessionGroups();
            if (groups.length > 0) expandedSessions.add(groups[0].session_id);
            currentPage = 1;
            renderPage(); updateRequestCount();
            // updateFilterOptions will find sessions already cached from /api/sessions
            updateFilterOptions();
        }
    })
    .catch(err => console.error('Failed to load requests:', err));

fetch('/api/mcp-destination')
    .then(r => r.json())
    .then(data => { if (data.destinationUrl) document.getElementById('mcp-destination').value = data.destinationUrl; });

fetch('/api/capture/status')
    .then(r => r.json())
    .then(data => { captureEnabled = data.enabled; updateCaptureButton(); });

fetch('/api/retention')
    .then(r => r.json())
    .then(data => {
        document.getElementById('ret-hours').value = data.request_retention_hours;
        document.getElementById('ret-max-sessions').value = data.session_max_count;
    })
    .catch(() => {});

// ── Retention panel ──
document.getElementById('btn-retention-save').addEventListener('click', async () => {
    const body = {
        request_retention_hours: parseInt(document.getElementById('ret-hours').value) || 0,
        session_max_count: parseInt(document.getElementById('ret-max-sessions').value) || 0,
    };
    const resp = await fetch('/api/retention', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body)
    });
    if (resp.ok) {
        const result = document.getElementById('ret-cleanup-result');
        result.className = 'cleanup-result success';
        result.textContent = 'Saved';
        result.classList.remove('hidden');
        setTimeout(() => result.classList.add('hidden'), 2000);
    }
});

document.getElementById('btn-cleanup-now').addEventListener('click', async () => {
    const btn = document.getElementById('btn-cleanup-now');
    btn.disabled = true;
    btn.textContent = 'Cleaning...';
    try {
        const resp = await fetch('/api/cleanup', { method: 'POST' });
        const data = await resp.json();
        const result = document.getElementById('ret-cleanup-result');
        result.className = 'cleanup-result success';
        result.textContent = `Cleaned: ${data.deleted_requests} requests, ${data.deleted_sessions} sessions`;
        result.classList.remove('hidden');
        document.getElementById('ret-last-cleanup').textContent = new Date().toLocaleTimeString();
    } catch (e) {
        const result = document.getElementById('ret-cleanup-result');
        result.className = 'cleanup-result';
        result.textContent = 'Failed to clean up';
        result.classList.remove('hidden');
    }
    btn.disabled = false;
    btn.textContent = 'Clean Up Now';
});

// ── Cost view ──

function localDateStr(d) {
    return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

const COST_PRESETS = {
    today: () => {
        const d = new Date();
        const from = localDateStr(d);
        const to = localDateStr(new Date(d.getFullYear(), d.getMonth(), d.getDate() + 1));
        return { from, to };
    },
    week: () => {
        const d = new Date();
        const start = new Date(d.getFullYear(), d.getMonth(), d.getDate() - d.getDay());
        const end = new Date(start.getFullYear(), start.getMonth(), start.getDate() + 7);
        return { from: localDateStr(start), to: localDateStr(end) };
    },
    month: () => {
        const d = new Date();
        const from = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-01`;
        const to = localDateStr(new Date(d.getFullYear(), d.getMonth() + 1, 1));
        return { from, to };
    },
};

function findProviderForModel(model) {
    if (!model) return null;
    for (const p of providerList) {
        if (p.models && p.models.some(m => m.id === model)) return p;
    }
    return null;
}

function calcModelCosts(byModel) {
    return byModel.map(m => {
        const price = lookupProviderPrice(m.model);
        const cost = m.input_tokens * (price ? price.in : 5) / 1e6
                   + m.output_tokens * (price ? price.out : 25) / 1e6;
        return Object.assign({}, m, { cost });
    });
}

function groupByProvider(modelCosts) {
    const map = {};
    modelCosts.forEach(m => {
        const p = findProviderForModel(m.model);
        const name = p ? p.name : 'Unknown';
        if (!map[name]) map[name] = { provider: name, cost: 0, input_tokens: 0, output_tokens: 0 };
        map[name].cost += m.cost;
        map[name].input_tokens += m.input_tokens;
        map[name].output_tokens += m.output_tokens;
    });
    return Object.values(map).sort((a, b) => b.cost - a.cost);
}

function formatCostValue(v) {
    return `¥${v.toFixed(4)}`;
}

function formatTokens(n) {
    if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
    if (n >= 1e3) return Math.round(n / 1e3) + 'K';
    return String(n);
}

async function loadCosts() {
    const from = document.getElementById('cost-from').value;
    const to = document.getElementById('cost-to').value;
    if (!from || !to) return;
    document.getElementById('cost-loading').classList.remove('hidden');
    try {
        const resp = await fetch(`/api/costs?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`);
        const data = await resp.json();
        renderCostView(data);
    } catch (e) {
        console.error('Failed to load costs:', e);
    }
    document.getElementById('cost-loading').classList.add('hidden');
}

function renderCostView(data) {
    const byModel = calcModelCosts(data.by_model || []);
    const totalCost = byModel.reduce((s, m) => s + m.cost, 0);
    const totalIn = byModel.reduce((s, m) => s + m.input_tokens, 0);
    const totalOut = byModel.reduce((s, m) => s + m.output_tokens, 0);
    const totalReqs = byModel.reduce((s, m) => s + m.request_count, 0);

    document.getElementById('cost-total').textContent = formatCostValue(totalCost);
    document.getElementById('cost-input-tokens').textContent = formatTokens(totalIn);
    document.getElementById('cost-output-tokens').textContent = formatTokens(totalOut);
    document.getElementById('cost-request-count').textContent = totalReqs;

    renderCostBySession(data.by_session || [], byModel);
    renderCostByModel(byModel);
    renderCostByProvider(byModel);
}

function renderCostBySession(bySess, byModel) {
    const modelCostMap = {};
    byModel.forEach(m => { modelCostMap[m.model] = m; });

    const tbody = document.getElementById('cost-by-session');
    if (bySess.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text-muted)">No data</td></tr>';
        return;
    }
    tbody.innerHTML = bySess.map(s => {
        const cost = s.models.reduce((sum, model) => {
            const mc = modelCostMap[model];
            if (!mc) return sum;
            const price = lookupProviderPrice(model);
            return sum + s.input_tokens * (price ? price.in : 5) / 1e6
                       + s.output_tokens * (price ? price.out : 25) / 1e6;
        }, 0);
        // Simpler: compute per-session cost from its own token counts using first matched model price
        const price = lookupProviderPrice(s.models[0]);
        const sessionCost = s.input_tokens * (price ? price.in : 5) / 1e6
                          + s.output_tokens * (price ? price.out : 25) / 1e6;
        const label = sessionCache[s.session_id] || s.session_label;
        return `<tr>
            <td title="${esc(s.session_id)}">${esc(label)}</td>
            <td style="font-size:0.72rem;color:var(--text-muted)">${esc(s.models.join(', '))}</td>
            <td>${s.request_count}</td>
            <td>${formatTokens(s.input_tokens)} / ${formatTokens(s.output_tokens)}</td>
            <td>${formatCostValue(sessionCost)}</td>
        </tr>`;
    }).join('');
}

function renderCostByModel(byModel) {
    const tbody = document.getElementById('cost-by-model');
    if (byModel.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No data</td></tr>';
        return;
    }
    tbody.innerHTML = byModel.map(m => `<tr>
        <td>${esc(m.model)}</td>
        <td>${m.request_count}</td>
        <td>${formatTokens(m.input_tokens)} / ${formatTokens(m.output_tokens)}</td>
        <td>${formatCostValue(m.cost)}</td>
    </tr>`).join('');
}

function renderCostByProvider(byModel) {
    const tbody = document.getElementById('cost-by-provider');
    const providers = groupByProvider(byModel);
    if (providers.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-muted)">No data</td></tr>';
        return;
    }
    tbody.innerHTML = providers.map(p => `<tr>
        <td>${esc(p.provider)}</td>
        <td>${formatTokens(p.input_tokens)}</td>
        <td>${formatTokens(p.output_tokens)}</td>
        <td>${formatCostValue(p.cost)}</td>
    </tr>`).join('');
}

document.querySelectorAll('.btn-cost-preset').forEach(btn => {
    btn.addEventListener('click', () => {
        document.querySelectorAll('.btn-cost-preset').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        const { from, to } = COST_PRESETS[btn.dataset.preset]();
        document.getElementById('cost-from').value = from;
        document.getElementById('cost-to').value = to;
        loadCosts();
    });
});

document.getElementById('btn-cost-refresh').addEventListener('click', loadCosts);
