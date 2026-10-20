/**
 * API Sentinel — frontend application logic
 * Pure vanilla JS, no build step required.
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const API = '';   // same origin

// ── Utility ───────────────────────────────────────────────────────────────────

function $(sel, ctx = document) { return ctx.querySelector(sel); }
function $$(sel, ctx = document) { return [...ctx.querySelectorAll(sel)]; }

function escHtml(str) {
  return String(str ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function severityClass(s) {
  return ({ critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium',
            low: 'sev-low', info: 'sev-info' })[s] ?? 'sev-info';
}

function confidenceClass(c) {
  return ({ high: 'conf-high', medium: 'conf-medium', low: 'conf-low' })[c] ?? 'conf-high';
}

function relTime(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso + 'Z').getTime();
  const s = Math.floor(diff / 1000);
  if (s <  60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return `${Math.floor(s/86400)}d ago`;
}

async function apiFetch(path, opts = {}) {
  const r = await fetch(API + path, opts);
  if (!r.ok) {
    const text = await r.text();
    throw new Error(`${r.status} ${r.statusText}: ${text}`);
  }
  return r.json();
}

// ── Tab navigation ────────────────────────────────────────────────────────────

function initTabs() {
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.tab;
      $$('.tab-btn').forEach(b => b.classList.remove('active'));
      $$('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      $(`#tab-${target}`).classList.add('active');
      if (target === 'dashboard') loadDashboard();
    });
  });
}

// ── Dashboard ─────────────────────────────────────────────────────────────────

let _allScans    = [];
let _allFindings = {};   // scan_id → findings[]
let _activeId    = null;
let _filterSev   = 'all';
let _filterText  = '';

// Last fetched stats — used by severity bar
let _lastStats   = null;

async function loadDashboard() {
  await Promise.all([loadStats(), loadScans()]);
}

async function loadStats() {
  try {
    const s = await apiFetch('/api/stats');
    _lastStats = s;

    // KPI cards
    $('#stat-total-scans').textContent    = s.total_scans;
    $('#stat-done-scans').textContent     = s.done_scans;
    $('#stat-total-findings').textContent = s.total_findings;
    $('#stat-critical').textContent       = s.critical;
    $('#stat-high').textContent           = s.high;
    $('#stat-medium').textContent         = s.medium;

    // Severity distribution bar
    drawSeverityBar(s);

    // Header live-status dot
    updateHeaderStatus(s);
  } catch (e) {
    console.error('stats error', e);
  }
}

// ── Severity distribution bar ─────────────────────────────────────────────────

function drawSeverityBar(s) {
  const total = s.critical + s.high + s.medium + s.low + s.info;
  const track = $('#sev-bar-track');
  if (!track) return;

  // Legend counts
  const update = (id, val) => { const el = $(`#sev-legend-${id}`); if (el) el.textContent = val; };
  update('critical', s.critical);
  update('high',     s.high);
  update('medium',   s.medium);
  update('low',      s.low);
  update('info',     s.info);

  const totalEl = $('#sev-bar-total');
  if (totalEl) totalEl.textContent = total > 0 ? `${total} total` : '';

  if (total === 0) {
    track.innerHTML = '<div class="sev-bar-empty">No findings recorded yet</div>';
    return;
  }

  const segs = [
    { key: 'critical', count: s.critical, cls: 'seg-critical' },
    { key: 'high',     count: s.high,     cls: 'seg-high' },
    { key: 'medium',   count: s.medium,   cls: 'seg-medium' },
    { key: 'low',      count: s.low,      cls: 'seg-low' },
    { key: 'info',     count: s.info,     cls: 'seg-info' },
  ].filter(seg => seg.count > 0);

  track.innerHTML = segs.map((seg, i) => {
    const pct = (seg.count / total * 100).toFixed(2);
    const isFirst = i === 0;
    const isLast  = i === segs.length - 1;
    const style = `width:${pct}%;animation-delay:${i * 60}ms`;
    return `<div class="sev-bar-seg ${seg.cls}${isFirst ? ' seg-first' : ''}${isLast ? ' seg-last' : ''}"
      style="${style}"
      title="${seg.key}: ${seg.count} (${pct}%)"
      role="img"
      aria-label="${seg.key}: ${seg.count} findings, ${pct}%">
    </div>`;
  }).join('');
}

// ── Header live-status indicator ──────────────────────────────────────────────

function updateHeaderStatus(s) {
  const el = $('#header-status');
  if (!el) return;
  const running = _allScans.filter(sc => sc.status === 'running').length;
  if (running > 0) {
    el.innerHTML = `<span class="hstatus hstatus--running"><span class="hstatus-dot"></span>${running} scan${running > 1 ? 's' : ''} running</span>`;
  } else if (s.total_scans > 0) {
    el.innerHTML = `<span class="hstatus hstatus--idle"><span class="hstatus-dot"></span>Idle</span>`;
  } else {
    el.innerHTML = '';
  }
}

// ── Scan list ─────────────────────────────────────────────────────────────────

async function loadScans() {
  const list = $('#scan-list');
  list.innerHTML = '<tr><td colspan="4" class="skeleton-cell"><div class="skeleton"></div></td></tr>';
  try {
    _allScans = await apiFetch('/api/scans');
    renderScanList();
    renderScannerList();
    if (_lastStats) updateHeaderStatus(_lastStats);
    // Update badge
    const badge = $('#scan-count-badge');
    if (badge) badge.textContent = _allScans.length > 0 ? _allScans.length : '';
  } catch (e) {
    list.innerHTML = `<tr><td colspan="4" class="error-cell">Failed to load scans: ${escHtml(e.message)}</td></tr>`;
  }
}

function renderScanList() {
  const list = $('#scan-list');
  if (_allScans.length === 0) {
    list.innerHTML = '<tr><td colspan="4" class="empty-cell"><span>No scans yet — start one from the Scanner tab.</span></td></tr>';
    return;
  }
  list.innerHTML = _allScans.map(s => `
    <tr class="scan-row${_activeId === s.id ? ' selected' : ''}${s.status === 'running' ? ' scan-row--running' : ''}" data-id="${s.id}">
      <td class="url-cell" title="${escHtml(s.target_url)}">${escHtml(s.target_url)}</td>
      <td><span class="status-badge status-${s.status}">${escHtml(s.status)}</span></td>
      <td class="col-num">${s.finding_count > 0 ? `<span class="finding-count-pill finding-count-${findingCountLevel(s.finding_count)}">${s.finding_count}</span>` : '<span class="muted-dash">—</span>'}</td>
      <td class="time-cell">${relTime(s.created_at)}</td>
    </tr>`).join('');

  $$('.scan-row').forEach(row => {
    row.addEventListener('click', () => selectScan(Number(row.dataset.id)));
  });

  if (_activeId) selectScan(_activeId);
}

// Mirror of scan list for the Scanner tab (read-only, no click handler)
function renderScannerList() {
  const list = $('#scanner-scan-list');
  if (!list) return;
  if (_allScans.length === 0) {
    list.innerHTML = '<tr><td colspan="4" class="empty-cell"><span>No scans yet.</span></td></tr>';
    return;
  }
  // Show most recent 8
  list.innerHTML = _allScans.slice(0, 8).map(s => `
    <tr class="${s.status === 'running' ? 'scan-row--running' : ''}">
      <td class="url-cell" title="${escHtml(s.target_url)}">${escHtml(s.target_url)}</td>
      <td><span class="status-badge status-${s.status}">${escHtml(s.status)}</span></td>
      <td class="col-num">${s.finding_count > 0 ? `<span class="finding-count-pill finding-count-${findingCountLevel(s.finding_count)}">${s.finding_count}</span>` : '<span class="muted-dash">—</span>'}</td>
      <td class="time-cell">${relTime(s.created_at)}</td>
    </tr>`).join('');
}

function findingCountLevel(n) {
  if (n === 0)  return 'zero';
  if (n <= 2)   return 'low';
  if (n <= 6)   return 'medium';
  return 'high';
}

// ── Scan selection & findings rendering ──────────────────────────────────────

async function selectScan(id) {
  _activeId = id;
  $$('.scan-row').forEach(r => r.classList.toggle('selected', Number(r.dataset.id) === id));

  const panel = $('#findings-panel');
  panel.innerHTML = `
    <div class="findings-loading">
      <div class="skeleton-block">
        <div class="skeleton"></div>
        <div class="skeleton"></div>
        <div class="skeleton"></div>
      </div>
    </div>`;

  try {
    const detail = await apiFetch(`/api/scans/${id}`);
    _allFindings[id] = detail.findings;
    renderFindings(id, detail.target_url, detail.status);
  } catch (e) {
    panel.innerHTML = `<div class="error-state">Could not load findings: ${escHtml(e.message)}</div>`;
  }
}

function renderFindings(id, url, status) {
  const allF = _allFindings[id] ?? [];
  const findings = allF.filter(f => {
    const sevOk  = _filterSev  === 'all' || f.severity === _filterSev;
    const textOk = !_filterText || [f.title, f.description, f.category]
      .some(s => s.toLowerCase().includes(_filterText));
    return sevOk && textOk;
  });

  const panel = $('#findings-panel');

  // ── Per-scan severity summary strip
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  allF.forEach(f => { if (f.severity in sevCounts) sevCounts[f.severity]++; });
  const hasSevData = allF.length > 0;

  const sevStrip = hasSevData ? `
    <div class="scan-sev-strip">
      ${Object.entries(sevCounts).filter(([,c]) => c > 0).map(([sev, c]) => `
        <span class="sev-strip-item sev-strip-${sev}">
          <span class="sev-strip-dot"></span>
          <span class="sev-strip-label">${sev}</span>
          <span class="sev-strip-count">${c}</span>
        </span>`).join('')}
    </div>` : '';

  const header = `
    <div class="findings-header">
      <div class="findings-header-main">
        <h3 class="findings-title">
          <span class="status-badge status-${status}">${escHtml(status)}</span>
          <span class="findings-url">${escHtml(url)}</span>
        </h3>
        ${sevStrip}
      </div>
      <div class="findings-actions">
        <button class="btn btn-sm" onclick="exportJson(${id})">
          <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M8 2v9M4 8l4 4 4-4M2 13h12"/></svg>
          JSON
        </button>
        <button class="btn btn-sm" onclick="exportHtml(${id})">
          <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="2" y="2" width="12" height="12" rx="1.5"/><path d="M5 6h6M5 9h4"/></svg>
          Report
        </button>
      </div>
    </div>`;

  if (findings.length === 0) {
    const msg = allF.length === 0
      ? `<div class="no-findings">
           <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/></svg>
           No findings — this scan returned clean.
         </div>`
      : `<div class="findings-filter-empty">
           <svg width="16" height="16" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><circle cx="7" cy="7" r="5.5"/><path d="m12 12 2.5 2.5"/></svg>
           No findings match the current filter.
         </div>`;
    panel.innerHTML = header + msg;
    return;
  }

  // Severity icon SVG paths
  const sevIcon = {
    critical: '<path d="M8 1.5L14.5 13H1.5L8 1.5z"/><path d="M8 6v3M8 10.5v.5"/>',
    high:     '<path d="M8 2v8M4.5 6l3.5-4 3.5 4M3.5 13h9"/>',
    medium:   '<path d="M3 5h10M3 8h10M3 11h6"/>',
    low:      '<circle cx="8" cy="8" r="6.5"/><path d="M8 5v3M8 10.5v.5"/>',
    info:     '<circle cx="8" cy="8" r="6.5"/><path d="M8 7v4M8 5.5v.5"/>',
  };

  const rows = findings.map((f, idx) => {
    const sev = f.severity ?? 'info';
    const iconPath = sevIcon[sev] ?? sevIcon.info;
    const detailId = `fd-${id}-${idx}`;

    // Build evidence block
    const evidenceBlock = f.evidence
      ? `<div class="fd-evidence-block">
           <div class="fd-section-label">
             <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><rect x="2" y="2" width="12" height="10" rx="1.5"/><path d="M5 6h6M5 9h3"/></svg>
             Evidence
           </div>
           <pre class="evidence">${escHtml(f.evidence)}</pre>
         </div>`
      : '';

    // Affected endpoint block
    const endpointBlock = f.affected_url
      ? `<div class="fd-endpoint-block">
           <span class="fd-section-label">
             <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><circle cx="8" cy="8" r="6.5"/><path d="M3.5 8h9M8 3.5C6.5 5.5 6 6.7 6 8s.5 2.5 2 4.5M8 3.5C9.5 5.5 10 6.7 10 8s-.5 2.5-2 4.5"/></svg>
             Affected Endpoint
           </span>
           <code class="fd-endpoint-url">${escHtml(f.affected_url)}</code>
         </div>`
      : '';

    // Remediation block
    const remediationBlock = f.remediation
      ? `<div class="fd-remediation-block">
           <div class="fd-section-label fd-section-label--remediation">
             <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M13 3L7 9M9 3h4v4"/><path d="M7 3H3v10h10v-4"/></svg>
             Remediation
           </div>
           <p class="fd-remediation-text">${escHtml(f.remediation)}</p>
         </div>`
      : '';

    return `
    <div class="finding-card finding-card--${sev}" data-sev="${sev}">
      <div class="finding-card-accent"></div>
      <div class="finding-card-body">
        <div class="finding-meta">
          <span class="finding-sev-badge sev-badge--${sev}">
            <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">${iconPath}</svg>
            ${escHtml(sev)}
          </span>
          <span class="finding-conf-tag conf-tag--${f.confidence ?? 'high'}">${escHtml(f.confidence ?? 'high')} confidence</span>
          <span class="finding-category-tag">${escHtml(f.category)}</span>
        </div>
        <h4 class="finding-title">${escHtml(f.title)}</h4>
        <p class="finding-desc">${escHtml(f.description)}</p>
        <details class="finding-detail" id="${detailId}">
          <summary>
            <svg class="fd-chevron" width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><path d="M5 7l3 3 3-3"/></svg>
            Details &amp; Remediation
          </summary>
          <div class="fd-detail-body">
            ${endpointBlock}
            ${remediationBlock}
            ${evidenceBlock}
          </div>
        </details>
      </div>
    </div>`;
  }).join('');

  panel.innerHTML = header + `<div class="findings-list">${rows}</div>`;
}

// ── Filter toolbar ─────────────────────────────────────────────────────────────

function initFilters() {
  $('#filter-text').addEventListener('input', e => {
    _filterText = e.target.value.trim().toLowerCase();
    if (_activeId) renderFindings(_activeId,
      _allScans.find(s => s.id === _activeId)?.target_url ?? '',
      _allScans.find(s => s.id === _activeId)?.status ?? '');
  });

  $$('.sev-filter-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      _filterSev = btn.dataset.sev;
      $$('.sev-filter-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      if (_activeId) renderFindings(_activeId,
        _allScans.find(s => s.id === _activeId)?.target_url ?? '',
        _allScans.find(s => s.id === _activeId)?.status ?? '');
    });
  });
}

// ── Exports ───────────────────────────────────────────────────────────────────

function exportJson(id) {
  const scan    = _allScans.find(s => s.id === id);
  const findings = _allFindings[id] ?? [];
  const blob = new Blob([JSON.stringify({ scan, findings }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sentinel-scan-${id}.json`;
  a.click();
}

function exportHtml(id) {
  const scan     = _allScans.find(s => s.id === id);
  const findings = _allFindings[id] ?? [];

  const rows = findings.map(f => `
    <tr>
      <td><span class="badge ${severityClass(f.severity)}">${escHtml(f.severity)}</span></td>
      <td>${escHtml(f.category)}</td>
      <td>${escHtml(f.title)}</td>
      <td>${escHtml(f.description)}</td>
      <td>${escHtml(f.remediation)}</td>
    </tr>`).join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Sentinel Report — ${escHtml(scan?.target_url ?? '')}</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 960px; margin: 2rem auto; color: #1f2328; }
  h1   { font-size: 1.4rem; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-top: 1rem; }
  th, td { border: 1px solid #e5e7eb; padding: 0.5rem 0.75rem; text-align: left; vertical-align: top; }
  th { background: #f7f8fa; font-weight: 600; }
  .badge { display:inline-block; padding:2px 7px; border-radius:4px; font-size:.75rem; font-weight:600; color:#fff; }
  .sev-critical { background:#dc2626; }
  .sev-high     { background:#ea580c; }
  .sev-medium   { background:#d97706; }
  .sev-low      { background:#2563eb; }
  .sev-info     { background:#6b7280; }
  footer { margin-top:2rem; font-size:.8rem; color:#57606a; border-top:1px solid #e5e7eb; padding-top:.75rem; }
</style>
</head>
<body>
<h1>API Sentinel Security Report</h1>
<p><strong>Target:</strong> ${escHtml(scan?.target_url ?? '—')}<br>
<strong>Status:</strong> ${escHtml(scan?.status ?? '—')}<br>
<strong>Findings:</strong> ${findings.length}<br>
<strong>Generated:</strong> ${new Date().toLocaleString()}</p>
<table>
<thead><tr><th>Severity</th><th>Category</th><th>Title</th><th>Description</th><th>Remediation</th></tr></thead>
<tbody>${rows}</tbody>
</table>
<footer>Generated by API Sentinel &mdash; for authorised use only</footer>
</body></html>`;

  const blob = new Blob([html], { type: 'text/html' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `sentinel-report-${id}.html`;
  a.click();
}

// ── Scanner tab ───────────────────────────────────────────────────────────────

function initScanner() {
  const form     = $('#scan-form');
  const urlInput = $('#scan-url');
  const authCb   = $('#scan-authorized');
  const status   = $('#scan-status');
  const submitBtn = form.querySelector('button[type="submit"]');

  // Live URL validation feedback
  urlInput.addEventListener('input', () => {
    const v = urlInput.value.trim();
    urlInput.classList.remove('url-input--valid', 'url-input--invalid');
    if (!v) return;
    if (v.startsWith('http://') || v.startsWith('https://')) {
      urlInput.classList.add('url-input--valid');
    } else {
      urlInput.classList.add('url-input--invalid');
    }
  });

  form.addEventListener('submit', async e => {
    e.preventDefault();
    const url = urlInput.value.trim();
    if (!url) return;

    // Must acknowledge authorisation
    if (!authCb.checked) {
      setStatus(status, 'error',
        '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="6.5"/><path d="M8 5v3M8 10.5v.5"/></svg>' +
        'Please confirm you are authorised to test this API before running a scan.');
      authCb.closest('label').classList.add('checkbox-label--error');
      return;
    }
    authCb.closest('label').classList.remove('checkbox-label--error');

    submitBtn.disabled = true;
    submitBtn.classList.add('btn-primary--loading');
    setStatus(status, 'info',
      '<span class="status-spinner"></span>Submitting scan request…');

    try {
      const res = await apiFetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_url: url, authorized: authCb.checked }),
      });
      setStatus(status, 'success',
        '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 8.5l3.5 3.5L13 5"/></svg>' +
        `Scan #${res.scan_id} queued. Results will appear in the Dashboard as they arrive.`);
      urlInput.value = '';
      urlInput.classList.remove('url-input--valid', 'url-input--invalid');
      authCb.checked = false;
      setTimeout(loadScans, 1500);
      setTimeout(loadScans, 5000);
      setTimeout(loadScans, 12000);
    } catch (err) {
      setStatus(status, 'error',
        '<svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="8" cy="8" r="6.5"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5"/></svg>' +
        `${escHtml(err.message)}`);
    } finally {
      submitBtn.disabled = false;
      submitBtn.classList.remove('btn-primary--loading');
    }
  });
}

/** Helper: set scan-status-bar content and class in one call */
function setStatus(el, type, html) {
  el.className = `scan-status-bar ${type}`;
  el.innerHTML = html;
  el.classList.remove('hidden');
}

// ── BOLA Lab tab ──────────────────────────────────────────────────────────────

function initBolaLab() {
  const runBtn     = $('#bola-run-btn');
  const modeSelect = $('#bola-mode');
  const results    = $('#bola-results');
  const modeDesc   = $('#lab-mode-desc');

  // Update mode description when toggle changes
  const modeDescText = {
    vulnerable: '<strong>Vulnerable mode:</strong> ownership checks are omitted — cross-user access is expected to succeed, demonstrating the BOLA vulnerability.',
    secure:     '<strong>Secure mode:</strong> each request is validated against the record owner — cross-user access is expected to be rejected with HTTP 403.',
  };
  document.querySelectorAll('input[name="bola-mode-radio"]').forEach(radio => {
    radio.addEventListener('change', () => {
      if (modeDesc) modeDesc.innerHTML = modeDescText[radio.value] ?? '';
    });
  });

  // Load lab info on tab open
  loadLabInfo();

  const btnInnerHTML = runBtn.innerHTML; // preserve original icon + text

  runBtn.addEventListener('click', async () => {
    const secure = modeSelect.value === 'secure';
    runBtn.disabled = true;
    runBtn.innerHTML = '<span class="status-spinner status-spinner--btn"></span>Running…';
    results.innerHTML = `
      <div class="bola-running-state">
        <div class="skeleton-block">
          <div class="skeleton"></div>
          <div class="skeleton"></div>
          <div class="skeleton"></div>
          <div class="skeleton"></div>
        </div>
      </div>`;

    try {
      const data = await apiFetch(`/api/lab/bola?secure=${secure}`, { method: 'POST' });
      renderBolaResults(data);
    } catch (err) {
      results.innerHTML = `
        <div class="bola-error-state">
          <svg width="18" height="18" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><circle cx="8" cy="8" r="6.5"/><path d="M5.5 5.5l5 5M10.5 5.5l-5 5"/></svg>
          <span>${escHtml(err.message)}</span>
        </div>`;
    } finally {
      runBtn.disabled = false;
      runBtn.innerHTML = btnInnerHTML;
    }
  });
}

async function loadLabInfo() {
  try {
    const info = await apiFetch('/api/lab/info');
    const el = $('#lab-info');
    if (!el) return;
    el.innerHTML = `
      <p class="muted" style="margin-bottom:.65rem">${escHtml(info.description)}</p>
      <div class="lab-info-grid">
        <div>
          <strong>Test Users</strong>
          <ul>${info.users.map(u => `<li>${escHtml(u.username)} <span class="muted">(id ${u.user_id})</span></li>`).join('')}</ul>
        </div>
        <div>
          <strong>Synthetic Records</strong>
          <ul>${info.records.map(r => `<li>#${r.id} — ${escHtml(r.title)} <span class="muted">(${escHtml(r.owner)})</span></li>`).join('')}</ul>
        </div>
      </div>`;
  } catch (e) {
    console.warn('lab info unavailable', e);
  }
}

function renderBolaResults(data) {
  const verdictClass = data.overall_verdict === 'PASS' ? 'verdict-pass' : 'verdict-fail';
  const results = $('#bola-results');

  const modeLabel = data.mode === 'vulnerable'
    ? '<span class="bola-mode-chip bola-mode-chip--vuln">Vulnerable Mode</span>'
    : '<span class="bola-mode-chip bola-mode-chip--secure">Secure Mode</span>';

  const passCount = data.passed ?? 0;
  const failCount = data.failed ?? 0;
  const total     = data.total  ?? (data.scenarios ?? []).length;

  const scenarioRows = (data.scenarios ?? []).map((sc, i) => {
    const vClass   = sc.verdict === 'PASS' ? 'verdict-pass' : 'verdict-fail';
    const isPass   = sc.verdict === 'PASS';
    const detailId = `bola-sc-${i}`;

    // Format request headers
    const hdrs = Object.entries(sc.request_headers ?? {})
      .map(([k, v]) => `${escHtml(k)}: <span class="rr-header-val">${escHtml(v)}</span>`)
      .join('\n');

    // HTTP status colour class
    const statusCls = sc.actual_status === 200
      ? 'rr-status--ok'
      : (sc.actual_status === 403 || sc.actual_status === 404)
        ? 'rr-status--blocked'
        : 'rr-status--other';

    // Truncate body for display
    const bodyText = sc.actual_body
      ? escHtml(sc.actual_body.length > 400 ? sc.actual_body.slice(0, 400) + '…' : sc.actual_body)
      : '<span class="rr-empty">(empty body)</span>';

    return `
      <div class="scenario-card ${vClass}">
        <div class="scenario-header">
          <div class="scenario-header-left">
            <span class="scenario-id">${escHtml(sc.scenario_id)}</span>
            <span class="scenario-title-text">${escHtml(sc.title ?? sc.description)}</span>
          </div>
          <span class="scenario-verdict-badge scenario-verdict--${isPass ? 'pass' : 'fail'}">
            <svg width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true">
              ${isPass
                ? '<path d="M3 8.5l3.5 3.5L13 5"/>'
                : '<path d="M4 4l8 8M12 4l-8 8"/>'}
            </svg>
            ${escHtml(sc.verdict)}
          </span>
        </div>

        <div class="scenario-meta">
          <span class="scenario-meta-item">
            <span class="scenario-meta-key">Attacker</span>
            <code>${escHtml(sc.attacker)}</code>
          </span>
          <span class="scenario-meta-item">
            <span class="scenario-meta-key">Victim</span>
            <code>${escHtml(sc.victim)}</code>
          </span>
          <span class="scenario-meta-item">
            <span class="scenario-meta-key">Record</span>
            <code>#${sc.record_id}</code>
          </span>
          <span class="scenario-meta-item">
            <span class="scenario-meta-key">Expected</span>
            <code>${sc.expected_status}</code>
          </span>
          <span class="scenario-meta-item">
            <span class="scenario-meta-key">Received</span>
            <code class="${statusCls}">${sc.actual_status}</code>
          </span>
        </div>

        <details class="scenario-detail" id="${detailId}">
          <summary>
            <svg class="fd-chevron" width="10" height="10" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="2.2" aria-hidden="true"><path d="M5 7l3 3 3-3"/></svg>
            Request / Response &amp; Verdict Details
          </summary>
          <div class="scenario-detail-body">
            <div class="rr-grid">
              <div class="rr-panel rr-panel--request">
                <div class="rr-panel-label">
                  <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M2 8h12M10 4l4 4-4 4"/></svg>
                  Request
                </div>
                <pre class="rr-block">${escHtml(sc.request_method)} <span class="rr-url">${escHtml(sc.request_url)}</span>
${hdrs}</pre>
              </div>
              <div class="rr-panel rr-panel--response">
                <div class="rr-panel-label">
                  <svg width="11" height="11" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.7" aria-hidden="true"><path d="M14 8H2M6 4L2 8l4 4"/></svg>
                  Response
                </div>
                <pre class="rr-block"><span class="${statusCls} rr-status-line">HTTP ${sc.actual_status}</span>
${bodyText}</pre>
              </div>
            </div>
            <div class="scenario-verdict-block ${vClass}">
              <svg width="14" height="14" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
                ${isPass
                  ? '<path d="M3 8.5l3.5 3.5L13 5"/>'
                  : '<path d="M8 1.5L14.5 13H1.5L8 1.5z"/><path d="M8 6v3M8 10.5v.5"/>'}
              </svg>
              <span>${escHtml(sc.verdict_reason)}</span>
            </div>
          </div>
        </details>
      </div>`;
  }).join('');

  results.innerHTML = `
    <div class="bola-results-header">
      <div class="overall-verdict ${verdictClass}">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          ${verdictClass === 'verdict-pass'
            ? '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M9 12l2 2 4-4"/>'
            : '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 15v1"/>'}
        </svg>
        <span class="verdict-label">Overall:</span>
        <span class="verdict-value">${escHtml(data.overall_verdict)}</span>
        ${modeLabel}
        <span class="bola-score">${passCount}/${total} passed</span>
      </div>
    </div>
    <div class="scenarios">${scenarioRows}</div>`;
}

// ── Auto-refresh while scans are running ──────────────────────────────────────

function startPolling() {
  setInterval(async () => {
    const hasRunning = _allScans.some(s => s.status === 'running');
    if (!hasRunning) return;
    await loadStats();
    const prev = _allScans.map(s => s.status).join(',');
    await loadScans();
    const next = _allScans.map(s => s.status).join(',');
    if (prev !== next && _activeId) selectScan(_activeId);
  }, 4000);
}

// ── Boot ──────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initFilters();
  initScanner();
  initBolaLab();
  loadDashboard();
  startPolling();
});
