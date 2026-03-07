/* socai UI — shared JS */

const API = '';  // same origin

function getToken() {
  return localStorage.getItem('socai_token');
}

function setToken(token) {
  localStorage.setItem('socai_token', token);
}

function clearToken() {
  localStorage.removeItem('socai_token');
}

function requireAuth() {
  if (!getToken()) {
    window.location.href = '/ui/index.html';
  }
}

function logout() {
  clearToken();
  window.location.href = '/ui/index.html';
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const headers = options.headers || {};
  if (token) {
    headers['Authorization'] = 'Bearer ' + token;
  }
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }
  const resp = await fetch(API + path, { ...options, headers });
  if (resp.status === 401) {
    clearToken();
    window.location.href = '/ui/index.html';
    return null;
  }
  return resp;
}

/* Status badge helper */
function statusBadge(status) {
  const colors = {
    queued: '#6c757d',
    running: '#0d6efd',
    complete: '#198754',
    failed: '#dc3545',
    open: '#0d6efd',
    closed: '#198754',
  };
  const color = colors[status] || '#6c757d';
  return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;background:' + color + ';font-size:0.85em;">' + (status || 'unknown') + '</span>';
}

function severityBadge(sev) {
  const colors = { critical: '#dc3545', high: '#fd7e14', medium: '#ffc107', low: '#198754' };
  const color = colors[sev] || '#6c757d';
  const text = sev === 'medium' || sev === 'low' ? '#000' : '#fff';
  return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;color:' + text + ';background:' + color + ';font-size:0.85em;">' + (sev || '-') + '</span>';
}

/* Poll job status */
function pollStatus(caseId, callback, interval = 5000) {
  const poll = async () => {
    const resp = await apiFetch('/api/investigations/' + caseId + '/status');
    if (!resp) return;
    const data = await resp.json();
    callback(data);
    if (data.status === 'queued' || data.status === 'running') {
      setTimeout(poll, interval);
    }
  };
  poll();
}

/* Disposition badge */
function dispositionBadge(disp) {
  const colors = {
    malicious: '#dc3545', true_positive: '#dc3545',
    suspicious: '#fd7e14', benign: '#198754',
    false_positive: '#198754', undetermined: '#6c757d',
  };
  const color = colors[disp] || '#6c757d';
  const textColor = (disp === 'undetermined') ? '#fff' : '#fff';
  return '<span style="display:inline-block;padding:2px 8px;border-radius:4px;color:' + textColor + ';background:' + color + ';font-size:0.85em;">' + (disp || 'undetermined') + '</span>';
}

/* Relative time helper */
function relativeTime(isoString) {
  if (!isoString) return '';
  try {
    const dt = new Date(isoString);
    const now = new Date();
    const diffMs = now - dt;
    const diffMins = Math.floor(diffMs / 60000);
    if (diffMins < 1) return 'just now';
    if (diffMins < 60) return diffMins + 'm ago';
    const diffHours = Math.floor(diffMins / 60);
    if (diffHours < 24) return diffHours + 'h ago';
    const diffDays = Math.floor(diffHours / 24);
    if (diffDays < 30) return diffDays + 'd ago';
    const diffMonths = Math.floor(diffDays / 30);
    return diffMonths + 'mo ago';
  } catch { return isoString; }
}

/* Escape HTML */
function esc(s) {
  const d = document.createElement('div');
  d.textContent = s || '';
  return d.innerHTML;
}

/* Active context persistence (per-user) */
function getActiveContext(email) {
  try {
    const raw = localStorage.getItem('socai_active_context_' + email);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function setActiveContext(email, ctx) {
  localStorage.setItem('socai_active_context_' + email,
    JSON.stringify({ sessionId: ctx.sessionId || null, caseId: ctx.caseId || null, ts: Date.now() }));
}

function clearActiveContext(email) {
  localStorage.removeItem('socai_active_context_' + email);
}
