/* Secure-Login admin dashboard */
const API = location.origin;
let TOKEN = localStorage.getItem('sl_token') || null;
let activityChart = null;

async function api(path, opts = {}) {
  const headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  if (TOKEN) headers['Authorization'] = 'Bearer ' + TOKEN;
  const res = await fetch(API + path, { ...opts, headers });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith('/auth/login')) { doLogout(true); throw new Error('unauthorized'); }
  if (!res.ok) throw new Error(body.error || res.statusText);
  return body;
}

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const dt = (v) => v ? new Date(v).toLocaleString() : '—';

/* ---------- Auth ---------- */
$('login-btn').onclick = async () => {
  $('login-error').textContent = '';
  try {
    const r = await api('/auth/login', { method: 'POST', body: JSON.stringify({
      email: $('login-email').value.trim(), password: $('login-password').value }) });
    if (r.mfa_required) {
      const code = prompt('Code MFA (TOTP ou code de récupération) :');
      if (!code) return;
      const r2 = await api('/auth/mfa/verify', { method: 'POST', body: JSON.stringify({ mfa_token: r.mfa_token, code }) });
      TOKEN = r2.access_token;
    } else TOKEN = r.access_token;
    localStorage.setItem('sl_token', TOKEN);
    enterApp();
  } catch (e) { $('login-error').textContent = e.message; }
};
$('logout-btn').onclick = () => doLogout(false);
function doLogout(expired) {
  if (!expired && TOKEN) api('/auth/logout', { method: 'POST', body: '{}' }).catch(() => {});
  TOKEN = null; localStorage.removeItem('sl_token'); location.reload();
}

/* ---------- Tabs ---------- */
document.querySelectorAll('#tabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('#tabs button').forEach(x => x.classList.remove('active'));
  b.classList.add('active');
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  $('tab-' + b.dataset.tab).classList.add('active');
  loadTab(b.dataset.tab);
});

function enterApp() {
  $('login-view').classList.add('hidden');
  $('app-view').classList.remove('hidden');
  loadTab('overview');
}
if (TOKEN) enterApp();

function loadTab(tab) {
  if (tab === 'overview') loadOverview();
  else if (tab === 'users') loadUsers();
  else if (tab === 'sessions') loadSessions();
  else if (tab === 'security') { loadSuspicious(); loadDoubles(); loadBlocked(); }
  else if (tab === 'logs') loadLogs();
  else if (tab === 'config') loadConfig();
}

/* ---------- Overview ---------- */
async function loadOverview() {
  try {
    const o = await api('/admin/overview');
    $('stats-cards').innerHTML = [
      ['Utilisateurs', o.users], ['Sessions actives', o.active_sessions],
      ['IP bloquées', o.blocked_ips], ['Échecs login (24h)', o.failed_logins_24h],
    ].map(([l, v]) => `<div class="stat"><div class="v">${esc(v)}</div><div class="l">${l}</div></div>`).join('');
    const a = await api('/admin/stats/activity?days=14');
    const days = a.days || [];
    const labels = days.map(d => d.day.slice(5));
    if (activityChart) activityChart.destroy();
    activityChart = new Chart($('activity-chart'), {
      type: 'line',
      data: { labels, datasets: [
        { label: 'Logins', data: days.map(d => d.logins), borderColor: '#3fb950', tension: .3 },
        { label: 'Échecs', data: days.map(d => d.failures), borderColor: '#f85149', tension: .3 },
        { label: 'Inscriptions', data: days.map(d => d.registrations), borderColor: '#2f81f7', tension: .3 },
      ]},
      options: { plugins: { legend: { labels: { color: '#8b949e' } } },
        scales: { x: { ticks: { color: '#8b949e' } }, y: { ticks: { color: '#8b949e' }, beginAtZero: true } } }
    });
  } catch (e) { console.error(e); }
}

/* ---------- Users ---------- */
async function loadUsers(q = '') {
  const r = await api('/admin/users?limit=100&q=' + encodeURIComponent(q));
  $('users-table').querySelector('tbody').innerHTML = (r.users || []).map(u => `<tr>
    <td class="muted">${esc(u.id.slice(0, 8))}…</td><td>${esc(u.email)}</td>
    <td><span class="tag">${esc(u.role)}</span></td>
    <td>${u.email_verified ? '<span class="tag no">oui</span>' : '<span class="tag yes">non</span>'}</td>
    <td>${esc(u.last_login_ip || '—')}</td><td>${dt(u.last_login_at)}</td>
    <td><button class="btn danger" onclick="deleteUser('${esc(u.id)}','${esc(u.email)}')">Supprimer</button></td></tr>`).join('');
}
$('user-search-btn').onclick = () => loadUsers($('user-search').value.trim());
window.deleteUser = async (id, email) => {
  if (!confirm(`Supprimer ${email} ?`)) return;
  await api('/admin/users/' + id, { method: 'DELETE' }); loadUsers();
};

/* ---------- Sessions ---------- */
async function loadSessions() {
  const r = await api('/admin/sessions?limit=200');
  $('sessions-table').querySelector('tbody').innerHTML = (r.sessions || []).map(s => `<tr>
    <td class="muted">${esc(s.id.slice(0, 8))}…</td><td>${esc(s.email)}</td><td>${esc(s.device || '—')}</td>
    <td>${esc(s.ip || '—')}</td><td>${esc(s.country || '—')}</td><td>${dt(s.last_seen_at)}</td><td>${dt(s.expires_at)}</td>
    <td><button class="btn danger" onclick="revokeSession('${esc(s.id)}')">Révoquer</button></td></tr>`).join('');
}
window.revokeSession = async (id) => { await api('/admin/sessions/' + id, { method: 'DELETE' }); loadSessions(); };

/* ---------- Security ---------- */
$('bl-submit').onclick = async () => {
  const ttl = $('bl-ttl').value ? parseInt($('bl-ttl').value) : undefined;
  try {
    await api('/admin/block-ip', { method: 'POST', body: JSON.stringify({
      ip: $('bl-ip').value.trim(), mode: $('bl-mode').value,
      reason: $('bl-reason').value.trim() || undefined, expires_in_minutes: ttl }) });
    $('bl-ip').value = ''; $('bl-reason').value = ''; $('bl-ttl').value = '';
    loadBlocked(); loadSuspicious();
  } catch (e) { alert(e.message); }
};

async function loadSuspicious() {
  const r = await api('/admin/suspicious-ips');
  $('suspicious-table').querySelector('tbody').innerHTML = (r.ips || []).map(i => `<tr>
    <td>${esc(i.ip)}</td><td>${i.failed_logins_24h}</td><td>${i.total_attempts_24h}</td>
    <td>${i.blacklisted ? '<span class="tag yes">oui</span>' : '<span class="tag no">non</span>'}</td>
    <td>${i.blacklisted ? '' : `<button class="btn danger" onclick="quickBlock('${esc(i.ip)}')">Blacklist</button>`}</td></tr>`).join('')
    || '<tr><td colspan="5" class="muted">Aucune IP suspecte 🎉</td></tr>';
}
window.quickBlock = async (ip) => {
  await api('/admin/block-ip', { method: 'POST', body: JSON.stringify({ ip, mode: 'blacklist', reason: 'suspicious' }) });
  loadSuspicious(); loadBlocked();
};

async function loadDoubles() {
  const r = await api('/admin/double-accounts');
  $('doubles-list').innerHTML = (r.groups || []).map(g => `<div class="dbl-group">
    <b>${esc(g.ip)}</b> — ${g.count} comptes
    <ul style="margin:6px 0 0 18px">${g.accounts.map(a =>
      `<li>${esc(a.email)} <span class="muted">(${esc(a.id.slice(0, 8))}…)</span></li>`).join('')}</ul></div>`).join('')
    || '<p class="muted">Aucun doublon détecté.</p>';
}

async function loadBlocked() {
  const r = await api('/admin/blocked-ips');
  $('blocked-table').querySelector('tbody').innerHTML = (r.blocked_ips || []).map(b => `<tr>
    <td>${esc(b.ip)}</td><td><span class="tag ${b.mode === 'blacklist' ? 'yes' : 'no'}">${esc(b.mode)}</span></td>
    <td>${esc(b.reason || '—')}</td><td>${dt(b.created_at)}</td><td>${dt(b.expires_at)}</td>
    <td><button class="btn" onclick="unblock('${esc(b.ip)}')">Retirer</button></td></tr>`).join('');
}
window.unblock = async (ip) => { await api('/admin/block-ip/' + ip, { method: 'DELETE' }); loadBlocked(); };

/* ---------- Logs ---------- */
async function loadLogs() {
  const r = await api('/admin/logs?limit=200');
  $('logs-table').querySelector('tbody').innerHTML = (r.logs || []).map(l => `<tr>
    <td>${dt(l.created_at)}</td><td class="sev-${esc(l.severity)}">${esc(l.severity)}</td>
    <td>${esc(l.event)}</td><td class="muted">${l.user_id ? esc(l.user_id.slice(0, 8)) + '…' : '—'}</td>
    <td>${esc(l.ip || '—')}</td><td>${esc(l.country || '—')}</td>
    <td class="muted small">${l.details ? esc(JSON.stringify(l.details)).slice(0, 120) : '—'}</td></tr>`).join('');
}

/* ---------- Config ---------- */
async function loadConfig() {
  const c = await api('/admin/config');
  $('cfg-max-failed').value = c.max_failed_logins;
  $('cfg-lockout').value = c.lockout_base_secs;
  $('cfg-suspicious').value = c.suspicious_fail_threshold;
  $('cfg-double').value = c.double_account_min;
  $('cfg-rate').value = c.rate_limit_per_min;
  $('cfg-raw').textContent = JSON.stringify(c, null, 2);
}
$('cfg-save').onclick = async () => {
  await api('/admin/config', { method: 'POST', body: JSON.stringify({
    max_failed_logins: +$('cfg-max-failed').value,
    lockout_base_secs: +$('cfg-lockout').value,
    suspicious_fail_threshold: +$('cfg-suspicious').value,
    double_account_min: +$('cfg-double').value,
    rate_limit_per_min: +$('cfg-rate').value,
  })});
  loadConfig();
};
