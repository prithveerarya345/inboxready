import { checkDomain, dohResolver, normalizeDomain, toCsvRow, CSV_HEADER } from './checks.js';

const resolve = dohResolver();
const $ = (s) => document.querySelector(s);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

// ---------- tabs ----------
for (const t of document.querySelectorAll('.tab')) {
  t.addEventListener('click', () => {
    for (const o of document.querySelectorAll('.tab')) { o.classList.toggle('active', o === t); o.setAttribute('aria-selected', o === t); }
    for (const p of document.querySelectorAll('.panel')) p.hidden = p.id !== t.dataset.tab;
  });
}

// ---------- single ----------
const verdict = (r) => {
  const bad = ['mx', 'spf', 'dkim', 'dmarc'].flatMap((k) => r[k].issues).filter((i) => i.level === 'bad').length;
  if (r.grade === 'A') return 'Authentication looks solid. Deliverability problems are more likely about content, volume or sender reputation.';
  if (bad) return `${bad} critical problem${bad > 1 ? 's' : ''} that can send mail straight to spam. The fixes are below.`;
  return 'No blockers, but tightening the warnings below will help inbox placement.';
};

function issueList(issues) {
  if (!issues.length) return '<ul class="issues"><li class="lv-good">All good</li></ul>';
  return `<ul class="issues">${issues.map((i) => `<li class="lv-${i.level}">${esc(i.msg)}</li>`).join('')}</ul>`;
}

function fixBlock(label, host, value) {
  if (!value) return '';
  return `<div class="fix"><b>Suggested ${esc(label)}</b> <span class="muted">(TXT on <code>${esc(host)}</code>)</span>
    <div class="rec"><span>${esc(value)}</span><button type="button" data-copy="${esc(value)}">Copy</button></div></div>`;
}

function card(title, sec, body) {
  return `<div class="card"><div class="card-h"><h4>${title}</h4><span class="pts">${sec.score}/${sec.max}</span></div>${body}</div>`;
}

function renderReport(r) {
  const mxBody = r.mx.hosts.length
    ? `<div class="chips">${r.mx.hosts.map((h) => `<span class="chip">${h.pri} ${esc(h.host || '.')}</span>`).join('')}</div>${r.mx.provider ? `<p class="muted">Provider: ${esc(r.mx.provider.name)}</p>` : ''}`
    : '';
  const spfBody = `${r.spf.record ? `<div class="rec">${esc(r.spf.record)}</div><p class="muted">DNS lookups: ${r.spf.lookups}/10</p>` : ''}${issueList(r.spf.issues)}${fixBlock('SPF', r.domain, r.spf.suggestion)}`;
  const dkimBody = `${r.dkim.selectors.length ? `<div class="chips">${r.dkim.selectors.map((s) => `<span class="chip">${esc(s.selector)} · ${s.revoked ? 'revoked' : `${s.keyType}${s.bits ? ' ~' + s.bits : ''}`}</span>`).join('')}</div>` : ''}${issueList(r.dkim.issues)}`;
  const dmarcBody = `${r.dmarc.record ? `<div class="rec">${esc(r.dmarc.record)}</div>` : ''}${issueList(r.dmarc.issues)}${fixBlock('DMARC', r.dmarc.host, r.dmarc.suggestion)}`;
  const exBody = issueList(r.extras.issues);
  $('#report').innerHTML = `
    <div class="summary">
      <div class="gauge g-${r.grade}"><div>${r.grade}<small>${r.score}/100</small></div></div>
      <div><h3>${esc(r.domain)}</h3><p>${esc(verdict(r))}</p></div>
    </div>
    ${card('MX: receiving mail', r.mx, mxBody + (r.mx.issues.length ? issueList(r.mx.issues) : ''))}
    ${card('SPF: who may send', r.spf, spfBody)}
    ${card('DKIM: signatures', r.dkim, dkimBody)}
    ${card('DMARC: policy', r.dmarc, dmarcBody)}
    ${card('Extras: MTA-STS, TLS-RPT, BIMI', r.extras, exBody)}
    <p class="muted">Checked ${new Date(r.checkedAt).toLocaleString()} · <a href="?d=${encodeURIComponent(r.domain)}">Share this report</a></p>`;
}

async function runSingle(input) {
  const d = normalizeDomain(input);
  if (!d) { $('#report').innerHTML = `<p class="error">That doesn't look like a domain.</p>`; return; }
  $('#report').innerHTML = `<p class="spinner">Checking ${esc(d)}…</p>`;
  try {
    const extra = $('#selectors').value.split(',');
    const r = await checkDomain(d, resolve, { extraSelectors: extra });
    renderReport(r);
    history.replaceState(null, '', `?d=${encodeURIComponent(d)}`);
  } catch (e) {
    $('#report').innerHTML = `<p class="error">${esc(e.message)}</p>`;
  }
}

$('#single-form').addEventListener('submit', (e) => { e.preventDefault(); runSingle($('#domain').value); });

document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-copy]');
  if (!b) return;
  try { await navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; setTimeout(() => (b.textContent = 'Copy'), 1500); } catch { /* clipboard blocked */ }
});

// ---------- bulk ----------
let bulkResults = [];

function scoreClass(s) { return s >= 75 ? 's-good' : s >= 50 ? 's-warn' : 's-bad'; }

function renderTable() {
  const tb = $('#bulk-table tbody');
  tb.innerHTML = bulkResults.map((r) => r.error
    ? `<tr><td>${esc(r.domain)}</td><td colspan="6" class="s-bad">${esc(r.error)}</td></tr>`
    : `<tr><td><a href="?d=${encodeURIComponent(r.domain)}" target="_blank">${esc(r.domain)}</a></td>
        <td class="score ${scoreClass(r.score)}">${r.score} ${r.grade}</td>
        <td>${esc(r.mx.provider?.name || r.mx.hosts[0]?.host || 'none')}</td>
        <td>${r.spf.record ? `${r.spf.lookups}/10 ${esc(r.spf.all || '')}all` : '<span class="s-bad">missing</span>'}</td>
        <td>${r.dkim.selectors.filter((s) => !s.revoked).map((s) => esc(s.selector)).join(', ') || '<span class="s-warn">not found</span>'}</td>
        <td>${r.dmarc.record ? esc(r.dmarc.policy) : '<span class="s-bad">missing</span>'}</td>
        <td>${['mx', 'spf', 'dkim', 'dmarc'].flatMap((k) => r[k].issues).filter((i) => i.level === 'bad').map((i) => esc(i.msg)).join('<br>')}</td></tr>`).join('');
  $('#bulk-table').hidden = !bulkResults.length;
}

document.querySelectorAll('#bulk-table th[data-k]').forEach((th) => th.addEventListener('click', () => {
  const k = th.dataset.k;
  bulkResults.sort((a, b) => (k === 'score' ? (a.score ?? -1) - (b.score ?? -1) : String(a[k]).localeCompare(String(b[k]))));
  renderTable();
}));

$('#bulk-run').addEventListener('click', async () => {
  const lines = $('#bulk-input').value.split(/[\n,;\s]+/).map(normalizeDomain).filter(Boolean);
  const domains = [...new Set(lines)].slice(0, 300);
  if (!domains.length) { $('#bulk-status').textContent = 'Paste at least one domain.'; return; }
  bulkResults = [];
  $('#bulk-run').disabled = true; $('#bulk-csv').disabled = true;
  let done = 0;
  const queue = [...domains];
  const worker = async () => {
    while (queue.length) {
      const d = queue.shift();
      try { bulkResults.push(await checkDomain(d, resolve)); } catch (e) { bulkResults.push({ domain: d, error: e.message }); }
      done++; $('#bulk-status').textContent = `${done}/${domains.length} checked`;
      renderTable();
    }
  };
  await Promise.all(Array.from({ length: 4 }, worker));
  bulkResults.sort((a, b) => (a.score ?? -1) - (b.score ?? -1));
  renderTable();
  $('#bulk-run').disabled = false; $('#bulk-csv').disabled = false;
  const failing = bulkResults.filter((r) => !r.error && r.score < 60).length;
  $('#bulk-status').textContent = `${domains.length} checked · ${failing} need attention`;
});

$('#bulk-csv').addEventListener('click', () => {
  const rows = bulkResults.filter((r) => !r.error).map(toCsvRow);
  const blob = new Blob([[CSV_HEADER, ...rows].join('\n')], { type: 'text/csv' });
  const a = Object.assign(document.createElement('a'), { href: URL.createObjectURL(blob), download: `inboxready-${new Date().toISOString().slice(0, 10)}.csv` });
  a.click(); URL.revokeObjectURL(a.href);
});

// ---------- deep link ----------
const params = new URLSearchParams(location.search);
const initial = params.get('d');
const bulk = params.get('bulk');
if (initial) { $('#domain').value = initial; runSingle(initial); }
else if (bulk) {
  document.querySelector('.tab[data-tab="bulk"]').click();
  $('#bulk-input').value = bulk.split(',').join('\n');
  $('#bulk-run').click();
}
