// InboxReady — email authentication checks over DNS-over-HTTPS.
// Pure logic; the DNS resolver is injected so everything is testable offline.

export const DKIM_SELECTORS = [
  'google', 'selector1', 'selector2', 'default', 'k1', 'k2', 'k3', 's1', 's2',
  'dkim', 'mail', 'smtp', 'zoho', 'zmail', 'mandrill', 'mxvault', 'everlytickey1',
  'protonmail', 'protonmail2', 'protonmail3', 'sig1', 'fm1', 'fm2', 'fm3', 'mailjet',
  'sendgrid', 'smtpapi', 'pm', 'resend', 'amazonses', 'hs1', 'hs2', 'krs', 'mailo',
];

const MX_PROVIDERS = [
  [/google\.com$|googlemail\.com$/i, 'Google Workspace', 'include:_spf.google.com'],
  [/outlook\.com$|protection\.outlook\.com$/i, 'Microsoft 365', 'include:spf.protection.outlook.com'],
  [/zoho\.(com|eu|in)$/i, 'Zoho Mail', 'include:zoho.com'],
  [/protonmail\.ch$/i, 'Proton Mail', 'include:_spf.protonmail.ch'],
  [/messagingengine\.com$/i, 'Fastmail', 'include:spf.messagingengine.com'],
  [/secureserver\.net$/i, 'GoDaddy', 'include:secureserver.net'],
  [/mail\.ovh\.net$|ovh\.net$/i, 'OVH', 'include:mx.ovh.com'],
  [/hostinger\.com$/i, 'Hostinger', 'include:_spf.mail.hostinger.com'],
  [/yandex\.(net|ru)$/i, 'Yandex', 'include:_spf.yandex.net'],
  [/amazonaws\.com$/i, 'Amazon SES / WorkMail', 'include:amazonses.com'],
];

// ---------- DNS ----------

export function dohResolver(endpoint = 'https://cloudflare-dns.com/dns-query', fetchFn = globalThis.fetch) {
  const cache = new Map();
  return async function resolve(name, type) {
    const key = `${name}|${type}`;
    if (cache.has(key)) return cache.get(key);
    const p = (async () => {
      const url = `${endpoint}?name=${encodeURIComponent(name)}&type=${type}`;
      const res = await fetchFn(url, { headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error(`DNS lookup failed (${res.status}) for ${name}`);
      const j = await res.json();
      const typeNum = { TXT: 16, MX: 15, A: 1, AAAA: 28, CNAME: 5 }[type];
      return (j.Answer || [])
        .filter((a) => a.type === typeNum)
        .map((a) => (type === 'TXT' ? joinTxt(a.data) : a.data));
    })();
    cache.set(key, p);
    return p;
  };
}

// TXT answers arrive as one or more quoted chunks: "v=spf1 ..." "more"
export function joinTxt(data) {
  const parts = data.match(/"((?:[^"\\]|\\.)*)"/g);
  if (!parts) return data;
  return parts.map((p) => p.slice(1, -1).replace(/\\"/g, '"')).join('');
}

export function normalizeDomain(input) {
  let d = String(input || '').trim().toLowerCase();
  d = d.replace(/^mailto:/, '').replace(/^.*@/, '');
  d = d.replace(/^[a-z]+:\/\//, '').split(/[/?#:]/)[0].replace(/^www\./, '').replace(/\.$/, '');
  return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) ? d : null;
}

// ---------- MX ----------

export async function checkMx(domain, resolve) {
  const raw = await resolve(domain, 'MX');
  const hosts = raw
    .map((r) => { const [pri, host] = r.split(/\s+/); return { pri: Number(pri), host: (host || '').replace(/\.$/, '') }; })
    .sort((a, b) => a.pri - b.pri);
  const nullMx = hosts.length === 1 && (hosts[0].host === '' || hosts[0].host === '.');
  const provider = detectProvider(hosts.map((h) => h.host));
  const issues = [];
  let score = 15;
  if (!hosts.length) { issues.push({ level: 'bad', msg: 'No MX records: this domain cannot receive mail, and replies to your campaigns will bounce.' }); score = 0; }
  else if (nullMx) { issues.push({ level: 'bad', msg: 'Null MX ("0 ."): the domain explicitly refuses mail.' }); score = 0; }
  return { hosts, provider, nullMx, issues, score, max: 15 };
}

export function detectProvider(hosts) {
  for (const h of hosts) for (const [re, name, include] of MX_PROVIDERS) if (re.test(h)) return { name, include };
  return null;
}

// ---------- SPF ----------

export function parseSpf(record) {
  const terms = record.trim().split(/\s+/).slice(1);
  const mechanisms = [];
  let redirect = null;
  let all = null;
  for (const t of terms) {
    const m = t.match(/^([+\-~?]?)(all|include|a|mx|ptr|ip4|ip6|exists)(?::(.*?))?(\/\d+)?$/i);
    if (m) {
      const q = m[1] || '+';
      const mech = m[2].toLowerCase();
      if (mech === 'all') all = q;
      else mechanisms.push({ q, mech, value: m[3] || null });
      continue;
    }
    const r = t.match(/^redirect=(.+)$/i);
    if (r) redirect = r[1];
  }
  return { mechanisms, redirect, all };
}

const LOOKUP_MECHS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);

// Counts DNS-querying terms per RFC 7208 §4.6.4 (limit 10), recursing into includes/redirects.
export async function countSpfLookups(domain, resolve, depth = 0, seen = new Set(), includes = []) {
  if (depth > 12 || seen.has(domain)) return { count: 0, includes, errors: seen.has(domain) ? [`SPF loop at ${domain}`] : [] };
  seen.add(domain);
  const recs = (await resolve(domain, 'TXT')).filter((t) => /^v=spf1(\s|$)/i.test(t));
  if (!recs.length) return { count: 0, includes, errors: depth ? [`${domain} has no SPF record (referenced by an include)`] : [] };
  const spf = parseSpf(recs[0]);
  let count = 0;
  const errors = [];
  for (const m of spf.mechanisms) {
    if (!LOOKUP_MECHS.has(m.mech)) continue;
    count++;
    if (m.mech === 'include' && m.value) {
      includes.push(m.value.toLowerCase());
      const sub = await countSpfLookups(m.value, resolve, depth + 1, seen, includes);
      count += sub.count; errors.push(...sub.errors);
    }
  }
  if (spf.redirect) {
    count++;
    includes.push(spf.redirect.toLowerCase());
    const sub = await countSpfLookups(spf.redirect, resolve, depth + 1, seen, includes);
    count += sub.count; errors.push(...sub.errors);
  }
  return { count, errors, includes };
}

export async function checkSpf(domain, resolve, mx) {
  const txt = await resolve(domain, 'TXT');
  const recs = txt.filter((t) => /^v=spf1(\s|$)/i.test(t));
  const issues = [];
  const max = 25;
  const suggestion = suggestSpf(mx?.provider);
  if (!recs.length) {
    issues.push({ level: 'bad', msg: 'No SPF record. Receivers cannot tell which servers may send for this domain.' });
    return { record: null, issues, score: 0, max, suggestion };
  }
  if (recs.length > 1) {
    issues.push({ level: 'bad', msg: `${recs.length} SPF records found. RFC 7208 says this is a permerror, so SPF fails everywhere. Merge them into one.` });
  }
  const record = recs[0];
  const spf = parseSpf(record);
  const { count, errors, includes } = await countSpfLookups(domain, resolve);
  let score = max;
  if (recs.length > 1) score -= 15;
  if (count > 10) { issues.push({ level: 'bad', msg: `${count} DNS lookups (limit is 10). SPF returns permerror and fails. Flatten or remove includes.` }); score -= 12; }
  else if (count >= 8) issues.push({ level: 'warn', msg: `${count}/10 DNS lookups. One more tool's include could break SPF.` });
  for (const e of errors) issues.push({ level: 'warn', msg: e });
  if (spf.all === '+') { issues.push({ level: 'bad', msg: '"+all" lets anyone on the internet send as you.' }); score -= 15; }
  else if (spf.all === '?') { issues.push({ level: 'warn', msg: '"?all" (neutral) gives receivers no guidance. Use "~all" or "-all".' }); score -= 5; }
  else if (!spf.all && !spf.redirect) { issues.push({ level: 'warn', msg: 'No "all" mechanism at the end. Unlisted senders are treated as neutral.' }); score -= 5; }
  if (spf.mechanisms.some((m) => m.mech === 'ptr')) { issues.push({ level: 'warn', msg: '"ptr" is deprecated and slow. Replace it with ip4/include.' }); score -= 2; }
  const providerHost = mx?.provider?.include.replace('include:', '');
  if (providerHost && !includes.includes(providerHost)) {
    issues.push({ level: 'warn', msg: `MX is ${mx.provider.name}, but SPF doesn't include ${mx.provider.include}. Mail you send from ${mx.provider.name} may fail SPF.` });
    score -= 3;
  }
  return { record, lookups: count, all: spf.all, issues, score: Math.max(0, score), max, suggestion: score < max ? suggestion : null };
}

export function suggestSpf(provider) {
  return `v=spf1 ${provider ? provider.include + ' ' : ''}~all`;
}

// ---------- DMARC ----------

export function parseTags(record) {
  const tags = {};
  for (const part of record.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    tags[part.slice(0, i).trim().toLowerCase()] = part.slice(i + 1).trim();
  }
  return tags;
}

export function orgDomain(domain) {
  const labels = domain.split('.');
  const twoPartTlds = /^(co|com|net|org|gov|ac|edu)\.[a-z]{2}$/;
  const lastTwo = labels.slice(-2).join('.');
  return twoPartTlds.test(lastTwo) ? labels.slice(-3).join('.') : lastTwo;
}

export async function checkDmarc(domain, resolve) {
  const max = 25;
  let source = domain;
  let recs = (await resolve(`_dmarc.${domain}`, 'TXT')).filter((t) => /^v=DMARC1/i.test(t));
  const org = orgDomain(domain);
  if (!recs.length && org !== domain) {
    recs = (await resolve(`_dmarc.${org}`, 'TXT')).filter((t) => /^v=DMARC1/i.test(t));
    source = org;
  }
  const suggestion = `v=DMARC1; p=none; rua=mailto:dmarc-reports@${org}; fo=1`;
  const issues = [];
  if (!recs.length) {
    issues.push({ level: 'bad', msg: 'No DMARC record. Gmail and Yahoo require one for bulk senders (Feb 2024 rules).' });
    return { record: null, issues, score: 0, max, suggestion, host: `_dmarc.${org}` };
  }
  if (recs.length > 1) issues.push({ level: 'bad', msg: 'Multiple DMARC records. Receivers will ignore all of them.' });
  const record = recs[0];
  const t = parseTags(record);
  const policy = (source === domain ? t.p : (t.sp || t.p) || '').toLowerCase();
  let score = max;
  if (recs.length > 1) score -= 20;
  if (!['none', 'quarantine', 'reject'].includes(policy)) { issues.push({ level: 'bad', msg: `Invalid or missing policy "p=${t.p ?? ''}".` }); score -= 15; }
  else if (policy === 'none') { issues.push({ level: 'warn', msg: 'p=none only monitors. Once reports look clean, move to quarantine, then reject.' }); score -= 6; }
  if (t.pct && Number(t.pct) < 100) { issues.push({ level: 'warn', msg: `pct=${t.pct}: the policy only applies to ${t.pct}% of failing mail.` }); score -= 2; }
  if (!t.rua) { issues.push({ level: 'warn', msg: 'No rua= address, so you get no aggregate reports and can\'t see who sends as you.' }); score -= 4; }
  if (source !== domain) issues.push({ level: 'info', msg: `No record on ${domain}; inheriting from ${source}.` });
  return { record, policy, tags: t, source, issues, score: Math.max(0, score), max, suggestion: score < max - 6 ? suggestion : null, host: `_dmarc.${org}` };
}

// ---------- DKIM ----------

export function estimateKeyBits(p) {
  const der = Math.floor((p.replace(/\s/g, '').length * 3) / 4);
  if (!der) return 0;
  if (der < 100) return 512;
  if (der < 200) return 1024;
  if (der < 330) return 2048;
  return 4096;
}

export async function checkDkim(domain, resolve, selectors = DKIM_SELECTORS) {
  const max = 25;
  const found = [];
  // A wildcard *._domainkey record answers for any selector; probe a random one so it isn't counted as real keys.
  const probe = `ir${Math.random().toString(36).slice(2, 10)}`;
  const wildcard = (await resolve(`${probe}._domainkey.${domain}`, 'TXT').catch(() => []))[0] || null;
  await Promise.all(selectors.map(async (sel) => {
    try {
      const txt = await resolve(`${sel}._domainkey.${domain}`, 'TXT');
      const rec = txt.find((t) => /(^|;)\s*p=/i.test(t) || /v=DKIM1/i.test(t));
      if (!rec || rec === wildcard) return;
      const tags = parseTags(rec);
      const p = tags.p || '';
      found.push({ selector: sel, revoked: p === '', bits: p ? estimateKeyBits(p) : 0, keyType: (tags.k || 'rsa').toLowerCase() });
    } catch { /* lookup failure for one selector is not fatal */ }
  }));
  found.sort((a, b) => a.selector.localeCompare(b.selector));
  const issues = [];
  const live = found.filter((f) => !f.revoked);
  let score = max;
  if (wildcard) issues.push({ level: 'info', msg: `A wildcard *._domainkey record exists (${/p=\s*(;|$)/.test(wildcard) ? 'revoked, i.e. "this domain never signs"' : 'answers for every selector'}).` });
  if (!live.length) {
    issues.push({ level: found.length ? 'bad' : 'warn', msg: found.length
      ? 'DKIM selectors exist but every key is revoked (empty p=).'
      : `No DKIM key found on ${selectors.length} common selectors. If you use a custom selector, add it under "Custom DKIM selectors". Otherwise enable DKIM signing in your mail provider.` });
    score = found.length ? 0 : 5;
  }
  const weak = live.filter((f) => f.keyType === 'rsa' && f.bits && f.bits < 1024).map((f) => f.selector);
  const legacy = live.filter((f) => f.keyType === 'rsa' && f.bits === 1024).map((f) => f.selector);
  if (weak.length) { issues.push({ level: 'bad', msg: `Keys under 1024 bits on ${weak.join(', ')}. Many receivers reject keys this weak.` }); score -= 10; }
  if (legacy.length) { issues.push({ level: 'warn', msg: `1024-bit keys on ${legacy.join(', ')}. Rotate to 2048-bit.` }); score -= 3; }
  return { selectors: found, wildcard, issues, score: Math.max(0, score), max };
}

// ---------- Extras ----------

export async function checkExtras(domain, resolve) {
  const max = 10;
  const [sts, tlsrpt, bimi] = await Promise.all([
    resolve(`_mta-sts.${domain}`, 'TXT').then((r) => r.find((t) => /^v=STSv1/i.test(t)) || null),
    resolve(`_smtp._tls.${domain}`, 'TXT').then((r) => r.find((t) => /^v=TLSRPTv1/i.test(t)) || null),
    resolve(`default._bimi.${domain}`, 'TXT').then((r) => r.find((t) => /^v=BIMI1/i.test(t)) || null),
  ]);
  const issues = [];
  if (!sts) issues.push({ level: 'info', msg: 'No MTA-STS. Optional: it forces TLS for mail sent to you.' });
  if (!tlsrpt) issues.push({ level: 'info', msg: 'No TLS-RPT. Optional: it reports TLS delivery failures to you.' });
  if (!bimi) issues.push({ level: 'info', msg: 'No BIMI. Optional: it shows your logo in Gmail/Yahoo (needs DMARC quarantine/reject).' });
  const score = (sts ? 4 : 0) + (tlsrpt ? 3 : 0) + (bimi ? 3 : 0);
  return { mtaSts: sts, tlsRpt: tlsrpt, bimi, issues, score, max };
}

// ---------- Orchestration ----------

export function grade(score) {
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  return 'F';
}

export async function checkDomain(input, resolve, { extraSelectors = [] } = {}) {
  const domain = normalizeDomain(input);
  if (!domain) throw new Error(`"${input}" doesn't look like a domain`);
  const mx = await checkMx(domain, resolve);
  const selectors = [...new Set([...extraSelectors.map((s) => s.trim().toLowerCase()).filter(Boolean), ...DKIM_SELECTORS])];
  const [spf, dmarc, dkim, extras] = await Promise.all([
    checkSpf(domain, resolve, mx),
    checkDmarc(domain, resolve),
    checkDkim(domain, resolve, selectors),
    checkExtras(domain, resolve),
  ]);
  const sections = { mx, spf, dkim, dmarc, extras };
  const total = Object.values(sections).reduce((a, s) => a + s.score, 0);
  const max = Object.values(sections).reduce((a, s) => a + s.max, 0);
  const score = Math.round((total / max) * 100);
  return { domain, score, grade: grade(score), ...sections, checkedAt: new Date().toISOString() };
}

export function toCsvRow(r) {
  const cells = [
    r.domain, r.score, r.grade, r.mx.provider?.name || (r.mx.hosts[0]?.host ?? ''),
    r.spf.record ? 'yes' : 'no', r.spf.lookups ?? '', r.spf.all ?? '',
    r.dmarc.record ? r.dmarc.policy : 'missing',
    r.dkim.selectors.filter((s) => !s.revoked).map((s) => s.selector).join(' '),
    [r.mx, r.spf, r.dkim, r.dmarc].flatMap((s) => s.issues).filter((i) => i.level === 'bad').map((i) => i.msg).join(' | '),
  ];
  return cells.map((c) => `"${String(c).replace(/"/g, '""')}"`).join(',');
}

export const CSV_HEADER = 'domain,score,grade,mail_provider,spf,spf_lookups,spf_all,dmarc_policy,dkim_selectors,critical_issues';
