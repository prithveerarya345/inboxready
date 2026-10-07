import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  joinTxt, normalizeDomain, parseSpf, countSpfLookups, checkSpf, checkDmarc, checkDkim,
  checkMx, checkDomain, estimateKeyBits, orgDomain, grade, toCsvRow, dohResolver,
} from '../checks.js';

// Fake zone: { 'name|TYPE': [answers] }
const fake = (zone) => async (name, type) => zone[`${name}|${type}`] || [];

const KEY_2048 = 'A'.repeat(392);
const KEY_1024 = 'A'.repeat(216);

const healthy = {
  'acme.com|MX': ['1 aspmx.l.google.com.', '5 alt1.aspmx.l.google.com.'],
  'acme.com|TXT': ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc'],
  '_spf.google.com|TXT': ['v=spf1 include:_netblocks.google.com include:_netblocks2.google.com ~all'],
  '_netblocks.google.com|TXT': ['v=spf1 ip4:35.190.247.0/24 ~all'],
  '_netblocks2.google.com|TXT': ['v=spf1 ip6:2001:4860:4000::/36 ~all'],
  '_dmarc.acme.com|TXT': ['v=DMARC1; p=reject; rua=mailto:d@acme.com'],
  [`google._domainkey.acme.com|TXT`]: [`v=DKIM1; k=rsa; p=${KEY_2048}`],
  '_mta-sts.acme.com|TXT': ['v=STSv1; id=1'],
  '_smtp._tls.acme.com|TXT': ['v=TLSRPTv1; rua=mailto:t@acme.com'],
};

test('joinTxt merges quoted chunks', () => {
  assert.equal(joinTxt('"v=spf1 include:a.com " "~all"'), 'v=spf1 include:a.com ~all');
  assert.equal(joinTxt('plain'), 'plain');
});

test('normalizeDomain accepts emails, urls, www', () => {
  assert.equal(normalizeDomain('Bob@Acme.COM'), 'acme.com');
  assert.equal(normalizeDomain('https://www.acme.co.uk/path?x=1'), 'acme.co.uk');
  assert.equal(normalizeDomain('not a domain'), null);
});

test('parseSpf reads qualifiers, all and redirect', () => {
  const s = parseSpf('v=spf1 ip4:1.2.3.4 include:x.com -all');
  assert.equal(s.all, '-');
  assert.equal(s.mechanisms.length, 2);
  assert.equal(parseSpf('v=spf1 redirect=_spf.x.com').redirect, '_spf.x.com');
});

test('countSpfLookups recurses includes', async () => {
  const { count } = await countSpfLookups('acme.com', fake(healthy));
  assert.equal(count, 3); // include:_spf.google.com + 2 nested includes
});

test('SPF over 10 lookups is flagged as bad', async () => {
  const zone = { 'x.com|TXT': [`v=spf1 ${Array.from({ length: 11 }, (_, i) => `include:i${i}.com`).join(' ')} -all`] };
  for (let i = 0; i < 11; i++) zone[`i${i}.com|TXT`] = ['v=spf1 ip4:1.1.1.1 -all'];
  const r = await checkSpf('x.com', fake(zone), null);
  assert.equal(r.lookups, 11);
  assert.ok(r.issues.some((i) => i.level === 'bad' && /limit is 10/.test(i.msg)));
});

test('multiple SPF records and +all are bad', async () => {
  const r = await checkSpf('x.com', fake({ 'x.com|TXT': ['v=spf1 +all', 'v=spf1 -all'] }), null);
  assert.ok(r.issues.filter((i) => i.level === 'bad').length >= 2);
  assert.ok(r.score <= 0 + 10);
});

test('SPF loop does not hang', async () => {
  const r = await countSpfLookups('a.com', fake({ 'a.com|TXT': ['v=spf1 include:b.com -all'], 'b.com|TXT': ['v=spf1 include:a.com -all'] }));
  assert.ok(r.errors.some((e) => /loop/.test(e)));
});

test('missing SPF suggests provider include', async () => {
  const mx = await checkMx('acme.com', fake(healthy));
  const r = await checkSpf('acme.com', fake({}), mx);
  assert.equal(r.suggestion, 'v=spf1 include:_spf.google.com ~all');
});

test('DMARC falls back to organizational domain', async () => {
  const r = await checkDmarc('mail.acme.com', fake(healthy));
  assert.equal(r.source, 'acme.com');
  assert.equal(r.policy, 'reject');
});

test('DMARC p=none is a warning and missing record suggests one', async () => {
  const r1 = await checkDmarc('x.com', fake({ '_dmarc.x.com|TXT': ['v=DMARC1; p=none'] }));
  assert.ok(r1.issues.some((i) => /monitors/.test(i.msg)));
  const r2 = await checkDmarc('x.com', fake({}));
  assert.match(r2.suggestion, /^v=DMARC1; p=none; rua=mailto:dmarc-reports@x\.com/);
});

test('orgDomain handles co.uk', () => {
  assert.equal(orgDomain('a.b.acme.co.uk'), 'acme.co.uk');
  assert.equal(orgDomain('a.acme.com'), 'acme.com');
});

test('DKIM key size estimation and weak key warning', async () => {
  assert.equal(estimateKeyBits(KEY_2048), 2048);
  assert.equal(estimateKeyBits(KEY_1024), 1024);
  const r = await checkDkim('x.com', fake({ 's1._domainkey.x.com|TXT': [`v=DKIM1; p=${KEY_1024}`] }), ['s1', 's2']);
  assert.equal(r.selectors.length, 1);
  assert.ok(r.issues.some((i) => /1024-bit keys on s1/.test(i.msg)));
});

test('healthy domain scores A', async () => {
  const r = await checkDomain('acme.com', fake(healthy));
  assert.equal(r.mx.provider.name, 'Google Workspace');
  assert.equal(r.grade, 'A');
  assert.ok(r.score >= 90, `score ${r.score}`);
  assert.match(toCsvRow(r), /^"acme\.com","\d+","A","Google Workspace"/);
});

test('empty domain scores F', async () => {
  const r = await checkDomain('nothing.com', fake({}));
  assert.equal(r.grade, 'F');
});

test('grade boundaries', () => {
  assert.equal(grade(90), 'A'); assert.equal(grade(75), 'B'); assert.equal(grade(39), 'F');
});

test('dohResolver parses Cloudflare JSON and caches', async () => {
  let calls = 0;
  const fetchFn = async () => { calls++; return { ok: true, json: async () => ({ Answer: [{ type: 16, data: '"v=spf1 " "-all"' }, { type: 5, data: 'x.' }] }) }; };
  const resolve = dohResolver('https://dns.test', fetchFn);
  assert.deepEqual(await resolve('a.com', 'TXT'), ['v=spf1 -all']);
  await resolve('a.com', 'TXT');
  assert.equal(calls, 1);
});

test('nested provider include is not a false positive', async () => {
  const zone = { ...healthy, 'acme.com|TXT': ['v=spf1 include:_spf.acme.com ~all'], '_spf.acme.com|TXT': ['v=spf1 include:_spf.google.com ~all'] };
  const mx = await checkMx('acme.com', fake(zone));
  const r = await checkSpf('acme.com', fake(zone), mx);
  assert.ok(!r.issues.some((i) => /doesn't include/.test(i.msg)));
});

test('wildcard DKIM is not counted as selectors', async () => {
  const wild = 'v=DKIM1; p=';
  const resolve = async (name, type) => (type === 'TXT' && name.endsWith('._domainkey.x.com') ? [wild] : []);
  const r = await checkDkim('x.com', resolve, ['a', 'b', 'c']);
  assert.equal(r.selectors.length, 0);
  assert.ok(r.issues.some((i) => /wildcard/.test(i.msg)));
});
