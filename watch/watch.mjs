#!/usr/bin/env node
// PROTOTYPE — daily look-alike watch. Run by .github/workflows/lookalike-watch.yml.
//
// For every domain in watch/domains.txt: generate look-alike names, check which are registered
// (public DNS), whether they take email, and whether a certificate was issued for them (a site is
// going live). Compares with watch/state.json and writes watch/alert.md when something is new.
//
//   node watch/watch.mjs            update state, write alert.md if anything changed
import { readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs';

const DIR = new URL('.', import.meta.url);
const TWO = ['com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg', 'co.uk', 'org.uk', 'com.au', 'net.au', 'co.nz', 'com.my', 'co.id', 'com.ph', 'co.th', 'com.hk', 'co.in', 'co.jp'];

function lookalikes(d) {
  const sfx = TWO.find(s => d.endsWith('.' + s)) || d.split('.').pop();
  const n = d.slice(0, -(sfx.length + 1)), tld = '.' + sfx, out = new Set();
  const add = x => { if (x !== d && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x) && !x.startsWith('-')) out.add(x); };
  const swap = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], m: ['rn'], g: ['q'], b: ['d'], d: ['b'], u: ['v'], w: ['vv'] };
  for (let i = 0; i < n.length; i++) {
    add(n.slice(0, i) + n.slice(i + 1) + tld);
    add(n.slice(0, i) + n[i] + n[i] + n.slice(i + 1) + tld);
    if (i < n.length - 1) add(n.slice(0, i) + n[i + 1] + n[i] + n.slice(i + 2) + tld);
    for (const s of swap[n[i]] || []) add(n.slice(0, i) + s + n.slice(i + 1) + tld);
  }
  for (const t of ['.com', '.net', '.co', '.sg', '.com.sg', '.org', '.online', '.shop']) add(n + t);
  for (const w of ['login', 'secure', 'pay', 'promo', 'official']) { add(`${n}-${w}${tld}`); add(`${w}-${n}${tld}`); }
  return [...out].slice(0, 60);
}

async function doh(name, type) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}`, { headers: { accept: 'application/dns-json' }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`DNS ${r.status}`);
  return r.json();
}

async function pool(items, n, fn) {
  let i = 0;
  await Promise.all(Array.from({ length: Math.min(n, items.length) }, async () => { while (i < items.length) await fn(items[i++]); }));
}

async function certCount(d) {
  try {
    const r = await fetch(`https://api.certspotter.com/v1/issuances?domain=${d}&include_subdomains=true`, { signal: AbortSignal.timeout(12000) });
    return r.ok ? (await r.json()).length : null;
  } catch { return null; }
}

async function check(d) {
  let list = lookalikes(d);
  // Endings where every name answers (wildcard DNS) cannot be judged.
  const endings = [...new Set(list.map(x => x.slice(x.indexOf('.') + 1)))];
  const wild = new Set();
  await Promise.all(endings.map(async e => { try { if (((await doh(`wpl-${Math.random().toString(36).slice(2, 10)}.${e}`, 'A')).Answer || []).length) wild.add(e); } catch { /* skip */ } }));
  list = list.filter(x => !wild.has(x.slice(x.indexOf('.') + 1)));
  const found = {};
  await pool(list, 6, async x => {
    try {
      if ((await doh(x, 'NS')).Status !== 0) return;
      const mx = await doh(x, 'MX');
      found[x] = { mail: (mx.Answer || []).some(a => a.type === 15 && !/^0 \.$/.test(a.data)) };
    } catch { /* skip */ }
  });
  return { checked: list.length, found };
}

const domains = readFileSync(new URL('domains.txt', DIR), 'utf8').split('\n').map(l => l.trim().toLowerCase()).filter(l => l && !l.startsWith('#'));
const statePath = new URL('state.json', DIR), alertPath = new URL('alert.md', DIR);
const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, 'utf8')) : {};
const today = new Date().toISOString().slice(0, 10);
const alerts = [], summary = [];

for (const d of domains) {
  const { checked, found } = await check(d);
  const before = state[d]?.found || null;
  const fresh = before ? Object.keys(found).filter(x => !before[x]) : [];
  const nowMail = before ? Object.keys(found).filter(x => found[x].mail && before[x] && !before[x].mail) : [];
  for (const x of fresh) found[x].firstSeen = today;
  for (const x of Object.keys(found)) if (before?.[x]) found[x].firstSeen = before[x].firstSeen;
  // Certificates only for the new ones, to stay inside certspotter's free limit.
  for (const x of fresh) found[x].certs = await certCount(x);
  state[d] = { checkedAt: today, checked, found };
  const n = Object.keys(found).length;
  summary.push(`| ${d} | ${checked} | ${n} | ${Object.values(found).filter(f => f.mail).length} | ${before ? fresh.length : 'first run'} |`);
  if (fresh.length || nowMail.length) {
    alerts.push(`### ${d}\n\n${fresh.map(x => `- **${x}** registered${found[x].mail ? ', receives email' : ''}${found[x].certs ? `, ${found[x].certs} certificate(s) issued, so a website is live or about to be` : ''}`).join('\n')}${nowMail.length ? `\n${nowMail.map(x => `- **${x}** started receiving email`).join('\n')}` : ''}`);
  }
}

writeFileSync(statePath, JSON.stringify(state, null, 2) + '\n');
const table = `| Domain | Look-alikes checked | Registered | Take email | New today |\n|---|---|---|---|---|\n${summary.join('\n')}\n`;
process.stdout.write(table);
if (alerts.length) {
  writeFileSync(alertPath, `New look-alike domains found by the WebPawlice watch on ${today}.\n\n${alerts.join('\n\n')}\n\nCheck what each one shows. If it copies the client's site or logo, report it to the registrar's abuse contact and warn customers.\n`);
} else if (existsSync(alertPath)) rmSync(alertPath);
