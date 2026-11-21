// PROTOTYPE — WebPawlice passive checks. Throwaway code that answers one question:
// "how much true, striking information can we read about a business site from public sources alone?"
// Runs unchanged in the Chrome extension (host_permissions lift CORS) and in Node 18+ (cli.mjs).
// Every check here is passive: public DNS, public registries, Certificate Transparency, and one
// ordinary page visit. Active testing (scans, load, form probes) is deliberately absent: it needs
// the owner's written permission.

const UA_NOTE = 'WebPawlice-prototype';
const TWO_LEVEL_SUFFIXES = ['com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg', 'co.uk', 'org.uk', 'com.au', 'net.au', 'co.nz', 'com.my', 'co.id', 'com.ph', 'co.th', 'com.hk', 'co.in', 'co.jp'];
const AI_CRAWLERS = ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-SearchBot', 'PerplexityBot', 'Google-Extended', 'CCBot', 'Applebot-Extended'];

export function normalizeDomain(input) {
  return String(input || '').trim().toLowerCase()
    .replace(/^[a-z]+:\/\//, '').replace(/^www\./, '').replace(/[/?#].*$/, '').replace(/:\d+$/, '');
}

export function splitDomain(domain) {
  const suffix = TWO_LEVEL_SUFFIXES.find(s => domain.endsWith('.' + s)) || domain.split('.').slice(-1)[0];
  const rest = domain.slice(0, -(suffix.length + 1));
  const label = rest.split('.').pop();
  return { label, suffix, registrable: `${label}.${suffix}` };
}

// ---------- low-level sources ----------

async function getJson(url, opts = {}) {
  const ctl = new AbortController();
  const timer = setTimeout(() => ctl.abort(), opts.timeout || 15000);
  try {
    const res = await fetch(url, { headers: opts.headers || {}, method: opts.method || 'GET', signal: ctl.signal });
    if (!res.ok) throw new Error(`${res.status} from ${new URL(url).host}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// DNS over HTTPS. Cloudflare first, Google as fallback; both return the same JSON shape.
export async function doh(name, type) {
  const qs = `name=${encodeURIComponent(name)}&type=${type}`;
  try {
    return await getJson(`https://cloudflare-dns.com/dns-query?${qs}`, { headers: { accept: 'application/dns-json' }, timeout: 8000 });
  } catch {
    return getJson(`https://dns.google/resolve?${qs}`, { timeout: 8000 });
  }
}

const txtOf = r => (r.Answer || []).filter(a => a.type === 16).map(a => a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''));

// ---------- checks: each returns { id, area, name, status: good|warn|bad|info|skip, finding, evidence } ----------

const result = (id, area, name, status, finding, evidence = '') => ({ id, area, name, status, finding, evidence });

export async function checkEmailSpoofing(domain) {
  const [spfR, dmarcR, mxR, mtaR, bimiR] = await Promise.all([
    doh(domain, 'TXT'), doh(`_dmarc.${domain}`, 'TXT'), doh(domain, 'MX'),
    doh(`_mta-sts.${domain}`, 'TXT'), doh(`default._bimi.${domain}`, 'TXT'),
  ]);
  const spf = txtOf(spfR).find(t => t.startsWith('v=spf1'));
  const dmarc = txtOf(dmarcR).find(t => t.toLowerCase().startsWith('v=dmarc1'));
  const policy = dmarc && (dmarc.match(/;\s*p=(\w+)/i) || [])[1]?.toLowerCase();
  const hasMx = (mxR.Answer || []).some(a => a.type === 15);
  const out = [];
  if (!dmarc) {
    out.push(result('dmarc', 'safe', 'Email pretending to be you', 'bad', `Anyone can send email that looks like it comes from @${domain}. There is no DMARC record telling inboxes to reject it.`, `_dmarc.${domain} TXT: none`));
  } else if (policy === 'none') {
    out.push(result('dmarc', 'safe', 'Email pretending to be you', 'warn', 'A DMARC record exists but is set to monitor only (p=none), so fake email still reaches inboxes.', dmarc));
  } else {
    out.push(result('dmarc', 'safe', 'Email pretending to be you', 'good', `Inboxes are told to ${policy === 'reject' ? 'reject' : 'quarantine'} email that fakes your address.`, dmarc));
  }
  if (!spf) out.push(result('spf', 'safe', 'Approved senders list (SPF)', hasMx ? 'bad' : 'warn', 'No SPF record lists which servers may send your email.', `${domain} TXT: no v=spf1`));
  else if (/[?+]all\b/.test(spf)) out.push(result('spf', 'safe', 'Approved senders list (SPF)', 'bad', 'SPF ends in a permissive rule, so it lets any server send as you.', spf));
  else out.push(result('spf', 'safe', 'Approved senders list (SPF)', spf.includes('-all') ? 'good' : 'warn', spf.includes('-all') ? 'SPF is strict.' : 'SPF is soft (~all): unlisted senders are flagged, not blocked.', spf));
  out.push(result('mta-sts', 'safe', 'Email encrypted in transit (MTA-STS)', txtOf(mtaR).length ? 'good' : 'info', txtOf(mtaR).length ? 'Mail servers must use encryption to deliver to you.' : 'Not set up. Optional, but banks and governments use it.', txtOf(mtaR)[0] || ''));
  if (txtOf(bimiR).length) out.push(result('bimi', 'trust', 'Logo shown in inboxes (BIMI)', 'good', 'Your logo can appear next to your emails in Gmail and Apple Mail.', txtOf(bimiR)[0]));
  return out;
}

export async function checkDnsHygiene(domain) {
  const [caa, a] = await Promise.all([doh(domain, 'CAA'), doh(domain, 'A')]);
  const caaRecs = (caa.Answer || []).filter(x => x.type === 257);
  return [
    result('dnssec', 'safe', 'Signed address book (DNSSEC)', a.AD ? 'good' : 'info', a.AD ? 'Your domain answers are signed, so they cannot be silently forged.' : 'Domain answers are not signed. Common, but a gap attackers can use to redirect visitors.', `AD flag: ${Boolean(a.AD)}`),
    result('caa', 'safe', 'Who may issue your certificates (CAA)', caaRecs.length ? 'good' : 'warn', caaRecs.length ? `Only ${[...new Set(caaRecs.map(r => (r.data.match(/"([^"]+)"/) || [])[1]).filter(Boolean))].join(', ')} may issue certificates for you.` : 'Any certificate authority may issue a certificate for your name. One DNS line fixes this.', caaRecs.map(r => r.data).join(' | ')),
  ];
}

let rdapBootstrap;
// rdap.org refuses some clients (403 to Node's fetch), so resolve the registry ourselves from IANA's bootstrap file.
async function rdapUrl(domain) {
  rdapBootstrap ||= getJson('https://data.iana.org/rdap/dns.json', { timeout: 10000 });
  const { services } = await rdapBootstrap;
  const tld = domain.split('.').pop();
  const hit = services.find(([tlds]) => tlds.includes(tld));
  if (!hit) throw new Error(`no RDAP service for .${tld}`);
  return `${hit[1][0].replace(/\/?$/, '/')}domain/${domain}`;
}

export async function checkRegistration(domain) {
  try {
    const r = await getJson(await rdapUrl(domain), { timeout: 10000, headers: { accept: 'application/rdap+json' } });
    const ev = Object.fromEntries((r.events || []).map(e => [e.eventAction, e.eventDate]));
    const born = ev.registration && new Date(ev.registration);
    const dies = ev.expiration && new Date(ev.expiration);
    const out = [];
    if (born) {
      const years = (Date.now() - born) / 31557600000;
      out.push(result('age', 'trust', 'Domain age', years >= 3 ? 'good' : years >= 1 ? 'info' : 'warn', `Registered ${born.toISOString().slice(0, 10)}, ${years.toFixed(1)} years ago. Older domains are trusted more by inbox and search filters.`, `RDAP registration ${ev.registration}`));
    }
    if (dies) {
      const days = Math.round((dies - Date.now()) / 86400000);
      out.push(result('expiry', 'safe', 'Domain renewal', days < 30 ? 'bad' : days < 90 ? 'warn' : 'good', days < 0 ? 'The domain registration has expired.' : `Renews by ${dies.toISOString().slice(0, 10)} (${days} days). ${days < 90 ? 'Check auto-renew is on: a lapsed domain takes the site and email down.' : ''}`.trim(), `RDAP expiration ${ev.expiration}`));
    }
    return out.length ? out : [result('rdap', 'trust', 'Domain registration', 'skip', 'Registry did not publish dates.', '')];
  } catch (e) {
    return [result('rdap', 'trust', 'Domain registration', 'skip', 'This registry has no public RDAP service (for example .sg), so age and renewal date are not readable here.', String(e.message || e))];
  }
}

export async function checkCertificates(domain) {
  try {
    const rows = await getJson(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json&exclude=expired`, { timeout: 25000 });
    const now = Date.now();
    const recent = rows.filter(r => now - new Date(r.not_before + 'Z') < 90 * 86400000);
    const names = new Set(rows.flatMap(r => String(r.name_value).split('\n')));
    const issuers = [...new Set(recent.map(r => (r.issuer_name.match(/O=([^,]+)/) || [])[1]).filter(Boolean))];
    const soonest = rows.map(r => new Date(r.not_after + 'Z')).filter(d => d > now).sort((x, y) => x - y)[0];
    return [
      result('ct', 'safe', 'Certificates issued for your name', 'info', `${rows.length} live certificates cover ${names.size} names under ${domain}. ${recent.length} were issued in the last 90 days${issuers.length ? ` by ${issuers.join(', ')}` : ''}. Any you do not recognise is worth a look.`, `crt.sh, ${rows.length} rows`),
      ...(soonest ? [result('cert-expiry', 'safe', 'Next certificate expiry', (soonest - now) / 86400000 < 14 ? 'warn' : 'good', `Next one expires ${soonest.toISOString().slice(0, 10)}.`, '')] : []),
      result('subdomains', 'safe', 'Public subdomains', names.size > 25 ? 'warn' : 'info', `Certificate logs reveal ${names.size} host names, e.g. ${[...names].filter(n => !n.startsWith('*')).slice(0, 6).join(', ')}. Forgotten ones (old staging, test) are a common way in.`, ''),
    ];
  } catch {
    // crt.sh is often slow or 502s; certspotter is the steadier second source (100 req/h free).
    try {
      const rows = await getJson(`https://api.certspotter.com/v1/issuances?domain=${domain}&include_subdomains=true&expand=dns_names`, { timeout: 15000 });
      const names = new Set(rows.flatMap(r => r.dns_names || []));
      return [result('ct', 'safe', 'Certificates issued for your name', 'info', `${rows.length} live certificates cover ${names.size} names under ${domain}, e.g. ${[...names].filter(n => !n.startsWith('*')).slice(0, 6).join(', ')}.`, 'certspotter')];
    } catch (e) {
      return [result('ct', 'safe', 'Certificates issued for your name', 'skip', 'Certificate Transparency logs (crt.sh, certspotter) did not answer in time. Try again.', String(e.message || e))];
    }
  }
}

// Mozilla's own grade for browser protections. Must be a plain POST with no custom headers (v2 rejects preflights).
export async function checkObservatory(domain) {
  try {
    const r = await getJson(`https://observatory-api.mdn.mozilla.net/api/v2/scan?host=${domain}`, { method: 'POST', timeout: 30000 });
    if (!r.grade) throw new Error(r.error || 'no grade');
    const g = r.grade[0];
    return [result('observatory', 'safe', 'Mozilla security grade', g === 'A' ? 'good' : g === 'B' || g === 'C' ? 'warn' : 'bad', `Mozilla Observatory grades the site ${r.grade} (${r.score}/100), passing ${r.tests_passed} of ${r.tests_quantity} tests.`, r.details_url || '')];
  } catch (e) {
    return [result('observatory', 'safe', 'Mozilla security grade', 'skip', 'Mozilla Observatory did not answer.', String(e.message || e))];
  }
}

// Tranco: research-grade top-sites list, a free popularity signal (replaces OpenPageRank, which now needs a key).
export async function checkPopularity(domain) {
  try {
    const r = await getJson(`https://tranco-list.eu/api/ranks/domain/${domain}`, { timeout: 8000 });
    const best = (r.ranks || []).map(x => x.rank).sort((a, b) => a - b)[0];
    return [result('rank', 'trust', 'How well-known the site is', 'info', best ? `Ranked #${best.toLocaleString()} among the world's top million sites (Tranco).` : 'Not in the world top million (normal for a local business).', '')];
  } catch {
    return [];
  }
}

export function lookalikes(domain) {
  const { label: n, suffix } = splitDomain(domain);
  const tld = '.' + suffix;
  const out = new Set();
  const add = d => { if (d !== domain && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && !d.startsWith('-')) out.add(d); };
  const swap = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], m: ['rn'], g: ['q'], b: ['d'], d: ['b'], u: ['v'], w: ['vv'] };
  for (let i = 0; i < n.length; i++) {
    add(n.slice(0, i) + n.slice(i + 1) + tld); // omission
    add(n.slice(0, i) + n[i] + n[i] + n.slice(i + 1) + tld); // repetition
    if (i < n.length - 1) add(n.slice(0, i) + n[i + 1] + n[i] + n.slice(i + 2) + tld); // transposition
    for (const s of swap[n[i]] || []) add(n.slice(0, i) + s + n.slice(i + 1) + tld); // homoglyph
    if (i > 0) add(n.slice(0, i) + '-' + n.slice(i) + tld); // hyphenation
  }
  for (const t of ['.com', '.net', '.co', '.sg', '.com.sg', '.org', '.online', '.shop', '.store', '.site', '.info', '.app']) add(n + t);
  for (const w of ['login', 'secure', 'pay', 'promo', 'sg', 'official', 'support', 'shop']) { add(`${n}-${w}${tld}`); add(`${w}-${n}${tld}`); add(`${n}${w}${tld}`); }
  return [...out];
}

async function pool(items, size, fn) {
  const out = [];
  let i = 0;
  await Promise.all(Array.from({ length: size }, async () => {
    while (i < items.length) { const k = i++; out[k] = await fn(items[k]); }
  }));
  return out;
}

// Real, live: resolves every look-alike over DoH. NOERROR with NS = registered; NXDOMAIN = free.
export async function checkLookalikes(domain, { limit = 80, onProgress } = {}) {
  const cands = lookalikes(domain).slice(0, limit);
  let done = 0;
  const rows = await pool(cands, 8, async d => {
    try {
      const ns = await doh(d, 'NS');
      const registered = ns.Status === 0;
      let live = false, mail = false;
      if (registered) {
        const [a, mx] = await Promise.all([doh(d, 'A'), doh(d, 'MX')]);
        live = (a.Answer || []).some(x => x.type === 1);
        mail = (mx.Answer || []).some(x => x.type === 15 && !/^0 \.$/.test(x.data));
      }
      return { d, registered, live, mail };
    } catch {
      return { d, registered: null };
    } finally {
      onProgress?.(++done, cands.length);
    }
  });
  const reg = rows.filter(r => r.registered);
  const mail = reg.filter(r => r.mail);
  const status = mail.length ? 'bad' : reg.length ? 'warn' : 'good';
  return [
    result('lookalikes', 'safe', 'Look-alike addresses', status,
      `${cands.length} addresses could pass for ${domain}. ${reg.length} are registered by someone${reg.length ? `: ${reg.slice(0, 6).map(r => r.d).join(', ')}${reg.length > 6 ? '…' : ''}` : ''}. ${mail.length ? `${mail.length} can receive email, so they could be used to trick your customers by email.` : ''}`.trim(),
      JSON.stringify(reg)),
  ];
}

// One ordinary visit to the homepage. In a plain web page CORS hides headers; in the extension and Node they are readable.
export async function checkHomepage(domain) {
  const out = [];
  let res, html = '';
  try {
    res = await fetch(`https://${domain}/`, { redirect: 'follow' });
    html = (await res.text()).slice(0, 600000);
  } catch (e) {
    return [result('reach', 'works', 'Site reachable over HTTPS', 'bad', `The homepage did not load over HTTPS: ${e.message || e}.`, '')];
  }
  const h = n => res.headers.get(n);
  out.push(result('reach', 'works', 'Site reachable over HTTPS', res.ok ? 'good' : 'bad', res.ok ? `Loads over HTTPS (final address ${res.url}).` : `Homepage answered ${res.status}.`, `HTTP ${res.status}`));
  try {
    const plain = await fetch(`http://${domain}/`, { redirect: 'manual' });
    const redirects = plain.type === 'opaqueredirect' || (plain.status >= 300 && plain.status < 400 && /^https:/.test(plain.headers.get('location') || ''));
    out.push(result('https-redirect', 'safe', 'Old http:// links upgrade to https', redirects ? 'good' : 'warn', redirects ? 'Visitors typing http:// are sent to the secure version.' : 'The http:// address does not redirect to https://.', ''));
  } catch { /* http blocked entirely is fine */ }
  const sec = {
    'strict-transport-security': 'Forces secure connections (HSTS)',
    'content-security-policy': 'Blocks injected scripts (CSP)',
    'x-content-type-options': 'Stops file-type tricks',
    'referrer-policy': 'Limits what leaks to other sites',
  };
  const missing = Object.keys(sec).filter(k => !h(k));
  const frame = h('x-frame-options') || /frame-ancestors/i.test(h('content-security-policy') || '');
  if (!frame) missing.push('x-frame-options');
  out.push(result('headers', 'safe', 'Browser protection headers', missing.length === 0 ? 'good' : missing.length <= 2 ? 'warn' : 'bad',
    missing.length ? `${5 - missing.length} of 5 protections are on. Missing: ${missing.join(', ')}.` : 'All five standard protections are on.', missing.join(',')));
  const server = [h('server'), h('x-powered-by')].filter(Boolean).join(' / ');
  const gen = (html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i) || [])[1];
  const disclosed = [server, gen].filter(s => s && /\d/.test(s));
  out.push(result('disclosure', 'safe', 'What your site reveals', disclosed.length ? 'warn' : 'good', disclosed.length ? `The site announces its software and version: ${disclosed.join('; ')}. Attackers search for exactly this.` : 'No software versions announced.', server));
  const title = (html.match(/<title[^>]*>([^<]*)/i) || [])[1]?.trim();
  const desc = (html.match(/<meta[^>]+name=["']description["'][^>]+content=["']([^"']*)/i) || [])[1];
  out.push(result('title', 'found', 'Search result title and description', title && desc ? 'good' : 'warn', `${title ? `Title: "${title.slice(0, 80)}".` : 'No page title.'} ${desc ? 'Has a description.' : 'No description, so Google and AI assistants write their own.'}`, ''));
  const ld = [...html.matchAll(/<script[^>]+application\/ld\+json[^>]*>([\s\S]*?)<\/script>/gi)].map(m => m[1]);
  const types = [...new Set(ld.flatMap(j => [...j.matchAll(/"@type"\s*:\s*"([^"]+)"/g)].map(m => m[1])))];
  out.push(result('schema', 'found', 'Facts machines can read (schema.org)', types.length ? 'good' : 'warn', types.length ? `Publishes structured facts: ${types.slice(0, 6).join(', ')}.` : 'No structured facts (opening hours, address, prices). AI assistants and Google have to guess them.', ''));
  const years = [...html.matchAll(/(?:©|&copy;|copyright)\s*(?:\d{4}\s*[-–]\s*)?(\d{4})/gi)].map(m => +m[1]);
  const yr = years.length ? Math.max(...years) : null;
  const thisYear = new Date().getFullYear();
  if (yr) out.push(result('freshness', 'trust', 'Looks looked-after', yr >= thisYear - 1 ? 'good' : 'warn', yr >= thisYear - 1 ? `Footer year ${yr}.` : `Footer still says © ${yr}. Visitors read that as an abandoned site.`, ''));
  return out;
}

export async function checkAiReadiness(domain) {
  const out = [];
  let robots = '';
  try { const r = await fetch(`https://${domain}/robots.txt`); robots = r.ok ? await r.text() : ''; } catch { /* none */ }
  const blocked = AI_CRAWLERS.filter(bot => {
    const re = new RegExp(`user-agent:\\s*${bot}\\s*\\n(?:[^\\n]*\\n)*?\\s*disallow:\\s*/\\s*(\\n|$)`, 'i');
    return re.test(robots);
  });
  const allBlocked = /user-agent:\s*\*\s*\n(?:(?!user-agent)[^\n]*\n)*?\s*disallow:\s*\/\s*(\n|$)/i.test(robots);
  out.push(result('ai-crawlers', 'found', 'AI assistants allowed to read you', allBlocked || blocked.length >= 3 ? 'bad' : blocked.length ? 'warn' : 'good',
    allBlocked ? 'robots.txt blocks every crawler, AI assistants included.' : blocked.length ? `robots.txt blocks ${blocked.join(', ')}. Those assistants cannot read your site when customers ask about you.` : 'No AI crawler is blocked.', blocked.join(',')));
  let llms = false;
  try { const r = await fetch(`https://${domain}/llms.txt`); llms = r.ok && !/<html/i.test((await r.text()).slice(0, 300)); } catch { /* none */ }
  out.push(result('llms-txt', 'found', 'Summary file for AI (llms.txt)', llms ? 'good' : 'info', llms ? 'Publishes an llms.txt summary for AI assistants.' : 'No llms.txt. A short plain-text summary helps assistants describe you correctly.', ''));
  const sitemap = /sitemap:/i.test(robots);
  out.push(result('sitemap', 'found', 'Sitemap announced', sitemap ? 'good' : 'warn', sitemap ? 'robots.txt points search engines to a sitemap.' : 'robots.txt does not point to a sitemap.', ''));
  return out;
}

export async function checkHistory(domain) {
  try {
    const rows = await getJson(`https://web.archive.org/cdx/search/cdx?url=${domain}&output=json&limit=1&fl=timestamp`, { timeout: 12000 });
    const ts = rows[1]?.[0];
    if (!ts) return [result('archive', 'trust', 'First seen on the web', 'info', 'The Internet Archive has no copy of this site.', '')];
    const d = `${ts.slice(0, 4)}-${ts.slice(4, 6)}-${ts.slice(6, 8)}`;
    return [result('archive', 'trust', 'First seen on the web', 'info', `The Internet Archive first saved this site on ${d}.`, `https://web.archive.org/web/${ts}/${domain}`)];
  } catch {
    return [result('archive', 'trust', 'First seen on the web', 'skip', 'Internet Archive did not answer in time.', '')];
  }
}

// Optional, slow (~20-40 s) and rate-limited without a key.
export async function checkPageSpeed(domain, key = '') {
  const cats = ['performance', 'accessibility', 'seo', 'best-practices'].map(c => `category=${c}`).join('&');
  const url = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent('https://' + domain + '/')}&strategy=mobile&${cats}${key ? `&key=${key}` : ''}`;
  try {
    const r = await getJson(url, { timeout: 70000 });
    const c = r.lighthouseResult.categories;
    const s = k => Math.round((c[k]?.score || 0) * 100);
    const lcp = r.lighthouseResult.audits['largest-contentful-paint']?.displayValue;
    return [
      result('speed', 'works', 'Speed on a phone', s('performance') >= 90 ? 'good' : s('performance') >= 50 ? 'warn' : 'bad', `Lighthouse performance ${s('performance')}/100. Main content appears in ${lcp}. Under 2.5 s is good.`, ''),
      result('a11y', 'works', 'Usable by everyone (accessibility)', s('accessibility') >= 90 ? 'good' : 'warn', `Lighthouse accessibility ${s('accessibility')}/100.`, ''),
      result('seo-basics', 'found', 'Search basics', s('seo') >= 90 ? 'good' : 'warn', `Lighthouse SEO ${s('seo')}/100.`, ''),
    ];
  } catch (e) {
    return [result('speed', 'works', 'Speed on a phone', 'skip', 'PageSpeed Insights quota reached or timed out. Add a free API key in options.', String(e.message || e))];
  }
}

// ---------- scoring ----------

const WEIGHT = { good: 1, info: 0.8, warn: 0.5, bad: 0 };
export const AREAS = { safe: 'Are you safe?', trust: 'Are you trusted?', found: 'Are you found?', works: 'Does your site work?' };

export function score(results) {
  const areas = {};
  for (const k of Object.keys(AREAS)) {
    const rs = results.filter(r => r.area === k && r.status in WEIGHT);
    areas[k] = rs.length ? Math.round(100 * rs.reduce((s, r) => s + WEIGHT[r.status], 0) / rs.length) : null;
  }
  const vals = Object.values(areas).filter(v => v !== null);
  return { areas, overall: vals.length ? Math.round(vals.reduce((a, b) => a + b, 0) / vals.length) : null };
}

export async function scan(input, { pagespeed = false, psiKey = '', onStep } = {}) {
  const domain = splitDomain(normalizeDomain(input)).registrable;
  const steps = [
    ['Reading public DNS records', () => checkEmailSpoofing(domain)],
    ['Checking DNS hygiene', () => checkDnsHygiene(domain)],
    ['Reading the domain registry', () => checkRegistration(domain)],
    ['Reading certificate logs', () => checkCertificates(domain)],
    ['Asking Mozilla Observatory', () => checkObservatory(domain)],
    ['Checking popularity rank', () => checkPopularity(domain)],
    ['Visiting the homepage once', () => checkHomepage(domain)],
    ['Checking what AI assistants can read', () => checkAiReadiness(domain)],
    ['Looking up the Internet Archive', () => checkHistory(domain)],
    ['Resolving look-alike addresses', () => checkLookalikes(domain, { onProgress: (d, t) => onStep?.(`Resolving look-alike addresses ${d}/${t}`) })],
    ...(pagespeed ? [['Running Lighthouse on a phone', () => checkPageSpeed(domain, psiKey)]] : []),
  ];
  const results = [];
  await Promise.all(steps.map(async ([label, fn]) => {
    onStep?.(label);
    try { results.push(...await fn()); } catch (e) { results.push(result(label, 'safe', label, 'skip', `Could not run: ${e.message || e}`, '')); }
  }));
  return { tool: UA_NOTE, domain, scannedAt: new Date().toISOString(), ...score(results), results };
}
