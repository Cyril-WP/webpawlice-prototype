/*!
 * WebPawlice embed — PROTOTYPE by Webpuppies. Throwaway code.
 *
 *   <script src="https://cyril-wp.github.io/webpawlice-prototype/embed/webpawlice.js" defer></script>
 *
 * Visitors see nothing and nothing runs for them. The owner opens their own site with
 * ?webpawlice (or #webpawlice) and a check-up panel appears with four views:
 *   Risks         security and trust findings, ranked critical / high / medium / low
 *   Launch guard  walks the site like a visitor: broken pages and images, staging leftovers, placeholder text
 *   Facts         phone, hours, prices, address and reviews as the site states them, and where pages disagree
 *   Compare       the public-record checks side by side with up to three competitors
 *
 * Options (attributes on the script tag):
 *   data-show="always"           show the paw button to everyone (demos only)
 *   data-domain="x.sg"           check another domain's public records (site checks then stay off)
 *   data-root="/"                where the site lives, if not at the domain root
 *   data-competitors="a.sg,b.sg" pre-fill the Compare view
 *   data-position="left"         put the button bottom-left
 *   data-open="true"             open the panel straight away
 * URL: ?webpawlice=other.sg checks another domain; &compare=a.sg,b.sg pre-fills Compare.
 *
 * Sources: public DNS (Cloudflare, Google), registry RDAP, certificate logs (certspotter), Mozilla
 * Observatory, Shodan InternetDB (open ports; free for non-commercial use, a paid key for commercial),
 * OSV.dev (known flaws in libraries), WordPress.org, endoflife.date, Tranco, Internet Archive.
 * On the owner's own site it also reads its pages and asks for a dozen commonly leaked file paths.
 * It never submits forms, never logs in and never sends load.
 */
(function () {
  'use strict';
  if (window.__webpawlice) return;
  window.__webpawlice = true;

  var script = document.currentScript || {};
  var ds = script.dataset || {};
  var triggered = /[?&#]webpawlice\b/.test(location.search + location.hash);
  if (ds.show !== 'always' && !triggered) return;

  var TWO = ['com.sg', 'net.sg', 'org.sg', 'edu.sg', 'gov.sg', 'per.sg', 'co.uk', 'org.uk', 'com.au', 'net.au', 'co.nz', 'com.my', 'co.id', 'com.ph', 'co.th', 'com.hk', 'co.in', 'co.jp', 'github.io', 'netlify.app', 'vercel.app', 'pages.dev'];
  var AI_BOTS = ['GPTBot', 'OAI-SearchBot', 'ChatGPT-User', 'ClaudeBot', 'Claude-SearchBot', 'PerplexityBot', 'Google-Extended', 'CCBot', 'Applebot-Extended'];
  var SEV = { critical: 0, high: 1, medium: 2, low: 3 };
  var SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };
  var PENALTY = { critical: 40, high: 20, medium: 8, low: 2 };
  var OTHER_AREAS = { found: 'Findability', works: 'Works for visitors', trust: 'Trust' };
  var ORDER = { bad: 0, warn: 1, info: 2, good: 3, skip: 4 };
  var LABEL = { good: 'Fine', warn: 'Improve', bad: 'Fix', info: 'Note', skip: 'Not run' };
  var CACHE_MS = 12 * 3600 * 1000;

  function registrable(host) {
    host = String(host).toLowerCase().replace(/^www\./, '').replace(/:\d+$/, '');
    var suffix = TWO.find(function (s) { return host === s || host.endsWith('.' + s); }) || host.split('.').slice(-1)[0];
    if (host === suffix) return host;
    var rest = host.slice(0, -(suffix.length + 1));
    return rest.split('.').pop() + '.' + suffix;
  }
  function cleanDomain(s) { return String(s || '').trim().toLowerCase().replace(/^[a-z]+:\/\//, '').replace(/^www\./, '').replace(/[/?#:].*$/, ''); }

  var here = registrable(location.hostname);
  var asked = (location.search.match(/[?&]webpawlice=([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
  var domain = asked ? registrable(asked) : ds.domain ? registrable(ds.domain) : here;
  var onSite = domain === here && /^https?:$/.test(location.protocol);
  var ROOT = new URL(ds.root || '/', location.href);
  var at = function (p) { return new URL(p, ROOT).href; };
  var compareAsked = ((location.search.match(/[?&]compare=([a-z0-9.,-]+)/i) || [])[1] || ds.competitors || '').split(',').map(cleanDomain).filter(Boolean).slice(0, 3);

  // ---------------- sources ----------------
  function getJson(url, opts) {
    opts = opts || {};
    var ctl = new AbortController();
    var t = setTimeout(function () { ctl.abort(); }, opts.timeout || 15000);
    return fetch(url, { method: opts.method || 'GET', headers: opts.headers || {}, body: opts.body, signal: ctl.signal, credentials: 'omit' })
      .then(function (r) { if (!r.ok) throw new Error(r.status + ' from ' + new URL(url).host); return r.json(); })
      .finally(function () { clearTimeout(t); });
  }
  function doh(name, type) {
    var qs = 'name=' + encodeURIComponent(name) + '&type=' + type;
    return getJson('https://cloudflare-dns.com/dns-query?' + qs, { headers: { accept: 'application/dns-json' }, timeout: 8000 })
      .catch(function () { return getJson('https://dns.google/resolve?' + qs, { timeout: 8000 }); });
  }
  function txt(r) { return (r.Answer || []).filter(function (a) { return a.type === 16; }).map(function (a) { return a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''); }); }

  // Reads a URL on the owner's own site. Redirects count as "not there" unless follow is set.
  async function peek(url, o) {
    o = o || {};
    try {
      var res = await fetch(url, { credentials: 'omit', cache: 'no-store', redirect: o.follow ? 'follow' : 'manual', method: o.method || 'GET' });
      var out = { status: res.status, ok: res.ok, type: res.headers.get('content-type') || '', headers: res.headers, url: res.url, text: '' };
      if (!res.ok || o.method === 'HEAD' || !res.body) return out;
      var reader = res.body.getReader(), dec = new TextDecoder(), t = '', max = o.n || 4096;
      while (t.length < max) { var c = await reader.read(); if (c.done) break; t += dec.decode(c.value, { stream: true }); }
      reader.cancel().catch(function () { /* done */ });
      out.text = t.slice(0, max);
      return out;
    } catch (e) { return { status: 0, ok: false, type: '', text: '', error: true }; }
  }
  async function pool(items, n, fn) {
    var i = 0;
    async function w() { while (i < items.length) { var k = i++; await fn(items[k], k); } }
    await Promise.all(Array.from({ length: Math.min(n, items.length) }, w));
  }

  // ---------------- result shapes ----------------
  // Security findings carry a risk level, why it matters and the fix. Other areas keep a simple status.
  function risk(id, name, level, finding, why, fix, v) { return { id: id, area: 'security', name: name, status: 'risk', risk: level, finding: finding, why: why || '', fix: fix || '', v: v }; }
  function ok(id, name, finding, v) { return { id: id, area: 'security', name: name, status: 'good', finding: finding, v: v }; }
  function note(id, name, finding, v) { return { id: id, area: 'security', name: name, status: 'info', finding: finding, v: v }; }
  function na(id, name, finding) { return { id: id, area: 'security', name: name, status: 'skip', finding: finding }; }
  function R(id, area, name, status, finding, v) { return { id: id, area: area, name: name, status: status, finding: finding, v: v }; }

  // ---------------- public-record checks (work for any domain) ----------------
  async function email(d) {
    var r = await Promise.all([doh(d, 'TXT'), doh('_dmarc.' + d, 'TXT'), doh(d, 'MX'), doh('_mta-sts.' + d, 'TXT')]);
    var spf = txt(r[0]).find(function (t) { return t.indexOf('v=spf1') === 0; });
    var dmarc = txt(r[1]).find(function (t) { return /^v=dmarc1/i.test(t); });
    var policy = dmarc ? ((dmarc.match(/;\s*p=(\w+)/i) || [])[1] || 'none').toLowerCase() : 'missing';
    var mx = (r[2].Answer || []).some(function (a) { return a.type === 15 && !/^0 \.$/.test(a.data); });
    var out = [], N = 'Fake email in your name', S = 'Approved email senders (SPF)';
    var loose = spf && (spf.match(/[?+]all\b/) || [])[0];
    if (loose) out.push(risk('spf', S, 'critical', 'SPF ends in "' + loose + '", which approves every server on the internet to send as @' + d + '.', 'Fake invoices sent "from" you pass the inbox checks meant to stop them.', 'Change the end of the SPF record to ~all or -all.', loose));
    if (policy === 'missing') out.push(risk('dmarc', N, mx ? 'high' : 'medium', 'No DMARC record. Inboxes are not told to reject email that pretends to come from @' + d + '.', mx ? 'Fake invoices and password-reset emails in your name reach customers\' inboxes.' : 'You send no email from this domain, but scammers can still use it as the sender.', mx ? 'Add a DMARC record at p=quarantine, then move to p=reject.' : 'Publish "v=DMARC1; p=reject" and an SPF record of "v=spf1 -all".', 'none set'));
    else if (policy === 'none') out.push(risk('dmarc', N, 'medium', 'DMARC is monitor-only (p=none), so fake email still reaches inboxes.', 'You receive reports about spoofing, but nothing stops it.', 'Move DMARC to p=quarantine, then p=reject.', 'monitor only'));
    else out.push(ok('dmarc', N, 'Inboxes are told to ' + (policy === 'reject' ? 'reject' : 'quarantine') + ' email that fakes @' + d + '.', policy));
    if (!spf) { if (mx) out.push(risk('spf', S, 'medium', 'No SPF record lists which servers may send your email.', 'Your real email lands in spam more often, and fakes are harder to tell apart.', 'Publish an SPF record that lists your mail provider.', 'missing')); else out.push(note('spf', S, 'No SPF record, and the domain receives no email.', 'missing')); }
    else if (!loose) out.push(ok('spf', S, spf.indexOf('-all') > -1 ? 'SPF is strict (-all).' : 'SPF is set (~all).', spf.indexOf('-all') > -1 ? 'strict' : 'soft'));
    out.push(txt(r[3]).length ? ok('mta-sts', 'Email encrypted in transit (MTA-STS)', 'MTA-STS is on.', 'on') : note('mta-sts', 'Email encrypted in transit (MTA-STS)', 'MTA-STS is not set up. Optional; banks and government agencies use it.', 'off'));
    return out;
  }

  async function dnsHygiene(d) {
    var r = await Promise.all([doh(d, 'CAA'), doh(d, 'A')]);
    var caa = (r[0].Answer || []).filter(function (x) { return x.type === 257; });
    return [
      r[1].AD ? ok('dnssec', 'Signed DNS (DNSSEC)', 'DNS answers are signed, so they cannot be silently forged.', 'yes') : risk('dnssec', 'Signed DNS (DNSSEC)', 'low', 'DNS answers are not signed.', 'Rare, but a forged DNS answer can send visitors to a fake copy of the site.', 'Turn on DNSSEC at the registrar or DNS host; most do it with one switch.', 'no'),
      caa.length ? ok('caa', 'Who may issue certificates (CAA)', 'Only named certificate authorities may issue certificates for ' + d + '.', 'yes') : risk('caa', 'Who may issue certificates (CAA)', 'low', 'Any certificate authority may issue a certificate for ' + d + '.', 'Makes a mis-issued certificate for your name easier.', 'Add one CAA record naming your certificate provider, e.g. letsencrypt.org.', 'no'),
    ];
  }

  async function registry(d) {
    try {
      var boot = await getJson('https://data.iana.org/rdap/dns.json', { timeout: 10000 });
      var tld = d.split('.').pop();
      var hit = boot.services.find(function (s) { return s[0].indexOf(tld) > -1; });
      if (!hit) throw new Error('none');
      var r = await getJson(hit[1][0].replace(/\/?$/, '/') + 'domain/' + d, { timeout: 10000, headers: { accept: 'application/rdap+json' } });
      var ev = {}; (r.events || []).forEach(function (e) { ev[e.eventAction] = e.eventDate; });
      var out = [];
      if (ev.registration) {
        var yrs = (Date.now() - new Date(ev.registration)) / 31557600000;
        out.push(R('age', 'trust', 'Domain age', yrs >= 3 ? 'good' : yrs >= 1 ? 'info' : 'warn', 'Registered ' + ev.registration.slice(0, 10) + ', ' + yrs.toFixed(1) + ' years ago.', Math.floor(yrs) + ' yrs'));
      }
      if (ev.expiration) {
        var days = Math.round((new Date(ev.expiration) - Date.now()) / 86400000);
        var lvl = days < 14 ? 'critical' : days < 30 ? 'high' : days < 60 ? 'medium' : null;
        out.push(lvl ? risk('expiry', 'Domain renewal', lvl, 'The domain expires on ' + ev.expiration.slice(0, 10) + ', in ' + days + ' days.', 'If it lapses, the site and email stop, and anyone can buy the name.', 'Renew now and turn on auto-renew with a card that will not expire.', days + ' days') : ok('expiry', 'Domain renewal', 'Paid up until ' + ev.expiration.slice(0, 10) + ' (' + days + ' days).', days + ' days'));
      }
      var st = (r.status || []).join(' ').toLowerCase();
      if (st) out.push(/transfer prohibited/.test(st) ? ok('lock', 'Domain transfer lock', 'The domain is locked against transfer to another registrar.', 'on') : risk('lock', 'Domain transfer lock', 'medium', 'The domain is not locked against transfer.', 'A hijacked registrar login is enough to move the domain away.', 'Turn on "transfer lock" at the registrar.', 'off'));
      return out;
    } catch (e) {
      return [R('rdap', 'trust', 'Domain registration', 'skip', 'The .' + d.split('.').pop() + ' registry publishes no public registration dates, so age and renewal are not readable here.')];
    }
  }

  async function certs(d) {
    var rows;
    try { rows = await getJson('https://api.certspotter.com/v1/issuances?domain=' + d + '&include_subdomains=true&expand=dns_names', { timeout: 15000 }); }
    catch (e) { return [na('subdomains', 'Forgotten subdomains', 'The certificate log did not answer (free limit is 100 lookups an hour).')]; }
    var names = {}; rows.forEach(function (r) { (r.dns_names || []).forEach(function (n) { if (n.charAt(0) !== '*' && n !== d) names[n.toLowerCase()] = 1; }); });
    var list = Object.keys(names).slice(0, 40), dangling = [];
    await pool(list, 6, async function (n) {
      try {
        var a = await doh(n, 'A');
        var cn = (a.Answer || []).filter(function (x) { return x.type === 5; });
        if (a.Status === 3 && cn.length) dangling.push(n + ' → ' + cn[cn.length - 1].data.replace(/\.$/, ''));
      } catch (e) { /* skip */ }
    });
    if (dangling.length) return [risk('subdomains', 'Forgotten subdomains', 'high', dangling.length + ' subdomain' + (dangling.length > 1 ? 's point' : ' points') + ' at a service that no longer exists: ' + dangling.slice(0, 3).join(', ') + '.', 'Whoever claims that service name controls a page on your domain, with a valid certificate. Used for phishing and cookie theft.', 'Delete the DNS record for each one, or point it somewhere you control.', dangling.length)];
    return [ok('subdomains', 'Forgotten subdomains', rows.length ? 'Checked ' + list.length + ' subdomains from public certificate logs; none points at a service that is gone.' : 'No certificates in public logs name subdomains of ' + d + '.', 0)];
  }

  async function observatory(host) {
    try {
      // Must stay a "simple" POST: Observatory v2 rejects preflighted requests.
      var res = await fetch('https://observatory-api.mdn.mozilla.net/api/v2/scan?host=' + host, { method: 'POST', credentials: 'omit' });
      var r = await res.json();
      if (!r.grade) return [na('observatory', 'Mozilla security grade', 'Mozilla Observatory could not grade the site: ' + String(r.message || r.error || res.status).replace(/\.$/, '') + '.')];
      var g = r.grade[0], f = 'Mozilla Observatory grades the site ' + r.grade + ' (' + r.score + '/100), ' + r.tests_passed + ' of ' + r.tests_quantity + ' tests passed.';
      if (g === 'A' || g === 'B') return [ok('observatory', 'Mozilla security grade', f, r.grade)];
      return [risk('observatory', 'Mozilla security grade', g === 'C' ? 'low' : 'medium', f, 'The grade sums up the browser protections listed below; low grades mean easier script injection and clickjacking.', 'Add the missing security headers; most hosts set them in one config file.', r.grade)];
    } catch (e) { return [na('observatory', 'Mozilla security grade', 'Mozilla Observatory did not answer.')]; }
  }

  var DB_PORTS = { 3306: 'MySQL', 5432: 'PostgreSQL', 1433: 'SQL Server', 27017: 'MongoDB', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 5984: 'CouchDB' };
  var ADMIN_PORTS = { 21: 'FTP', 23: 'Telnet', 3389: 'Remote Desktop', 5900: 'VNC', 2082: 'cPanel', 2083: 'cPanel', 2086: 'WHM', 2087: 'WHM', 8443: 'Plesk', 10000: 'Webmin' };
  async function exposedServices(host) {
    var N = 'Exposed services';
    var a = await doh(host, 'A');
    var ip = ((a.Answer || []).filter(function (x) { return x.type === 1; })[0] || {}).data;
    if (!ip) return [na('ports', N, 'The site has no IPv4 address to look up.')];
    var r;
    try { r = await getJson('https://internetdb.shodan.io/' + ip, { timeout: 10000 }); }
    catch (e) { return /^404/.test(e.message) ? [ok('ports', N, 'Public internet scans list no open services on ' + ip + '.', 'none listed')] : [na('ports', N, 'Shodan InternetDB did not answer.')]; }
    var ports = r.ports || [], shared = (r.tags || []).indexOf('cdn') > -1 || /cloudflare|fastly|akamai|cloudfront|varnish/i.test((r.cpes || []).join(' ')) || (r.hostnames || []).length > 4;
    var db = ports.filter(function (p) { return DB_PORTS[p]; }), adm = ports.filter(function (p) { return ADMIN_PORTS[p]; }), out = [];
    var label = function (list, map) { return list.map(function (p) { return map[p] + ' (' + p + ')'; }).join(', '); };
    if (db.length) out.push(risk('ports-db', 'Database open to the internet', 'critical', 'Public scans see ' + label(db, DB_PORTS) + ' answering on ' + ip + '.', 'Databases facing the internet are found by bots within hours and are the most common source of customer-data leaks.', 'Close the port in the server firewall so only the web server can reach the database.', db.length));
    if (adm.length) out.push(risk('ports-admin', 'Admin access open to the internet', 'high', 'Public scans see ' + label(adm, ADMIN_PORTS) + ' answering on ' + ip + '.', 'Login pages for server control panels and file transfer are attacked with stolen and guessed passwords all day.', 'Limit these ports to your office IP or a VPN, and turn off FTP in favour of SFTP.', adm.length));
    var vulns = r.vulns || [];
    if (vulns.length && !shared) out.push(risk('ports-cve', 'Server software with known flaws', 'high', 'Public scans match ' + vulns.length + ' published vulnerabilities to the software versions seen on ' + ip + ', e.g. ' + vulns.slice(0, 3).join(', ') + '. Matched by version number, not confirmed.', 'Attack tools search for exactly these version numbers.', 'Ask the host to update the server software, or move to managed hosting.', vulns.length));
    if (!out.length) out.push(shared ? note('ports', N, 'The site sits behind a shared network (' + ((r.cpes || [])[0] || 'CDN').replace(/^cpe:\/a:/, '').split(':')[0] + '), so the server behind it is not visible to scans.', 'CDN') : ok('ports', N, 'Only ' + (ports.join(', ') || 'no') + ' ports answer on ' + ip + '. No databases or admin panels exposed.', ports.join(', ')));
    return out;
  }

  async function rank(d) {
    try {
      var r = await getJson('https://tranco-list.eu/api/ranks/domain/' + d, { timeout: 8000 });
      var best = (r.ranks || []).map(function (x) { return x.rank; }).sort(function (a, b) { return a - b; })[0];
      return [R('rank', 'trust', 'How well-known', 'info', best ? 'Ranked #' + best.toLocaleString() + ' in the world top million (Tranco).' : 'Not in the world top million. Normal for a local business.', best ? '#' + best.toLocaleString() : 'not ranked')];
    } catch (e) { return []; }
  }

  async function archive(d) {
    try {
      var r = await getJson('https://archive.org/wayback/available?url=' + d + '&timestamp=19900101', { timeout: 12000 });
      var ts = r.archived_snapshots && r.archived_snapshots.closest && r.archived_snapshots.closest.timestamp;
      return [R('archive', 'trust', 'First seen on the web', 'info', ts ? 'The Internet Archive first saved this site around ' + ts.slice(0, 4) + '-' + ts.slice(4, 6) + '.' : 'The Internet Archive has no copy of this site.', ts ? ts.slice(0, 4) : '–')];
    } catch (e) { return [R('archive', 'trust', 'First seen on the web', 'skip', 'Internet Archive did not answer.')]; }
  }

  // ---------------- look-alikes, with "new since last check" ----------------
  function lookalikeList(d) {
    var sfx = TWO.find(function (s) { return d.endsWith('.' + s); }) || d.split('.').pop();
    var n = d.slice(0, -(sfx.length + 1)), tld = '.' + sfx, out = {};
    function add(x) { if (x !== d && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(x) && x.charAt(0) !== '-') out[x] = 1; }
    var swap = { o: ['0'], l: ['1', 'i'], i: ['1', 'l'], e: ['3'], a: ['4'], s: ['5'], m: ['rn'], g: ['q'], b: ['d'], d: ['b'], u: ['v'], w: ['vv'] };
    for (var i = 0; i < n.length; i++) {
      add(n.slice(0, i) + n.slice(i + 1) + tld);
      add(n.slice(0, i) + n[i] + n[i] + n.slice(i + 1) + tld);
      if (i < n.length - 1) add(n.slice(0, i) + n[i + 1] + n[i] + n.slice(i + 2) + tld);
      (swap[n[i]] || []).forEach(function (s) { add(n.slice(0, i) + s + n.slice(i + 1) + tld); });
    }
    ['.com', '.net', '.co', '.sg', '.com.sg', '.org', '.online', '.shop'].forEach(function (t) { add(n + t); });
    ['login', 'secure', 'pay', 'promo', 'official'].forEach(function (w) { add(n + '-' + w + tld); add(w + '-' + n + tld); });
    return Object.keys(out).slice(0, 60);
  }

  async function lookalikes(d, progress) {
    var N = 'Look-alike domains';
    var list = lookalikeList(d), rows = [], done = 0, wild = {};
    var endings = {}; list.forEach(function (x) { endings[x.slice(x.indexOf('.') + 1)] = 1; });
    await Promise.all(Object.keys(endings).map(function (e) {
      return doh('wpl-' + Math.random().toString(36).slice(2, 10) + '.' + e, 'A').then(function (r) { if ((r.Answer || []).length) wild[e] = 1; }, function () { /* ignore */ });
    }));
    var skipped = list.filter(function (x) { return wild[x.slice(x.indexOf('.') + 1)]; }).length;
    list = list.filter(function (x) { return !wild[x.slice(x.indexOf('.') + 1)]; });
    if (!list.length && !skipped) return [na('lookalikes', N, 'No look-alike names can be made from ' + d + '.')];
    if (!list.length) return [na('lookalikes', N, 'Every look-alike sits under ' + Object.keys(wild).join(', ') + ', where any name answers, so they cannot be judged.')];
    await pool(list, 6, async function (x) {
      try {
        var ns = await doh(x, 'NS');
        if (ns.Status === 0) { var mx = await doh(x, 'MX'); rows.push({ d: x, mail: (mx.Answer || []).some(function (y) { return y.type === 15 && !/^0 \.$/.test(y.data); }) }); }
      } catch (e) { /* skip */ }
      if (progress) progress(++done, list.length);
    });
    // Watch: remember what was registered last time in this browser, flag anything new.
    var key = 'webpawlice:la:' + d, before = null;
    try { before = JSON.parse(localStorage.getItem(key) || 'null'); localStorage.setItem(key, JSON.stringify({ t: Date.now(), list: rows.map(function (r) { return r.d; }) })); } catch (e) { /* storage blocked */ }
    var fresh = before ? rows.filter(function (r) { return before.list.indexOf(r.d) < 0; }) : [];
    var mail = rows.filter(function (r) { return r.mail; });
    var head = list.length + ' addresses could pass for ' + d + (skipped ? ' (' + skipped + ' more under ' + Object.keys(wild).join(', ') + ' cannot be judged)' : '') + '. ' + rows.length + ' are registered by someone' + (rows.length ? ': ' + rows.slice(0, 5).map(function (r) { return r.d; }).join(', ') + (rows.length > 5 ? ' and more' : '') : '') + '.';
    var since = before ? (fresh.length ? ' New since ' + new Date(before.t).toLocaleDateString() + ': ' + fresh.map(function (r) { return r.d; }).join(', ') + '.' : ' Nothing new since ' + new Date(before.t).toLocaleDateString() + '.') : ' First check in this browser; the next one shows what is new.';
    var v = rows.length + ' registered, ' + mail.length + ' take email';
    if (fresh.length) return [risk('lookalikes', N, 'high', head + since, 'A look-alike registered recently is the usual first step of a phishing campaign against your customers.', 'Check what the new domain shows; if it copies you, report it to the registrar and warn customers.', v)];
    if (mail.length) return [risk('lookalikes', N, 'medium', head + ' ' + mail.length + ' can receive email.' + since, 'A look-alike that takes email can send and receive messages that pass for yours.', 'Buy the closest ones if cheap; watch the rest. The repo includes a daily watch that opens an issue when one appears.', v)];
    if (rows.length) return [risk('lookalikes', N, 'low', head + since, 'Most are parked or unrelated, but each one could be switched on later.', 'Keep watching; buy the one or two closest to your name.', v)];
    return [ok('lookalikes', N, head + since, v)];
  }

  // ---------------- the owner's own site ----------------
  async function siteHeaders() {
    if (!onSite) return [];
    var out = [], res = await fetch(ROOT.href, { cache: 'no-store', credentials: 'omit' });
    var h = function (n) { return res.headers.get(n) || ''; };
    var forms = document.querySelectorAll('form').length > 0;
    var csp = h('content-security-policy') || ((document.querySelector('meta[http-equiv="Content-Security-Policy" i]') || {}).content || '');
    if (location.protocol === 'https:') out.push(h('strict-transport-security') ? ok('hsts', 'Always use https (HSTS)', 'Browsers are told to use https only.') : risk('hsts', 'Always use https (HSTS)', 'medium', 'No HSTS header.', 'On public Wi-Fi a visitor can be pushed to an insecure copy of the site before the redirect happens.', 'Send Strict-Transport-Security: max-age=31536000 from the server.'));
    out.push(csp ? ok('csp', 'Script injection guard (CSP)', 'A Content-Security-Policy limits which scripts may run.') : risk('csp', 'Script injection guard (CSP)', forms ? 'medium' : 'low', 'No Content-Security-Policy.', 'If anything injects a script, for example a hacked plugin or a skimmer, the browser runs it without question.', 'Start with a report-only policy, then enforce it.'));
    out.push(h('x-frame-options') || /frame-ancestors/i.test(csp) ? ok('frames', 'Clickjacking guard', 'Other sites cannot show this one inside a frame.') : risk('frames', 'Clickjacking guard', forms ? 'medium' : 'low', 'Any site can show this one inside an invisible frame.', 'Attackers overlay your real buttons and forms to trick visitors into clicking or typing.', 'Send X-Frame-Options: SAMEORIGIN, or frame-ancestors in the CSP.'));
    var minor = ['x-content-type-options', 'referrer-policy'].filter(function (k) { return !h(k); });
    out.push(minor.length ? risk('minor-headers', 'Smaller browser protections', 'low', 'Missing: ' + minor.join(', ') + '.', 'Small hardening steps; each closes a narrow trick.', 'Add both headers in the same server config as HSTS.') : ok('minor-headers', 'Smaller browser protections', 'nosniff and Referrer-Policy are set.'));
    var powered = h('x-powered-by'), gen = (document.querySelector('meta[name="generator"]') || {}).content || '';
    var shown = [h('server'), powered, gen].filter(function (s) { return /\d/.test(s); });
    var php = (powered.match(/PHP\/(\d+\.\d+)/i) || [])[1];
    if (php) {
      try {
        var cyc = (await getJson('https://endoflife.date/api/php.json', { timeout: 8000 })).find(function (c) { return c.cycle === php; });
        if (cyc && cyc.eol && new Date(cyc.eol) < new Date()) out.push(risk('php-eol', 'PHP version', 'high', 'The server runs PHP ' + php + ', which stopped getting security fixes on ' + cyc.eol + '.', 'New PHP flaws are published and never fixed for this version.', 'Ask the host to move the site to a supported PHP version, and test plugins first.'));
      } catch (e) { /* skip */ }
    }
    out.push(shown.length ? risk('disclosure', 'Software versions shown', 'low', 'The site announces: ' + shown.join('; ') + '.', 'Attack tools look for these exact version strings.', 'Hide version numbers in the server and CMS settings.') : ok('disclosure', 'Software versions shown', 'No software versions announced.'));

    var robots = '';
    try { var rr = await fetch(at('robots.txt'), { credentials: 'omit' }); robots = rr.ok ? await rr.text() : ''; } catch (e) { /* none */ }
    if (/<html/i.test(robots.slice(0, 200))) robots = '';
    siteRobots = robots;
    var blocked = AI_BOTS.filter(function (b) { return new RegExp('user-agent:\\s*' + b + '\\s*\\n(?:[^\\n]*\\n)*?\\s*disallow:\\s*/\\s*(\\n|$)', 'i').test(robots); });
    var all = /user-agent:\s*\*\s*\n(?:(?!user-agent)[^\n]*\n)*?\s*disallow:\s*\/\s*(\n|$)/i.test(robots);
    out.push(R('ai-bots', 'found', 'AI assistants may read you', all || blocked.length >= 3 ? 'bad' : blocked.length ? 'warn' : 'good', all ? 'robots.txt blocks every crawler, AI assistants included.' : blocked.length ? 'robots.txt blocks ' + blocked.join(', ') + '. Those assistants cannot read the site when customers ask about you.' : 'No AI crawler is blocked.'));
    out.push(R('sitemap', 'found', 'Sitemap announced', /sitemap:/i.test(robots) ? 'good' : 'warn', /sitemap:/i.test(robots) ? 'robots.txt points search engines to a sitemap.' : 'robots.txt does not point to a sitemap.'));
    var llms = await peek(at('llms.txt'), { n: 300 });
    out.push(R('llms', 'found', 'Summary for AI (llms.txt)', llms.ok && !/<html/i.test(llms.text) ? 'good' : 'info', llms.ok && !/<html/i.test(llms.text) ? 'Publishes llms.txt for AI assistants.' : 'No llms.txt. A short plain-text summary helps assistants describe you correctly.'));
    return out;
  }
  var siteRobots = '';

  // Files that should never be downloadable. Only presence is reported; contents are never shown or kept.
  var NOT_HTML = function (t) { return !/^\s*(<!doctype|<html)/i.test(t); };
  var LEAKS = [
    ['.env', function (t) { return NOT_HTML(t) && /^\s*[A-Z][A-Z0-9_]*\s*=/m.test(t); }, 'critical', 'Environment file (.env)', 'It usually holds database passwords and API keys. Bots request /.env on every site, every day.', 'Delete it from the public folder or block dotfiles in the server config, then change every password and key that was in it.'],
    ['.git/HEAD', function (t) { return /^ref: refs\//.test(t); }, 'critical', 'Source code history (.git)', 'Anyone can download the full source code and its history, including passwords ever committed.', 'Block /.git in the server config and deploy without the .git folder.'],
    ['wp-config.php.bak', function (t) { return NOT_HTML(t) && /DB_PASSWORD/.test(t); }, 'critical', 'WordPress config backup', 'A backup of wp-config.php is served as plain text, database password included.', 'Delete the backup and change the database password.'],
    ['wp-config.php~', function (t) { return NOT_HTML(t) && /DB_PASSWORD/.test(t); }, 'critical', 'WordPress config backup', 'An editor backup of wp-config.php is served as plain text, database password included.', 'Delete the backup and change the database password.'],
    ['backup.sql', function (t) { return NOT_HTML(t) && /CREATE TABLE|INSERT INTO/i.test(t); }, 'critical', 'Database dump', 'A copy of the database is downloadable: customer records and password hashes.', 'Delete it and check the server logs for who downloaded it.'],
    ['dump.sql', function (t) { return NOT_HTML(t) && /CREATE TABLE|INSERT INTO/i.test(t); }, 'critical', 'Database dump', 'A copy of the database is downloadable: customer records and password hashes.', 'Delete it and check the server logs for who downloaded it.'],
    ['.htpasswd', function (t) { return NOT_HTML(t) && /^[^:\s<]+:\S{10,}$/m.test(t); }, 'high', 'Password file (.htpasswd)', 'Password hashes for protected areas can be downloaded and cracked offline.', 'Move the file outside the public folder.'],
    ['phpinfo.php', function (t) { return /phpinfo\(\)|PHP Version/i.test(t); }, 'high', 'PHP info page', 'Shows server paths, versions and settings: a map for attackers.', 'Delete phpinfo.php.'],
    ['info.php', function (t) { return /phpinfo\(\)|PHP Version/i.test(t); }, 'high', 'PHP info page', 'Shows server paths, versions and settings: a map for attackers.', 'Delete info.php.'],
    ['wp-content/debug.log', function (t) { return /PHP (Fatal|Warning|Notice|Parse|Deprecated)/.test(t); }, 'high', 'WordPress debug log', 'Error logs reveal file paths, plugin names and sometimes data customers typed.', 'Turn off WP_DEBUG_LOG in wp-config.php and delete the log.'],
    ['server-status', function (t) { return /Apache Server Status/i.test(t); }, 'medium', 'Apache status page', 'Shows every address visitors are opening right now, including private links.', 'Restrict /server-status to localhost.'],
    ['.DS_Store', function (t) { return t.indexOf('Bud1') === 4; }, 'low', 'Mac folder index (.DS_Store)', 'Lists file names in the folder, including ones never linked.', 'Delete .DS_Store files from the server.'],
  ];
  async function leakedFiles() {
    if (!onSite) return [];
    var hits = [];
    await pool(LEAKS, 4, async function (l) {
      var r = await peek(at(l[0]), { n: 3000 });
      if (r.ok && l[1](r.text)) hits.push(risk('leak-' + l[0], l[3], l[2], at(l[0]).replace(location.origin, '') + ' can be downloaded by anyone. (WebPawlice does not show or keep its contents.)', l[4], l[5]));
    });
    if (!hits.length) return [ok('leaks', 'Leaked files', 'None of ' + LEAKS.length + ' commonly leaked files (.env, .git, config backups, database dumps, logs) can be downloaded.')];
    return hits;
  }

  // Keys in page code, original source published, old libraries, hijacked script hosts.
  var SECRETS = [
    ['Stripe secret key', /\b[sr]k_live_[0-9a-zA-Z]{20,}/g, 'critical'],
    ['AWS access key', /\bAKIA[0-9A-Z]{16}\b/g, 'critical'],
    ['GitHub token', /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g, 'critical'],
    ['Private key', /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, 'critical'],
    ['AI API key', /\bsk-(?:proj-|ant-)?(?=[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{32,}/g, 'critical'],
    ['Slack token', /\bxox[abprs]-[0-9A-Za-z-]{10,}/g, 'high'],
    ['SendGrid key', /\bSG\.[\w-]{22}\.[\w-]{43}\b/g, 'high'],
    ['Mailchimp key', /\b[0-9a-f]{32}-us\d{1,2}\b/g, 'high'],
  ];
  var BAD_HOSTS = ['polyfill.io', 'bootcdn.net', 'bootcss.com', 'staticfile.net', 'staticfile.org'];
  var CDNS = /^(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|ajax\.googleapis\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|cdn\.datatables\.net)$/;
  var CDNJS_NAMES = { jqueryui: 'jquery-ui', 'twitter-bootstrap': 'bootstrap', 'lodash.js': 'lodash', 'moment.js': 'moment', 'angular.js': 'angular', 'handlebars.js': 'handlebars', 'vue': 'vue', 'jquery': 'jquery', 'dompurify': 'dompurify' };

  function cmpVer(a, b) {
    var x = String(a).split(/[.-]/).map(function (n) { return parseInt(n, 10) || 0; }), y = String(b).split(/[.-]/).map(function (n) { return parseInt(n, 10) || 0; });
    for (var i = 0; i < Math.max(x.length, y.length); i++) { var d = (x[i] || 0) - (y[i] || 0); if (d) return d > 0 ? 1 : -1; }
    return 0;
  }
  function detectLibs(srcs) {
    var found = {};
    function add(n, v) { var m = String(v || '').match(/^\d+\.\d+(?:\.\d+)?/); if (m && !found[n]) found[n] = m[0]; }
    try {
      var jq = window.jQuery;
      if (jq && jq.fn) { add('jquery', jq.fn.jquery); if (jq.ui) add('jquery-ui', jq.ui.version); if (jq.fn.tooltip && jq.fn.tooltip.Constructor) add('bootstrap', jq.fn.tooltip.Constructor.VERSION); }
      if (window.bootstrap && window.bootstrap.Tooltip) add('bootstrap', window.bootstrap.Tooltip.VERSION);
      if (window._ && window._.VERSION && window._.cloneDeep) add('lodash', window._.VERSION);
      if (window.moment) add('moment', window.moment.version);
      if (window.angular && window.angular.version) add('angular', window.angular.version.full);
      if (window.Vue && window.Vue.version) add('vue', window.Vue.version);
      if (window.Handlebars) add('handlebars', window.Handlebars.VERSION);
      if (window.DOMPurify) add('dompurify', window.DOMPurify.version);
    } catch (e) { /* page globals can throw */ }
    srcs.forEach(function (s) {
      var m = s.match(/\/ajax\/libs\/([a-z0-9.-]+)\/(\d+\.\d+\.\d+)\//i); if (m && CDNJS_NAMES[m[1].toLowerCase()]) add(CDNJS_NAMES[m[1].toLowerCase()], m[2]);
      m = s.match(/\/npm\/((?:@[a-z0-9.-]+\/)?[a-z0-9.-]+)@(\d+\.\d+\.\d+)/i) || s.match(/unpkg\.com\/((?:@[a-z0-9.-]+\/)?[a-z0-9.-]+)@(\d+\.\d+\.\d+)/i); if (m) add(m[1].toLowerCase(), m[2]);
      m = s.match(/\/(jquery|jquery-ui|bootstrap|lodash|moment|angular|vue|handlebars)[.-](\d+\.\d+\.\d+)/i); if (m) add(m[1].toLowerCase(), m[2]);
    });
    return found;
  }
  async function osvLib(name, version) {
    var j = await getJson('https://api.osv.dev/v1/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ package: { name: name, ecosystem: 'npm' }, version: version }), timeout: 12000 });
    var vulns = j.vulns || [], worst = 3, fix = null;
    vulns.forEach(function (v) {
      var s = { CRITICAL: 0, HIGH: 1, MODERATE: 2, LOW: 3 }[((v.database_specific || {}).severity || '').toUpperCase()];
      worst = Math.min(worst, s == null ? 2 : s);
      (v.affected || []).forEach(function (a) {
        if (!a.package || a.package.name !== name) return;
        (a.ranges || []).forEach(function (rg) {
          var intro = '0';
          (rg.events || []).forEach(function (e) {
            if (e.introduced != null) intro = e.introduced;
            if (e.fixed != null && cmpVer(version, intro) >= 0 && cmpVer(version, e.fixed) < 0 && (!fix || cmpVer(e.fixed, fix) > 0)) fix = e.fixed;
          });
        });
      });
    });
    return { count: vulns.length, worst: ['critical', 'high', 'medium', 'low'][worst], fix: fix, ids: vulns.slice(0, 3).map(function (v) { return v.id; }) };
  }

  async function pageCode() {
    if (!onSite) return [];
    var out = [], own = script.src || '', texts = [], ext = [], srcs = [];
    [].slice.call(document.scripts).forEach(function (s) {
      if (s.src) { srcs.push(s.src); if (s.src !== own && new URL(s.src).origin === location.origin) ext.push(s.src); }
      else if (!/ld\+json/i.test(s.type)) texts.push({ where: 'inline script on this page', text: s.textContent });
    });
    performance.getEntriesByType('resource').forEach(function (e) { if (e.initiatorType === 'script' && srcs.indexOf(e.name) < 0) srcs.push(e.name); });
    await pool(ext.slice(0, 15), 4, async function (u) { var r = await peek(u, { n: 3000000, follow: true }); if (r.ok) texts.push({ where: u.replace(location.origin, ''), text: r.text, url: u }); });

    // 1. Keys in page code.
    var found = [];
    texts.forEach(function (t) {
      SECRETS.forEach(function (s) {
        (t.text.match(s[1]) || []).slice(0, 2).forEach(function (m) { found.push({ kind: s[0], level: s[2], where: t.where, sample: m.slice(0, 6) + '…', example: m === 'AKIAIOSFODNN7EXAMPLE' }); });
      });
    });
    if (found.length) {
      var real = found.filter(function (f) { return !f.example; });
      var worst = real.length ? real.slice().sort(function (a, b) { return SEV[a.level] - SEV[b.level]; })[0].level : 'low';
      out.push(risk('secrets', 'Keys in page code', worst, found.slice(0, 3).map(function (f) { return f.kind + ' (' + f.sample + ') in ' + f.where + (f.example ? ', Amazon\'s documentation example, so harmless here, but this is exactly where real keys leak' : ''); }).join('; ') + '.', 'Every visitor downloads page code. A live key there lets anyone use your paid account or read your data.', 'Revoke the key in that provider\'s dashboard today, then move it to the server.'));
    } else out.push(ok('secrets', 'Keys in page code', 'No API keys or tokens found in ' + texts.length + ' scripts on this page.'));

    // 2. Original source code published through source maps.
    var maps = [];
    await pool(texts.filter(function (t) { return t.url; }).slice(0, 6), 3, async function (t) {
      var m = t.text.slice(-400).match(/\/\/[#@] sourceMappingURL=(?!data:)(\S+)\s*$/);
      if (!m) return;
      var r = await peek(new URL(m[1], t.url).href, { n: 400, follow: true });
      if (r.ok && /"mappings"|"sources"/.test(r.text)) maps.push(t.where);
    });
    if (maps.length) out.push(risk('sourcemaps', 'Original source code published', 'medium', 'Source maps for ' + maps.length + ' script' + (maps.length > 1 ? 's' : '') + ' can be downloaded, e.g. ' + maps[0] + '.', 'Anyone can read the readable original code, comments and internal addresses included.', 'Stop uploading .map files in the production build.'));

    // 3. Hijacked script hosts and unchecked CDN scripts.
    var hosts = srcs.concat([].slice.call(document.querySelectorAll('link[href]')).map(function (l) { return l.href; })).map(function (u) { try { return new URL(u).hostname; } catch (e) { return ''; } });
    var bad = BAD_HOSTS.filter(function (b) { return hosts.some(function (h) { return h === b || h.endsWith('.' + b); }); });
    if (bad.length) out.push(risk('bad-hosts', 'Code from a hijacked host', 'critical', 'This page loads code from ' + bad.join(', ') + '.', 'These hosts were taken over in 2024 and served malware to the visitors of sites that used them.', 'Remove the script tag today; host the file yourself if still needed.'));
    var unchecked = [].slice.call(document.querySelectorAll('script[src]')).filter(function (s) { try { return CDNS.test(new URL(s.src).hostname) && !s.integrity; } catch (e) { return false; } });
    if (unchecked.length) out.push(risk('sri', 'Unchecked code from public CDNs', 'low', unchecked.length + ' script' + (unchecked.length > 1 ? 's load' : ' loads') + ' from a public CDN without an integrity check: ' + unchecked.slice(0, 2).map(function (s) { return new URL(s.src).pathname.split('/').slice(-3).join('/'); }).join(', ') + '.', 'If that CDN file is ever changed, the new code runs on your site unchecked.', 'Add integrity="sha384-…" and crossorigin="anonymous" to each tag.'));

    // 4. Libraries with published flaws.
    var libs = detectLibs(srcs), names = Object.keys(libs).slice(0, 8), libRisks = [];
    await pool(names, 4, async function (n) {
      try {
        var r = await osvLib(n, libs[n]);
        if (r.count) libRisks.push(risk('lib-' + n, 'Old ' + n + ' library', r.worst === 'critical' ? 'high' : r.worst, n + ' ' + libs[n] + ' has ' + r.count + ' published flaw' + (r.count > 1 ? 's' : '') + ' (' + r.ids.join(', ') + ').' + (r.fix ? ' Fixed in ' + r.fix + '.' : ''), 'Mostly cross-site scripting: exploitable where the site passes visitor input into the affected feature.', 'Update ' + n + (r.fix ? ' to ' + r.fix + ' or later' : '') + ' and re-test the pages that use it.'));
      } catch (e) { /* OSV unreachable */ }
    });
    out = out.concat(libRisks);
    if (!libRisks.length) out.push(ok('libs', 'JavaScript libraries', names.length ? 'No published flaws for ' + names.map(function (n) { return n + ' ' + libs[n]; }).join(', ') + ' (OSV.dev).' : 'No well-known libraries with a readable version on this page.'));
    return out;
  }

  async function wordpress() {
    if (!onSite) return [];
    var isWP = !!document.querySelector('link[href*="/wp-content/"],script[src*="/wp-content/"],script[src*="/wp-includes/"],link[rel="https://api.w.org/"]');
    if (!isWP) return [];
    var out = [], urls = [].slice.call(document.querySelectorAll('script[src],link[href]')).map(function (e) { return e.src || e.href; }).concat(performance.getEntriesByType('resource').map(function (e) { return e.name; }));
    var gen = ((document.querySelector('meta[name="generator"]') || {}).content || '').match(/WordPress\s+(\d+\.\d+(?:\.\d+)?)/i);
    var wpv = gen ? gen[1] : null;
    if (!wpv) { var c = {}; urls.forEach(function (u) { var m = u.match(/\/wp-includes\/[^?]*\?ver=(\d+\.\d+(?:\.\d+)?)/); if (m) c[m[1]] = (c[m[1]] || 0) + 1; }); wpv = Object.keys(c).sort(function (a, b) { return c[b] - c[a]; })[0]; }
    if (wpv) {
      try {
        var latest = (await getJson('https://api.wordpress.org/core/version-check/1.7/', { timeout: 10000 })).offers[0].current;
        var behind = cmpVer(wpv, latest) < 0, a = wpv.split('.'), b = latest.split('.');
        var minors = (+b[0] - +a[0]) * 10 + (+b[1] - +a[1]);
        out.push(behind ? risk('wp-core', 'WordPress version', minors >= 2 ? 'high' : 'medium', 'The site runs WordPress ' + wpv + '; the current release is ' + latest + '.', 'Security fixes ship in new releases; the gap is what mass-hacking bots look for.', 'Update WordPress after a backup, then test forms and checkout.') : ok('wp-core', 'WordPress version', 'WordPress ' + wpv + ' is current.'));
      } catch (e) { /* skip */ }
    }
    var plugins = {};
    urls.forEach(function (u) { var m = u.match(/\/wp-content\/plugins\/([a-z0-9_-]+)\/[^?#]*\?(?:[^#]*&)?ver=(\d+(?:\.\d+)+)/i); if (m && m[2] !== wpv && (!plugins[m[1]] || cmpVer(m[2], plugins[m[1]]) > 0)) plugins[m[1]] = m[2]; });
    var slugs = Object.keys(plugins).slice(0, 12), old = [], closed = [];
    await pool(slugs, 4, async function (s) {
      try {
        var r = await getJson('https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=' + s + '&request[fields][sections]=0&request[fields][description]=0', { timeout: 10000 });
        if (r.error === 'closed' || r.closed) closed.push(s + (r.reason_text ? ' (' + r.reason_text + ')' : ''));
        else if (r.version && cmpVer(plugins[s], r.version) < 0) old.push(s + ' ' + plugins[s] + ' → ' + r.version);
      } catch (e) { /* premium or custom plugin */ }
    });
    if (closed.length) out.push(risk('wp-closed', 'Plugins removed from WordPress.org', 'high', closed.join(', ') + '.', 'WordPress.org removes plugins for unfixed security problems or abandonment; no more fixes will come.', 'Replace each one with a maintained alternative.'));
    if (old.length) out.push(risk('wp-plugins', 'Plugins behind the latest version', old.length >= 3 ? 'high' : 'medium', old.length + ' of ' + slugs.length + ' plugins seen on this page are behind: ' + old.slice(0, 4).join(', ') + '. Versions read from file links.', 'Outdated plugins are the most common way WordPress sites are hacked.', 'Update them after a backup, ideally on a staging copy first.'));
    else if (slugs.length && !closed.length) out.push(ok('wp-plugins', 'Plugins up to date', slugs.length + ' plugins seen on this page are at the latest version.'));
    var users = await peek(at('wp-json/wp/v2/users'), { n: 4000 });
    var names = users.ok ? (users.text.match(/"slug":"([^"]+)"/g) || []).map(function (m) { return m.split('"')[3]; }) : [];
    if (names.length) out.push(risk('wp-users', 'Login names listed publicly', 'medium', 'The site lists ' + names.length + ' login name' + (names.length > 1 ? 's' : '') + ' at /wp-json/wp/v2/users, e.g. ' + names.slice(0, 2).join(', ') + '.', 'Half of a password-guessing attack is knowing the username.', 'Turn off the users endpoint for visitors with a security plugin.'));
    var xr = await peek(at('xmlrpc.php'), { n: 200 });
    if (xr.status === 405 || /XML-RPC server accepts POST requests only/i.test(xr.text)) out.push(risk('wp-xmlrpc', 'XML-RPC switched on', 'medium', '/xmlrpc.php answers.', 'Lets bots try hundreds of passwords in one request.', 'Disable XML-RPC unless the Jetpack app or a mobile app needs it.'));
    return out;
  }

  // Reads the live page the owner is looking at.
  function thisPage() {
    if (!onSite) return [];
    var out = [];
    // Security first.
    var ANALYTICS = /^(_ga|_gid|_gat|_gcl|_fbp|_fbc|_hj|_clck|_clsk|_uet|__utm|_pk_|mp_|ajs_|intercom|hubspot|__hs|_tt|_pin|_scid|cookieyes|cookielawinfo|CookieConsent|OptanonConsent|wp-settings|wordpress_test_cookie|pll_language|woocommerce_items_in_cart|woocommerce_cart_hash)/i;
    var exposed = document.cookie.split(';').map(function (s) { return s.split('=')[0].trim(); }).filter(function (n) { return n && /sess|sid$|^sid|auth|token|jwt|logged_in|login|remember/i.test(n) && !ANALYTICS.test(n); });
    out.push(exposed.length ? risk('cookies', 'Login cookies readable by scripts', 'high', 'Page scripts can read ' + exposed.join(', ') + ' (no HttpOnly flag).', 'One injected script, for example from a hacked plugin, can copy a visitor\'s session and log in as them.', 'Set the HttpOnly, Secure and SameSite=Lax flags on session cookies.') : ok('cookies', 'Login cookies readable by scripts', 'No login cookies are readable by scripts on this page. Log in and check again to test signed-in pages.'));
    var forms = [].slice.call(document.forms).filter(function (f) { return !f.closest('[data-webpawlice]'); });
    var pw = forms.some(function (f) { return f.querySelector('input[type=password]'); });
    var plain = forms.filter(function (f) { return /^http:/i.test(f.getAttribute('action') || '') || (location.protocol === 'http:' && f.querySelector('input')); });
    if (plain.length) out.push(risk('forms', 'Forms sent without encryption', pw ? 'critical' : 'high', plain.length + ' form' + (plain.length > 1 ? 's send' : ' sends') + ' what visitors type over plain http.', 'Anyone on the same Wi-Fi can read ' + (pw ? 'passwords and ' : '') + 'messages as they are sent.', 'Serve the site and every form address over https.'));
    var mixed = [].slice.call(document.querySelectorAll('img[src^="http:"],script[src^="http:"],link[href^="http:"][rel=stylesheet],iframe[src^="http:"]')).length;
    if (location.protocol === 'https:' && mixed) out.push(risk('mixed', 'Insecure items on a secure page', 'medium', mixed + ' items load over plain http://.', 'Browsers block or warn, and the padlock disappears.', 'Change the item addresses to https://.'));

    var desc = (document.querySelector('meta[name="description"]') || {}).content;
    out.push(R('title', 'found', 'Search title and description', document.title && desc ? 'good' : 'warn', (document.title ? 'Title: "' + document.title.slice(0, 70) + '". ' : 'No page title. ') + (desc ? 'Has a description.' : 'No description, so Google and AI assistants write their own.')));
    var types = {};
    document.querySelectorAll('script[type="application/ld+json"]').forEach(function (s) { (s.textContent.match(/"@type"\s*:\s*"([^"]+)"/g) || []).forEach(function (m) { types[m.split('"')[3]] = 1; }); });
    var tl = Object.keys(types);
    out.push(R('schema', 'found', 'Facts machines can read', tl.length ? 'good' : 'warn', tl.length ? 'Publishes structured facts: ' + tl.slice(0, 5).join(', ') + '.' : 'No structured facts (hours, address, prices). AI assistants and Google have to guess them.'));
    var imgs = [].slice.call(document.images).filter(function (i) { return i.offsetWidth > 40 && !i.closest('[data-webpawlice]'); });
    var noAlt = imgs.filter(function (i) { return !i.hasAttribute('alt'); }).length;
    out.push(R('alt', 'works', 'Images described for blind visitors', noAlt === 0 ? 'good' : noAlt <= 3 ? 'warn' : 'bad', imgs.length ? (noAlt ? noAlt + ' of ' + imgs.length + ' images have no description (alt text). Screen readers skip them.' : 'All ' + imgs.length + ' images have descriptions.') : 'No images on this page.'));
    var fields = [].slice.call(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]),select,textarea')).filter(function (f) { return !f.closest('[data-webpawlice]'); });
    var unlabeled = fields.filter(function (f) { return !(f.labels && f.labels.length) && !f.getAttribute('aria-label') && !f.getAttribute('aria-labelledby'); }).length;
    if (fields.length) out.push(R('labels', 'works', 'Form fields named', unlabeled ? 'warn' : 'good', unlabeled ? unlabeled + ' of ' + fields.length + ' form fields have no label, so screen readers cannot say what to type.' : 'Every form field has a label.'));
    var hosts = {};
    performance.getEntriesByType('resource').forEach(function (e) { try { var hh = new URL(e.name).hostname; if (registrable(hh) !== here) hosts[registrable(hh)] = 1; } catch (x) { /* ignore */ } });
    try { delete hosts[registrable(new URL(script.src || location.href).hostname)]; } catch (x) { /* ignore */ }
    var third = Object.keys(hosts);
    out.push(R('third', 'trust', 'Other companies on this page', third.length > 10 ? 'warn' : 'info', third.length ? third.length + ' other companies load code or files here: ' + third.slice(0, 8).join(', ') + (third.length > 8 ? ' and more' : '') + '. Each one can see your visitors.' : 'No third-party code loads on this page.'));
    var nav = performance.getEntriesByType('navigation')[0];
    if (nav && nav.loadEventEnd > 0) {
      var s = nav.loadEventEnd / 1000;
      out.push(R('load', 'works', 'Load time, this visit', s < 2.5 ? 'good' : s < 5 ? 'warn' : 'bad', 'This page fully loaded in ' + s.toFixed(1) + ' s on your connection. Under 2.5 s is good.'));
    }
    if (window.__webpawliceLcp) out.push(R('lcp', 'works', 'Main content appears', window.__webpawliceLcp < 2500 ? 'good' : window.__webpawliceLcp < 4000 ? 'warn' : 'bad', 'Largest content appeared after ' + (window.__webpawliceLcp / 1000).toFixed(1) + ' s.'));
    var years = (document.body.innerText.match(/(?:©|copyright)\s*(?:\d{4}\s*[-–]\s*)?(\d{4})/gi) || []).map(function (m) { return +m.slice(-4); });
    if (years.length) {
      var y = Math.max.apply(null, years), now = new Date().getFullYear();
      out.push(R('fresh', 'trust', 'Looks looked-after', y >= now - 1 ? 'good' : 'warn', y >= now - 1 ? 'Footer year ' + y + '.' : 'Footer still says © ' + y + '. Visitors read that as an abandoned site.'));
    }
    return out;
  }

  function score(results) {
    var counts = { critical: 0, high: 0, medium: 0, low: 0 };
    results.forEach(function (r) { if (r.status === 'risk') counts[r.risk]++; });
    var security = Math.max(0, 100 - Object.keys(counts).reduce(function (s, k) { return s + PENALTY[k] * counts[k]; }, 0));
    var W = { good: 1, info: 0.8, warn: 0.5, bad: 0 }, o = results.filter(function (r) { return r.area !== 'security' && r.status in W; });
    return { counts: counts, security: security, other: o.length ? Math.round(100 * o.reduce(function (s, r) { return s + W[r.status]; }, 0) / o.length) : null };
  }

  // ---------------- launch guard: walk the site like a visitor ----------------
  var crawl = null;
  function textOf(doc) {
    var b = doc.body ? doc.body.cloneNode(true) : null;
    if (!b) return '';
    b.querySelectorAll('script,style,noscript,template,[data-webpawlice]').forEach(function (e) { e.remove(); });
    return (b.textContent || '').replace(/\s+/g, ' ');
  }
  function inScope(u) { try { var x = new URL(u, location.href); return x.origin === location.origin && x.pathname.indexOf(ROOT.pathname) === 0 && !/\.(pdf|jpe?g|png|gif|webp|svg|zip|mp4|mp3|docx?|xlsx?)$/i.test(x.pathname); } catch (e) { return false; } }
  function norm(u) { var x = new URL(u, location.href); x.hash = ''; x.searchParams.delete('webpawlice'); x.searchParams.delete('compare'); return x.href; }

  async function walk(progress) {
    if (crawl) return crawl;
    var MAX = 25, start = norm(location.href), queue = [start], seen = {}, pages = [], from = {}, imgs = {}, ext = {};
    seen[start] = 1;
    while (queue.length && pages.length < MAX) {
      var batch = queue.splice(0, 3);
      await Promise.all(batch.map(async function (u) {
        var r = u === start ? { ok: true, status: 200, type: 'text/html', text: document.documentElement.outerHTML } : await peek(u, { n: 600000, follow: true });
        var p = { url: u, status: r.status, ok: r.ok, from: from[u] };
        pages.push(p);
        if (progress) progress(pages.length);
        if (!r.ok || !/html/i.test(r.type)) return;
        var doc = new DOMParser().parseFromString(r.text, 'text/html');
        p.title = (doc.querySelector('title') || {}).textContent || '';
        p.desc = (doc.querySelector('meta[name="description"]') || {}).content || '';
        p.robots = (doc.querySelector('meta[name="robots"]') || {}).content || '';
        p.canonical = (doc.querySelector('link[rel="canonical"]') || {}).href || '';
        p.h1 = doc.querySelectorAll('h1').length;
        p.text = textOf(doc);
        p.doc = doc;
        p.insecureForms = [].slice.call(doc.querySelectorAll('form[action]')).filter(function (f) { return /^http:/i.test(f.getAttribute('action')); }).map(function (f) { return f.getAttribute('action'); });
        p.httpLinks = [].slice.call(doc.querySelectorAll('a[href^="http:"]')).length;
        p.staging = [].slice.call(doc.querySelectorAll('a[href],link[href],img[src],form[action]')).map(function (e) { return e.getAttribute('href') || e.getAttribute('src') || e.getAttribute('action'); })
          .concat([p.canonical]).filter(function (h) { return /^https?:\/\/(?:[^/]*\.)?(?:staging|stage|dev|test|uat|preview)[.-][^/]+|^https?:\/\/(?:localhost|127\.0\.0\.1)[:/]/i.test(h || ''); });
        doc.querySelectorAll('img[src]').forEach(function (i) { var s = i.getAttribute('src'); if (!/^data:/i.test(s)) { var a = new URL(s, u).href; if (!imgs[a]) imgs[a] = u; } });
        doc.querySelectorAll('a[href]').forEach(function (a) {
          var h = a.getAttribute('href');
          if (!h || /^(mailto|tel|javascript|#)/i.test(h)) return;
          var abs; try { abs = new URL(h, u).href; } catch (e) { return; }
          if (inScope(abs)) { var n = norm(abs); if (!seen[n]) { seen[n] = 1; from[n] = u; queue.push(n); } }
          else if (/^https?:/.test(abs) && new URL(abs).origin !== location.origin) { var o = new URL(abs).origin; if (!ext[o]) ext[o] = u; }
        });
      }));
    }
    // Images: same-origin ones by status; others by whether their host answers at all.
    var badImgs = [], deadHosts = [];
    await pool(Object.keys(imgs).slice(0, 60), 4, async function (src) {
      if (new URL(src).origin === location.origin) { var r = await peek(src, { method: 'HEAD', follow: true }); if (!r.ok) badImgs.push({ src: src, page: imgs[src] }); }
    });
    await pool(Object.keys(ext).slice(0, 20), 4, async function (o) {
      try { await fetch(o, { mode: 'no-cors', credentials: 'omit', cache: 'no-store' }); } catch (e) { deadHosts.push({ host: o, page: ext[o] }); }
    });
    var notFound = await peek(at('wpl-check-' + Math.random().toString(36).slice(2, 8)), { n: 200, follow: true });
    var icon = document.querySelector('link[rel~="icon"]') ? { ok: true } : await peek(location.origin + '/favicon.ico', { method: 'HEAD', follow: true });
    crawl = { pages: pages, badImgs: badImgs, deadHosts: deadHosts, softNotFound: notFound.ok, favicon: icon.ok, extCount: Object.keys(ext).length, imgCount: Object.keys(imgs).length, capped: queue.length > 0 };
    return crawl;
  }

  function launchFindings(c) {
    var out = [], rel = function (u) { return (u || '').replace(location.origin, '') || '/'; };
    var html = c.pages.filter(function (p) { return p.text != null; });
    var broken = c.pages.filter(function (p) { return !p.ok; });
    if (broken.length) out.push(risk('lg-broken', 'Broken pages', 'high', broken.length + ' linked page' + (broken.length > 1 ? 's do' : ' does') + ' not open: ' + broken.slice(0, 4).map(function (p) { return rel(p.url) + ' (' + (p.status || 'no answer') + ', linked from ' + rel(p.from) + ')'; }).join('; ') + '.', 'Visitors hit a dead end, and search engines lower trust in the site.', 'Fix or remove each link.'));
    var allBlocked = /user-agent:\s*\*\s*\n(?:(?!user-agent)[^\n]*\n)*?\s*disallow:\s*\/\s*(\n|$)/i.test(siteRobots);
    if (allBlocked) out.push(risk('lg-robots', 'Search engines blocked', 'critical', 'robots.txt tells every search engine to stay out ("Disallow: /").', 'The site will not appear on Google. Usually a staging setting carried over at launch.', 'Remove "Disallow: /" from robots.txt.'));
    var noindex = html.filter(function (p) { return /noindex/i.test(p.robots); });
    if (noindex.length) out.push(risk('lg-noindex', 'Pages hidden from search', 'high', noindex.length + ' page' + (noindex.length > 1 ? 's are' : ' is') + ' marked noindex: ' + noindex.slice(0, 4).map(function (p) { return rel(p.url); }).join(', ') + '.', 'Those pages never appear on Google. In WordPress this is the "Discourage search engines" box.', 'Remove the noindex tag, or untick the box in Settings → Reading.'));
    var staging = html.filter(function (p) { return p.staging.length; });
    if (staging.length) out.push(risk('lg-staging', 'Links to the staging site', 'high', staging.length + ' page' + (staging.length > 1 ? 's point' : ' points') + ' at a test address, e.g. ' + staging[0].staging[0] + ' on ' + rel(staging[0].url) + '.', 'Visitors and Google get sent to an unfinished copy, and search credit goes to the wrong address.', 'Search the database and templates for the staging address and replace it.'));
    var insecure = html.filter(function (p) { return p.insecureForms.length; });
    if (insecure.length) out.push(risk('lg-forms', 'Forms sent without encryption', 'high', 'The form on ' + rel(insecure[0].url) + ' sends to ' + insecure[0].insecureForms[0] + '.', 'What customers type travels unencrypted and browsers show a warning.', 'Change the form address to https.'));
    if (c.badImgs.length) out.push(risk('lg-images', 'Broken images', 'medium', c.badImgs.length + ' image' + (c.badImgs.length > 1 ? 's do' : ' does') + ' not load: ' + c.badImgs.slice(0, 3).map(function (i) { return rel(i.src) + ' on ' + rel(i.page); }).join('; ') + '.', 'Visitors see empty boxes; it reads as an unfinished site.', 'Upload the missing files or remove the image tags.'));
    var PH = /lorem ipsum|dolor sit amet|\[placeholder\]|insert (?:text|image) here|coming soon|\btodo\b|test@test|example@example|123[ -]?456[ -]?789/i;
    var ph = html.filter(function (p) { return PH.test(p.text); });
    if (ph.length) out.push(risk('lg-placeholder', 'Placeholder text left in', 'medium', ph.length + ' page' + (ph.length > 1 ? 's contain' : ' contains') + ' placeholder text, e.g. "' + p0(ph[0].text.match(PH)[0]) + '" on ' + rel(ph[0].url) + '.', 'Customers notice it first, and it signals the site was not checked.', 'Replace it with real copy.'));
    var noTitle = html.filter(function (p) { return !p.title.trim(); }), noDesc = html.filter(function (p) { return !p.desc; });
    var dupes = {}; html.forEach(function (p) { if (p.title) (dupes[p.title] = dupes[p.title] || []).push(rel(p.url)); });
    var dupList = Object.keys(dupes).filter(function (t) { return dupes[t].length > 1; });
    if (noTitle.length || dupList.length) out.push(risk('lg-titles', 'Page titles', 'medium', (noTitle.length ? noTitle.length + ' pages have no title. ' : '') + (dupList.length ? dupList.length + ' titles are used on more than one page, e.g. "' + dupList[0] + '".' : ''), 'The title is the blue link on Google; duplicates compete with each other.', 'Give every page its own title.'));
    if (noDesc.length) out.push(risk('lg-desc', 'Search descriptions missing', 'low', noDesc.length + ' of ' + html.length + ' pages have no description: ' + noDesc.slice(0, 3).map(function (p) { return rel(p.url); }).join(', ') + '.', 'Google and AI assistants write their own summary instead.', 'Write one or two sentences per page.'));
    if (c.deadHosts.length) out.push(risk('lg-dead-links', 'Links to sites that no longer exist', 'medium', c.deadHosts.length + ' outside link' + (c.deadHosts.length > 1 ? 's go' : ' goes') + ' to an address that does not answer: ' + c.deadHosts.slice(0, 3).map(function (h) { return h.host.replace(/^https?:\/\//, '') + ' (on ' + rel(h.page) + ')'; }).join(', ') + '.', 'Dead ends for visitors; an expired domain in a link can be bought by someone else.', 'Remove or update each link.'));
    var http = html.reduce(function (s, p) { return s + p.httpLinks; }, 0);
    if (http) out.push(risk('lg-http', 'Links that use http://', 'low', http + ' links use http:// instead of https://.', 'Visitors pass through an insecure hop, or see a warning.', 'Change them to https://.'));
    var multiH1 = html.filter(function (p) { return p.h1 !== 1; });
    if (multiH1.length) out.push(risk('lg-h1', 'Main headings', 'low', multiH1.length + ' page' + (multiH1.length > 1 ? 's have' : ' has') + ' no single main heading (h1).', 'Screen readers and search engines use it to tell what the page is about.', 'Give each page exactly one h1.'));
    if (c.softNotFound) out.push(risk('lg-404', 'Missing pages return "found"', 'low', 'An address that does not exist still answers 200 OK.', 'Search engines index error pages, and broken links are harder to spot.', 'Return a 404 status for missing pages.'));
    if (!c.favicon) out.push(risk('lg-favicon', 'No browser tab icon', 'low', 'No favicon is set.', 'Tabs and bookmarks show a blank page icon.', 'Add a favicon.'));
    return out;
  }
  function p0(s) { return String(s).slice(0, 40); }

  // ---------------- facts: what the site says, and where it disagrees with itself ----------------
  var DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  function dayIdx(s) { return ['mo', 'tu', 'we', 'th', 'fr', 'sa', 'su'].indexOf(String(s).slice(0, 2).toLowerCase()); }
  function hhmm(h, m, ap) { h = +h; m = +(m || 0); if (ap) { ap = ap.toLowerCase(); if (ap === 'pm' && h < 12) h += 12; if (ap === 'am' && h === 12) h = 0; } return (h < 10 ? '0' : '') + h + ':' + (m < 10 ? '0' : '') + m; }
  var DAY_RE = '(mon|tue|tues|wed|thu|thur|thurs|fri|sat|sun|mo|tu|we|th|fr|sa|su)[a-z]*\\.?';
  var HOURS_RE = new RegExp('\\b' + DAY_RE + '(?:\\s*(?:-|–|to)\\s*' + DAY_RE + ')?\\s*:?,?\\s*(\\d{1,2})(?:[:.](\\d{2}))?\\s*(am|pm)?\\s*(?:-|–|to)\\s*(\\d{1,2})(?:[:.](\\d{2}))?\\s*(am|pm)?', 'gi');
  function hoursIn(s) {
    var out = [], m; HOURS_RE.lastIndex = 0;
    while ((m = HOURS_RE.exec(s))) {
      var d1 = dayIdx(m[1]), d2 = m[2] ? dayIdx(m[2]) : -1;
      if (d1 < 0) continue;
      out.push(DAYS[d1] + (d2 > -1 ? '–' + DAYS[d2] : '') + ' ' + hhmm(m[3], m[4], m[5] || (m[8] && +m[3] < +m[6] ? m[8] : null)) + '–' + hhmm(m[6], m[7], m[8]));
    }
    return out;
  }
  function phonesIn(s) { return (s.match(/(?:\+65[\s-]?)?\b[3689]\d{3}[\s-]?\d{4}\b|\+\d{1,3}[\s-]?\(?\d{1,4}\)?(?:[\s-]?\d{2,4}){2,4}/g) || []).map(function (p) { return p.trim(); }); }
  function digits(p) { var d = p.replace(/\D/g, ''); return d.length > 8 ? d.slice(-8) : d; }
  var PRICE_RE = /(?:S\$|SGD\s?|\$)\s?(\d{1,5}(?:\.\d{2})?)/;
  function jsonLd(doc) {
    var items = [];
    function walkLd(o) { if (!o || typeof o !== 'object') return; if (Array.isArray(o)) { o.forEach(walkLd); return; } items.push(o); Object.keys(o).forEach(function (k) { if (typeof o[k] === 'object') walkLd(o[k]); }); }
    doc.querySelectorAll('script[type="application/ld+json"]').forEach(function (s) { try { walkLd(JSON.parse(s.textContent)); } catch (e) { /* bad JSON-LD */ } });
    return items;
  }

  function extractFacts(c) {
    var f = { phones: {}, emails: {}, hours: {}, prices: {}, postcodes: {}, schema: {}, reviews: [], rating: null };
    var add = function (bag, key, label, page) { if (!bag[key]) bag[key] = { value: label, pages: [] }; if (bag[key].pages.indexOf(page) < 0) bag[key].pages.push(page); };
    c.pages.forEach(function (p) {
      if (!p.doc) return;
      var page = p.url.replace(location.origin, '') || '/', doc = p.doc;
      phonesIn(p.text).forEach(function (v) { add(f.phones, digits(v), v, page); });
      doc.querySelectorAll('a[href^="tel:"]').forEach(function (a) { var v = a.getAttribute('href').slice(4); add(f.phones, digits(v), decodeURIComponent(v), page); });
      doc.querySelectorAll('a[href^="mailto:"]').forEach(function (a) { var v = a.getAttribute('href').slice(7).split('?')[0].toLowerCase(); add(f.emails, v, v, page); });
      hoursIn(p.text).forEach(function (h) { add(f.hours, h, h, page); });
      (p.text.match(/Singapore\s*(\d{6})/g) || []).forEach(function (m) { var v = m.match(/\d{6}/)[0]; add(f.postcodes, v, v, page); });
      doc.querySelectorAll('li,p,td,dd,h3,h4').forEach(function (el) {
        var t = (el.textContent || '').replace(/\s+/g, ' ').trim(), m = t.match(PRICE_RE);
        if (!m || t.length > 90 || (t.match(new RegExp(PRICE_RE.source, 'g')) || []).length > 1) return;
        var item = t.replace(m[0], '').replace(/[^a-z0-9() ]/gi, ' ').replace(/\s+/g, ' ').trim();
        if (item.length < 4) return;
        var k = item.toLowerCase();
        if (!f.prices[k]) f.prices[k] = { item: item, seen: {} };
        add(f.prices[k].seen, m[1], '$' + m[1], page);
      });
      jsonLd(doc).forEach(function (o) {
        if (o.telephone && !f.schema.telephone) f.schema.telephone = o.telephone;
        if (o.email && !f.schema.email) f.schema.email = o.email;
        if (o.openingHours && !f.schema.hours) f.schema.hours = [].concat(o.openingHours).join(', ');
        if (o.postalCode && !f.schema.postcode) f.schema.postcode = String(o.postalCode);
        if (o.name && /Organization|Business|Bakery|Restaurant|Store|Cafe|Shop|Clinic|Hotel/i.test([].concat(o['@type']).join(' ')) && !f.schema.name) f.schema.name = o.name;
        if (/AggregateRating/.test([].concat(o['@type']).join(' ')) && !f.rating) f.rating = { value: +o.ratingValue, count: +(o.reviewCount || o.ratingCount) };
        if (/^Review$/.test([].concat(o['@type']).join(' ')) && f.reviews.length < 50) f.reviews.push({ author: (o.author && (o.author.name || o.author)) || '', rating: o.reviewRating ? +o.reviewRating.ratingValue : null, text: String(o.reviewBody || o.description || '').slice(0, 600), page: page });
      });
    });
    // Structured hours "Mo-Sa 08:00-18:00" in the same shape as text hours.
    if (f.schema.hours) f.schema.hoursNorm = f.schema.hours.split(/,\s*/).map(function (h) { var m = h.match(/^(Mo|Tu|We|Th|Fr|Sa|Su)(?:-(Mo|Tu|We|Th|Fr|Sa|Su))?\s+(\d{2}):(\d{2})-(\d{2}):(\d{2})$/); return m ? DAYS[dayIdx(m[1])] + (m[2] ? '–' + DAYS[dayIdx(m[2])] : '') + ' ' + m[3] + ':' + m[4] + '–' + m[5] + ':' + m[6] : h; });
    return f;
  }

  function factFindings(f) {
    var out = [], list = function (bag) { return Object.keys(bag).map(function (k) { return bag[k]; }); };
    var where = function (x) { return x.value + ' (' + x.pages.join(', ') + ')'; };
    var phones = list(f.phones);
    if (phones.length > 1) out.push(risk('facts-phone', 'Phone numbers disagree', 'high', 'The site shows ' + phones.length + ' different numbers: ' + phones.map(where).join('; ') + '.', 'Customers call the wrong number and give up; AI assistants pick one at random.', 'Use one number everywhere, including the Google listing.'));
    var hours = list(f.hours);
    if (hours.length > 1) out.push(risk('facts-hours', 'Opening hours disagree', 'high', 'The site gives ' + hours.length + ' different opening hours: ' + hours.map(where).join('; ') + '.', 'Customers turn up to a closed shop. Reviews already mention it on this demo site.', 'Pick the right hours, update every page and the Google listing.'));
    var prices = Object.keys(f.prices).map(function (k) { return f.prices[k]; }).filter(function (p) { return Object.keys(p.seen).length > 1; });
    if (prices.length) out.push(risk('facts-price', 'Prices disagree', 'high', prices.slice(0, 3).map(function (p) { return p.item + ': ' + list(p.seen).map(where).join(' vs '); }).join('; ') + '.', 'Charging more than a published price breaks consumer-protection rules and trust.', 'Correct the price on every page, then check the listings and menus.'));
    var pcs = list(f.postcodes);
    if (pcs.length > 1) out.push(risk('facts-address', 'Addresses disagree', 'medium', pcs.map(where).join('; ') + '.', 'Deliveries and visitors go to the wrong place.', 'Use one address everywhere.'));
    if (f.schema.telephone && phones.length && !f.phones[digits(f.schema.telephone)]) out.push(risk('facts-schema-phone', 'Search data shows a different number', 'medium', 'The structured data tells Google and AI assistants ' + f.schema.telephone + ', which no page shows.', 'Google and AI answers repeat the structured data, not the page.', 'Make the structured data match the visible number.'));
    if (f.schema.hoursNorm && hours.length && f.schema.hoursNorm.some(function (h) { return !f.hours[h]; })) out.push(risk('facts-schema-hours', 'Search data shows different hours', 'medium', 'The structured data says ' + f.schema.hoursNorm.join(', ') + '; pages say ' + hours.map(function (h) { return h.value; }).join(', ') + '.', 'Google shows the structured-data hours in search and Maps.', 'Make the structured data match the real hours.'));
    if (!out.length) out.push(ok('facts', 'Facts agree', 'Phone, hours, prices and address agree across ' + crawl.pages.length + ' pages.'));
    return out;
  }

  // ---------------- compare ----------------
  var ROWS = [['dmarc', 'Fake-email protection'], ['spf', 'Approved senders'], ['dnssec', 'Signed DNS'], ['caa', 'Certificate issuers locked'], ['ports', 'Exposed services'], ['observatory', 'Mozilla grade'], ['lock', 'Domain transfer lock'], ['expiry', 'Domain paid until'], ['age', 'Domain age'], ['rank', 'Popularity'], ['archive', 'Online since'], ['score', 'Public security score']];
  async function profile(d) {
    var parts = await Promise.all([email(d), dnsHygiene(d), registry(d), observatory(d), exposedServices(d), rank(d), archive(d)].map(function (p) { return p.catch(function () { return []; }); }));
    var res = [].concat.apply([], parts), row = {};
    res.forEach(function (r) { var id = /^ports/.test(r.id) ? 'ports' : r.id; if (!row[id] || r.status === 'risk') row[id] = r; });
    row.score = { v: score(res).security, status: 'score' };
    return { domain: d, row: row };
  }

  // Largest Contentful Paint for this visit, recorded from the start.
  try { new PerformanceObserver(function (l) { var e = l.getEntries(); window.__webpawliceLcp = e[e.length - 1].startTime; }).observe({ type: 'largest-contentful-paint', buffered: true }); } catch (e) { /* unsupported */ }

  // ---------------- UI (shadow DOM, so the host site's CSS never leaks in or out) ----------------
  var host = document.createElement('div');
  host.setAttribute('data-webpawlice', '');
  var root = host.attachShadow({ mode: 'open' });
  var side = ds.position === 'left' ? 'left' : 'right';
  root.innerHTML = '<style>' +
    ':host{all:initial}*{box-sizing:border-box}' +
    '.w{--bg:#fff;--sunk:#EEF1F7;--ink:#151A26;--muted:#5A6275;--line:#D9DDE6;--brand:#2344C4;--good:#1D7349;--goodbg:#E2F3EA;--warn:#8A5A00;--warnbg:#FBF0D5;--bad:#B42318;--badbg:#FDE7E4;--crit:#9B1C1C;--oncrit:#fff;--onbrand:#fff;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink)}' +
    '@media (prefers-color-scheme:dark){.w{--bg:#161B25;--sunk:#1F2533;--ink:#E8EBF2;--muted:#9BA3B5;--line:#2C3446;--brand:#8FA6FF;--good:#63C796;--goodbg:#12291F;--warn:#F2BE4B;--warnbg:#33270B;--bad:#FF8A7A;--badbg:#3A1512;--crit:#FF8A7A;--oncrit:#1A0B08;--onbrand:#0E1118}}' +
    '.fab{position:fixed;bottom:max(20px,env(safe-area-inset-bottom));' + side + ':max(20px,env(safe-area-inset-' + side + '));z-index:2147483646;display:flex;align-items:center;gap:8px;border:0;border-radius:999px;padding:10px 16px 10px 12px;background:var(--brand);color:var(--onbrand);font:600 14px system-ui,sans-serif;cursor:pointer;box-shadow:0 6px 20px rgba(20,30,70,.28)}' +
    '.fab svg{width:22px;height:22px}' +
    '.panel{position:fixed;bottom:max(80px,calc(env(safe-area-inset-bottom) + 80px));' + side + ':max(16px,env(safe-area-inset-' + side + '));z-index:2147483647;width:min(460px,calc(100vw - 32px));max-height:min(680px,calc(100vh - 110px));overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 50px rgba(10,15,40,.3)}' +
    '.head{position:sticky;top:0;z-index:1;background:var(--bg);padding:14px 16px 10px;border-bottom:1px solid var(--line);display:grid;gap:6px}' +
    '.head h2{margin:0;font-size:17px;color:var(--brand);letter-spacing:-.01em}' +
    '.dom,.step{font:12px ui-monospace,Menlo,monospace;color:var(--muted);overflow-wrap:anywhere}.step{min-height:16px}' +
    '.nav{display:flex;gap:4px;background:var(--sunk);border-radius:10px;padding:3px}' +
    '.nav button{flex:1;font:600 12.5px system-ui,sans-serif;border:0;background:none;color:var(--muted);padding:6px 4px;border-radius:8px;cursor:pointer}' +
    '.nav button[aria-pressed="true"]{background:var(--bg);color:var(--ink);box-shadow:0 1px 2px rgba(0,0,0,.1)}' +
    '.body{padding:12px 16px 4px;display:grid;gap:12px}' +
    '.verdict{font-size:16px;font-weight:700}' +
    '.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{font:600 12px system-ui,sans-serif;border-radius:999px;padding:3px 9px;background:var(--sunk);color:var(--muted)}' +
    '.chip.critical{background:var(--crit);color:var(--oncrit)}.chip.high{background:var(--badbg);color:var(--bad)}.chip.medium{background:var(--warnbg);color:var(--warn)}' +
    'h3{margin:4px 0 0;font:700 11px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.07em;color:var(--muted)}' +
    '.list{list-style:none;margin:0;padding:0;display:grid;gap:8px}' +
    '.list li{border:1px solid var(--line);border-radius:10px;padding:9px 11px;display:grid;gap:4px}' +
    '.list li.critical{border-color:var(--crit)}' +
    '.list p{margin:0}.why,.fix{font-size:13px;color:var(--muted)}.why b,.fix b{color:var(--ink);font-weight:600}' +
    '.pill{display:inline-block;font:700 10px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.05em;border-radius:999px;padding:2px 7px;margin-right:6px;vertical-align:1px}' +
    '.pill.critical{background:var(--crit);color:var(--oncrit)}.pill.high,.pill.bad{background:var(--badbg);color:var(--bad)}.pill.medium,.pill.warn{background:var(--warnbg);color:var(--warn)}.pill.low,.pill.info,.pill.skip{background:var(--sunk);color:var(--muted)}.pill.good{background:var(--goodbg);color:var(--good)}' +
    'details{border-top:1px solid var(--line);padding-top:8px}summary{cursor:pointer;font-weight:600;padding:2px 0 6px}' +
    'table{border-collapse:collapse;width:100%;font-size:12.5px}th,td{text-align:left;vertical-align:top;padding:6px 8px 6px 0;border-bottom:1px solid var(--line)}th{font-weight:600;color:var(--muted)}' +
    'td.good{color:var(--good)}td.risk{color:var(--bad);font-weight:600}' +
    '.tw{overflow-x:auto}' +
    '.row{display:flex;gap:6px;flex-wrap:wrap;align-items:center}' +
    'input{font:13px system-ui,sans-serif;color:var(--ink);background:var(--sunk);border:1px solid var(--line);border-radius:8px;padding:7px 9px;flex:1 1 200px;min-width:0}' +
    '.muted{color:var(--muted)}.small{font-size:12.5px}' +
    '.bar{display:flex;gap:8px;flex-wrap:wrap;padding:10px 16px 16px}' +
    'button.b{font:600 13px system-ui,sans-serif;border-radius:8px;padding:7px 12px;border:1px solid var(--brand);background:none;color:var(--brand);cursor:pointer}' +
    'button.b.solid{background:var(--brand);color:var(--onbrand)}button.b:disabled{opacity:.5;cursor:default}' +
    '.foot{padding:0 16px 16px;color:var(--muted);font-size:11.5px}' +
    'button:focus-visible,input:focus-visible{outline:2px solid var(--brand);outline-offset:2px}' +
    '@media (prefers-reduced-motion:no-preference){.panel{animation:in .18s ease-out}@keyframes in{from{opacity:0;transform:translateY(8px)}}}' +
    '</style>' +
    '<div class="w">' +
    '<button class="fab" type="button" aria-expanded="false" aria-controls="wp-panel"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><ellipse cx="6" cy="9" rx="2.1" ry="2.7"/><ellipse cx="10" cy="5.6" rx="2.1" ry="2.8"/><ellipse cx="14.2" cy="5.6" rx="2.1" ry="2.8"/><ellipse cx="18.2" cy="9" rx="2.1" ry="2.7"/><path d="M12 11c-3.3 0-6.2 3.6-6.2 6.4 0 1.8 1.4 2.6 3 2.6 1.3 0 2-.6 3.2-.6s1.9.6 3.2.6c1.6 0 3-.8 3-2.6C18.2 14.6 15.3 11 12 11z"/></svg><span class="lab">Check this site</span></button>' +
    '<div class="panel" id="wp-panel" role="dialog" aria-label="WebPawlice check-up" hidden>' +
    '<div class="head"><h2>WebPawlice</h2><div class="dom"></div>' +
    '<div class="nav" role="group" aria-label="Views"><button type="button" data-v="risks" aria-pressed="true">Risks</button><button type="button" data-v="launch" aria-pressed="false">Launch guard</button><button type="button" data-v="facts" aria-pressed="false">Facts</button><button type="button" data-v="compare" aria-pressed="false">Compare</button></div>' +
    '<div class="step" aria-live="polite"></div></div>' +
    '<div class="body"></div>' +
    '<div class="bar"><button class="b rescan" type="button">Check again</button><button class="b copy" type="button">Copy report</button></div>' +
    '<div class="foot">Prototype by Webpuppies. Public records (DNS, registries, certificate logs, Mozilla, Shodan InternetDB, OSV.dev, WordPress.org) and read-only visits to this site\'s own pages. Never submits forms or logs in.</div>' +
    '</div></div>';

  var $ = function (s) { return root.querySelector(s); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); };
  var report = null, running = false, view = 'risks', launch = null, facts = null, compare = null, busy = {};
  $('.dom').textContent = domain + (onSite ? ' · installed here' : ' · public records only');
  var setStep = function (t) { $('.step').textContent = t; };

  function item(r) {
    var lvl = r.status === 'risk' ? r.risk : r.status;
    return '<li class="' + esc(lvl) + '"><p><span class="pill ' + esc(lvl) + '">' + esc(r.status === 'risk' ? SEV_LABEL[r.risk] : LABEL[r.status]) + '</span><b>' + esc(r.name) + '.</b> ' + esc(r.finding) + '</p>' +
      (r.why ? '<p class="why"><b>Why it matters.</b> ' + esc(r.why) + '</p>' : '') + (r.fix ? '<p class="fix"><b>Fix.</b> ' + esc(r.fix) + '</p>' : '') + '</li>';
  }
  function riskBlock(results, emptyText) {
    var rs = results.filter(function (r) { return r.status === 'risk'; }).sort(function (a, b) { return SEV[a.risk] - SEV[b.risk]; });
    var c = { critical: 0, high: 0, medium: 0, low: 0 }; rs.forEach(function (r) { c[r.risk]++; });
    var urgent = c.critical + c.high;
    var verdict = c.critical ? c.critical + ' critical risk' + (c.critical > 1 ? 's' : '') + ' to fix today' : c.high ? c.high + ' high risk' + (c.high > 1 ? 's' : '') + ' to fix this week' : c.medium ? 'Nothing urgent. ' + c.medium + ' to tighten.' : emptyText;
    var group = function (title, levels) { var g = rs.filter(function (r) { return levels.indexOf(r.risk) > -1; }); return g.length ? '<h3>' + title + ' · ' + g.length + '</h3><ul class="list">' + g.map(item).join('') + '</ul>' : ''; };
    return { urgent: urgent, html: '<div class="verdict">' + esc(verdict) + '</div><div class="chips">' + ['critical', 'high', 'medium', 'low'].map(function (k) { return '<span class="chip ' + (c[k] ? k : '') + '">' + c[k] + ' ' + SEV_LABEL[k].toLowerCase() + '</span>'; }).join('') + '</div>' +
      group('Fix first', ['critical', 'high']) + group('Fix soon', ['medium']) + group('Worth tightening', ['low']) };
  }

  function renderRisks() {
    if (!report) { $('.body').innerHTML = '<p class="muted">Checking…</p>'; return; }
    var b = riskBlock(report.results, 'No risks found in what was checked.');
    var passed = report.results.filter(function (r) { return r.area === 'security' && r.status !== 'risk' && r.status !== 'skip'; });
    var other = report.results.filter(function (r) { return r.area !== 'security' && r.status !== 'skip'; }).sort(function (a, b) { return ORDER[a.status] - ORDER[b.status]; });
    var skipped = report.results.filter(function (r) { return r.status === 'skip'; });
    $('.body').innerHTML = b.html +
      (passed.length ? '<details><summary>Passed · ' + passed.length + '</summary><ul class="list">' + passed.map(item).join('') + '</ul></details>' : '') +
      (other.length ? '<details><summary>Beyond security: search, AI, speed, access · ' + (report.other == null ? '–' : report.other) + '/100</summary><ul class="list">' + other.map(item).join('') + '</ul></details>' : '') +
      (skipped.length ? '<details><summary>Not run · ' + skipped.length + '</summary><ul class="list">' + skipped.map(item).join('') + '</ul></details>' : '');
    $('.fab .lab').textContent = 'WebPawlice · ' + (b.urgent ? b.urgent + ' urgent' : 'no urgent risks');
  }

  function needsInstall(what) { return '<p class="muted">' + what + ' reads the site\'s own pages, so it runs only when the script is installed on ' + esc(domain) + '. Try it on the demo site, or use Compare for public records.</p>'; }

  function renderLaunch() {
    if (!onSite) { $('.body').innerHTML = needsInstall('Launch guard'); return; }
    if (!launch) { $('.body').innerHTML = '<p>Walks up to 25 pages the way a visitor would and checks what breaks before go-live: dead pages and images, staging leftovers, pages hidden from Google, placeholder text, insecure forms, dead outside links.</p><div class="row"><button class="b solid run-launch" type="button"' + (busy.crawl ? ' disabled' : '') + '>' + (busy.crawl ? 'Walking the site…' : 'Walk the site') + '</button></div>'; return; }
    var b = riskBlock(launch.results, 'Ready to launch: nothing broken found.');
    $('.body').innerHTML = '<p class="small muted">Walked ' + crawl.pages.length + ' pages' + (crawl.capped ? ' (stopped at 25)' : '') + ', ' + crawl.imgCount + ' images, ' + crawl.extCount + ' outside sites.</p>' + b.html +
      '<details><summary>Pages walked · ' + crawl.pages.length + '</summary><div class="tw"><table><thead><tr><th>Page</th><th>Status</th><th>Title</th></tr></thead><tbody>' + crawl.pages.map(function (p) { return '<tr><td>' + esc(p.url.replace(location.origin, '')) + '</td><td class="' + (p.ok ? 'good' : 'risk') + '">' + esc(p.status || 'no answer') + '</td><td>' + esc(p.title || '') + '</td></tr>'; }).join('') + '</tbody></table></div></details>';
  }

  function renderFacts() {
    if (!onSite) { $('.body').innerHTML = needsInstall('Facts'); return; }
    if (!facts) { $('.body').innerHTML = '<p>Collects phone numbers, opening hours, prices, address and reviews from every page and the search data, and shows where the site contradicts itself. Copy the result into the WebPawlice page to compare it with an AI assistant\'s answer and the Google listing, and to get one summary of the reviews.</p><div class="row"><button class="b solid run-facts" type="button"' + (busy.crawl ? ' disabled' : '') + '>' + (busy.crawl ? 'Reading the pages…' : 'Collect the facts') + '</button></div>'; return; }
    var f = facts.data, b = riskBlock(facts.results, 'Phone, hours, prices and address agree everywhere.');
    var row = function (label, bag) { var xs = Object.keys(bag).map(function (k) { return bag[k]; }); return '<tr><th>' + label + '</th><td>' + (xs.length ? xs.map(function (x) { return esc(x.value) + ' <span class="muted">(' + esc(x.pages.join(', ')) + ')</span>'; }).join('<br>') : '<span class="muted">not found</span>') + '</td></tr>'; };
    var prices = Object.keys(f.prices).map(function (k) { var p = f.prices[k]; return esc(p.item) + ': ' + Object.keys(p.seen).map(function (s) { return esc(p.seen[s].value) + ' <span class="muted">(' + esc(p.seen[s].pages.join(', ')) + ')</span>'; }).join(', '); });
    var avg = f.reviews.length ? (f.reviews.reduce(function (s, r) { return s + (r.rating || 0); }, 0) / f.reviews.filter(function (r) { return r.rating; }).length).toFixed(1) : null;
    $('.body').innerHTML = b.html + '<h3>What the site says</h3><div class="tw"><table><tbody>' + row('Phone', f.phones) + row('Email', f.emails) + row('Hours', f.hours) + row('Postcode', f.postcodes) +
      '<tr><th>Prices</th><td>' + (prices.join('<br>') || '<span class="muted">not found</span>') + '</td></tr>' +
      '<tr><th>Search data</th><td>' + esc([f.schema.name, f.schema.telephone, f.schema.hours, f.schema.postcode].filter(Boolean).join(' · ') || 'none') + '</td></tr>' +
      '<tr><th>Reviews</th><td>' + (f.reviews.length ? f.reviews.length + ' on the site, average ' + avg + (f.rating ? ' (listed rating ' + f.rating.value + ' from ' + f.rating.count + ')' : '') : '<span class="muted">none on the site</span>') + '</td></tr>' +
      '</tbody></table></div><p class="small muted">Google reviews and listings need a Google key on the relay (next step). Today: copy the report and paste it into the WebPawlice page, where Claude summarises the reviews and checks its own answer about the business against these facts.</p>';
  }

  function renderCompare() {
    var input = '<div class="row"><input class="comp" aria-label="Competitor domains, comma separated" placeholder="competitor1.sg, competitor2.sg" value="' + esc(compareAsked.join(', ')) + '"><button class="b solid run-compare" type="button"' + (busy.compare ? ' disabled' : '') + '>' + (busy.compare ? 'Comparing…' : 'Compare') + '</button></div>';
    if (!compare) { $('.body').innerHTML = '<p>Runs the public-record checks on ' + esc(domain) + ' and up to three competitors, side by side: email protection, exposed services, Mozilla grade, domain age, popularity.</p>' + input; return; }
    var cell = function (r) { if (!r) return '<td class="muted">–</td>'; if (r.status === 'score') return '<td class="' + (r.v >= 80 ? 'good' : r.v < 55 ? 'risk' : '') + '">' + r.v + '</td>'; return '<td class="' + (r.status === 'risk' ? 'risk' : r.status === 'good' ? 'good' : '') + '">' + esc(r.v == null ? (r.status === 'skip' ? 'n/a' : '–') : r.v) + '</td>'; };
    $('.body').innerHTML = input + '<div class="tw"><table><thead><tr><th></th>' + compare.map(function (c, i) { return '<th>' + esc(c.domain) + (i === 0 ? ' (you)' : '') + '</th>'; }).join('') + '</tr></thead><tbody>' +
      ROWS.map(function (r) { return '<tr><th>' + r[1] + '</th>' + compare.map(function (c) { return cell(c.row[r[0]]); }).join('') + '</tr>'; }).join('') + '</tbody></table></div><p class="small muted">Red: a risk. Green: fine. Public records only, so every site is measured the same way.</p>';
  }

  function render() { ({ risks: renderRisks, launch: renderLaunch, facts: renderFacts, compare: renderCompare })[view](); }

  async function runCrawl(then) {
    busy.crawl = true; render();
    try {
      var c = await walk(function (n) { setStep('Walked ' + n + ' pages…'); });
      if (!launch) launch = { results: launchFindings(c) };
      if (!facts) { var data = extractFacts(c); facts = { data: data, results: factFindings(data) }; }
      setStep('Walked ' + c.pages.length + ' pages.');
    } catch (e) { setStep('Could not walk the site: ' + (e.message || e)); }
    busy.crawl = false; render();
    if (then) then();
  }
  async function runCompare() {
    var list = $('.comp').value.split(/[,\s]+/).map(cleanDomain).filter(function (d) { return /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && d !== domain; }).slice(0, 3);
    if (!list.length) { setStep('Type one to three competitor domains.'); return; }
    compareAsked = list; busy.compare = true; render(); setStep('Checking ' + [domain].concat(list).join(', ') + '…');
    compare = await Promise.all([domain].concat(list).map(profile));
    busy.compare = false; setStep('Compared ' + compare.length + ' sites.'); render();
  }

  async function run(force) {
    if (running) return;
    var key = 'webpawlice2:' + domain + ':' + onSite;
    if (!force) {
      try { var c = JSON.parse(localStorage.getItem(key) || 'null'); if (c && Date.now() - c.t < CACHE_MS) { report = c.r; render(); setStep('Checked ' + new Date(c.t).toLocaleString() + '. Press "Check again" for a fresh check.'); return; } } catch (e) { /* storage blocked */ }
    }
    running = true; $('.rescan').disabled = true;
    var results = thisPage();
    var steps = [['email', function () { return email(domain); }], ['DNS', function () { return dnsHygiene(domain); }], ['registry', function () { return registry(domain); }], ['certificate logs', function () { return certs(domain); }], ['Mozilla', function () { return observatory(onSite ? location.hostname : domain); }], ['exposed services', function () { return exposedServices(onSite ? location.hostname : domain); }], ['popularity', function () { return rank(domain); }], ['archive', function () { return archive(domain); }], ['site headers', siteHeaders], ['leaked files', leakedFiles], ['page code', pageCode], ['WordPress', wordpress], ['look-alikes', function () { return lookalikes(domain, function (d, t) { setStep('Looking up look-alike domains ' + d + '/' + t + '…'); }); }]];
    setStep('Checking ' + steps.map(function (s) { return s[0]; }).join(', ') + '…');
    var update = function () { report = Object.assign({ tool: 'WebPawlice', domain: domain, scannedAt: new Date().toISOString(), installedHere: onSite, results: results }, score(results)); if (view === 'risks') render(); };
    update();
    await Promise.all(steps.map(function (s) {
      return Promise.resolve().then(s[1]).then(function (rs) { results.push.apply(results, rs); }, function (e) { results.push(na(s[0], s[0], 'Could not run: ' + (e.message || e))); }).then(update);
    }));
    setStep('Done. ' + results.length + ' checks.');
    try { localStorage.setItem(key, JSON.stringify({ t: Date.now(), r: report })); } catch (e) { /* storage blocked */ }
    running = false; $('.rescan').disabled = false;
  }

  $('.fab').addEventListener('click', function () {
    var p = $('.panel'), open = p.hidden;
    p.hidden = !open; $('.fab').setAttribute('aria-expanded', String(open));
    if (open) run(false);
  });
  root.addEventListener('click', function (e) {
    var t = e.target.closest('button');
    if (!t) return;
    if (t.dataset.v) { view = t.dataset.v; root.querySelectorAll('.nav button').forEach(function (b) { b.setAttribute('aria-pressed', String(b === t)); }); render(); }
    else if (t.classList.contains('run-launch') || t.classList.contains('run-facts')) runCrawl();
    else if (t.classList.contains('run-compare')) runCompare();
  });
  root.addEventListener('keydown', function (e) { if (e.key === 'Enter' && e.target.classList && e.target.classList.contains('comp')) runCompare(); });
  $('.rescan').addEventListener('click', function () { crawl = null; launch = null; facts = null; run(true); if (view === 'launch' || view === 'facts') runCrawl(); });
  $('.copy').addEventListener('click', function () {
    if (!report) return;
    var out = Object.assign({}, report, {
      launch: launch ? { pages: crawl.pages.length, results: launch.results } : undefined,
      facts: facts ? { data: facts.data, results: facts.results } : undefined,
      compare: compare ? compare.map(function (c) { var r = {}; Object.keys(c.row).forEach(function (k) { r[k] = { v: c.row[k].v, status: c.row[k].status, risk: c.row[k].risk }; }); return { domain: c.domain, row: r }; }) : undefined,
    });
    navigator.clipboard.writeText(JSON.stringify(out)).then(function () { $('.copy').textContent = 'Copied'; }, function () { $('.copy').textContent = 'Copy blocked by browser'; });
  });
  window.WebPawlice = {
    open: function () { if ($('.panel').hidden) $('.fab').click(); },
    report: function () { return report; },
    show: function (v) { var b = root.querySelector('.nav button[data-v="' + v + '"]'); if (b) b.click(); },
    launch: function () { return new Promise(function (res) { runCrawl(function () { res({ launch: launch, facts: facts && { data: facts.data, results: facts.results } }); }); }); },
    compare: function (list) { compareAsked = list; view = 'compare'; render(); return runCompare().then(function () { return compare; }); },
  };

  (document.body ? Promise.resolve() : new Promise(function (r) { document.addEventListener('DOMContentLoaded', r); })).then(function () {
    document.body.appendChild(host);
    if (compareAsked.length && /[?&]compare=/.test(location.search)) { view = 'compare'; root.querySelectorAll('.nav button').forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.v === 'compare')); }); }
    if (triggered || ds.open === 'true') $('.fab').click();
  });
})();
