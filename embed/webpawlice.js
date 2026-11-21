/*!
 * WebPawlice embed — PROTOTYPE by Webpuppies. Throwaway code.
 *
 *   <script src="https://cyril-wp.github.io/webpawlice-prototype/embed/webpawlice.js" defer></script>
 *
 * Visitors see nothing and nothing runs for them. The owner opens their own site with
 * ?webpawlice (or #webpawlice) and a check-up panel appears. Because the script runs on the
 * site itself, it can read the site's own headers, robots.txt and page, which a third-party
 * scanner cannot do from a browser.
 *
 * Options (attributes on the script tag):
 *   data-show="always"     show the paw button to everyone (demos only)
 *   data-domain="x.sg"     check another domain's public records (page checks then stay off)
 *   data-position="left"   put the button bottom-left
 *
 * Passive only: public DNS, registries, certificate logs, Mozilla Observatory, Tranco,
 * Internet Archive, and reads of this site's own pages. No probing, no load, no form tests.
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
  var AREAS = { safe: 'Safe', trust: 'Trusted', found: 'Found', works: 'Works' };
  var WEIGHT = { good: 1, info: 0.8, warn: 0.5, bad: 0 };
  var ORDER = { bad: 0, warn: 1, info: 2, good: 3, skip: 4 };
  var LABEL = { good: 'Fine', warn: 'Improve', bad: 'Fix now', info: 'Note', skip: 'Not run' };
  var CACHE_MS = 12 * 3600 * 1000;

  function registrable(host) {
    host = String(host).toLowerCase().replace(/^www\./, '').replace(/:\d+$/, '');
    var suffix = TWO.find(function (s) { return host === s || host.endsWith('.' + s); }) || host.split('.').slice(-1)[0];
    if (host === suffix) return host;
    var rest = host.slice(0, -(suffix.length + 1));
    return rest.split('.').pop() + '.' + suffix;
  }

  var here = registrable(location.hostname);
  // ?webpawlice=other.sg checks another domain's public records (used by the demo page's "try any domain").
  var asked = (location.search.match(/[?&]webpawlice=([a-z0-9.-]+\.[a-z]{2,})/i) || [])[1];
  var domain = asked ? registrable(asked) : ds.domain ? registrable(ds.domain) : here;
  var onSite = domain === here && /^https?:$/.test(location.protocol);

  // ---------------- sources ----------------
  function getJson(url, opts) {
    opts = opts || {};
    var ctl = new AbortController();
    var t = setTimeout(function () { ctl.abort(); }, opts.timeout || 15000);
    return fetch(url, { method: opts.method || 'GET', headers: opts.headers || {}, signal: ctl.signal, credentials: 'omit' })
      .then(function (r) { if (!r.ok) throw new Error(r.status + ' from ' + new URL(url).host); return r.json(); })
      .finally(function () { clearTimeout(t); });
  }
  function doh(name, type) {
    var qs = 'name=' + encodeURIComponent(name) + '&type=' + type;
    return getJson('https://cloudflare-dns.com/dns-query?' + qs, { headers: { accept: 'application/dns-json' }, timeout: 8000 })
      .catch(function () { return getJson('https://dns.google/resolve?' + qs, { timeout: 8000 }); });
  }
  function txt(r) { return (r.Answer || []).filter(function (a) { return a.type === 16; }).map(function (a) { return a.data.replace(/^"|"$/g, '').replace(/"\s*"/g, ''); }); }
  function R(id, area, name, status, finding) { return { id: id, area: area, name: name, status: status, finding: finding }; }

  // ---------------- checks ----------------
  async function email() {
    var r = await Promise.all([doh(domain, 'TXT'), doh('_dmarc.' + domain, 'TXT'), doh(domain, 'MX'), doh('_mta-sts.' + domain, 'TXT')]);
    var spf = txt(r[0]).find(function (t) { return t.indexOf('v=spf1') === 0; });
    var dmarc = txt(r[1]).find(function (t) { return /^v=dmarc1/i.test(t); });
    var policy = dmarc && ((dmarc.match(/;\s*p=(\w+)/i) || [])[1] || '').toLowerCase();
    var mx = (r[2].Answer || []).some(function (a) { return a.type === 15; });
    var out = [];
    if (!dmarc) out.push(R('dmarc', 'safe', 'Email pretending to be you', 'bad', 'Anyone can send email that looks like it comes from @' + domain + '. No DMARC record tells inboxes to reject it.'));
    else if (policy === 'none') out.push(R('dmarc', 'safe', 'Email pretending to be you', 'warn', 'DMARC is set to monitor only (p=none), so fake email still reaches inboxes.'));
    else out.push(R('dmarc', 'safe', 'Email pretending to be you', 'good', 'Inboxes are told to ' + (policy === 'reject' ? 'reject' : 'quarantine') + ' email that fakes your address.'));
    if (!spf) out.push(R('spf', 'safe', 'Approved senders (SPF)', mx ? 'bad' : 'warn', 'No SPF record lists which servers may send your email.'));
    else if (/[?+]all\b/.test(spf)) out.push(R('spf', 'safe', 'Approved senders (SPF)', 'bad', 'SPF ends in a permissive rule, so any server may send as you.'));
    else out.push(R('spf', 'safe', 'Approved senders (SPF)', spf.indexOf('-all') > -1 ? 'good' : 'warn', spf.indexOf('-all') > -1 ? 'SPF is strict.' : 'SPF is soft (~all): unlisted senders are flagged, not blocked.'));
    out.push(R('mta-sts', 'safe', 'Email encrypted in transit', txt(r[3]).length ? 'good' : 'info', txt(r[3]).length ? 'MTA-STS is on.' : 'MTA-STS not set up. Optional; banks and governments use it.'));
    return out;
  }

  async function dns() {
    var r = await Promise.all([doh(domain, 'CAA'), doh(domain, 'A')]);
    var caa = (r[0].Answer || []).filter(function (x) { return x.type === 257; });
    return [
      R('dnssec', 'safe', 'Signed DNS (DNSSEC)', r[1].AD ? 'good' : 'info', r[1].AD ? 'DNS answers are signed, so they cannot be silently forged.' : 'DNS answers are not signed. Common, but a gap attackers can use to redirect visitors.'),
      R('caa', 'safe', 'Who may issue certificates (CAA)', caa.length ? 'good' : 'warn', caa.length ? 'Only named certificate authorities may issue for you.' : 'Any certificate authority may issue a certificate for your name. One DNS line fixes this.'),
    ];
  }

  async function registry() {
    try {
      var boot = await getJson('https://data.iana.org/rdap/dns.json', { timeout: 10000 });
      var tld = domain.split('.').pop();
      var hit = boot.services.find(function (s) { return s[0].indexOf(tld) > -1; });
      if (!hit) throw new Error('none');
      var r = await getJson(hit[1][0].replace(/\/?$/, '/') + 'domain/' + domain, { timeout: 10000, headers: { accept: 'application/rdap+json' } });
      var ev = {}; (r.events || []).forEach(function (e) { ev[e.eventAction] = e.eventDate; });
      var out = [];
      if (ev.registration) {
        var yrs = (Date.now() - new Date(ev.registration)) / 31557600000;
        out.push(R('age', 'trust', 'Domain age', yrs >= 3 ? 'good' : yrs >= 1 ? 'info' : 'warn', 'Registered ' + ev.registration.slice(0, 10) + ', ' + yrs.toFixed(1) + ' years ago.'));
      }
      if (ev.expiration) {
        var days = Math.round((new Date(ev.expiration) - Date.now()) / 86400000);
        out.push(R('expiry', 'safe', 'Domain renewal', days < 30 ? 'bad' : days < 90 ? 'warn' : 'good', 'Renews by ' + ev.expiration.slice(0, 10) + ' (' + days + ' days).' + (days < 90 ? ' Check auto-renew is on.' : '')));
      }
      return out;
    } catch (e) {
      return [R('rdap', 'trust', 'Domain registration', 'skip', 'The .' + domain.split('.').pop() + ' registry publishes no public registration dates, so age and renewal are not readable here.')];
    }
  }

  async function certs() {
    try {
      var rows = await getJson('https://api.certspotter.com/v1/issuances?domain=' + domain + '&include_subdomains=true&expand=dns_names', { timeout: 15000 });
      var names = {}; rows.forEach(function (r) { (r.dns_names || []).forEach(function (n) { names[n] = 1; }); });
      var list = Object.keys(names).filter(function (n) { return n.charAt(0) !== '*'; });
      if (!rows.length) return [R('ct', 'safe', 'Certificates and hidden subdomains', 'info', 'No certificates in public logs name ' + domain + ' directly (it may share its host\'s certificate).')];
      return [R('ct', 'safe', 'Certificates and hidden subdomains', list.length > 25 ? 'warn' : 'info', rows.length + ' live certificates name ' + Object.keys(names).length + ' hosts, e.g. ' + list.slice(0, 5).join(', ') + '. Forgotten ones (old staging, test) are a common way in.')];
    } catch (e) {
      return [R('ct', 'safe', 'Certificates and hidden subdomains', 'skip', 'Certificate log did not answer (free limit is 100 lookups an hour).')];
    }
  }

  async function observatory() {
    try {
      // Must stay a "simple" POST: Observatory v2 rejects preflighted requests.
      var res = await fetch('https://observatory-api.mdn.mozilla.net/api/v2/scan?host=' + (onSite ? location.hostname : domain), { method: 'POST', credentials: 'omit' });
      var r = await res.json();
      if (!r.grade) return [R('observatory', 'safe', 'Mozilla security grade', 'skip', 'Mozilla Observatory could not grade the site: ' + (r.message || r.error || res.status) + '.')];
      var g = r.grade[0];
      return [R('observatory', 'safe', 'Mozilla security grade', g === 'A' ? 'good' : g === 'B' || g === 'C' ? 'warn' : 'bad', 'Mozilla Observatory grades the site ' + r.grade + ' (' + r.score + '/100), ' + r.tests_passed + ' of ' + r.tests_quantity + ' tests passed.')];
    } catch (e) { return [R('observatory', 'safe', 'Mozilla security grade', 'skip', 'Mozilla Observatory did not answer.')]; }
  }

  async function rank() {
    try {
      var r = await getJson('https://tranco-list.eu/api/ranks/domain/' + domain, { timeout: 8000 });
      var best = (r.ranks || []).map(function (x) { return x.rank; }).sort(function (a, b) { return a - b; })[0];
      return [R('rank', 'trust', 'How well-known', 'info', best ? 'Ranked #' + best.toLocaleString() + ' in the world top million (Tranco).' : 'Not in the world top million. Normal for a local business.')];
    } catch (e) { return []; }
  }

  async function archive() {
    try {
      var r = await getJson('https://archive.org/wayback/available?url=' + domain + '&timestamp=19900101', { timeout: 12000 });
      var ts = r.archived_snapshots && r.archived_snapshots.closest && r.archived_snapshots.closest.timestamp;
      return [R('archive', 'trust', 'First seen on the web', 'info', ts ? 'The Internet Archive first saved this site around ' + ts.slice(0, 4) + '-' + ts.slice(4, 6) + '.' : 'The Internet Archive has no copy of this site.')];
    } catch (e) { return [R('archive', 'trust', 'First seen on the web', 'skip', 'Internet Archive did not answer.')]; }
  }

  // Same-origin reads: possible only because this script runs on the site itself.
  async function ownSite() {
    if (!onSite) return [R('own', 'safe', 'Checks of the site itself', 'skip', 'These run only when the script is installed on ' + domain + ' itself.')];
    var out = [];
    var res = await fetch(location.origin + '/', { cache: 'no-store', credentials: 'omit' });
    var h = function (n) { return res.headers.get(n); };
    var csp = h('content-security-policy') || '';
    var checks = { 'strict-transport-security': 'HSTS', 'content-security-policy': 'CSP', 'x-content-type-options': 'nosniff', 'referrer-policy': 'Referrer-Policy' };
    var missing = Object.keys(checks).filter(function (k) { return !h(k); }).map(function (k) { return checks[k]; });
    if (!h('x-frame-options') && !/frame-ancestors/i.test(csp)) missing.push('clickjacking guard');
    out.push(R('headers', 'safe', 'Browser protection headers', !missing.length ? 'good' : missing.length <= 2 ? 'warn' : 'bad', missing.length ? (5 - missing.length) + ' of 5 protections on. Missing: ' + missing.join(', ') + '.' : 'All five standard protections are on.'));
    var sw = [h('server'), h('x-powered-by')].filter(Boolean).join(' / ');
    var gen = (document.querySelector('meta[name="generator"]') || {}).content || '';
    var shown = [sw, gen].filter(function (s) { return /\d/.test(s); });
    out.push(R('disclosure', 'safe', 'What your site reveals', shown.length ? 'warn' : 'good', shown.length ? 'The site announces its software and version: ' + shown.join('; ') + '. Attackers search for exactly this.' : 'No software versions announced.'));

    var robots = '';
    try { var rr = await fetch(location.origin + '/robots.txt', { credentials: 'omit' }); robots = rr.ok ? await rr.text() : ''; } catch (e) { /* none */ }
    if (/<html/i.test(robots.slice(0, 200))) robots = '';
    var blocked = AI_BOTS.filter(function (b) { return new RegExp('user-agent:\\s*' + b + '\\s*\\n(?:[^\\n]*\\n)*?\\s*disallow:\\s*/\\s*(\\n|$)', 'i').test(robots); });
    var all = /user-agent:\s*\*\s*\n(?:(?!user-agent)[^\n]*\n)*?\s*disallow:\s*\/\s*(\n|$)/i.test(robots);
    out.push(R('ai-bots', 'found', 'AI assistants may read you', all || blocked.length >= 3 ? 'bad' : blocked.length ? 'warn' : 'good', all ? 'robots.txt blocks every crawler, AI assistants included.' : blocked.length ? 'robots.txt blocks ' + blocked.join(', ') + '. Those assistants cannot read the site when customers ask about you.' : 'No AI crawler is blocked.'));
    out.push(R('sitemap', 'found', 'Sitemap announced', /sitemap:/i.test(robots) ? 'good' : 'warn', /sitemap:/i.test(robots) ? 'robots.txt points search engines to a sitemap.' : 'robots.txt does not point to a sitemap.'));
    var llms = false;
    try { var lr = await fetch(location.origin + '/llms.txt', { credentials: 'omit' }); llms = lr.ok && !/<html/i.test((await lr.text()).slice(0, 300)); } catch (e) { /* none */ }
    out.push(R('llms', 'found', 'Summary for AI (llms.txt)', llms ? 'good' : 'info', llms ? 'Publishes llms.txt for AI assistants.' : 'No llms.txt. A short plain-text summary helps assistants describe you correctly.'));
    return out;
  }

  // Reads the live page the owner is looking at.
  function thisPage() {
    if (!onSite) return [];
    var out = [];
    var desc = (document.querySelector('meta[name="description"]') || {}).content;
    out.push(R('title', 'found', 'Search title and description', document.title && desc ? 'good' : 'warn', (document.title ? 'Title: "' + document.title.slice(0, 70) + '". ' : 'No page title. ') + (desc ? 'Has a description.' : 'No description, so Google and AI assistants write their own.')));
    var types = {};
    document.querySelectorAll('script[type="application/ld+json"]').forEach(function (s) { (s.textContent.match(/"@type"\s*:\s*"([^"]+)"/g) || []).forEach(function (m) { types[m.split('"')[3]] = 1; }); });
    var tl = Object.keys(types);
    out.push(R('schema', 'found', 'Facts machines can read', tl.length ? 'good' : 'warn', tl.length ? 'Publishes structured facts: ' + tl.slice(0, 5).join(', ') + '.' : 'No structured facts (hours, address, prices). AI assistants and Google have to guess them.'));
    var imgs = [].slice.call(document.images).filter(function (i) { return i.offsetWidth > 40 && !i.closest('[data-webpawlice]'); });
    var noAlt = imgs.filter(function (i) { return !i.hasAttribute('alt'); }).length;
    out.push(R('alt', 'works', 'Images described for blind visitors', noAlt === 0 ? 'good' : noAlt <= 3 ? 'warn' : 'bad', imgs.length ? (noAlt ? noAlt + ' of ' + imgs.length + ' images have no description (alt text). Screen readers skip them.' : 'All ' + imgs.length + ' images have descriptions.') : 'No images on this page.'));
    var fields = [].slice.call(document.querySelectorAll('input:not([type=hidden]):not([type=submit]):not([type=button]),select,textarea'));
    var unlabeled = fields.filter(function (f) { return !(f.labels && f.labels.length) && !f.getAttribute('aria-label') && !f.getAttribute('aria-labelledby'); }).length;
    if (fields.length) out.push(R('labels', 'works', 'Form fields named', unlabeled ? 'warn' : 'good', unlabeled ? unlabeled + ' of ' + fields.length + ' form fields have no label, so screen readers cannot say what to type.' : 'Every form field has a label.'));
    var mixed = [].slice.call(document.querySelectorAll('img[src^="http:"],script[src^="http:"],link[href^="http:"][rel=stylesheet],iframe[src^="http:"]')).length;
    if (location.protocol === 'https:') out.push(R('mixed', 'safe', 'Everything loads securely', mixed ? 'bad' : 'good', mixed ? mixed + ' items load over plain http:// on a secure page. Browsers block or warn.' : 'Every item on this page loads over https.'));
    var hosts = {};
    performance.getEntriesByType('resource').forEach(function (e) { try { var hh = new URL(e.name).hostname; if (registrable(hh) !== here) hosts[registrable(hh)] = 1; } catch (x) { /* ignore */ } });
    delete hosts[registrable(new URL(script.src || location.href).hostname)];
    var third = Object.keys(hosts);
    out.push(R('third', 'trust', 'Other companies on this page', third.length > 10 ? 'warn' : 'info', third.length ? third.length + ' other companies load code or files here: ' + third.slice(0, 8).join(', ') + (third.length > 8 ? '…' : '') + '. Each one can see your visitors.' : 'No third-party code loads on this page.'));
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

  function lookalikeList() {
    var sfx = TWO.find(function (s) { return domain.endsWith('.' + s); }) || domain.split('.').pop();
    var n = domain.slice(0, -(sfx.length + 1)), tld = '.' + sfx, out = {};
    function add(d) { if (d !== domain && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d) && d.charAt(0) !== '-') out[d] = 1; }
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

  async function lookalikes(progress) {
    var list = lookalikeList(), rows = [], i = 0, done = 0, wild = {};
    var endings = {}; list.forEach(function (d) { endings[d.slice(d.indexOf('.') + 1)] = 1; });
    await Promise.all(Object.keys(endings).map(function (e) {
      return doh('wpl-' + Math.random().toString(36).slice(2, 10) + '.' + e, 'A').then(function (r) { if ((r.Answer || []).length) wild[e] = 1; }, function () { /* ignore */ });
    }));
    var skipped = list.filter(function (d) { return wild[d.slice(d.indexOf('.') + 1)]; }).length;
    list = list.filter(function (d) { return !wild[d.slice(d.indexOf('.') + 1)]; });
    async function worker() {
      while (i < list.length) {
        var d = list[i++];
        try {
          var ns = await doh(d, 'NS');
          if (ns.Status === 0) {
            var mx = await doh(d, 'MX');
            rows.push({ d: d, mail: (mx.Answer || []).some(function (x) { return x.type === 15 && !/^0 \.$/.test(x.data); }) });
          }
        } catch (e) { /* skip */ }
        progress(++done, list.length);
      }
    }
    await Promise.all([worker(), worker(), worker(), worker(), worker(), worker()]);
    var mail = rows.filter(function (r) { return r.mail; });
    return [R('lookalikes', 'safe', 'Look-alike addresses', !list.length ? 'skip' : mail.length ? 'bad' : rows.length ? 'warn' : 'good',
      (skipped ? skipped + ' look-alikes sit under ' + Object.keys(wild).join(', ') + ', where every name answers, so they cannot be judged. ' : '') + list.length + ' addresses could pass for ' + domain + '. ' + rows.length + ' are registered by someone' + (rows.length ? ': ' + rows.slice(0, 5).map(function (r) { return r.d; }).join(', ') + (rows.length > 5 ? '…' : '') : '') + '.' + (mail.length ? ' ' + mail.length + ' can receive email, so they could be used to trick your customers.' : ''))];
  }

  function score(results) {
    var areas = {};
    Object.keys(AREAS).forEach(function (k) {
      var rs = results.filter(function (r) { return r.area === k && r.status in WEIGHT; });
      areas[k] = rs.length ? Math.round(100 * rs.reduce(function (s, r) { return s + WEIGHT[r.status]; }, 0) / rs.length) : null;
    });
    var v = Object.values(areas).filter(function (x) { return x !== null; });
    return { areas: areas, overall: v.length ? Math.round(v.reduce(function (a, b) { return a + b; }, 0) / v.length) : null };
  }

  // Largest Contentful Paint for this visit, recorded from the start.
  try { new PerformanceObserver(function (l) { var e = l.getEntries(); window.__webpawliceLcp = e[e.length - 1].startTime; }).observe({ type: 'largest-contentful-paint', buffered: true }); } catch (e) { /* unsupported */ }

  // ---------------- UI (shadow DOM, so the host site's CSS never leaks in or out) ----------------
  var host = document.createElement('div');
  host.setAttribute('data-webpawlice', '');
  var root = host.attachShadow({ mode: 'open' });
  var side = ds.position === 'left' ? 'left' : 'right';
  root.innerHTML = '<style>' +
    ':host{all:initial}' +
    '*{box-sizing:border-box}' +
    '.w{--bg:#fff;--sunk:#EEF1F7;--ink:#151A26;--muted:#5A6275;--line:#D9DDE6;--brand:#2344C4;--good:#1D7349;--goodbg:#E2F3EA;--warn:#8A5A00;--warnbg:#FBF0D5;--bad:#B42318;--badbg:#FDE7E4;--onbrand:#fff;font:14px/1.45 system-ui,-apple-system,"Segoe UI",sans-serif;color:var(--ink)}' +
    '@media (prefers-color-scheme:dark){.w{--bg:#161B25;--sunk:#1F2533;--ink:#E8EBF2;--muted:#9BA3B5;--line:#2C3446;--brand:#8FA6FF;--good:#63C796;--goodbg:#12291F;--warn:#F2BE4B;--warnbg:#33270B;--bad:#FF8A7A;--badbg:#3A1512;--onbrand:#0E1118}}' +
    '.fab{position:fixed;bottom:max(20px,env(safe-area-inset-bottom));' + side + ':max(20px,env(safe-area-inset-' + side + '));z-index:2147483646;display:flex;align-items:center;gap:8px;border:0;border-radius:999px;padding:10px 16px 10px 12px;background:var(--brand);color:var(--onbrand);font:600 14px system-ui,sans-serif;cursor:pointer;box-shadow:0 6px 20px rgba(20,30,70,.28)}' +
    '.fab svg{width:22px;height:22px}' +
    '.fab b{font-variant-numeric:tabular-nums}' +
    '.panel{position:fixed;bottom:max(80px,calc(env(safe-area-inset-bottom) + 80px));' + side + ':max(16px,env(safe-area-inset-' + side + '));z-index:2147483647;width:min(420px,calc(100vw - 32px));max-height:min(640px,calc(100vh - 110px));overflow:auto;background:var(--bg);border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 50px rgba(10,15,40,.3)}' +
    '.head{position:sticky;top:0;background:var(--bg);padding:16px 16px 10px;border-bottom:1px solid var(--line);display:grid;gap:4px}' +
    '.head h2{margin:0;font-size:17px;color:var(--brand);letter-spacing:-.01em}' +
    '.dom{font:12px ui-monospace,Menlo,monospace;color:var(--muted);overflow-wrap:anywhere}' +
    '.step{font:12px ui-monospace,Menlo,monospace;color:var(--muted);min-height:16px}' +
    '.tiles{display:grid;grid-template-columns:repeat(5,1fr);gap:4px;padding:14px 16px 6px}' +
    '.tile{background:var(--sunk);border-radius:10px;padding:8px 6px;text-align:center}' +
    '.tile b{display:block;font-size:20px;font-variant-numeric:tabular-nums}' +
    '.tile span{font-size:11px;color:var(--muted)}' +
    '.list{list-style:none;margin:0;padding:10px 16px 6px;display:grid;gap:8px}' +
    '.list li{border:1px solid var(--line);border-radius:10px;padding:9px 11px}' +
    '.pill{display:inline-block;font:700 10px system-ui,sans-serif;text-transform:uppercase;letter-spacing:.05em;border-radius:999px;padding:2px 7px;margin-right:6px;vertical-align:1px}' +
    '.good{color:var(--good)}.warn{color:var(--warn)}.bad{color:var(--bad)}.info,.skip{color:var(--muted)}' +
    '.pill.good{background:var(--goodbg)}.pill.warn{background:var(--warnbg)}.pill.bad{background:var(--badbg)}.pill.info,.pill.skip{background:var(--sunk)}' +
    '.bar{display:flex;gap:8px;flex-wrap:wrap;padding:10px 16px 16px}' +
    'button.b{font:600 13px system-ui,sans-serif;border-radius:8px;padding:7px 12px;border:1px solid var(--brand);background:none;color:var(--brand);cursor:pointer}' +
    'button.b:disabled{opacity:.5}' +
    '.foot{padding:0 16px 16px;color:var(--muted);font-size:11.5px}' +
    'button:focus-visible{outline:2px solid var(--brand);outline-offset:2px}' +
    '@media (prefers-reduced-motion:no-preference){.panel{animation:in .18s ease-out}@keyframes in{from{opacity:0;transform:translateY(8px)}}}' +
    '</style>' +
    '<div class="w">' +
    '<button class="fab" type="button" aria-expanded="false" aria-controls="wp-panel"><svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><ellipse cx="6" cy="9" rx="2.1" ry="2.7"/><ellipse cx="10" cy="5.6" rx="2.1" ry="2.8"/><ellipse cx="14.2" cy="5.6" rx="2.1" ry="2.8"/><ellipse cx="18.2" cy="9" rx="2.1" ry="2.7"/><path d="M12 11c-3.3 0-6.2 3.6-6.2 6.4 0 1.8 1.4 2.6 3 2.6 1.3 0 2-.6 3.2-.6s1.9.6 3.2.6c1.6 0 3-.8 3-2.6C18.2 14.6 15.3 11 12 11z"/></svg><span class="lab">Check this site</span></button>' +
    '<div class="panel" id="wp-panel" role="dialog" aria-label="WebPawlice check-up" hidden>' +
    '<div class="head"><h2>WebPawlice</h2><div class="dom"></div><div class="step" aria-live="polite"></div></div>' +
    '<div class="out"></div>' +
    '<div class="bar"><button class="b rescan" type="button">Check again</button><button class="b copy" type="button">Copy report</button></div>' +
    '<div class="foot">Prototype by Webpuppies. Public information only: DNS, registries, certificate logs, Mozilla Observatory, the Internet Archive and this site\'s own pages. No active testing.</div>' +
    '</div></div>';

  var $ = function (s) { return root.querySelector(s); };
  var esc = function (s) { return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; }); };
  var band = function (v) { return v == null ? 'skip' : v >= 80 ? 'good' : v >= 55 ? 'warn' : 'bad'; };
  var report = null, running = false;
  $('.dom').textContent = domain + (onSite ? ' · installed here' : ' · public records only');

  function render() {
    if (!report) return;
    var rows = report.results.slice().sort(function (a, b) { return ORDER[a.status] - ORDER[b.status]; });
    $('.out').innerHTML = '<div class="tiles"><div class="tile"><b class="' + band(report.overall) + '">' + (report.overall == null ? '–' : report.overall) + '</b><span>Overall</span></div>' +
      Object.keys(AREAS).map(function (k) { return '<div class="tile"><b class="' + band(report.areas[k]) + '">' + (report.areas[k] == null ? '–' : report.areas[k]) + '</b><span>' + AREAS[k] + '</span></div>'; }).join('') + '</div>' +
      '<ul class="list">' + rows.map(function (r) { return '<li><span class="pill ' + r.status + '">' + LABEL[r.status] + '</span><b>' + esc(r.name) + '.</b> ' + esc(r.finding) + '</li>'; }).join('') + '</ul>';
    $('.fab .lab').innerHTML = 'WebPawlice <b>' + (report.overall == null ? '–' : report.overall) + '</b>';
  }

  async function run(force) {
    if (running) return;
    var key = 'webpawlice:' + domain + ':' + onSite;
    if (!force) {
      try { var c = JSON.parse(localStorage.getItem(key) || 'null'); if (c && Date.now() - c.t < CACHE_MS) { report = c.r; render(); $('.step').textContent = 'Checked ' + new Date(c.t).toLocaleString() + '.'; return; } } catch (e) { /* storage blocked */ }
    }
    running = true; $('.rescan').disabled = true;
    var results = [];
    var steps = [['public DNS', email], ['DNS hygiene', dns], ['domain registry', registry], ['certificate logs', certs], ['Mozilla Observatory', observatory], ['popularity rank', rank], ['Internet Archive', archive], ['this site', ownSite], ['look-alike addresses', function () { return lookalikes(function (d, t) { $('.step').textContent = 'Resolving look-alike addresses ' + d + '/' + t + '…'; }); }]];
    $('.step').textContent = 'Reading ' + steps.map(function (s) { return s[0]; }).join(', ') + '…';
    results = results.concat(thisPage());
    report = Object.assign({ domain: domain, scannedAt: new Date().toISOString(), installedHere: onSite, results: results }, score(results));
    render();
    await Promise.all(steps.map(function (s) {
      return Promise.resolve().then(s[1]).then(function (rs) { results.push.apply(results, rs); }).catch(function (e) { results.push(R(s[0], 'safe', s[0], 'skip', 'Could not run: ' + (e.message || e))); })
        .then(function () { report = Object.assign({ domain: domain, scannedAt: new Date().toISOString(), installedHere: onSite, results: results }, score(results)); render(); });
    }));
    $('.step').textContent = 'Done. ' + results.length + ' checks.';
    try { localStorage.setItem(key, JSON.stringify({ t: Date.now(), r: report })); } catch (e) { /* storage blocked */ }
    running = false; $('.rescan').disabled = false;
  }

  $('.fab').addEventListener('click', function () {
    var p = $('.panel'), open = p.hidden;
    p.hidden = !open; $('.fab').setAttribute('aria-expanded', String(open));
    if (open) run(false);
  });
  $('.rescan').addEventListener('click', function () { run(true); });
  $('.copy').addEventListener('click', function () {
    if (!report) return;
    navigator.clipboard.writeText(JSON.stringify(report)).then(function () { $('.copy').textContent = 'Copied'; }, function () { $('.copy').textContent = 'Copy blocked by browser'; });
  });
  window.WebPawlice = { open: function () { if ($('.panel').hidden) $('.fab').click(); }, report: function () { return report; } };

  (document.body ? Promise.resolve() : new Promise(function (r) { document.addEventListener('DOMContentLoaded', r); })).then(function () {
    document.body.appendChild(host);
    if (triggered || ds.open === 'true') $('.fab').click();
  });
})();
