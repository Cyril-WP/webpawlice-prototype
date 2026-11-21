// PROTOTYPE — popup: asks for permission to read this one site, starts the scan in the
// service worker, and renders whatever is in chrome.storage.session for the domain.
import { AREAS, normalizeDomain, splitDomain } from './checks.js';

const $ = id => document.getElementById(id);
const ORDER = { bad: 0, warn: 1, info: 2, good: 3, skip: 4 };
const LABEL = { good: 'Fine', warn: 'Improve', bad: 'Fix now', info: 'Note', skip: 'Not run' };
const esc = s => String(s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));

const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
const host = tab?.url?.startsWith('http') ? normalizeDomain(tab.url) : '';
const domain = host ? splitDomain(host).registrable : '';
$('dom').textContent = domain || 'not a website';
$('scan').disabled = !domain;

function render(state) {
  $('step').textContent = state?.step ? `${state.step}…` : state?.error ? `Stopped: ${state.error}` : '';
  $('scan').disabled = !domain || Boolean(state?.step);
  const r = state?.report;
  $('copy').hidden = !r;
  if (!r) { $('out').innerHTML = ''; return; }
  const cls = v => (v == null ? 'skip' : v >= 80 ? 'good' : v >= 55 ? 'warn' : 'bad');
  const rows = [...r.results].sort((a, b) => ORDER[a.status] - ORDER[b.status]);
  $('out').innerHTML = `
    <div class="tiles">${Object.entries(AREAS).map(([k, q]) => `<div class="tile"><b class="${cls(r.areas[k])}">${r.areas[k] ?? '–'}</b><span>${esc(q)}</span></div>`).join('')}</div>
    <ul>${rows.map(x => `<li><span class="pill ${x.status}">${LABEL[x.status]}</span><b>${esc(x.name)}</b><br>${esc(x.finding)}</li>`).join('')}</ul>`;
}

chrome.storage.session.get(domain).then(s => render(s[domain]));
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'session' && changes[domain]) render(changes[domain].newValue);
});

$('scan').onclick = async () => {
  // Permission is per site and asked at the click, so the extension never holds blanket access.
  const origins = [`https://${domain}/*`, `http://${domain}/*`, `https://www.${domain}/*`];
  const ok = await chrome.permissions.request({ origins });
  if (!ok) { $('step').textContent = 'Without permission to read this site, only DNS and registry checks can run.'; }
  chrome.runtime.sendMessage({ type: 'scan', domain, tabId: tab.id, pagespeed: $('psi').checked });
};

$('copy').onclick = async () => {
  const s = (await chrome.storage.session.get(domain))[domain];
  await navigator.clipboard.writeText(JSON.stringify(s.report));
  $('copy').textContent = 'Copied. Paste it into the WebPawlice page.';
};
