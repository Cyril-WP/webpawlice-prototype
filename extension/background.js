// PROTOTYPE — runs the scan in the service worker so it survives the popup closing.
// State lives in chrome.storage.session (wiped when the browser closes): { [domain]: { step, report } }.
import { scan } from './checks.js';

const BADGE = s => (s >= 80 ? '#1D7349' : s >= 55 ? '#8A5A00' : '#B42318');

async function setState(domain, patch) {
  const all = await chrome.storage.session.get(domain);
  await chrome.storage.session.set({ [domain]: { ...(all[domain] || {}), ...patch } });
}

chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type !== 'scan') return false;
  const { domain, tabId, pagespeed } = msg;
  setState(domain, { step: 'Starting', report: null, error: null }).then(async () => {
    try {
      const report = await scan(domain, { pagespeed, onStep: step => setState(domain, { step }) });
      await setState(domain, { step: null, report });
      if (tabId) {
        await chrome.action.setBadgeText({ tabId, text: String(report.overall ?? '?') });
        await chrome.action.setBadgeBackgroundColor({ tabId, color: BADGE(report.overall ?? 0) });
      }
    } catch (e) {
      await setState(domain, { step: null, error: String(e.message || e) });
    }
  });
  reply({ started: true });
  return false;
});
