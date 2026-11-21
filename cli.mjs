#!/usr/bin/env node
// PROTOTYPE — run WebPawlice passive checks from the terminal.
//   node webpawlice/cli.mjs example.com            human-readable report
//   node webpawlice/cli.mjs example.com --json     JSON to paste into the WebPawlice artifact
//   node webpawlice/cli.mjs example.com --speed    also run Lighthouse via PageSpeed Insights (slow)
import { AREAS, scan } from './extension/checks.js';

const args = process.argv.slice(2);
const domain = args.find(a => !a.startsWith('--'));
if (!domain) {
  process.stderr.write('usage: node webpawlice/cli.mjs <domain> [--json] [--speed]\n');
  process.exit(1);
}

const report = await scan(domain, {
  pagespeed: args.includes('--speed'),
  psiKey: process.env.PSI_KEY || '',
  onStep: s => process.stderr.write(`\r\x1b[K${s}`),
});
process.stderr.write('\r\x1b[K');

if (args.includes('--json')) {
  process.stdout.write(JSON.stringify(report, null, 2) + '\n');
  process.exit(0);
}

// Findings can quote text from the scanned site (its page title), so strip terminal control characters.
const clean = s => String(s).replace(/[\x00-\x1f\x7f-\x9f]/g, '');
const mark = { good: '✓', info: '·', warn: '!', bad: '✗', skip: '–' };
process.stdout.write(`\nWebPawlice ${clean(report.domain)}  overall ${report.overall}\n`);
for (const [k, q] of Object.entries(AREAS)) {
  process.stdout.write(`\n${q} ${report.areas[k] ?? '—'}\n`);
  for (const r of report.results.filter(x => x.area === k)) process.stdout.write(`  ${mark[r.status]} ${clean(r.name)}: ${clean(r.finding)}\n`);
}
process.stdout.write('\n');
