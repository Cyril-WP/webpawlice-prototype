# WebPawlice — prototype

> Throwaway prototype by Webpuppies (21 Nov 2026). It answers one question: can a one-line embed give a site owner a useful, true check-up from public information alone?

**Live demo:** https://cyril-wp.github.io/webpawlice-prototype/

## Put it on a site

```html
<script src="https://cyril-wp.github.io/webpawlice-prototype/embed/webpawlice.js" defer></script>
```

Visitors see nothing and nothing runs for them. The owner opens their own site with `?webpawlice` on the end and a check-up panel appears. Because the script runs on the site itself, it can read the site's own headers, robots.txt and page, which an outside scanner cannot do from a browser.

| Attribute | Effect |
| --- | --- |
| `data-show="always"` | Show the paw to everyone (demos, or for admins only via the WordPress plugin) |
| `data-domain="x.sg"` | Check another domain's public records |
| `data-position="left"` | Button bottom-left |

WordPress: copy `wordpress/webpawlice.php` to `wp-content/mu-plugins/`. Administrators get the paw on every page.

## Other ways to run it

- **Bookmarklet:** on the demo page. Runs the full check on any site that allows outside scripts.
- **Chrome extension:** `chrome://extensions` → Developer mode → Load unpacked → `extension/`.
- **CLI:** `node cli.mjs example.com [--json] [--speed]` (Node 18+).
- **Locally:** `npm run demo`, then open http://localhost:8731/demo-site/?webpawlice

## What it reads

Public DNS over HTTPS (Cloudflare, Google), registry RDAP via the IANA bootstrap, Certificate Transparency (certspotter), Mozilla HTTP Observatory v2, Tranco, the Internet Archive, and — only when installed on the site — the site's own homepage headers, robots.txt, llms.txt and the page being viewed.

Passive only. No port scans, no load tests, no form submissions. Those need the owner's written permission and are out of scope.

## Known limits

- `.sg` has no public RDAP, so domain age and renewal are not readable for most Singapore sites.
- certspotter's free tier allows 100 lookups an hour per IP.
- The embed and `extension/checks.js` duplicate the check logic. Fine for a prototype; one shared build if this goes further.

## Four views (embed)

- **Risks**: every finding ranked critical, high, medium or low, with why it matters and the fix. Adds leaked files, keys in page code, source maps, hijacked script hosts, libraries with published flaws (OSV.dev), WordPress core and plugin age, open databases and admin panels (Shodan InternetDB, free for non-commercial use only), forgotten subdomains, domain transfer lock, and look-alikes that are new since the last check.
- **Launch guard**: walks up to 25 pages like a visitor and reports dead pages and images, noindex and robots blocks, staging addresses, placeholder text, insecure forms and dead outside links.
- **Facts**: phone, hours, prices, address and reviews from every page and the structured data, and where they disagree.
- **Compare**: public-record checks side by side with up to three competitors (`?webpawlice=site.sg&compare=a.sg,b.sg` or `data-competitors`).

The demo bakery (`demo-site/`) carries deliberate faults for each view, including a fake `.env`.

## Daily look-alike watch

`.github/workflows/lookalike-watch.yml` runs `watch/watch.mjs` every day for the domains in `watch/domains.txt`, keeps what it saw in `watch/state.json`, and opens an issue when a new look-alike is registered or starts taking email.
