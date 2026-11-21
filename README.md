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
