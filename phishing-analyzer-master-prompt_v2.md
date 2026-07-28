# Master Prompt: Phishing Email Analyzer

> Paste this entire document into Cline as your task prompt. Self-contained, unambiguous, step-by-step.

## 1. Project Summary

A fully client-side web application that analyzes suspicious emails for phishing indicators. The user pastes raw email headers/source or uploads a `.eml` file. The app parses headers and body, extracts IOCs, evaluates SPF/DKIM/DMARC, scans body language for urgency/fraud patterns, and presents a clear verdict — all in the browser.

## 2. Hard Constraints

1. **All parsing/scoring/analysis is local by default** — no network calls for core analysis. No CDN calls, no telemetry.
2. **No build step required** — plain HTML + CSS + vanilla JS (ES modules), served via `node server.js`.
3. **No external libraries from CDN** — all parsing is local.
4. **Opt-in API lookups only** — VirusTotal/AbuseIPDB require user's own API key and explicit per-IOC click.

## 3. Inputs Supported

- Paste box: raw headers only, or full raw email source (headers + body)
- File upload: `.eml` files (plain-text MIME)
- Auto-detect: blank-line-separated header block = full source; headers-only = disable body sections gracefully
- `.msg` files: show "not yet supported" message (Phase 2)

## 4. File Structure

```
/index.html              -- app shell
/styles/main.css         -- design system (HTB-inspired dark theme)
/scripts/main.js         -- app init, event wiring, API lookups
/scripts/parse-headers.js    -- header extraction & unfolding
/scripts/parse-auth.js       -- SPF/DKIM/DMARC + domain alignment
/scripts/parse-body.js       -- MIME body extraction, link parsing
/scripts/extract-iocs.js     -- IOC extraction + risk flagging
/scripts/analyze-language.js -- urgency/fraud keyword scoring
/scripts/score.js            -- composite verdict scoring
/scripts/render.js           -- DOM rendering for all panels
/scripts/hash-utils.js       -- SHA-256 & MD5 for attachment hashing
/sample-data/                -- 3 test .eml files
/server.js                   -- local HTTP server (required for ES modules)
/README.md                   -- project documentation
```

## 5. Feature Spec

### 5.1 Header Parsing (`parse-headers.js`)

- Unfold multi-line headers (RFC 5322)
- Extract: From, Reply-To, Return-Path, To, Subject, Date, Message-ID, Received (ordered array), X-\*, Authentication-Results, Received-SPF, DKIM-Signature, Content-Type
- Decode RFC 2047 encoded-word subjects

### 5.2 Focused Summary Panel (`render.js`)

Responsive grid of cards with colored left borders:

| Card           | Content               | Risk Color               |
| -------------- | --------------------- | ------------------------ |
| Subject        | Truncated subject     | neutral                  |
| Sender         | From email + domain   | red if suspicious domain |
| Reply-To       | Reply-To address      | red if domain mismatch   |
| Sender IP      | Last hop IP           | red if private IP        |
| Authentication | SPF/DKIM/DMARC status | green/red/amber/gray     |
| URLs           | Count + top 5 URLs    | per-URL risk color       |
| Language Flags | Category match counts | red if any flags         |
| Attachments    | Count + filenames     | red if risky extension   |

### 5.3 Authentication Panel (`render.js`)

- **Mechanism Results**: SPF/DKIM/DMARC boxes with status + explanation
- **Domain Alignment Table**: From, Return-Path, DKIM(d=), Reply-To domains with ✓/✗ MISMATCH
- **Received Chain**: Vertical timeline of hops (number, from, by, IP, date), flag suspicious hops

### 5.4 Body Analysis (`parse-body.js`)

- Handle text/plain and text/html MIME parts
- Decode quoted-printable and base64 locally
- Extract `<a href>` targets with visible link text (for mismatch detection)
- Extract attachment metadata (filename, content-type, size)
- Render plain text + HTML preview (sandboxed iframe) with tab switcher

### 5.5 IOC Section (`extract-iocs.js` + `render.js`)

Extracted IOCs with risk flags:

- **URLs**: URL shorteners, punycode, raw IP host, mismatched anchor text
- **Domains**: punycode detection
- **IPs**: from Received headers and body
- **Emails**: disposable domain detection
- **Attachments**: double extensions, risky extensions (.exe, .scr, .js, .hta, .vbs, .bat, .cmd, .ps1, .dll, .jar)
- **Mismatched Links**: display text vs actual href

Each IOC row has:

- **Copy** button — copies currently visible value (original or defanged)
- **Defang** button — toggles between original and defanged (`http`→`hxxp`, `.`→`[.]`)
- **Check VT** button — VirusTotal lookup (URLs, domains, IPs, file hashes)
- **Check AbuseIPDB** button — IP reputation lookup (IPs only)

### 5.6 Language Analysis (`analyze-language.js`)

Categories with keyword lists:

- **Urgency**: "act now", "immediately", "within 24 hours", "account will be suspended", "verify now"
- **Authority/Fear**: "legal action", "IRS", "law enforcement", "compromised", "final notice"
- **Financial/Fraud**: wire transfer, gift card, cryptocurrency, invoice, banking details
- **Credential Harvesting**: "click here to verify", "confirm your password", "login to secure"

Score each category independently. Highlight triggering phrases inline in body text.

### 5.7 Verdict / Scoring (`score.js`)

- Composite score: auth failures (heavily weighted) + IOC risk flags + language analysis
- Three tiers: Low / Suspicious / High Risk
- Show breakdown: "Score: X/100 — reasons: [list]"
- Score bars for auth / iocs / language sub-scores

### 5.8 Headers Table (`render.js`)

- Structured table: Header | Value
- Ordered: From, Reply-To, Return-Path, To, Subject, Date, Message-ID, Authentication-Results, Received-SPF, DKIM-Signature, Content-Type, X-Mailer, then remaining headers
- "Copy All Headers" button copies raw unfolded headers to clipboard
- Collapsed by default

## 6. UI/UX Design

### Design Direction: Hack The Box Inspired

- Dark theme: `#0a0a0a` background, `#111`/`#161b22` cards, `#2a2a2a` borders
- Accent: `#9fef00` (HTB green) for success/primary
- Risk colors: `#22c55e` green (pass), `#ef4444` red (fail/danger), `#f59e0b` amber (warning), `#9ca3af` gray (neutral)
- Monospace for technical values, sans-serif for labels
- Rounded corners (6–8px), subtle shadows, 1px borders
- Inline SVG icons (no icon fonts/CDNs)

### Layout (top to bottom)

1. Trust Banner — "This tool runs entirely in your browser..."
2. Header Bar — App title + Settings gear
3. Input Section — Paste textarea + file upload + Analyze/Clear
4. Status Message — Inline feedback
5. Focused Summary Panel — Card grid
6. Verdict Panel — Risk tier + score breakdown
7. Authentication Panel — Mechanisms + alignment + received chain
8. IOC Panel — URLs, domains, IPs, emails, attachments, mismatched links
9. Body & Language Panel — Plain text / HTML tabs + language analysis
10. Headers Panel — Structured table (collapsed by default)
11. Settings Modal — API keys, save/clear

### Interaction Details

- All panels except Input hidden until analysis completes
- Settings modal: gear icon, close on X/outside/Escape
- Copy buttons on IOC rows and summary cards
- Defang/Refang toggle on IOC rows
- Per-IOC lookup buttons only appear if API key configured
- Responsive: stack cards on mobile, grid on desktop

## 7. API Integrations (Section 11 — Opt-in Only)

### VirusTotal

- **Settings**: VT API Key input, stored in localStorage only
- **URL lookup**: `POST/GET /api/v3/urls` — auto-submits if not found
- **Domain lookup**: `GET /api/v3/domains/{domain}`
- **IP lookup**: `GET /api/v3/ip_addresses/{ip}`
- **File hash lookup**: Compute SHA-256 of attachment content, then `GET /api/v3/files/{hash}`
- Results displayed inline: reputation badge, scan stats (malicious/suspicious/harmless/undetected), last analysis date, metadata (AS owner, country, meaningful name)

### AbuseIPDB

- **Settings**: AbuseIPDB API Key input, stored in localStorage only
- **IP lookup**: `GET /api/v2/check?ipAddress={ip}&maxAgeInDays=90`
- Results displayed inline: abuse confidence score, total reports, country, ISP, domain, usage type, last reported date

### Lookup Behavior

- Single explicit per-row click — never auto-submit, never bulk
- Cache results per session (don't re-call API for same IOC)
- Loading state while in flight
- Clear error states: rate limited, invalid key, CORS failure
- If direct fetch fails due to CORS, fallback to opening vendor web report in new tab

## 8. CSS Design System

```css
:root {
  --bg: #0a0a0a;
  --surface: #111;
  --raised: #1a1a1a;
  --border: #2a2a2a;
  --border-hover: #3a3a3a;
  --text: #e0e0e0;
  --text-secondary: #9ca3af;
  --muted: #6b7280;
  --accent: #9fef00;
  --accent-bg: rgba(159, 239, 0, 0.08);
  --red: #ff4d4d;
  --red-bg: rgba(255, 77, 77, 0.08);
  --yellow: #ffe600;
  --yellow-bg: rgba(255, 230, 0, 0.08);
  --blue: #3b82f6;
  --blue-bg: rgba(59, 130, 246, 0.08);
}
```

## 9. Testing

Three synthetic `.eml` files included:

- `legitimate-email.eml` — clean, all auth passes → Low Risk
- `phishing-spoofed.eml` — spoofed domain, auth fails, domain mismatch → High Risk
- `phishing-urgency.eml` — urgency/financial language → Low-Medium Risk

Verify app works via `node server.js` at `http://localhost:8080`.

## 10. Server

`server.js` — simple HTTP server on localhost:8080. Required because ES modules are blocked by `file://` protocol.

## 11. Build Order (for future agents)

1. App shell + input + auto-detect header-only vs full-source
2. Header parsing + structured headers table
3. Focused Summary Panel
4. Authentication panel (prioritize accuracy)
5. Body MIME parsing (plain + HTML, decoding)
6. IOC extraction + display
7. Language/urgency/fraud analysis with inline highlighting
8. Composite verdict/scoring panel
9. UI/UX polish — HTB design system, test with sample files
10. Settings panel + localStorage + VT/AbuseIPDB lookup wiring
11. (Phase 2) `.msg` support

## 12. Current Implementation Status

**Completed:**

- All parsers (headers, auth, body, IOCs, language, scoring)
- All renderers (summary, auth, IOCs, body, headers, verdict)
- HTB-inspired dark theme with CSS custom properties
- Defang toggle + copy buttons on all IOC rows
- VirusTotal integration: URLs, domains, IPs, file hashes
- AbuseIPDB integration: IP reputation
- Settings modal with API key management (localStorage)
- Sample .eml test files
- Local HTTP server

**Known Limitations / TODO:**

- `.msg` file support (Phase 2)
- CORS fallback for API lookups (open vendor web page in new tab)
- Session caching of lookup results
- Rate limit handling improvements
- Additional language support beyond English
