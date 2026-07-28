# Phishing Email Analyzer

A fully client-side web application that analyzes suspicious emails for phishing indicators. All parsing, scoring, and analysis happens locally in your browser — your email data never leaves your machine unless you explicitly choose to look up an IOC with your own API key.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Status](https://img.shields.io/badge/status-active-green.svg)

## Features

- **Header Analysis** — Parses email headers, extracts authentication results (SPF/DKIM/DMARC), and detects domain alignment issues
- **Body Analysis** — Extracts plain text and HTML content, identifies mismatched links (display text vs actual URL)
- **IOC Extraction** — Automatically finds URLs, domains, IP addresses, email addresses, and attachments with risk flagging
- **Language Analysis** — Detects urgency, authority/fear, financial fraud, and credential-harvesting language patterns with inline highlighting
- **Risk Scoring** — Composite score based on authentication failures, IOC risk flags, and language analysis
- **VirusTotal Integration** — Optional per-IOC lookup for URLs, domains, IPs, and file hashes (requires your own API key)
- **AbuseIPDB Integration** — Optional per-IOC IP reputation lookup (requires your own API key)
- **Defang/Copy** — One-click defanging for safe sharing, and copy-to-clipboard for any IOC

## Privacy

This tool runs entirely in your browser. Nothing is uploaded or transmitted, except IOCs you explicitly submit to VirusTotal/AbuseIPDB using your own API key. See the Settings panel to configure API keys.

## Quick Start

```bash
# Clone the repository
git clone https://github.com/boode-hub/phishing-email-analyzer.git
cd phishing-email-analyzer

# Start the local server
node server.js

# Open http://localhost:8080 in your browser
```

## Usage

1. **Paste** raw email headers/source into the text area, or **upload** a `.eml` file
2. Click **Analyze Email**
3. Review the panels:
   - **Quick Summary** — Key signals at a glance
   - **Analysis Result** — Risk tier, score breakdown, and reasons
   - **Email Authentication** — SPF/DKIM/DMARC results and domain alignment
   - **Indicators of Compromise (IOCs)** — Extracted URLs, domains, IPs, emails, attachments
   - **Body & Language Analysis** — Plain text, HTML preview, and highlighted suspicious phrases
   - **Email Headers** — Structured header table
4. (Optional) Add VirusTotal/AbuseIPDB API keys in **Settings** to enable per-IOC enrichment

## Project Structure

```
/
├── index.html              # App shell
├── styles/
│   └── main.css            # Design system & styling
├── scripts/
│   ├── main.js             # App init, event wiring, API lookups
│   ├── parse-headers.js    # Header extraction & unfolding
│   ├── parse-auth.js       # SPF/DKIM/DMARC + domain alignment
│   ├── parse-body.js       # MIME body extraction, link parsing
│   ├── extract-iocs.js     # IOC extraction + risk flagging
│   ├── analyze-language.js # Urgency/fraud keyword scoring
│   ├── score.js            # Composite verdict scoring
│   ├── render.js           # DOM rendering for all panels
│   └── hash-utils.js       # SHA-256 & MD5 for attachment hashing
├── sample-data/            # Test .eml files
│   ├── legitimate-email.eml
│   ├── phishing-spoofed.eml
│   └── phishing-urgency.eml
├── server.js               # Simple local HTTP server
└── README.md
```

## Tech Stack

- Pure HTML5 + CSS3 + vanilla JavaScript (ES modules)
- No build step required
- No external libraries or CDN dependencies
- Web Crypto API for SHA-256 hashing
- LocalStorage for API key persistence

## API Integrations (Optional)

### VirusTotal

- URL lookup via `/api/v3/urls/{url_id}`
- Domain lookup via `/api/v3/domains/{domain}`
- IP lookup via `/api/v3/ip_addresses/{ip}`
- File hash lookup via `/api/v3/files/{sha256}`
- Auto-submits URLs for analysis if not found

### AbuseIPDB

- IP reputation check via `/api/v2/check`
- Shows abuse confidence score, total reports, country, ISP

## Sample Data

Three synthetic `.eml` files are included for testing:

| File                   | Description                                    | Expected Result |
| ---------------------- | ---------------------------------------------- | --------------- |
| `legitimate-email.eml` | Clean email with passing auth                  | Low Risk        |
| `phishing-spoofed.eml` | Spoofed domain, auth failures, domain mismatch | High Risk       |
| `phishing-urgency.eml` | Urgency/financial language patterns            | Low-Medium Risk |

## License

MIT
