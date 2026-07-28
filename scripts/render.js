import { sha256, md5 } from "./hash-utils.js";

// ===== FOCUSED SUMMARY =====
export async function renderSummary(container, analysis) {
  const h = analysis.headers;
  const auth = analysis.auth;
  const iocs = analysis.iocs;
  const lang = analysis.languageAnalysis;

  const from = h.from?.email || h.from || "N/A";
  const replyTo =
    h.replyTo?.email ||
    h.replyTo ||
    h.returnPath?.email ||
    h.returnPath ||
    "N/A";
  const subject = h.subject || "N/A";
  const sip = extractSenderIP(h);
  const sd = extractDomain(from);
  const rd = extractDomain(replyTo);
  const dm = rd !== sd && rd !== "N/A";

  let html = '<div class="summary-grid">';

  html += mkCard(
    "Subject",
    "file",
    [{ l: "Subject", v: trunc(subject, 40), t: subject, m: 1 }],
    "neutral",
  );

  html += mkCard(
    "Sender",
    "user",
    [
      { l: "From", v: trunc(from, 35), t: from, m: 1 },
      {
        l: "Domain",
        v: sd,
        m: 1,
        c: isSuspiciousDomain(sd) ? "suspicious" : "",
      },
    ],
    isSuspiciousDomain(sd) ? "high" : "low",
  );

  html += mkCard(
    "Reply-To",
    "edit",
    [
      {
        l: "Address",
        v: trunc(replyTo, 35),
        t: replyTo,
        m: 1,
        c: dm ? "suspicious" : "",
      },
      ...(dm
        ? [
            {
              l: "Mismatch",
              v: "Reply-To domain differs from From",
              c: "malicious",
            },
          ]
        : []),
    ],
    dm ? "high" : "low",
  );

  html += mkCard(
    "Sender IP",
    "globe",
    [
      { l: "Last Hop IP", v: sip, m: 1 },
      ...(isPrivateIP(sip)
        ? [{ l: "Warning", v: "Private/residential IP", c: "malicious" }]
        : []),
    ],
    isPrivateIP(sip) ? "high" : "neutral",
  );

  html += mkCard(
    "Authentication",
    "shield",
    [
      {
        l: "Status",
        v: auth?.overallStatus?.level
          ? auth.overallStatus.level.toUpperCase()
          : "N/A",
        c:
          getAuthRisk(auth) === "high"
            ? "malicious"
            : getAuthRisk(auth) === "low"
              ? "verified"
              : "suspicious",
      },
      {
        l: "Alignment",
        v:
          auth?.domainAlignment?.mismatches?.length > 0
            ? "MISMATCHED"
            : "ALIGNED",
        c:
          auth?.domainAlignment?.mismatches?.length > 0
            ? "malicious"
            : "verified",
      },
    ],
    getAuthRisk(auth),
  );

  const urlRows = [];
  const urls = iocs?.urls || [];
  if (urls.length) {
    urlRows.push({ l: "Count", v: String(urls.length), m: 1 });
    urls.slice(0, 5).forEach((u, i) => {
      const hr = u.riskFlags?.some((f) => f.type === "high");
      const mr = u.riskFlags?.some((f) => f.type === "medium");
      const rc = hr ? "malicious" : mr ? "suspicious" : "verified";
      urlRows.push({
        l: `URL ${i + 1}`,
        v: trunc(u.url, 35),
        t: u.url,
        m: 1,
        c: rc,
      });
    });
  }
  html += mkCard(
    "URLs",
    "link",
    urlRows.length ? urlRows : [{ l: "URLs", v: "None found", m: 1 }],
    urls.some((u) => u.riskFlags?.some((f) => f.type === "high"))
      ? "high"
      : "low",
  );

  const langRows = buildLangRows(lang);
  html += mkCard(
    "Language Flags",
    "file",
    langRows.length ? langRows : [{ l: "Flags", v: "None detected", m: 1 }],
    hasLangFlags(lang) ? "high" : "low",
  );

  const atts = iocs?.attachments || [];
  html += mkCard(
    "Attachments",
    "clip",
    atts.length
      ? [
          { l: "Count", v: String(atts.length), m: 1 },
          ...atts.slice(0, 3).map((a) => ({
            l: trunc(a.filename || "unnamed", 20),
            v: formatBytes(a.size || 0),
            m: 1,
            c: isRiskyExt(a.filename) ? "malicious" : "",
          })),
        ]
      : [{ l: "Attachments", v: "None", m: 1 }],
    atts.some((a) => isRiskyExt(a.filename)) ? "high" : "low",
  );

  html += "</div>";
  container.innerHTML = html;
}

const ICONS = {
  user: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>`,
  edit: `<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>`,
  globe: `<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>`,
  shield: `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
  link: `<path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/>`,
  file: `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/><polyline points="10 9 9 9 8 9"/>`,
  clip: `<path d="M21.44 11.05l-9.19 9.19a6 6 0 0 1-8.49-8.49l9.19-9.19a4 4 0 0 1 5.66 5.66l-9.2 9.19a2 2 0 0 1-2.83-2.83l8.49-8.48"/>`,
};

function mkCard(title, iconKey, rows, risk) {
  const rh = rows
    .map((r) => {
      if (r.r) return `<div class="summary-row">${r.v}</div>`;
      return `<div class="summary-row"><span class="label">${r.l}</span><span class="value ${r.m ? "mono" : ""} ${r.c || ""}" title="${r.t || ""}">${esc(r.v)}</span></div>`;
    })
    .join("");

  return `<div class="summary-card risk-border-${risk}">
    <div class="card-header">
      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">${ICONS[iconKey] || ""}</svg>
      <h3>${esc(title)}</h3>
    </div>
    ${rh}
  </div>`;
}

function trunc(s, m) {
  return !s || typeof s !== "string"
    ? "N/A"
    : s.length > m
      ? s.slice(0, m) + "..."
      : s;
}
function isSuspiciousDomain(d) {
  return d && d !== "N/A" && (d.startsWith("xn--") || /^\d/.test(d));
}
function isPrivateIP(ip) {
  return (
    ip &&
    ip !== "N/A" &&
    /^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.0\.0\.0)/.test(ip)
  );
}
function isRiskyExt(f) {
  if (!f) return false;
  const r = [
    ".exe",
    ".scr",
    ".js",
    ".hta",
    ".vbs",
    ".bat",
    ".cmd",
    ".ps1",
    ".dll",
    ".jar",
  ];
  const l = f.toLowerCase();
  return r.some((e) => l.endsWith(e)) || /\.\w+\.\w{3,4}$/.test(l);
}
function getAuthRisk(a) {
  if (!a) return "neutral";
  const level = a.overallStatus?.level || a.overall;
  return level === "fail" ? "high" : level === "pass" ? "low" : "medium";
}
function hasLangFlags(a) {
  return (
    a &&
    a.categories &&
    Object.values(a.categories).some((c) => c.matchCount > 0)
  );
}
function extractDomain(e) {
  if (!e) return "N/A";
  const s = typeof e === "string" ? e : e?.email || e?.raw || "";
  const m = s.match(/@([^>\s]+)/);
  return m ? m[1] : "N/A";
}
function extractSenderIP(h) {
  const r = h.received;
  if (!r || !r.length) return "N/A";
  const lh = r[r.length - 1];
  const m = lh.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
  return m ? m[0] : "N/A";
}

function renderAuthBadges(auth) {
  if (!auth || !auth.mechanisms)
    return '<span class="auth-badge none">N/A</span>';
  return Object.entries(auth.mechanisms)
    .map(([n, r]) => {
      const s = r.status || "none";
      const cls =
        s === "pass"
          ? "pass"
          : s === "fail"
            ? "fail"
            : s === "softfail"
              ? "softfail"
              : "none";
      return `<span class="auth-badge ${cls}">${esc(n.toUpperCase())} ${esc(s.toUpperCase())}</span>`;
    })
    .join("");
}

function renderUrlList(urls) {
  if (!urls.length)
    return '<p style="color:var(--muted);font-size:12px;">No URLs found</p>';
  return urls
    .slice(0, 10)
    .map((u) => {
      const hr = u.riskFlags?.some((f) => f.type === "high");
      const mr = u.riskFlags?.some((f) => f.type === "medium");
      const rc = hr ? "malicious" : mr ? "suspicious" : "verified";
      return `<div class="url-item ${rc}" title="${esc(u.url)}">${esc(trunc(u.url, 40))}</div>`;
    })
    .join("");
}

async function renderAttList(atts) {
  if (!atts.length)
    return '<p style="color:var(--muted);font-size:12px;">No attachments</p>';
  const items = await Promise.all(
    atts.map(async (a) => {
      const risky = isRiskyExt(a.filename);
      const h = a.content ? await sha256(a.content) : "N/A";
      const m = a.content ? await md5(a.content) : "N/A";
      return `<div class="attachment-item ${risky ? "malicious" : ""}"><div class="att-name">${esc(a.filename || "unnamed")}</div><div class="att-hash" title="SHA-256">${esc(h)}</div><div class="att-hash" title="MD5">${esc(m)}</div></div>`;
    }),
  );
  return items.join("");
}

function buildLangRows(a) {
  if (!a || !a.categories) return [];
  const rows = [];
  Object.entries(a.categories)
    .filter(([, c]) => c.matchCount > 0)
    .forEach(([n, c]) => {
      rows.push({ l: esc(n), v: `${c.matchCount} matches`, c: "suspicious" });
      (c.matches || []).slice(0, 3).forEach((m) => {
        rows.push({
          l: "",
          v: `"${trunc(m.phrase, 30)}"`,
          m: 1,
          c: "suspicious",
        });
      });
    });
  return rows;
}

function formatBytes(b) {
  if (b === 0 || b == null) return "0 B";
  const sizes = ["B", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(b) / Math.log(1024));
  return `${(b / Math.pow(1024, i)).toFixed(1)} ${sizes[i]}`;
}

function renderLangFlags(a) {
  if (!a || !a.categories)
    return '<p style="color:var(--muted);font-size:12px;">No suspicious language detected</p>';
  const flags = Object.entries(a.categories)
    .filter(([, c]) => c.matchCount > 0)
    .map(
      ([n, c]) =>
        `<div class="lang-flag"><span class="flag-name">${esc(n)}</span><span class="flag-count">${c.matchCount}</span></div>`,
    );
  return flags.length
    ? flags.join("")
    : '<p style="color:var(--muted);font-size:12px;">No suspicious language detected</p>';
}

// ===== VERDICT =====
export function renderVerdict(c, sc) {
  if (!sc) {
    c.innerHTML = "<p>No score data</p>";
    return;
  }
  const tc =
    sc.tier === "High Risk"
      ? "tier-high"
      : sc.tier === "Suspicious"
        ? "tier-medium"
        : "tier-low";
  c.innerHTML = `<div class="verdict-box ${tc}"><div class="verdict-tier">${esc(sc.tier || "Unknown")}</div><div class="verdict-score">Score: ${sc.score || 0}/100</div><div class="verdict-reasons">${(sc.reasons || []).map((r) => `<span class="reason-tag">${esc(r)}</span>`).join("")}</div></div><div class="score-breakdown">${["auth", "iocs", "language"].map((k) => `<div class="score-item"><span class="score-label">${esc(k.toUpperCase())}</span><div class="score-bar"><div class="score-fill" style="width:${sc.breakdown?.[k] || 0}%"></div></div><span class="score-value">${sc.breakdown?.[k] || 0}</span></div>`).join("")}</div>`;
}

// ===== AUTHENTICATION =====
export function renderAuth(c, auth) {
  if (!auth) {
    c.innerHTML = "<p>No authentication data</p>";
    return;
  }
  const mech = auth.mechanisms || {};
  const align = auth.domainAlignment || {};
  const recv = auth.receivedChain || [];

  // Render mechanism badges with colored indicators
  const mechHtml = Object.entries(mech)
    .map(([n, r]) => {
      const s = r.status || "none";
      const cls =
        s === "pass"
          ? "pass"
          : s === "fail"
            ? "fail"
            : s === "softfail"
              ? "softfail"
              : "none";
      const color =
        s === "pass"
          ? "#22c55e"
          : s === "fail"
            ? "#ef4444"
            : s === "softfail"
              ? "#f59e0b"
              : "#9ca3af";
      return `<div class="auth-mech ${cls}" style="border-left:4px solid ${color}"><div class="mech-name">${esc(n.toUpperCase())}</div><div class="mech-status" style="color:${color};font-weight:700">${esc(s.toUpperCase())}</div>${r.details ? `<div class="mech-details mono">${esc(r.details)}</div>` : ""}</div>`;
    })
    .join("");

  // Fix: align.domains is an object, not an array
  const alignEntries = Object.entries(align.domains || {});
  const alignRows = alignEntries
    .map(([source, domain]) => {
      const matched = align.aligned?.[source] ?? true;
      return `<tr class="${matched ? "" : "mismatch-row"}"><td>${esc(source)}</td><td class="mono">${esc(domain)}</td><td class="${matched ? "verified" : "malicious"}">${matched ? "✓ ALIGNED" : "✗ MISMATCH"}</td></tr>`;
    })
    .join("");

  const recvHtml = recv
    .map(
      (hop, i) =>
        `<div class="received-hop ${hop.suspicious ? "suspicious-hop" : ""}"><div class="hop-num">${i + 1}</div><div class="hop-details"><div class="hop-from">From: ${esc(hop.from || "N/A")}</div><div class="hop-by">By: ${esc(hop.by || "N/A")}</div><div class="hop-ip">IP: <span class="mono">${esc(hop.ip || "N/A")}</span></div><div class="hop-date">${esc(hop.date || "N/A")}</div>${hop.suspicious ? '<div class="hop-warning">⚠ Suspicious hop</div>' : ""}</div></div>`,
    )
    .join("");

  c.innerHTML = `<div class="auth-section"><h3>Mechanism Results</h3><div class="auth-mechanisms">${mechHtml || "<p>No auth data</p>"}</div></div><div class="auth-section"><h3>Domain Alignment</h3><table class="alignment-table"><thead><tr><th>Source</th><th>Domain</th><th>Status</th></tr></thead><tbody>${alignRows || '<tr><td colspan="3">No alignment data</td></tr>'}</tbody></table></div><div class="auth-section"><h3>Received Chain</h3><div class="received-chain">${recvHtml || "<p>No received chain data</p>"}</div></div>`;
}

// ===== IOCS =====
export function renderIOCs(container, iocs, apiKeys) {
  if (!iocs) {
    container.innerHTML = "<p>No IOCs found</p>";
    return;
  }
  const sections = [];
  if (iocs.urls?.length)
    sections.push(renderIOCSection("URLs", iocs.urls, "url", apiKeys));
  if (iocs.domains?.length)
    sections.push(renderIOCSection("Domains", iocs.domains, "domain", apiKeys));
  if (iocs.ips?.length)
    sections.push(renderIOCSection("IP Addresses", iocs.ips, "ip", apiKeys));
  if (iocs.emails?.length)
    sections.push(
      renderIOCSection("Email Addresses", iocs.emails, "email", apiKeys),
    );
  if (iocs.attachments?.length)
    sections.push(
      renderIOCSection("Attachments", iocs.attachments, "attachment", apiKeys),
    );
  if (iocs.mismatchedLinks?.length)
    sections.push(renderMismatchedLinks(iocs.mismatchedLinks));
  container.innerHTML = sections.join("") || "<p>No IOCs found</p>";
}

function renderIOCSection(title, items, type, apiKeys) {
  const rows = items
    .map((item) => {
      const value =
        typeof item === "string"
          ? item
          : item.value ||
            item.url ||
            item.domain ||
            item.ip ||
            item.filename ||
            "N/A";
      const riskFlags = item.riskFlags || [];
      const riskHtml = riskFlags
        .map((f) => `<span class="risk-tag ${f.type}">${esc(f.label)}</span>`)
        .join("");
      const defanged = defang(value);
      let lookupBtn = "";
      const hasVtKey = apiKeys?.virustotal;
      const hasAbuseKey = apiKeys?.abuseipdb;

      if (type === "url" || type === "domain") {
        lookupBtn = hasVtKey
          ? `<button class="btn-lookup" data-value="${esc(value)}" data-type="${type}" onclick="lookupVirusTotal(this)">Check VT</button>`
          : '<span class="lookup-hint">Add VT key in Settings</span>';
      } else if (type === "ip") {
        // Show both VT and AbuseIPDB for IPs
        const vtBtn = hasVtKey
          ? `<button class="btn-lookup" data-value="${esc(value)}" data-type="ip" onclick="lookupVirusTotal(this)">Check VT</button>`
          : "";
        const abuseBtn = hasAbuseKey
          ? `<button class="btn-lookup" data-value="${esc(value)}" onclick="lookupAbuseIPDB(this)">Check AbuseIPDB</button>`
          : "";
        if (!vtBtn && !abuseBtn) {
          lookupBtn =
            '<span class="lookup-hint">Add API keys in Settings</span>';
        } else {
          lookupBtn = vtBtn + abuseBtn;
        }
      } else if (type === "attachment") {
        // For attachments, show hash lookup if content available
        const itemObj = typeof item === "object" ? item : {};
        if (itemObj.content && hasVtKey) {
          lookupBtn = `<button class="btn-lookup" data-value="${esc(value)}" data-type="attachment" data-has-content="true" onclick="lookupVirusTotal(this)">Check VT Hash</button>`;
        } else if (hasVtKey) {
          lookupBtn = `<button class="btn-lookup" data-value="${esc(value)}" data-type="attachment" data-has-content="false" onclick="lookupVirusTotal(this)">Check VT Hash</button>`;
        } else {
          lookupBtn = '<span class="lookup-hint">Add VT key in Settings</span>';
        }
      }
      return `<tr><td><span class="ioc-original mono">${esc(value)}</span><span class="ioc-defanged mono hidden">${esc(defanged)}</span></td><td>${riskHtml}</td><td class="ioc-actions"><button class="btn-sm" onclick="copyIOC(this)">Copy</button><button class="btn-sm" onclick="toggleDefang(this)">Defang</button>${lookupBtn}</td></tr><tr class="lookup-result-row hidden" data-ioc-value="${esc(value)}"><td colspan="3" class="lookup-result-cell"><div class="lookup-result-content"></div></td></tr>`;
    })
    .join("");
  return `<div class="ioc-section"><h3>${esc(title)} (${items.length})</h3><table class="ioc-table"><thead><tr><th>Value</th><th>Risk</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function renderMismatchedLinks(links) {
  const rows = links
    .map(
      (link) =>
        `<tr><td class="mono">${esc(link.displayText || "N/A")}</td><td class="mono">${esc(link.actualHref || "N/A")}</td><td><span class="risk-tag high">MISMATCH</span></td></tr>`,
    )
    .join("");
  return `<div class="ioc-section"><h3>Mismatched Links (${links.length})</h3><table class="ioc-table"><thead><tr><th>Display Text</th><th>Actual URL</th><th>Risk</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function defang(value) {
  return value.replace(/http/gi, "hxxp").replace(/\./g, "[.]");
}

// ===== BODY & LANGUAGE =====
export function renderBody(container, body, languageAnalysis) {
  if (!body) {
    container.innerHTML = "<p>No body content</p>";
    return;
  }
  const plainText = body.text || "";
  const htmlContent = body.html || "";
  let highlightedText = esc(plainText);
  if (languageAnalysis && languageAnalysis.matches) {
    languageAnalysis.matches.forEach((match) => {
      const escaped = esc(match.phrase);
      highlightedText = highlightedText.replace(
        new RegExp(escaped, "gi"),
        `<mark class="lang-highlight ${match.category}">${escaped}</mark>`,
      );
    });
  }
  container.innerHTML = `<div class="body-tabs"><button class="tab-btn active" data-tab="plain">Plain Text</button><button class="tab-btn" data-tab="html">HTML Preview</button></div><div class="tab-content" id="tab-plain"><pre class="body-text">${highlightedText}</pre></div><div class="tab-content hidden" id="tab-html"><iframe class="html-preview" sandbox="allow-same-origin"></iframe></div>${renderLanguageAnalysis(languageAnalysis)}`;
  const iframe = container.querySelector(".html-preview");
  if (iframe && htmlContent) iframe.srcdoc = htmlContent;
  container.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      container
        .querySelectorAll(".tab-btn")
        .forEach((b) => b.classList.remove("active"));
      container
        .querySelectorAll(".tab-content")
        .forEach((c) => c.classList.add("hidden"));
      btn.classList.add("active");
      const tabId = "tab-" + btn.dataset.tab;
      const tabEl = container.querySelector("#" + tabId);
      if (tabEl) tabEl.classList.remove("hidden");
    });
  });
}

function renderLanguageAnalysis(analysis) {
  if (!analysis) return "";
  const categories = Object.entries(analysis.categories || {})
    .filter(([, cat]) => cat.matchCount > 0)
    .map(
      ([name, cat]) =>
        `<div class="lang-category"><div class="lang-cat-header"><span class="lang-cat-name">${esc(name)}</span><span class="lang-cat-count">${cat.matchCount}</span></div><div class="lang-cat-phrases">${(
          cat.matches || []
        )
          .slice(0, 5)
          .map((m) => `<span class="lang-phrase">${esc(m.phrase)}</span>`)
          .join("")}</div></div>`,
    )
    .join("");
  return `<div class="language-panel"><h3>Language Analysis</h3><div class="lang-summary">${esc(analysis.summary || "No suspicious language detected")}</div><div class="lang-categories">${categories || "<p>No flags</p>"}</div></div>`;
}

// ===== HEADERS TABLE =====
export function renderHeaders(container, headers) {
  if (!headers) {
    container.innerHTML = "<p>No header data</p>";
    return;
  }
  const rows = [];
  const headerOrder = [
    "from",
    "reply-to",
    "return-path",
    "to",
    "subject",
    "date",
    "message-id",
    "authentication-results",
    "received-spf",
    "dkim-signature",
    "content-type",
    "x-mailer",
  ];
  headerOrder.forEach((key) => {
    if (headers[key] !== undefined) {
      const value = headers[key];
      if (Array.isArray(value)) {
        value.forEach((v) =>
          rows.push({ key: formatHeaderName(key), value: v }),
        );
      } else {
        rows.push({ key: formatHeaderName(key), value });
      }
    }
  });
  Object.entries(headers).forEach(([key, value]) => {
    if (!headerOrder.includes(key)) {
      if (Array.isArray(value)) {
        value.forEach((v) =>
          rows.push({ key: formatHeaderName(key), value: v }),
        );
      } else {
        rows.push({ key: formatHeaderName(key), value });
      }
    }
  });
  const tableRows = rows
    .map((row) => {
      const displayValue =
        typeof row.value === "object"
          ? JSON.stringify(row.value)
          : String(row.value);
      return `<tr><td class="header-name">${esc(row.key)}</td><td class="header-value mono">${esc(displayValue)}</td></tr>`;
    })
    .join("");
  container.innerHTML = `<div class="headers-table-wrapper"><button class="btn-sm" id="copy-headers">Copy All Headers</button><table class="headers-table"><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>${tableRows}</tbody></table></div>`;
  const copyBtn = container.querySelector("#copy-headers");
  if (copyBtn) {
    copyBtn.addEventListener("click", () => {
      const raw = rows
        .map(
          (r) =>
            `${r.key}: ${typeof r.value === "object" ? JSON.stringify(r.value) : r.value}`,
        )
        .join("\n");
      navigator.clipboard.writeText(raw).then(() => {
        copyBtn.textContent = "Copied!";
        setTimeout(() => (copyBtn.textContent = "Copy All Headers"), 2000);
      });
    });
  }
}

function formatHeaderName(key) {
  return key
    .split("-")
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join("-");
}

function esc(s) {
  if (s == null) return "";
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
