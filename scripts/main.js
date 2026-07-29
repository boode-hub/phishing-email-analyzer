// Main Application Entry Point
// Phishing Email Analyzer - Local Browser-Based

import { parseHeaders } from "./parse-headers.js";
import { parseAuth } from "./parse-auth.js";
import { parseBody } from "./parse-body.js";
import { extractIOCs } from "./extract-iocs.js";
import { analyzeLanguage } from "./analyze-language.js";
import { calculateScore } from "./score.js";
import { sha256 } from "./hash-utils.js";
import {
  renderVerdict,
  renderAuth,
  renderIOCs,
  renderBody,
  renderHeaders,
  renderSummary,
} from "./render.js";

// State
let currentAnalysis = null;
let apiKeys = {
  virustotal: "",
  abuseipdb: "",
  corsProxyUrl: "",
};

// Detect if running locally (via node server.js) vs GitHub Pages
const isLocalhost =
  window.location.hostname === "localhost" ||
  window.location.hostname === "127.0.0.1";

// Store attachment contents for hash lookups (keyed by attachment filename)
const attachmentContentMap = new Map();

// CORS proxy URL - user configurable in settings
function getCORSProxy() {
  return apiKeys.corsProxyUrl || "";
}

// Build API endpoint - uses local proxy when running locally, CORS proxy on GitHub Pages
function getVTEndpoint(path) {
  if (isLocalhost) {
    return "http://localhost:8080/proxy/vt" + path;
  }
  const proxy = getCORSProxy();
  if (proxy) {
    return proxy + "https://www.virustotal.com" + path;
  }
  return "https://www.virustotal.com" + path;
}

function getVTSubmitEndpoint() {
  if (isLocalhost) {
    return "http://localhost:8080/proxy/vt-submit";
  }
  const proxy = getCORSProxy();
  if (proxy) {
    return proxy + "https://www.virustotal.com/api/v3/urls";
  }
  return "https://www.virustotal.com/api/v3/urls";
}

function getAbuseIPDBEndpoint(query) {
  if (isLocalhost) {
    return "http://localhost:8080/proxy/abuseipdb" + query;
  }
  const proxy = getCORSProxy();
  if (proxy) {
    return proxy + "https://api.abuseipdb.com/api/v2" + query;
  }
  return "https://api.abuseipdb.com/api/v2" + query;
}

// Safely get localStorage value
try {
  apiKeys.virustotal = localStorage.getItem("vt-api-key") || "";
  apiKeys.abuseipdb = localStorage.getItem("abuseipdb-api-key") || "";
  apiKeys.corsProxyUrl = localStorage.getItem("cors-proxy-url") || "";
} catch (e) {
  console.warn("localStorage not available:", e);
}

const elements = {};

function queryElements() {
  const ids = {
    emailInput: "email-input",
    fileUpload: "file-upload",
    analyzeBtn: "analyze-btn",
    clearBtn: "clear-btn",
    inputStatus: "input-status",
    settingsBtn: "settings-btn",
    settingsModal: "settings-modal",
    closeSettings: "close-settings",
    saveSettings: "save-settings",
    clearKeys: "clear-keys",
    virustotalKeyInput: "virustotal-key",
    abuseipdbKeyInput: "abuseipdb-key",
    corsProxyUrlInput: "cors-proxy-url",
  };
  for (const [key, id] of Object.entries(ids)) {
    elements[key] = document.getElementById(id);
  }
}

// Initialize
function init() {
  console.log("[Phishing Analyzer] Initializing...");

  // Query DOM elements now that DOM is ready
  queryElements();

  // Load saved API keys into inputs
  if (elements.virustotalKeyInput) {
    elements.virustotalKeyInput.value = apiKeys.virustotal;
  }
  if (elements.abuseipdbKeyInput) {
    elements.abuseipdbKeyInput.value = apiKeys.abuseipdb;
  }
  if (elements.corsProxyUrlInput) {
    elements.corsProxyUrlInput.value = apiKeys.corsProxyUrl;
  }

  // Event Listeners
  if (elements.analyzeBtn) {
    elements.analyzeBtn.addEventListener("click", handleAnalyze);
  }
  if (elements.clearBtn) {
    elements.clearBtn.addEventListener("click", handleClear);
  }
  if (elements.fileUpload) {
    elements.fileUpload.addEventListener("change", handleFileUpload);
  }
  if (elements.settingsBtn) {
    elements.settingsBtn.addEventListener("click", () => {
      if (elements.settingsModal) {
        elements.settingsModal.classList.remove("hidden");
      }
    });
  }
  if (elements.closeSettings) {
    elements.closeSettings.addEventListener("click", () => {
      if (elements.settingsModal) {
        elements.settingsModal.classList.add("hidden");
      }
    });
  }
  if (elements.saveSettings) {
    elements.saveSettings.addEventListener("click", handleSaveSettings);
  }
  if (elements.clearKeys) {
    elements.clearKeys.addEventListener("click", handleClearKeys);
  }

  // Close modal on outside click
  if (elements.settingsModal) {
    elements.settingsModal.addEventListener("click", (e) => {
      if (e.target === elements.settingsModal) {
        elements.settingsModal.classList.add("hidden");
      }
    });
  }

  // Keyboard shortcut: Escape to close modal
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && elements.settingsModal) {
      elements.settingsModal.classList.add("hidden");
    }
  });

  console.log("[Phishing Analyzer] Initialized successfully");
}

// Handle Analyze Button
async function handleAnalyze() {
  const input = elements.emailInput ? elements.emailInput.value.trim() : "";

  if (!input) {
    showStatus("Please paste an email or upload a file first.", "error");
    return;
  }

  try {
    showStatus("Analyzing email...", "info");
    console.log("[Phishing Analyzer] Starting analysis...");

    // Detect if it's headers-only or full email
    const isFullEmail = detectFullEmail(input);
    console.log("[Phishing Analyzer] isFullEmail:", isFullEmail);

    // Parse headers
    const headers = parseHeaders(input);
    console.log("[Phishing Analyzer] Headers parsed");

    // Parse authentication
    const auth = parseAuth(headers);
    console.log("[Phishing Analyzer] Auth parsed:", auth?.overall);

    // Parse body (if full email)
    let body = null;
    if (isFullEmail) {
      body = parseBody(input);
      console.log("[Phishing Analyzer] Body parsed");
    }

    // Extract IOCs
    const iocs = extractIOCs(headers, body);
    console.log("[Phishing Analyzer] IOCs extracted:", {
      urls: iocs?.urls?.length,
      domains: iocs?.domains?.length,
      ips: iocs?.ips?.length,
    });

    // Store attachment contents for hash lookups
    attachmentContentMap.clear();
    if (iocs.attachments) {
      for (const att of iocs.attachments) {
        if (att.content) {
          attachmentContentMap.set(att.value, att.content);
        }
      }
    }

    // Analyze language (if body available)
    let languageAnalysis = null;
    if (body && body.text) {
      languageAnalysis = analyzeLanguage(body.text);
      console.log("[Phishing Analyzer] Language analyzed");
    }

    // Calculate score
    const score = calculateScore(auth, iocs, languageAnalysis);
    console.log("[Phishing Analyzer] Score calculated:", score?.tier);

    // Store analysis
    currentAnalysis = {
      headers,
      auth,
      body,
      iocs,
      languageAnalysis,
      score,
      rawInput: input,
      isFullEmail,
    };

    // Render results
    await renderResults(currentAnalysis);

    showStatus("Analysis complete!", "success");
    console.log("[Phishing Analyzer] Analysis complete");
  } catch (error) {
    console.error("[Phishing Analyzer] Analysis error:", error);
    showStatus("Error analyzing email: " + error.message, "error");
  }
}

// Detect if input is full email or headers-only
function detectFullEmail(input) {
  // Look for blank line separating headers from body
  const blankLineIndex = input.indexOf("\r\n\r\n");
  const blankLineIndexLF = input.indexOf("\n\n");

  if (blankLineIndex !== -1 || blankLineIndexLF !== -1) {
    return true;
  }

  // Check if it looks like headers only (no body-like content)
  const lines = input.split(/\r?\n/);
  let headerCount = 0;
  let bodyLikeCount = 0;

  for (const line of lines) {
    if (line.match(/^[\w-]+:/)) {
      headerCount++;
    } else if (line.length > 50 && !line.match(/^\s/)) {
      bodyLikeCount++;
    }
  }

  // If most lines are headers, treat as headers-only (not full email)
  return bodyLikeCount > headerCount;
}

// Handle Clear Button
function handleClear() {
  if (elements.emailInput) elements.emailInput.value = "";
  if (elements.fileUpload) elements.fileUpload.value = "";
  currentAnalysis = null;

  // Hide all result panels
  const panels = [
    "summary-section",
    "verdict-section",
    "auth-section",
    "ioc-section",
    "body-section",
    "headers-section",
  ];
  panels.forEach((id) => {
    const el = document.getElementById(id);
    if (el) el.classList.add("hidden");
  });

  showStatus("");
}

// Handle File Upload
function handleFileUpload(e) {
  const file = e.target.files[0];
  if (!file) return;

  if (file.name.toLowerCase().endsWith(".msg")) {
    showStatus(
      ".msg files are not yet supported. Please convert to .eml or paste the raw source.",
      "error",
    );
    if (elements.fileUpload) elements.fileUpload.value = "";
    return;
  }

  const reader = new FileReader();
  reader.onload = (event) => {
    if (elements.emailInput) {
      elements.emailInput.value = event.target.result;
    }
    showStatus(`Loaded: ${file.name}`, "success");
  };
  reader.onerror = () => {
    showStatus("Error reading file", "error");
  };
  reader.readAsText(file);
}

// Handle Save Settings
function handleSaveSettings() {
  apiKeys.virustotal = elements.virustotalKeyInput
    ? elements.virustotalKeyInput.value.trim()
    : "";
  apiKeys.abuseipdb = elements.abuseipdbKeyInput
    ? elements.abuseipdbKeyInput.value.trim()
    : "";
  apiKeys.corsProxyUrl = elements.corsProxyUrlInput
    ? elements.corsProxyUrlInput.value.trim()
    : "";

  try {
    if (apiKeys.virustotal) {
      localStorage.setItem("vt-api-key", apiKeys.virustotal);
    } else {
      localStorage.removeItem("vt-api-key");
    }

    if (apiKeys.abuseipdb) {
      localStorage.setItem("abuseipdb-api-key", apiKeys.abuseipdb);
    } else {
      localStorage.removeItem("abuseipdb-api-key");
    }

    if (apiKeys.corsProxyUrl) {
      localStorage.setItem("cors-proxy-url", apiKeys.corsProxyUrl);
    } else {
      localStorage.removeItem("cors-proxy-url");
    }
  } catch (e) {
    console.warn("localStorage not available:", e);
  }

  if (elements.settingsModal) {
    elements.settingsModal.classList.add("hidden");
  }
  showStatus("Settings saved!", "success");
}

// Handle Clear Keys
function handleClearKeys() {
  apiKeys.virustotal = "";
  apiKeys.abuseipdb = "";
  apiKeys.corsProxyUrl = "";
  if (elements.virustotalKeyInput) elements.virustotalKeyInput.value = "";
  if (elements.abuseipdbKeyInput) elements.abuseipdbKeyInput.value = "";
  if (elements.corsProxyUrlInput) elements.corsProxyUrlInput.value = "";
  try {
    localStorage.removeItem("vt-api-key");
    localStorage.removeItem("abuseipdb-api-key");
    localStorage.removeItem("cors-proxy-url");
  } catch (e) {
    console.warn("localStorage not available:", e);
  }
  showStatus("API keys cleared.", "info");
}

// Render Results
async function renderResults(analysis) {
  // Show summary section
  const summarySection = document.getElementById("summary-section");
  const summaryContent = document.getElementById("summary-content");
  if (summarySection) summarySection.classList.remove("hidden");
  if (summaryContent) await renderSummary(summaryContent, analysis);

  // Show verdict section
  const verdictSection = document.getElementById("verdict-section");
  const verdictContent = document.getElementById("verdict-content");
  if (verdictSection) verdictSection.classList.remove("hidden");
  if (verdictContent) renderVerdict(verdictContent, analysis.score);

  // Show auth section
  const authSection = document.getElementById("auth-section");
  const authContent = document.getElementById("auth-content");
  if (authSection) authSection.classList.remove("hidden");
  if (authContent) renderAuth(authContent, analysis.auth);

  // Show IOC section
  const iocSection = document.getElementById("ioc-section");
  const iocContent = document.getElementById("ioc-content");
  if (iocSection) iocSection.classList.remove("hidden");
  if (iocContent) renderIOCs(iocContent, analysis.iocs, apiKeys);

  // Show body section
  const bodySection = document.getElementById("body-section");
  const bodyContent = document.getElementById("body-content");
  if (analysis.isFullEmail && analysis.body) {
    if (bodySection) bodySection.classList.remove("hidden");
    if (bodyContent)
      renderBody(bodyContent, analysis.body, analysis.languageAnalysis);
  } else {
    if (bodySection) bodySection.classList.add("hidden");
  }

  // Show headers section
  const headersSection = document.getElementById("headers-section");
  const headersContent = document.getElementById("headers-content");
  if (headersSection) headersSection.classList.remove("hidden");
  if (headersContent) renderHeaders(headersContent, analysis.headers);
}

// Show Status Message
function showStatus(message, type = "info") {
  if (elements.inputStatus) {
    elements.inputStatus.textContent = message;
    elements.inputStatus.className = "status-message " + type;
  }
}

// ===== COPY IOC =====
function copyIOC(btn) {
  const row = btn.closest("tr");
  const original = row?.querySelector(".ioc-original");
  const defanged = row?.querySelector(".ioc-defanged");
  // Copy whichever is visible
  const textToCopy =
    defanged && !defanged.classList.contains("hidden")
      ? defanged.textContent
      : original?.textContent || "";
  navigator.clipboard
    .writeText(textToCopy)
    .then(() => {
      btn.textContent = "Copied!";
      setTimeout(() => (btn.textContent = "Copy"), 2000);
    })
    .catch(() => {
      btn.textContent = "Failed";
      setTimeout(() => (btn.textContent = "Copy"), 2000);
    });
}

// ===== TOGGLE DEFANG =====
function toggleDefang(btn) {
  const row = btn.closest("tr");
  const original = row?.querySelector(".ioc-original");
  const defanged = row?.querySelector(".ioc-defanged");
  if (!original || !defanged) return;

  const isDefanged = !defanged.classList.contains("hidden");
  if (isDefanged) {
    defanged.classList.add("hidden");
    original.classList.remove("hidden");
    btn.textContent = "Defang";
  } else {
    defanged.classList.remove("hidden");
    original.classList.add("hidden");
    btn.textContent = "Original";
  }
}

// ===== VIRUSTOTAL LOOKUP =====
async function lookupVirusTotal(btn) {
  const value = btn.dataset.value;
  const type = btn.dataset.type;
  if (!value || !apiKeys.virustotal) return;

  // Find the result row
  const row = btn.closest("tr");
  const resultRow = row?.nextElementSibling;
  const resultContent = resultRow?.querySelector(".lookup-result-content");
  if (!resultContent) return;

  resultRow.classList.remove("hidden");
  resultContent.innerHTML =
    '<span class="lookup-loading">Loading VirusTotal...</span>';
  btn.disabled = true;

  try {
    let endpoint = "";
    let submitEndpoint = "";
    let submitBody = "";
    let submitContentType = "";

    if (type === "attachment") {
      // File hash lookup - get content from the map using filename as key
      const content = attachmentContentMap.get(value);
      if (content) {
        // Compute SHA-256 hash of the attachment content
        resultContent.innerHTML =
          '<span class="lookup-loading">Computing hash...</span>';
        const hash = await sha256(content);
        endpoint = getVTEndpoint(`/api/v3/files/${hash}`);
      } else {
        // No content available
        resultContent.innerHTML =
          '<span class="lookup-error">Cannot compute hash: attachment content not available. The email may not contain the full attachment data.</span>';
        btn.disabled = false;
        return;
      }
    } else if (type === "ip") {
      // IP address lookup
      endpoint = getVTEndpoint(`/api/v3/ip_addresses/${encodeURIComponent(value)}`);
    } else if (type === "domain") {
      // Domain lookup
      endpoint = getVTEndpoint(`/api/v3/domains/${encodeURIComponent(value)}`);
    } else {
      // URL lookup (default)
      const urlId = btoa(value).replace(/=/g, "");
      endpoint = getVTEndpoint(`/api/v3/urls/${urlId}`);
      submitEndpoint = getVTSubmitEndpoint();
      submitBody = `url=${encodeURIComponent(value)}`;
      submitContentType = "application/x-www-form-urlencoded";
    }

    console.log("[VT] Fetching:", endpoint);
    console.log("[VT] Key prefix:", apiKeys.virustotal.substring(0, 8) + "...");

    const response = await fetch(endpoint, {
      method: "GET",
      headers: {
        "x-apikey": apiKeys.virustotal,
        Accept: "application/json",
      },
    });

    console.log("[VT] Response status:", response.status);

    if (response.status === 404 && submitEndpoint) {
      // URL not analyzed yet - submit for analysis
      resultContent.innerHTML =
        '<span class="lookup-info">URL not found in VirusTotal. Submitting for analysis...</span>';
      const submitResponse = await fetch(submitEndpoint, {
        method: "POST",
        headers: {
          "x-apikey": apiKeys.virustotal,
          "Content-Type": submitContentType,
        },
        body: submitBody,
      });
      console.log("[VT] Submit response status:", submitResponse.status);
      if (submitResponse.ok) {
        resultContent.innerHTML =
          '<span class="lookup-info">URL submitted to VirusTotal for analysis. Check back in a few minutes.</span>';
      } else {
        const err = await submitResponse.json();
        resultContent.innerHTML = `<span class="lookup-error">Error: ${esc(err.error?.message || "Unknown error")}</span>`;
      }
      return;
    }

    if (response.status === 404) {
      resultContent.innerHTML = `<span class="lookup-info">Not found in VirusTotal database.</span>`;
      return;
    }

    if (!response.ok) {
      const err = await response.json();
      resultContent.innerHTML = `<span class="lookup-error">Error: ${esc(err.error?.message || `HTTP ${response.status}`)}</span>`;
      return;
    }

    const data = await response.json();
    const attrs = data.data?.attributes || {};
    const stats = attrs.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;

    const reputationClass =
      malicious > 0
        ? "lookup-malicious"
        : suspicious > 0
          ? "lookup-suspicious"
          : "lookup-clean";

    // Build type-specific display
    let typeLabel = "VirusTotal";
    if (type === "attachment") typeLabel = "VirusTotal (File Hash)";
    else if (type === "ip") typeLabel = "VirusTotal (IP)";
    else if (type === "domain") typeLabel = "VirusTotal (Domain)";

    resultContent.innerHTML = `
      <div class="lookup-result vt-result">
        <div class="lookup-header">
          <strong>${esc(typeLabel)}</strong>
          <span class="lookup-reputation ${reputationClass}">
            ${malicious > 0 ? "⚠ MALICIOUS" : suspicious > 0 ? "⚡ SUSPICIOUS" : "✓ CLEAN"}
          </span>
        </div>
        <div class="lookup-stats">
          <span class="stat malicious">${malicious} malicious</span>
          <span class="stat suspicious">${suspicious} suspicious</span>
          <span class="stat harmless">${stats.harmless || 0} harmless</span>
          <span class="stat undetected">${stats.undetected || 0} undetected</span>
        </div>
        ${attrs.last_analysis_date ? `<div class="lookup-date">Last analyzed: ${new Date(attrs.last_analysis_date * 1000).toLocaleString()}</div>` : ""}
        ${attrs.reputation != null ? `<div class="lookup-rep-score">Reputation: ${attrs.reputation}</div>` : ""}
        ${attrs.as_owner ? `<div class="lookup-usage">AS Owner: ${esc(attrs.as_owner)}</div>` : ""}
        ${attrs.country ? `<div class="lookup-usage">Country: ${esc(attrs.country)}</div>` : ""}
        ${attrs.meaningful_name ? `<div class="lookup-usage">Name: ${esc(attrs.meaningful_name)}</div>` : ""}
      </div>
    `;
  } catch (error) {
    // Always provide web fallback for any error (CORS, network, rate limit, etc.)
    let webUrl = "";
    if (type === "attachment") {
      const content = attachmentContentMap.get(value);
      if (content) {
        try {
          const hash = await sha256(content);
          webUrl = `https://www.virustotal.com/gui/file/${hash}`;
        } catch {
          webUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
        }
      } else {
        webUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
      }
    } else if (type === "ip") {
      webUrl = `https://www.virustotal.com/gui/ip-address/${encodeURIComponent(value)}`;
    } else if (type === "domain") {
      webUrl = `https://www.virustotal.com/gui/domain/${encodeURIComponent(value)}`;
    } else {
      webUrl = `https://www.virustotal.com/gui/search/${encodeURIComponent(value)}`;
    }

    resultContent.innerHTML = `
      <div class="lookup-result">
        <div class="lookup-header">
          <strong>VirusTotal</strong>
          <span class="lookup-reputation lookup-suspicious">API UNAVAILABLE</span>
        </div>
        <div class="lookup-info">
          ${esc(error.message || "Could not connect to VirusTotal API.")}
          <a href="${webUrl}" target="_blank" rel="noopener" class="btn-lookup" style="display:inline-block;margin-top:8px;">Open in VirusTotal ↗</a>
        </div>
      </div>
    `;
  } finally {
    btn.disabled = false;
  }
}

// ===== ABUSEIPDB LOOKUP =====
async function lookupAbuseIPDB(btn) {
  const ip = btn.dataset.value;
  if (!ip || !apiKeys.abuseipdb) return;

  // Find the result row
  const row = btn.closest("tr");
  const resultRow = row?.nextElementSibling;
  const resultContent = resultRow?.querySelector(".lookup-result-content");
  if (!resultContent) return;

  resultRow.classList.remove("hidden");
  resultContent.innerHTML =
    '<span class="lookup-loading">Loading AbuseIPDB...</span>';
  btn.disabled = true;

  try {
    const response = await fetch(
      getAbuseIPDBEndpoint(`/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`),
      {
        method: "GET",
        headers: {
          Key: apiKeys.abuseipdb,
          Accept: "application/json",
        },
      },
    );

    if (!response.ok) {
      const err = await response.json();
      resultContent.innerHTML = `<span class="lookup-error">Error: ${esc(err.errors?.[0]?.detail || `HTTP ${response.status}`)}</span>`;
      return;
    }

    const data = await response.json();
    const attrs = data.data || {};
    const score = attrs.abuseConfidenceScore || 0;

    const reputationClass =
      score >= 50
        ? "lookup-malicious"
        : score >= 25
          ? "lookup-suspicious"
          : "lookup-clean";

    resultContent.innerHTML = `
      <div class="lookup-result abuse-result">
        <div class="lookup-header">
          <strong>AbuseIPDB</strong>
          <span class="lookup-reputation ${reputationClass}">
            ${score >= 50 ? "⚠ HIGH RISK" : score >= 25 ? "⚡ ELEVATED" : "✓ LOW RISK"}
          </span>
        </div>
        <div class="lookup-stats">
          <span class="stat malicious">Abuse Score: ${score}%</span>
          <span class="stat suspicious">Total Reports: ${attrs.totalReports || 0}</span>
          <span class="stat harmless">Country: ${esc(attrs.countryCode || "N/A")}</span>
          <span class="stat undetected">ISP: ${esc(attrs.isp || "N/A")}</span>
        </div>
        ${attrs.domain ? `<div class="lookup-domain">Domain: ${esc(attrs.domain)}</div>` : ""}
        ${attrs.usageType ? `<div class="lookup-usage">Usage: ${esc(attrs.usageType)}</div>` : ""}
        ${attrs.lastReportedAt ? `<div class="lookup-date">Last reported: ${new Date(attrs.lastReportedAt).toLocaleString()}</div>` : ""}
      </div>
    `;
  } catch (error) {
    const webUrl = `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`;
    resultContent.innerHTML = `
      <div class="lookup-result">
        <div class="lookup-header">
          <strong>AbuseIPDB</strong>
          <span class="lookup-reputation lookup-suspicious">API UNAVAILABLE</span>
        </div>
        <div class="lookup-info">
          ${esc(error.message || "Could not connect to AbuseIPDB API.")}
          <a href="${webUrl}" target="_blank" rel="noopener" class="btn-lookup" style="display:inline-block;margin-top:8px;">Open in AbuseIPDB ↗</a>
        </div>
      </div>
    `;
  } finally {
    btn.disabled = false;
  }
}

// Escape HTML helper (uses DOM to avoid entity encoding issues)
function esc(s) {
  if (s == null) return "";
  const div = document.createElement("div");
  div.textContent = String(s);
  return div.innerHTML;
}

// Expose functions globally for inline onclick handlers
window.lookupVirusTotal = lookupVirusTotal;
window.lookupAbuseIPDB = lookupAbuseIPDB;
window.copyIOC = copyIOC;
window.toggleDefang = toggleDefang;

// Initialize on DOM ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
