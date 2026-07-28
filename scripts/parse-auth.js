// Authentication Parsing Module
// SPF/DKIM/DMARC parsing and domain alignment

/**
 * Parse authentication results from headers
 * @param {Object} headers - Parsed headers object
 * @returns {Object} Authentication analysis
 */
export function parseAuth(headers) {
  const spf = parseSPF(headers.authenticationResults, headers.receivedSpf);
  const dkim = parseDKIM(headers.authenticationResults, headers.dkimSignature);
  const dmarc = parseDMARC(headers.authenticationResults);
  const domainAlignment = checkDomainAlignment(headers);
  const receivedChain = parseReceivedChain(headers.received, domainAlignment);

  const overallStatus = determineOverallStatus({
    spf,
    dkim,
    dmarc,
    domainAlignment,
  });

  return {
    mechanisms: {
      spf: {
        status: spf.status,
        details: spf.raw || null,
      },
      dkim: {
        status: dkim.status,
        details: dkim.domain || null,
      },
      dmarc: {
        status: dmarc.status,
        details: dmarc.raw || null,
      },
    },
    domainAlignment,
    receivedChain,
    overallStatus,
  };
}

/**
 * Parse SPF results
 */
function parseSPF(authResults, receivedSpf) {
  const result = { mechanism: "spf", status: "unknown", raw: null };

  // Try Authentication-Results first
  if (authResults) {
    const spfMatch = authResults.match(/spf=(\w+)/i);
    if (spfMatch) {
      result.status = normalizeAuthStatus(spfMatch[1]);
      result.raw = authResults;
      return result;
    }
  }

  // Fall back to Received-SPF
  if (receivedSpf) {
    const spfMatch = receivedSpf.match(/result=(\w+)/i);
    if (spfMatch) {
      result.status = normalizeAuthStatus(spfMatch[1]);
      result.raw = receivedSpf;
      return result;
    }
  }

  return result;
}

/**
 * Parse DKIM results
 */
function parseDKIM(authResults, dkimSignature) {
  const result = {
    mechanism: "dkim",
    status: "unknown",
    domain: null,
    raw: null,
  };

  // Try Authentication-Results
  if (authResults) {
    const dkimMatch = authResults.match(/dkim=(\w+)/i);
    if (dkimMatch) {
      result.status = normalizeAuthStatus(dkimMatch[1]);
      result.raw = authResults;

      // Try to extract DKIM domain from auth results
      // Matches: header.d=domain.com or d=domain.com
      const domainMatch = authResults.match(
        /dkim=[^;]*(?:header\.d|d)=([^;\s]+)/i,
      );
      if (domainMatch) {
        result.domain = domainMatch[1];
      }
    }
  }

  // Extract from DKIM-Signature header
  if (dkimSignature) {
    const dMatch = dkimSignature.match(/d=([^;\s]+)/);
    if (dMatch) {
      result.domain = dMatch[1];
    }
    if (result.status === "unknown") {
      // DKIM signature present but no auth result - might be neutral
      result.status = "none";
    }
  }

  return result;
}

/**
 * Parse DMARC results
 */
function parseDMARC(authResults) {
  const result = { mechanism: "dmarc", status: "unknown", raw: null };

  if (authResults) {
    const dmarcMatch = authResults.match(/dmarc=(\w+)/i);
    if (dmarcMatch) {
      result.status = normalizeAuthStatus(dmarcMatch[1]);
      result.raw = authResults;
    }
  }

  return result;
}

/**
 * Normalize authentication status to standard values
 */
function normalizeAuthStatus(status) {
  const statusMap = {
    pass: "pass",
    fail: "fail",
    softfail: "softfail",
    neutral: "none",
    none: "none",
    temperror: "unknown",
    permerror: "fail",
  };

  return statusMap[status.toLowerCase()] || "unknown";
}

/**
 * Check domain alignment between From, Reply-To, Return-Path, and DKIM
 */
function checkDomainAlignment(headers) {
  const domains = {};
  const aligned = {};

  // Get domains from headers
  if (headers.from && headers.from.email) {
    domains.From = headers.from.email.split("@")[1];
  }
  if (headers.replyTo && headers.replyTo.email) {
    domains["Reply-To"] = headers.replyTo.email.split("@")[1];
  }
  if (headers.returnPath && headers.returnPath.email) {
    domains["Return-Path"] = headers.returnPath.email.split("@")[1];
  }
  if (headers.dkimSignature) {
    const dkimMatch = headers.dkimSignature.match(/d=([^;\s]+)/);
    if (dkimMatch) {
      domains.DKIM = dkimMatch[1];
    }
  }

  // Check alignment against From domain
  const fromDomain = domains.From;
  const mismatches = [];

  for (const [source, domain] of Object.entries(domains)) {
    if (source === "From") {
      aligned[source] = true;
      continue;
    }

    if (fromDomain) {
      const isAligned = isDomainAligned(fromDomain, domain);
      aligned[source] = isAligned;
      if (!isAligned) {
        mismatches.push(
          `${source} domain (${domain}) doesn't match From domain (${fromDomain})`,
        );
      }
    } else {
      aligned[source] = true; // Can't determine without From
    }
  }

  return {
    domains,
    aligned,
    mismatches,
    mismatchWarning:
      mismatches.length > 0
        ? `Domain mismatch detected: ${mismatches.join("; ")}`
        : null,
  };
}

/**
 * Check if domains are aligned (same domain or subdomain)
 */
function isDomainAligned(fromDomain, otherDomain) {
  if (!fromDomain || !otherDomain) return true;

  const fromLower = fromDomain.toLowerCase();
  const otherLower = otherDomain.toLowerCase();

  // Exact match
  if (fromLower === otherLower) return true;

  // Subdomain check
  if (otherLower.endsWith("." + fromLower)) return true;

  return false;
}

/**
 * Parse Received headers into chain
 */
function parseReceivedChain(receivedHeaders, domainAlignment) {
  if (!receivedHeaders) return [];

  const headers = Array.isArray(receivedHeaders)
    ? receivedHeaders
    : [receivedHeaders];

  return headers.map((header, index) => {
    const hop = {
      number: headers.length - index,
      raw: header,
      from: null,
      by: null,
      date: null,
      ip: null,
      suspicious: false,
    };

    // Extract IP if present
    const ipMatch = header.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    if (ipMatch) {
      hop.ip = ipMatch[1];
    }

    // Extract from hostname
    const fromMatch = header.match(/from\s+([^\s\[]+)/i);
    if (fromMatch) {
      hop.from = fromMatch[1];
    }

    // Extract by hostname
    const byMatch = header.match(/by\s+([^\s\[]+)/i);
    if (byMatch) {
      hop.by = byMatch[1];
    }

    // Extract date/time
    const timeMatch = header.match(/;\s*(.+)$/);
    if (timeMatch) {
      hop.date = timeMatch[1].trim();
    }

    // Heuristic: flag suspicious hops
    // If the from domain doesn't align with the From header domain
    if (
      hop.from &&
      domainAlignment &&
      domainAlignment.domains &&
      domainAlignment.domains.From
    ) {
      const fromDomain = domainAlignment.domains.From;
      // Simple heuristic: if the hop's from doesn't contain the From domain
      if (
        !hop.from.toLowerCase().includes(fromDomain.toLowerCase()) &&
        !hop.from.toLowerCase().endsWith(".com") &&
        !hop.from.toLowerCase().endsWith(".org") &&
        !hop.from.toLowerCase().endsWith(".net")
      ) {
        // Only flag if it looks like a random/mismatched server
        hop.suspicious = true;
      }
    }

    return hop;
  });
}

/**
 * Determine overall authentication status
 */
function determineOverallStatus(auth) {
  const issues = [];

  // Check SPF
  if (auth.spf.status === "fail") {
    issues.push("SPF authentication failed");
  }

  // Check DKIM
  if (auth.dkim.status === "fail") {
    issues.push("DKIM signature verification failed");
  }

  // Check DMARC
  if (auth.dmarc.status === "fail") {
    issues.push("DMARC policy failure");
  }

  // Check domain alignment
  if (!auth.domainAlignment.aligned) {
    issues.push("Domain alignment mismatch detected");
  }

  // Determine status
  if (issues.length === 0) {
    return { level: "pass", issues: [] };
  }

  // Count failures
  const failures = issues.filter(
    (i) => i.includes("failed") || i.includes("failure"),
  ).length;

  if (failures >= 2) {
    return { level: "fail", issues };
  }

  return { level: "suspicious", issues };
}
