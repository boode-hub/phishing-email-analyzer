// Header Parsing Module
// RFC 5322 compliant header extraction and unfolding

/**
 * Parse email headers from raw input
 * @param {string} rawInput - Raw email headers or full email
 * @returns {Object} Parsed headers object
 */
export function parseHeaders(rawInput) {
  // Split headers from body (if present)
  const headerEnd = findHeaderBodyBoundary(rawInput);
  const headerSection = rawInput.substring(0, headerEnd);
  const bodySection = rawInput.substring(headerEnd);

  // Unfold and parse headers
  const unfolded = unfoldHeaders(headerSection);
  const headers = parseHeaderLines(unfolded);

  // Extract specific headers (keys are lowercased with hyphens preserved)
  const result = {
    raw: headerSection,
    all: headers,
    from: extractAddress(headers.from),
    replyTo: extractAddress(headers["reply-to"]),
    returnPath: extractAddress(headers["return-path"]),
    to: extractAddress(headers.to),
    subject: decodeEncodedWords(headers.subject || ""),
    date: headers.date,
    messageId: headers["message-id"],
    received: Array.isArray(headers.received)
      ? headers.received
      : headers.received
        ? [headers.received]
        : [],
    authenticationResults: headers["authentication-results"],
    receivedSpf: headers["received-spf"],
    dkimSignature: headers["dkim-signature"],
    contentType: headers["content-type"],
    xMailer: headers["x-mailer"],
    xOriginatingIp: headers["x-originating-ip"],
    xHeaders: extractXHeaders(headers),
  };

  // Extract domains
  result.domains = extractDomains(result);

  return result;
}

/**
 * Find the boundary between headers and body
 */
function findHeaderBodyBoundary(input) {
  // RFC 5322: headers end with a blank line (CRLF CRLF or LF LF)
  const crlfIndex = input.indexOf("\r\n\r\n");
  const lfIndex = input.indexOf("\n\n");

  if (crlfIndex !== -1 && (lfIndex === -1 || crlfIndex < lfIndex)) {
    return crlfIndex;
  }
  if (lfIndex !== -1) {
    return lfIndex;
  }
  return input.length;
}

/**
 * Unfold multi-line headers (RFC 5322)
 * Continuation lines start with whitespace
 */
function unfoldHeaders(headerSection) {
  return headerSection.replace(/\r?\n[ \t]+/g, " ");
}

/**
 * Parse header lines into key-value pairs
 */
function parseHeaderLines(unfolded) {
  const headers = {};
  const lines = unfolded.split(/\r?\n/);

  for (const line of lines) {
    const colonIndex = line.indexOf(":");
    if (colonIndex === -1) continue;

    const key = line.substring(0, colonIndex).trim().toLowerCase();
    const value = line.substring(colonIndex + 1).trim();

    // Handle duplicate headers (like Received)
    if (headers[key]) {
      if (Array.isArray(headers[key])) {
        headers[key].push(value);
      } else {
        headers[key] = [headers[key], value];
      }
    } else {
      headers[key] = value;
    }
  }

  return headers;
}

/**
 * Extract email address from header value
 */
function extractAddress(headerValue) {
  if (!headerValue) return null;

  // Handle "Name <email@domain>" format
  const angleMatch = headerValue.match(/<([^>]+)>/);
  if (angleMatch) {
    const name = headerValue.replace(/<[^>]+>/, "").trim();
    return {
      raw: headerValue,
      email: angleMatch[1].toLowerCase(),
      name: name || null,
    };
  }

  // Handle plain email@domain format
  const plainMatch = headerValue.match(/([^\s<>]+@[^\s<>]+)/);
  if (plainMatch) {
    return {
      raw: headerValue,
      email: plainMatch[1].toLowerCase(),
      name: null,
    };
  }

  return { raw: headerValue, email: null, name: null };
}

/**
 * Decode RFC 2047 encoded-words
 * Format: =?charset?encoding?encoded_text?=
 */
function decodeEncodedWords(text) {
  if (!text) return "";

  // Pattern: =?charset?encoding?text?=
  const pattern = /=\?([^?]+)\?([BQbq])\?([^?]*)\?=/g;

  return text.replace(pattern, (match, charset, encoding, encodedText) => {
    try {
      if (encoding.toUpperCase() === "B") {
        // Base64
        const decoded = atob(encodedText);
        return decodeString(decoded, charset);
      } else if (encoding.toUpperCase() === "Q") {
        // Quoted-printable
        const decoded = encodedText
          .replace(/_/g, " ")
          .replace(/=([0-9A-Fa-f]{2})/g, (m, hex) =>
            String.fromCharCode(parseInt(hex, 16)),
          );
        return decodeString(decoded, charset);
      }
    } catch (e) {
      // Return original if decode fails
    }
    return match;
  });
}

/**
 * Decode string with charset
 */
function decodeString(str, charset) {
  try {
    // Try to decode as the specified charset
    const decoder = new TextDecoder(charset, { fatal: false });
    return decoder.decode(new Uint8Array([...str].map((c) => c.charCodeAt(0))));
  } catch (e) {
    return str;
  }
}

/**
 * Extract X-* headers
 */
function extractXHeaders(headers) {
  const xHeaders = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.startsWith("x-")) {
      xHeaders[key] = value;
    }
  }
  return xHeaders;
}

/**
 * Extract domains from various header sources
 */
function extractDomains(headerData) {
  const domains = [];

  // From address
  if (headerData.from && headerData.from.email) {
    const domain = headerData.from.email.split("@")[1];
    if (domain) {
      domains.push({ source: "From", domain, email: headerData.from.email });
    }
  }

  // Reply-To
  if (headerData.replyTo && headerData.replyTo.email) {
    const domain = headerData.replyTo.email.split("@")[1];
    if (domain) {
      domains.push({
        source: "Reply-To",
        domain,
        email: headerData.replyTo.email,
      });
    }
  }

  // Return-Path
  if (headerData.returnPath && headerData.returnPath.email) {
    const domain = headerData.returnPath.email.split("@")[1];
    if (domain) {
      domains.push({
        source: "Return-Path",
        domain,
        email: headerData.returnPath.email,
      });
    }
  }

  // DKIM domain
  if (headerData.dkimSignature) {
    const dkimMatch = headerData.dkimSignature.match(/d=([^;\s]+)/);
    if (dkimMatch) {
      domains.push({ source: "DKIM", domain: dkimMatch[1] });
    }
  }

  return domains;
}
