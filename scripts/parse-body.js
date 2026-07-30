// Body Parsing Module
// MIME body extraction, decoding, and link extraction

/**
 * Parse email body from raw input
 * @param {string} rawInput - Raw email (headers + body)
 * @returns {Object} Parsed body content
 */
export function parseBody(rawInput) {
  // Find header/body boundary
  const headerEnd = findHeaderBodyBoundary(rawInput);
  const bodyContent = rawInput.substring(headerEnd).trim();

  // Get content type from headers
  const contentType = extractContentType(rawInput);
  const transferEncoding = extractTransferEncoding(rawInput);

  // Parse based on content type
  if (contentType && contentType.includes("multipart")) {
    return parseMultipart(bodyContent, contentType);
  }

  // Single part - decode and extract
  const decoded = decodeContent(bodyContent, transferEncoding);

  return {
    text: extractPlainText(decoded, contentType),
    html: extractHtml(decoded, contentType),
    raw: decoded,
    contentType,
    attachments: extractAttachments(rawInput),
    links: extractLinks(decoded, contentType),
  };
}

/**
 * Find header/body boundary
 */
function findHeaderBodyBoundary(input) {
  const crlfIndex = input.indexOf("\r\n\r\n");
  const lfIndex = input.indexOf("\n\n");

  if (crlfIndex !== -1 && (lfIndex === -1 || crlfIndex < lfIndex)) {
    return crlfIndex + 4;
  }
  if (lfIndex !== -1) {
    return lfIndex + 2;
  }
  return input.length;
}

/**
 * Extract Content-Type header (full value including parameters)
 */
function extractContentType(rawInput) {
  const match = rawInput.match(/Content-Type:\s*(.+)/i);
  return match ? match[1].trim() : "text/plain";
}

/**
 * Extract Content-Transfer-Encoding
 */
function extractTransferEncoding(rawInput) {
  const match = rawInput.match(/Content-Transfer-Encoding:\s*([\w-]+)/i);
  return match ? match[1].toLowerCase() : "7bit";
}

/**
 * Parse multipart message
 */
function parseMultipart(bodyContent, contentType) {
  const boundaryMatch = contentType.match(/boundary=["']?([^"'\s;]+)["']?/i);
  if (!boundaryMatch) {
    return {
      text: bodyContent,
      html: null,
      raw: bodyContent,
      attachments: [],
      links: [],
    };
  }

  const boundary = boundaryMatch[1];
  const parts = bodyContent
    .split("--" + boundary)
    .filter((p) => p.trim() && !p.trim().startsWith("--"));

  let text = "";
  let html = "";
  const attachments = [];
  const allLinks = [];

  for (const part of parts) {
    const partBoundary = part.indexOf("\r\n\r\n");
    const partBoundaryLF = part.indexOf("\n\n");
    const boundaryPos = partBoundary !== -1 ? partBoundary : partBoundaryLF;
    const partHeaders = part.substring(0, boundaryPos);
    const partBody = part.substring(
      boundaryPos + (partBoundary !== -1 ? 4 : 2),
    );

    const partContentType = extractContentType(partHeaders);
    const partEncoding = extractTransferEncoding(partHeaders);
    const decoded = decodeContent(partBody, partEncoding);

    // Check disposition
    const disposition = partHeaders.match(/Content-Disposition:\s*(\w+)/i);
    const isAttachment =
      disposition && disposition[1].toLowerCase() === "attachment";

    if (isAttachment) {
      attachments.push(extractAttachmentInfo(partHeaders, partBody));
    } else if (partContentType.includes("text/plain")) {
      text += decoded + "\n";
    } else if (partContentType.includes("text/html")) {
      html += decoded;
    }

    // Extract links from this part
    if (partContentType.includes("text/html")) {
      allLinks.push(...extractLinksFromHtml(decoded));
    } else if (partContentType.includes("text/plain")) {
      allLinks.push(...extractLinksFromText(decoded));
    }
  }

  return {
    text: text.trim(),
    html: html.trim() || null,
    raw: text.trim() || html.trim(),
    contentType,
    attachments,
    links: allLinks,
  };
}

/**
 * Decode content based on transfer encoding
 */
function decodeContent(content, encoding) {
  switch (encoding) {
    case "base64":
      return decodeBase64(content);
    case "quoted-printable":
      return decodeQuotedPrintable(content);
    case "7bit":
    case "8bit":
    default:
      return content;
  }
}

/**
 * Decode base64 content
 */
function decodeBase64(content) {
  // Remove whitespace and padding
  const cleaned = content.replace(/[\s\r\n]/g, "");
  try {
    return atob(cleaned);
  } catch (e) {
    return content;
  }
}

/**
 * Decode quoted-printable content
 */
function decodeQuotedPrintable(content) {
  return content
    .replace(/=\r?\n/g, "") // Soft line breaks
    .replace(/=([0-9A-Fa-f]{2})/g, (match, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    )
    .replace(/_\s/g, " "); // Underscore to space
}

/**
 * Extract plain text from content
 */
function extractPlainText(content, contentType) {
  if (contentType.includes("text/html")) {
    return stripHtml(content);
  }
  return content;
}

/**
 * Extract HTML from content
 */
function extractHtml(content, contentType) {
  if (contentType.includes("text/html")) {
    return content;
  }
  return null;
}

/**
 * Strip HTML tags and decode entities
 */
function stripHtml(html) {
  return html
    .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
    .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&#(\d+);/g, (m, num) => String.fromCharCode(num))
    .replace(/&#x([0-9a-f]+);/gi, (m, hex) =>
      String.fromCharCode(parseInt(hex, 16)),
    )
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, '"')
    .replace(/&#39;/gi, "'")
    .replace(/\s+/g, " ")
    .trim();
}

/**
 * Extract attachment info
 */
function extractAttachmentInfo(headers, body) {
  const filenameMatch = headers.match(/filename=["']?([^"'\r\n;]+)["']?/i);
  const nameMatch = headers.match(/name=["']?([^"'\r\n;]+)["']?/i);
  const contentTypeMatch = headers.match(/Content-Type:\s*([^;\r\n]+)/i);

  return {
    filename: filenameMatch
      ? filenameMatch[1]
      : nameMatch
        ? nameMatch[1]
        : "unknown",
    contentType: contentTypeMatch
      ? contentTypeMatch[1]
      : "application/octet-stream",
    size: body.length,
  };
}

/**
 * Extract attachments from raw email
 */
function extractAttachments(rawInput) {
  const attachments = [];
  const boundaryMatch = rawInput.match(/boundary=["']?([^"'\s;]+)["']?/i);

  if (!boundaryMatch) return attachments;

  const boundary = boundaryMatch[1];
  const parts = rawInput.split("--" + boundary);

  for (const part of parts) {
    if (part.includes("attachment") || part.includes("filename=")) {
      const filenameMatch = part.match(/filename=["']?([^"'\r\n;]+)["']?/i);
      const contentTypeMatch = part.match(/Content-Type:\s*([^;\r\n]+)/i);

      if (filenameMatch) {
        attachments.push({
          filename: filenameMatch[1],
          contentType: contentTypeMatch
            ? contentTypeMatch[1]
            : "application/octet-stream",
        });
      }
    }
  }

  return attachments;
}

/**
 * Extract links from content
 */
function extractLinks(content, contentType) {
  if (contentType.includes("text/html")) {
    return extractLinksFromHtml(content);
  }
  return extractLinksFromText(content);
}

/**
 * Extract links from HTML
 */
function extractLinksFromHtml(html) {
  const links = [];
  const linkPattern = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]*)<\/a>/gi;
  let match;

  while ((match = linkPattern.exec(html)) !== null) {
    const href = match[1].trim();
    const text = stripHtml(match[2]).trim();

    links.push({
      href,
      text: text || href,
      isMismatch: text && text !== href && !href.startsWith("mailto:"),
    });
  }

  return links;
}

/**
 * Extract links from plain text
 */
function extractLinksFromText(text) {
  const links = [];
  const urlPattern = /https?:\/\/[^\s<>"]+/gi;
  let match;

  while ((match = urlPattern.exec(text)) !== null) {
    links.push({
      href: match[0],
      text: match[0],
      isMismatch: false,
    });
  }

  return links;
}
