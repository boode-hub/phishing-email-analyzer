// Language / Urgency / Fraud Analysis
// Local keyword/pattern-based detection - no external API calls

// Keyword/pattern lists
const KEYWORD_PATTERNS = {
  urgency: {
    keywords: [
      "act now",
      "immediately",
      "urgent",
      "as soon as possible",
      "right away",
      "within 24 hours",
      "within 48 hours",
      "deadline",
      "expires soon",
      "account will be suspended",
      "account will be locked",
      "account will be closed",
      "verify now",
      "confirm now",
      "update now",
      "limited time",
      "time sensitive",
      "action required",
      "immediate action",
      "respond immediately",
      "your account expires",
      "final warning",
      "last chance",
      "don't delay",
      "hurry",
      "act fast",
      "time running out",
      "expires today",
      "expires in",
    ],
    weight: 1.0,
    label: "Urgency",
  },
  authority: {
    keywords: [
      "legal action",
      "lawsuit",
      "court",
      "attorney",
      "law enforcement",
      "irs",
      "tax authority",
      "government",
      "federal",
      "official notice",
      "your account has been compromised",
      "unauthorized access",
      "security breach",
      "suspicious activity",
      "final notice",
      "cease and desist",
      "penalty",
      "fine",
      "violation",
      "compliance required",
      "mandatory",
      "obligatory",
    ],
    weight: 1.2,
    label: "Authority/Fear",
  },
  financial: {
    keywords: [
      "wire transfer",
      "bank transfer",
      "swift",
      "iban",
      "gift card",
      "itunes gift card",
      "amazon gift card",
      "cryptocurrency",
      "bitcoin",
      "btc",
      "wallet address",
      "invoice payment",
      "payment request",
      "outstanding payment",
      "banking details",
      "account details",
      "routing number",
      "update your payment information",
      "payment method expired",
      "credit card expired",
      "billing information",
      "refund",
      "reimbursement",
      "compensation",
      "transaction",
      "payment confirmation",
      "order confirmation",
    ],
    weight: 1.1,
    label: "Financial/Fraud",
  },
  credential: {
    keywords: [
      "click here to verify",
      "click here to confirm",
      "verify your account",
      "confirm your password",
      "confirm your identity",
      "login to secure",
      "login to verify",
      "sign in to verify",
      "update your password",
      "reset your password",
      "validate your account",
      "authenticate your account",
      "security check",
      "account verification",
      "confirm login details",
      "update account information",
      "verify credentials",
      "secure your account now",
    ],
    weight: 1.3,
    label: "Credential Harvesting",
  },
};

// Simple language detection wordlists
const LANGUAGE_MARKERS = {
  en: {
    words: [
      "the",
      "and",
      "is",
      "to",
      "of",
      "a",
      "in",
      "that",
      "have",
      "it",
      "for",
      "not",
      "on",
      "with",
      "he",
      "as",
      "you",
      "do",
      "at",
      "this",
      "be",
      "are",
      "was",
      "were",
      "been",
      "will",
      "would",
      "could",
      "should",
      "can",
      "may",
      "might",
      "must",
      "shall",
      "has",
      "had",
      "did",
      "does",
      "doing",
      "done",
    ],
    threshold: 0.2,
  },
  es: {
    words: [
      "el",
      "la",
      "de",
      "que",
      "y",
      "a",
      "en",
      "un",
      "ser",
      "se",
      "no",
      "haber",
      "por",
      "con",
      "su",
      "para",
      "como",
      "estar",
      "tener",
    ],
    threshold: 0.25,
  },
  fr: {
    words: [
      "le",
      "de",
      "et",
      "à",
      "un",
      "il",
      "être",
      "avoir",
      "ne",
      "je",
      "son",
      "que",
      "se",
      "qui",
      "ce",
      "dans",
      "en",
      "du",
      "elle",
      "au",
    ],
    threshold: 0.25,
  },
  de: {
    words: [
      "der",
      "die",
      "und",
      "in",
      "den",
      "von",
      "zu",
      "das",
      "mit",
      "sich",
      "des",
      "auf",
      "für",
      "ist",
      "im",
      "dem",
      "nicht",
      "ein",
      "eine",
    ],
    threshold: 0.25,
  },
};

/**
 * Analyze text for urgency, authority, financial, and credential-harvesting patterns
 * @param {string} text - The email body text to analyze
 * @returns {Object} Analysis results with scores, matches, and highlighted text
 */
export function analyzeLanguage(text) {
  if (!text || typeof text !== "string") {
    return {
      categories: {},
      totalScore: 0,
      detectedLanguage: "unknown",
      languageMismatch: false,
      highlightedText: "",
      summary: "No text provided for analysis",
    };
  }

  const lowerText = text.toLowerCase();
  const categories = {};
  const allMatches = [];

  // Analyze each category
  for (const [categoryKey, config] of Object.entries(KEYWORD_PATTERNS)) {
    const matches = [];

    for (const keyword of config.keywords) {
      const regex = new RegExp(
        keyword.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"),
        "gi",
      );

      let match;
      while ((match = regex.exec(text)) !== null) {
        matches.push({
          phrase: match[0],
          index: match.index,
          length: match[0].length,
        });
        allMatches.push({
          phrase: match[0],
          index: match.index,
          length: match[0].length,
          category: categoryKey,
        });
      }
    }

    // Deduplicate matches (same phrase at same position)
    const uniqueMatches = [];
    const seen = new Set();
    for (const match of matches) {
      const key = `${match.index}-${match.phrase}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueMatches.push(match);
      }
    }

    const score = Math.min(uniqueMatches.length * config.weight * 10, 100);

    categories[categoryKey] = {
      label: config.label,
      score: Math.round(score),
      matches: uniqueMatches,
      matchCount: uniqueMatches.length,
      weight: config.weight,
    };
  }

  // Calculate total score
  const totalScore = Math.min(
    Object.values(categories).reduce((sum, cat) => sum + cat.score, 0),
    100,
  );

  // Detect language
  const detectedLanguage = detectLanguage(text);

  // Generate highlighted text
  const highlightedText = generateHighlightedText(text, allMatches);

  // Generate summary
  const summary = generateSummary(categories, totalScore);

  return {
    categories,
    totalScore: Math.round(totalScore),
    detectedLanguage,
    languageMismatch: false,
    highlightedText,
    summary,
    matches: allMatches,
  };
}

/**
 * Simple language detection based on common word frequency
 * @param {string} text - Text to analyze
 * @returns {string} Detected language code or "unknown"
 */
function detectLanguage(text) {
  const words = text.toLowerCase().match(/\b\w+\b/g) || [];
  const totalWords = words.length;

  if (totalWords < 10) return "unknown";

  let bestLang = "unknown";
  let bestScore = 0;

  for (const [lang, config] of Object.entries(LANGUAGE_MARKERS)) {
    const matches = words.filter((word) => config.words.includes(word)).length;
    const score = matches / totalWords;

    if (score > config.threshold && score > bestScore) {
      bestScore = score;
      bestLang = lang;
    }
  }

  return bestLang;
}

/**
 * Generate HTML with highlighted phrases
 * @param {string} text - Original text
 * @param {Array} matches - Array of match objects
 * @returns {string} HTML with highlighted spans
 */
function generateHighlightedText(text, matches) {
  if (!matches.length) return escapeHtml(text);

  // Sort matches by index
  matches.sort((a, b) => a.index - b.index);

  // Merge overlapping matches
  const merged = [];
  for (const match of matches) {
    const last = merged[merged.length - 1];
    if (last && match.index < last.index + last.length) {
      last.length = Math.max(
        last.length,
        match.index + match.length - last.index,
      );
      last.categories = last.categories || [last.category];
      if (!last.categories.includes(match.category)) {
        last.categories.push(match.category);
      }
    } else {
      merged.push({
        index: match.index,
        length: match.length,
        category: match.category,
        categories: [match.category],
      });
    }
  }

  // Build HTML
  let result = "";
  let lastIndex = 0;

  for (const match of merged) {
    result += escapeHtml(text.substring(lastIndex, match.index));
    const matchedText = text.substring(match.index, match.index + match.length);
    result += `<mark class="highlight-${match.category}" title="${getCategoryLabel(match.category)}">${escapeHtml(matchedText)}</mark>`;
    lastIndex = match.index + match.length;
  }

  result += escapeHtml(text.substring(lastIndex));
  return result;
}

/**
 * Get human-readable label for a category
 * @param {string} category - Category key
 * @returns {string} Human-readable label
 */
function getCategoryLabel(category) {
  const labels = {
    urgency: "Urgency indicator",
    authority: "Authority/Fear tactic",
    financial: "Financial fraud indicator",
    credential: "Credential harvesting attempt",
  };
  return labels[category] || category;
}

/**
 * Generate analysis summary
 * @param {Object} categories - Category analysis results
 * @param {number} totalScore - Total risk score
 * @returns {string} Human-readable summary
 */
function generateSummary(categories, totalScore) {
  const parts = [];

  for (const [key, cat] of Object.entries(categories)) {
    if (cat.matchCount > 0) {
      parts.push(
        `${cat.matchCount} ${cat.label.toLowerCase()} phrase${cat.matchCount > 1 ? "s" : ""}`,
      );
    }
  }

  if (parts.length === 0) {
    return "No suspicious language patterns detected.";
  }

  return `Detected: ${parts.join(", ")}.`;
}

/**
 * Escape HTML special characters
 * @param {string} text - Text to escape
 * @returns {string} Escaped text
 */
function escapeHtml(text) {
  if (!text) return "";
  return text
    .replace(/&/g, "&" + "amp;")
    .replace(/</g, "&" + "lt;")
    .replace(/>/g, "&" + "gt;")
    .replace(/"/g, "&" + "quot;")
    .replace(/'/g, "&#39;");
}
