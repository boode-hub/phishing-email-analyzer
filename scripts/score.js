// Scoring Module
// Composite risk score calculation

/**
 * Calculate overall risk score
 * @param {Object} auth - Authentication analysis
 * @param {Object} iocs - Extracted IOCs
 * @param {Object} languageAnalysis - Language analysis results
 * @returns {Object} Risk score and breakdown
 */
export function calculateScore(auth, iocs, languageAnalysis) {
  const result = {
    tier: "Low Risk",
    score: 0,
    reasons: [],
    breakdown: {
      authentication: 0,
      iocs: 0,
      language: 0,
    },
  };

  // Authentication scoring (heavily weighted)
  const authScore = scoreAuthentication(auth);
  result.breakdown.authentication = Math.min(authScore, 100);

  if (authScore >= 20) {
    result.reasons.push(...auth.overallStatus.issues);
  }

  // IOC scoring
  const iocScore = scoreIOCs(iocs);
  result.breakdown.iocs = Math.min(iocScore, 100);

  // Language scoring
  const langScore = languageAnalysis ? scoreLanguage(languageAnalysis) : 0;
  result.breakdown.language = Math.min(langScore, 100);

  // Calculate total score (weighted average)
  const totalScore = authScore * 0.5 + iocScore * 0.3 + langScore * 0.2;
  result.score = Math.round(Math.min(totalScore, 100));

  // Determine tier
  if (result.score >= 60) {
    result.tier = "High Risk";
  } else if (result.score >= 30) {
    result.tier = "Suspicious";
  } else {
    result.tier = "Low Risk";
  }

  // Add language reasons
  if (languageAnalysis && languageAnalysis.categories) {
    const cats = languageAnalysis.categories;
    if (cats.urgency && cats.urgency.matchCount > 0) {
      result.reasons.push(
        `${cats.urgency.matchCount} urgency phrase(s) detected`,
      );
    }
    if (cats.authority && cats.authority.matchCount > 0) {
      result.reasons.push(
        `${cats.authority.matchCount} authority/fear phrase(s) detected`,
      );
    }
    if (cats.financial && cats.financial.matchCount > 0) {
      result.reasons.push(
        `${cats.financial.matchCount} financial/fraud phrase(s) detected`,
      );
    }
    if (cats.credential && cats.credential.matchCount > 0) {
      result.reasons.push(
        `${cats.credential.matchCount} credential-harvesting phrase(s) detected`,
      );
    }
  }

  // Add IOC reasons
  if (iocScore > 0) {
    if (
      iocs.urls &&
      iocs.urls.some(
        (u) => u.risks && u.risks.some((r) => r.type === "mismatch"),
      )
    ) {
      result.reasons.push("Link text mismatch detected");
    }
    if (
      iocs.urls &&
      iocs.urls.some((u) => u.risks && u.risks.some((r) => r.type === "ip-url"))
    ) {
      result.reasons.push("URL uses raw IP address");
    }
    if (
      iocs.urls &&
      iocs.urls.some(
        (u) => u.risks && u.risks.some((r) => r.type === "punycode"),
      )
    ) {
      result.reasons.push("Punycode domain detected");
    }
    if (
      iocs.attachments &&
      iocs.attachments.some((a) => a.risks && a.risks.length > 0)
    ) {
      result.reasons.push("Risky attachment detected");
    }
  }

  // Deduplicate reasons
  result.reasons = [...new Set(result.reasons)];

  // If no reasons but score is elevated, add a generic reason
  if (result.reasons.length === 0 && result.score > 0) {
    result.reasons.push("Minor risk indicators present");
  }

  return result;
}

/**
 * Score authentication results
 */
function scoreAuthentication(auth) {
  let score = 0;

  // SPF
  switch (auth.mechanisms.spf.status) {
    case "fail":
      score += 30;
      break;
    case "softfail":
      score += 15;
      break;
    case "none":
      score += 5;
      break;
    case "pass":
      score -= 5;
      break;
  }

  // DKIM
  switch (auth.mechanisms.dkim.status) {
    case "fail":
      score += 25;
      break;
    case "none":
      score += 5;
      break;
    case "pass":
      score -= 5;
      break;
  }

  // DMARC
  switch (auth.mechanisms.dmarc.status) {
    case "fail":
      score += 35;
      break;
    case "none":
      score += 5;
      break;
    case "pass":
      score -= 5;
      break;
  }

  // Domain alignment
  if (auth.domainAlignment && auth.domainAlignment.mismatches.length > 0) {
    score += 40;
  }

  return Math.max(0, score);
}

/**
 * Score IOCs
 */
function scoreIOCs(iocs) {
  if (!iocs) return 0;
  let score = 0;

  // High-risk URLs
  const highRiskUrls = iocs.urls
    ? iocs.urls.filter(
        (u) => u.risks && u.risks.some((r) => r.level === "high"),
      )
    : [];
  score += highRiskUrls.length * 15;

  // Medium-risk URLs
  const mediumRiskUrls = iocs.urls
    ? iocs.urls.filter(
        (u) =>
          u.risks &&
          u.risks.some((r) => r.level === "medium") &&
          !u.risks.some((r) => r.level === "high"),
      )
    : [];
  score += mediumRiskUrls.length * 8;

  // Risky attachments
  const riskyAttachments = iocs.attachments
    ? iocs.attachments.filter(
        (a) => a.risks && a.risks.some((r) => r.level === "high"),
      )
    : [];
  score += riskyAttachments.length * 20;

  // Punycode domains
  const punycodeDomains = iocs.domains
    ? iocs.domains.filter(
        (d) => d.risks && d.risks.some((r) => r.type === "punycode"),
      )
    : [];
  score += punycodeDomains.length * 15;

  return score;
}

/**
 * Score language analysis
 */
function scoreLanguage(lang) {
  if (!lang || !lang.categories) return 0;
  let score = 0;

  const cats = lang.categories;

  // Urgency
  if (cats.urgency) {
    score += cats.urgency.score * 0.5;
  }

  // Authority/fear
  if (cats.authority) {
    score += cats.authority.score * 0.5;
  }

  // Financial/fraud
  if (cats.financial) {
    score += cats.financial.score * 0.8;
  }

  // Credential harvesting
  if (cats.credential) {
    score += cats.credential.score * 0.8;
  }

  return Math.round(score);
}
