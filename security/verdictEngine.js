// security/verdictEngine.js
// Combines Safe Browsing + VirusTotal results into one final verdict

const { checkSafeBrowsing } = require('./safeBrowsingCheck');
const { checkVirusTotal } = require('./virusTotalCheck');

/**
 * Runs all security checks on a URL and returns a combined verdict.
 * @param {string} url - The decoded URL from the QR code.
 * @returns {Promise<{verdict: string, riskScore: number, details: object}>}
 *   verdict: "Safe" | "Suspicious" | "Malicious"
 */
async function getVerdict(url) {
  // Run both checks in parallel to save time (important in a 5-hour hackathon!)
  const [safeBrowsingResult, virusTotalResult] = await Promise.all([
    checkSafeBrowsing(url),
    checkVirusTotal(url),
  ]);

  let verdict = 'Safe';
  let riskScore = 0;

  // Safe Browsing flagged it -> big red flag
  if (safeBrowsingResult.status === 'unsafe') {
    verdict = 'Malicious';
    riskScore += 60;
  }

  // VirusTotal scoring
  if (virusTotalResult.status === 'unsafe') {
    riskScore += 40;
    verdict = 'Malicious';
  } else if (virusTotalResult.status === 'suspicious') {
    riskScore += 20;
    if (verdict === 'Safe') verdict = 'Suspicious';
  }

  // Cap risk score at 100
  riskScore = Math.min(riskScore, 100);

  return {
    verdict,
    riskScore,
    details: {
      safeBrowsing: safeBrowsingResult.status,
      safeBrowsingThreats: safeBrowsingResult.threats,
      virusTotal: virusTotalResult.status,
      virusTotalStats: {
        malicious: virusTotalResult.malicious,
        suspicious: virusTotalResult.suspicious,
        harmless: virusTotalResult.harmless,
      },
    },
  };
}

module.exports = { getVerdict };
