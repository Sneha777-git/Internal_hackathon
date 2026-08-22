// security/virusTotalCheck.js
// Checks a URL against VirusTotal (aggregates 70+ security scanners)
// Get a free API key: https://www.virustotal.com/ -> sign up -> Profile -> API Key

const fetch = require('node-fetch'); // npm install node-fetch@2

const VT_API_KEY = process.env.VIRUSTOTAL_API_KEY;

/**
 * Submits a URL to VirusTotal and retrieves the analysis verdict.
 * @param {string} url - The URL to check.
 * @returns {Promise<{status: string, malicious: number, suspicious: number, harmless: number}>}
 *   status: "safe" | "suspicious" | "unsafe" | "error"
 */
async function checkVirusTotal(url) {
  try {
    // Step 1: Submit the URL for scanning
    const submitResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': VT_API_KEY,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `url=${encodeURIComponent(url)}`,
    });

    if (!submitResponse.ok) {
      console.error('VirusTotal submit error:', submitResponse.status);
      return { status: 'error', malicious: 0, suspicious: 0, harmless: 0 };
    }

    const submitData = await submitResponse.json();
    const analysisId = submitData.data.id;

    // Step 2: Retrieve the analysis result
    // VirusTotal needs a moment to process — small delay helps for a hackathon demo
    await new Promise((resolve) => setTimeout(resolve, 3000));

    const analysisResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
      {
        headers: { 'x-apikey': VT_API_KEY },
      }
    );

    if (!analysisResponse.ok) {
      console.error('VirusTotal analysis fetch error:', analysisResponse.status);
      return { status: 'error', malicious: 0, suspicious: 0, harmless: 0 };
    }

    const analysisData = await analysisResponse.json();
    const stats = analysisData.data.attributes.stats;

    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const harmless = stats.harmless || 0;

    let status = 'safe';
    if (malicious > 0) status = 'unsafe';
    else if (suspicious > 0) status = 'suspicious';

    return { status, malicious, suspicious, harmless };
  } catch (err) {
    console.error('VirusTotal check failed:', err.message);
    return { status: 'error', malicious: 0, suspicious: 0, harmless: 0 };
  }
}

module.exports = { checkVirusTotal };
