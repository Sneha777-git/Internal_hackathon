// security/safeBrowsingCheck.js
// Checks a URL against Google's Safe Browsing API
// Get a free API key: https://console.cloud.google.com/ -> enable "Safe Browsing API"

const fetch = require('node-fetch'); // npm install node-fetch@2

const SAFE_BROWSING_API_KEY = process.env.SAFE_BROWSING_API_KEY;
const SAFE_BROWSING_URL = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;

/**
 * Checks a URL against Google Safe Browsing.
 * @param {string} url - The URL to check.
 * @returns {Promise<{status: string, threats: string[]}>}
 *   status: "safe" | "unsafe" | "error"
 */
async function checkSafeBrowsing(url) {
  const requestBody = {
    client: {
      clientId: 'qr-safety-scanner',
      clientVersion: '1.0.0',
    },
    threatInfo: {
      threatTypes: [
        'MALWARE',
        'SOCIAL_ENGINEERING',
        'UNWANTED_SOFTWARE',
        'POTENTIALLY_HARMFUL_APPLICATION',
      ],
      platformTypes: ['ANY_PLATFORM'],
      threatEntryTypes: ['URL'],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(SAFE_BROWSING_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(requestBody),
    });

    if (!response.ok) {
      console.error('Safe Browsing API error:', response.status);
      return { status: 'error', threats: [] };
    }

    const data = await response.json();

    // If "matches" exists, the URL was flagged
    if (data.matches && data.matches.length > 0) {
      const threats = data.matches.map((m) => m.threatType);
      return { status: 'unsafe', threats };
    }

    return { status: 'safe', threats: [] };
  } catch (err) {
    console.error('Safe Browsing check failed:', err.message);
    return { status: 'error', threats: [] };
  }
}

module.exports = { checkSafeBrowsing };
