// frontend/script.js
// Actually decodes the uploaded QR image client-side using jsQR (no backend needed).
// Applies simple, explainable heuristic checks to produce a real verdict —
// same logic pattern as our backend security module, running in-browser for the demo.

document.getElementById('scanBtn').addEventListener('click', () => {
  const fileInput = document.getElementById('qrInput');
  if (!fileInput.files[0]) {
    alert('Please select a QR code image first');
    return;
  }

  const file = fileInput.files[0];
  const btn = document.getElementById('scanBtn');
  btn.textContent = 'Scanning...';
  btn.disabled = true;

  const reader = new FileReader();
  reader.onload = function (e) {
    const img = new Image();
    img.onload = function () {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);

      const code = jsQR(imageData.data, imageData.width, imageData.height);

      btn.textContent = 'Scan QR Code';
      btn.disabled = false;

      if (!code) {
        alert('Could not detect a QR code in this image. Try a clearer image.');
        return;
      }

      const decodedUrl = code.data;
      const verdictResult = evaluateUrl(decodedUrl);

      showResult(decodedUrl, verdictResult);
    };
    img.src = e.target.result;
  };
  reader.readAsDataURL(file);
});

function evaluateUrl(url) {
  let riskScore = 0;
  const flags = [];

  const lower = url.toLowerCase();

  const suspiciousKeywords = ['login', 'verify', 'secure', 'update', 'confirm', 'free', 'gift', 'claim', 'account'];
  suspiciousKeywords.forEach((word) => {
    if (lower.includes(word)) {
      riskScore += 15;
      flags.push(`Contains suspicious keyword: "${word}"`);
    }
  });

  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.gq', '.xyz'];
  suspiciousTlds.forEach((tld) => {
    if (lower.includes(tld)) {
      riskScore += 40;
      flags.push(`Uses commonly-abused domain extension: "${tld}"`);
    }
  });

  const shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co'];
  shorteners.forEach((s) => {
    if (lower.includes(s)) {
      riskScore += 25;
      flags.push(`Uses a URL shortener: "${s}"`);
    }
  });

  if (lower.startsWith('http://')) {
    riskScore += 10;
    flags.push('Does not use HTTPS');
  }

  const trustedDomains = ['wikipedia.org', 'google.com', 'github.com', 'microsoft.com'];
  if (trustedDomains.some((d) => lower.includes(d))) {
    riskScore = 0;
    flags.length = 0;
    flags.push('Matches a known trusted domain');
  }

  riskScore = Math.min(riskScore, 100);

  let verdict = 'Safe';
  if (riskScore >= 60) verdict = 'Malicious';
  else if (riskScore >= 25) verdict = 'Suspicious';

  return { verdict, riskScore, flags };
}

function showResult(decodedUrl, result) {
  document.getElementById('result').classList.remove('hidden');
  document.getElementById('decodedUrl').textContent = decodedUrl;
  document.getElementById('riskScore').textContent = `${result.riskScore} / 100`;

  const verdictCard = document.getElementById('verdictCard');
  verdictCard.textContent = result.verdict;
  verdictCard.className = result.verdict.toLowerCase();

  const flagsContainer = document.getElementById('flagsList');
  if (flagsContainer) {
    flagsContainer.innerHTML = result.flags.length
      ? result.flags.map((f) => `<li>${f}</li>`).join('')
      : '<li>No risk indicators found</li>';
  }
}
