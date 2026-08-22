(function(){
  "use strict";

  /* ---------------- state ---------------- */
  let apiKey = "";
  let stream = null;
  let rafId = null;

  const els = {
    dropzone: document.getElementById('dropzone'),
    fileInput: document.getElementById('fileInput'),
    uploadBtn: document.getElementById('uploadBtn'),
    cameraBtn: document.getElementById('cameraBtn'),
    scanStage: document.getElementById('scanStage'),
    mediaWrap: document.getElementById('mediaWrap'),
    scanCaption: document.getElementById('scanCaption'),
    decodeError: document.getElementById('decodeError'),
    payloadStrip: document.getElementById('payloadStrip'),
    payloadVal: document.getElementById('payloadVal'),
    consoleStatus: document.getElementById('consoleStatus'),
    lanesSection: document.getElementById('lanesSection'),
    verdictSection: document.getElementById('verdictSection'),
    stamp: document.getElementById('stamp'),
    ticket: document.getElementById('ticket'),
    rescanBtn: document.getElementById('rescanBtn'),
    apiKeyInput: document.getElementById('apiKeyInput'),
    saveKeyBtn: document.getElementById('saveKeyBtn'),
  };

  const lane = {
    1:{num:document.getElementById('lane1num'), status:document.getElementById('lane1status'), findings:document.getElementById('lane1findings')},
    2:{num:document.getElementById('lane2num'), status:document.getElementById('lane2status'), findings:document.getElementById('lane2findings')},
    3:{num:document.getElementById('lane3num'), status:document.getElementById('lane3status'), findings:document.getElementById('lane3findings')},
  };

  /* ---------------- helpers ---------------- */
  function setLaneStatus(n, cls, text){
    lane[n].status.className = 'lane-status ' + cls;
    lane[n].status.textContent = text;
    lane[n].num.className = 'lane-num' + (cls==='running' ? ' running' : '');
  }
  function addFinding(n, level, text){
    const li = document.createElement('li');
    li.className = level === 'ok' ? 'flag-ok' : (level === 'warn' ? 'flag-warn' : 'flag-bad');
    const icon = level === 'ok' ? '✓' : (level === 'warn' ? '!' : '✕');
    li.textContent = icon + '  ' + text;
    lane[n].findings.appendChild(li);
  }
  function clearLane(n){ lane[n].findings.innerHTML = ''; }
  function escapeHtml(s){
    return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
  }

  function levenshtein(a,b){
    const m=a.length,n=b.length;
    const dp=Array.from({length:m+1},()=>new Array(n+1).fill(0));
    for(let i=0;i<=m;i++)dp[i][0]=i;
    for(let j=0;j<=n;j++)dp[0][j]=j;
    for(let i=1;i<=m;i++){
      for(let j=1;j<=n;j++){
        dp[i][j]=Math.min(
          dp[i-1][j]+1,
          dp[i][j-1]+1,
          dp[i-1][j-1]+(a[i-1]===b[j-1]?0:1)
        );
      }
    }
    return dp[m][n];
  }

  const POPULAR_DOMAINS = [
    'google.com','youtube.com','facebook.com','instagram.com','whatsapp.com',
    'amazon.com','apple.com','icloud.com','microsoft.com','outlook.com','live.com',
    'paypal.com','netflix.com','twitter.com','x.com','linkedin.com','github.com',
    'dropbox.com','adobe.com','ebay.com','walmart.com','target.com','spotify.com',
    'chase.com','bankofamerica.com','wellsfargo.com','venmo.com','zoom.us',
    'yahoo.com','wordpress.com','steam.com','steampowered.com'
  ];
  const SHORTENERS = ['bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','is.gd','buff.ly',
    'cutt.ly','rebrand.ly','tiny.cc','rb.gy','shorturl.at','s.id','v.gd'];
  const BRAND_TO_DOMAIN = {
    paypal:'paypal.com', apple:'apple.com', google:'google.com', microsoft:'microsoft.com',
    amazon:'amazon.com', netflix:'netflix.com', facebook:'facebook.com', instagram:'instagram.com',
    whatsapp:'whatsapp.com', icloud:'icloud.com', chase:'chase.com', wellsfargo:'wellsfargo.com',
    linkedin:'linkedin.com', dropbox:'dropbox.com'
  };

  /* ---------------- Lane 01: structure analysis (no network) ---------------- */
  function runStructureLane(rawUrl){
    return new Promise(resolve=>{
      clearLane(1);
      let score = 0; // higher = riskier
      let parsed;
      try{ parsed = new URL(rawUrl); }
      catch(e){
        addFinding(1,'bad','Not a well-formed URL — cannot be safely parsed.');
        resolve({score:100, hostname:null});
        return;
      }
      const host = parsed.hostname.toLowerCase();
      const labels = host.split('.');
      const registrable = labels.slice(-2).join('.');

      // protocol
      if(parsed.protocol !== 'https:'){
        addFinding(1,'warn','Not served over HTTPS ('+parsed.protocol.replace(':','')+').');
        score += 15;
      } else {
        addFinding(1,'ok','Uses HTTPS.');
      }

      // raw IP host
      const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
      if(ipRegex.test(host) || host.includes(':')){
        addFinding(1,'bad','Destination is a raw IP address, not a domain name.');
        score += 35;
      }

      // punycode / homograph
      if(labels.some(l=>l.startsWith('xn--'))){
        addFinding(1,'bad','Domain uses punycode encoding — possible look-alike character attack.');
        score += 30;
      }

      // credentials in URL (user@host trick)
      if(parsed.username){
        addFinding(1,'bad','URL embeds a credential/username before the host — a classic obfuscation trick.');
        score += 30;
      }

      // excessive subdomains
      if(labels.length > 4){
        addFinding(1,'warn','Unusually many subdomain levels ('+labels.length+').');
        score += 10;
      }

      // length
      if(rawUrl.length > 120){
        addFinding(1,'warn','Very long URL ('+rawUrl.length+' characters).');
        score += 8;
      }

      // shorteners
      if(SHORTENERS.includes(registrable)){
        addFinding(1,'warn','Uses a link shortener — real destination is hidden until visited.');
        score += 15;
      }

      // typosquat check against popular domains
      let closest = null, closestDist = Infinity;
      for(const d of POPULAR_DOMAINS){
        const dist = levenshtein(registrable, d);
        if(dist < closestDist){ closestDist = dist; closest = d; }
      }
      if(closestDist > 0 && closestDist <= 2 && registrable !== closest){
        addFinding(1,'bad','Domain "'+registrable+'" is suspiciously close to "'+closest+'" (possible typosquat).');
        score += 35;
      }

      // brand impersonation: brand name embedded in a hostname that isn't the brand's real domain
      for(const [brand, legit] of Object.entries(BRAND_TO_DOMAIN)){
        if(host.includes(brand) && registrable !== legit){
          addFinding(1,'bad','Hostname contains "'+brand+'" but is not '+legit+' — likely impersonation.');
          score += 30;
          break;
        }
      }

      if(score === 0){
        addFinding(1,'ok','No structural red flags found.');
      }

      resolve({score, hostname: host});
    });
  }

  /* ---------------- Lane 02: DNS + hosting (network, no key) ---------------- */
  async function runHostingLane(hostname){
    clearLane(2);
    if(!hostname){
      addFinding(2,'warn','Skipped — no valid hostname to resolve.');
      return {score:0, resolved:false, ip:null, org:null, country:null};
    }
    let score = 0;
    let ip=null, org=null, country=null;
    try{
      const dnsResp = await fetch('https://dns.google/resolve?name='+encodeURIComponent(hostname)+'&type=A', {cache:'no-store'});
      const dnsJson = await dnsResp.json();
      const answer = (dnsJson.Answer||[]).find(a=>a.type===1);
      if(!answer){
        addFinding(2,'bad','Domain does not resolve to any address — dead or throwaway infrastructure.');
        score += 40;
        return {score, resolved:false, ip:null, org:null, country:null};
      }
      ip = answer.data;
      addFinding(2,'ok','Resolves to '+ip+'.');
    }catch(e){
      addFinding(2,'warn','DNS lookup failed (network or CORS issue) — could not verify resolution.');
      return {score:5, resolved:null, ip:null, org:null, country:null};
    }

    try{
      const geoResp = await fetch('https://ipwho.is/'+ip, {cache:'no-store'});
      const geoJson = await geoResp.json();
      if(geoJson && geoJson.success !== false){
        org = (geoJson.connection && (geoJson.connection.org || geoJson.connection.isp)) || null;
        country = geoJson.country || null;
        addFinding(2,'ok','Hosted via '+(org||'unknown provider')+(country?(' — '+country):'')+'.');
      }
    }catch(e){
      addFinding(2,'warn','Hosting lookup unavailable — proceeding without it.');
    }

    if(score===0) addFinding(2,'ok','No hosting-level red flags found.');
    return {score, resolved:true, ip, org, country};
  }

  /* ---------------- Lane 03: Safe Browsing (network, needs key) ---------------- */
  async function runThreatLane(rawUrl){
    clearLane(3);
    if(!apiKey){
      addFinding(3,'warn','No API key set — live threat-database lookup skipped (see settings below).');
      return {score:0, skipped:true, matched:false};
    }
    try{
      const body = {
        client:{clientId:'checkpoint-qr-scanner', clientVersion:'1.0.0'},
        threatInfo:{
          threatTypes:['MALWARE','SOCIAL_ENGINEERING','UNWANTED_SOFTWARE','POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes:['ANY_PLATFORM'],
          threatEntryTypes:['URL'],
          threatEntries:[{url: rawUrl}]
        }
      };
      const resp = await fetch('https://safebrowsing.googleapis.com/v4/threatMatches:find?key='+encodeURIComponent(apiKey), {
        method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(body)
      });
      if(!resp.ok){
        addFinding(3,'warn','Threat-database request failed (HTTP '+resp.status+') — check API key.');
        return {score:0, skipped:true, matched:false};
      }
      const json = await resp.json();
      if(json.matches && json.matches.length){
        const types = [...new Set(json.matches.map(m=>m.threatType))].join(', ');
        addFinding(3,'bad','Matched known threat database entry: '+types+'.');
        return {score:100, skipped:false, matched:true};
      }
      addFinding(3,'ok','No match in Google Safe Browsing\u2019s live database.');
      return {score:0, skipped:false, matched:false};
    }catch(e){
      addFinding(3,'warn','Threat-database lookup failed (network/CORS) — treated as inconclusive.');
      return {score:0, skipped:true, matched:false};
    }
  }

  /* ---------------- orchestration ---------------- */
  async function inspect(rawUrl){
    els.lanesSection.classList.add('show');
    els.verdictSection.classList.remove('show');
    [1,2,3].forEach(n=>{ clearLane(n); setLaneStatus(n,'pending','PENDING'); });
    els.consoleStatus.textContent = '● INSPECTING';

    // Lane 1
    setLaneStatus(1,'running','RUNNING');
    const r1 = await runStructureLane(rawUrl);
    setLaneStatus(1, r1.score>=50?'flagged':(r1.score>0?'caution':'clear'), r1.score>=50?'FLAGGED':(r1.score>0?'CAUTION':'CLEAR'));

    // Lane 2
    setLaneStatus(2,'running','RUNNING');
    const r2 = await runHostingLane(r1.hostname);
    setLaneStatus(2, r2.score>=40?'flagged':(r2.score>0?'caution':'clear'), r2.score>=40?'FLAGGED':(r2.score>0?'CAUTION':'CLEAR'));

    // Lane 3
    setLaneStatus(3,'running','RUNNING');
    const r3 = await runThreatLane(rawUrl);
    if(r3.skipped){ setLaneStatus(3,'skipped','SKIPPED'); }
    else{ setLaneStatus(3, r3.matched?'flagged':'clear', r3.matched?'FLAGGED':'CLEAR'); }

    renderVerdict(rawUrl, r1, r2, r3);
    els.consoleStatus.textContent = '● INSPECTION COMPLETE';
  }

  function renderVerdict(rawUrl, r1, r2, r3){
    const totalScore = r1.score + r2.score + r3.score;
    let level, label;
    if(r3.matched || totalScore >= 60){ level='danger'; label='FLAGGED\\nDo not open'; }
    else if(totalScore >= 20){ level='caution'; label='CAUTION\\nProceed carefully'; }
    else { level='clear'; label='CLEARED\\nLooks safe'; }

    els.stamp.className = 'stamp ' + level;
    els.stamp.innerHTML = label.split('\\n').join('<br>');

    let host = r1.hostname || '—';
    const favicon = r1.hostname ? ('https://www.google.com/s2/favicons?sz=64&domain='+encodeURIComponent(r1.hostname)) : '';

    els.ticket.innerHTML = `
      <div class="ticket-row"><span class="k">Destination</span><span class="v">${favicon?'<img class="ticket-fav" src="'+favicon+'">':''}${escapeHtml(host)}</span></div>
      <div class="ticket-row"><span class="k">Full URL</span><span class="v">${escapeHtml(rawUrl)}</span></div>
      <div class="ticket-row"><span class="k">Resolved IP</span><span class="v">${escapeHtml(r2.ip || 'unresolved')}</span></div>
      <div class="ticket-row"><span class="k">Hosting org</span><span class="v">${escapeHtml(r2.org || '—')}${r2.country?(' · '+escapeHtml(r2.country)):''}</span></div>
      <div class="ticket-row"><span class="k">Threat DB</span><span class="v">${r3.skipped ? 'not checked' : (r3.matched ? 'match found' : 'no match')}</span></div>
      <div class="ticket-row"><span class="k">Risk score</span><span class="v">${totalScore} / 100+</span></div>
      <div class="ticket-actions">
        <button class="btn" id="copyLinkBtn">Copy link</button>
        <button class="btn btn-danger" id="openAnywayBtn">Open anyway ↗</button>
      </div>
    `;
    els.verdictSection.classList.add('show');

    document.getElementById('copyLinkBtn').onclick = ()=>{
      navigator.clipboard && navigator.clipboard.writeText(rawUrl);
    };
    document.getElementById('openAnywayBtn').onclick = ()=>{
      window.open(rawUrl, '_blank', 'noopener,noreferrer');
    };
  }

  /* ---------------- decode from image ---------------- */
  function decodeImageElement(imgEl){
    const canvas = document.createElement('canvas');
    canvas.width = imgEl.naturalWidth || imgEl.videoWidth;
    canvas.height = imgEl.naturalHeight || imgEl.videoHeight;
    const ctx = canvas.getContext('2d');
    ctx.drawImage(imgEl, 0, 0, canvas.width, canvas.height);
    const imageData = ctx.getImageData(0,0,canvas.width, canvas.height);
    return jsQR(imageData.data, canvas.width, canvas.height);
  }

  // Classify the decoded payload so every payload type gets an appropriate
  // analysis path — not just http(s) links.
  function classifyPayload(raw){
    const text = raw.trim();
    if(/^https?:\/\//i.test(text)) return {type:'web', value:text};
    if(/^www\./i.test(text)) return {type:'web', value:'https://'+text};
    const bareDomain = text.match(/^((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}(?::\d+)?(?:[\/?#][^\s]*)?)$/i);
    if(bareDomain) return {type:'web', value:'https://'+bareDomain[1]};
    if(/^upi:\/\//i.test(text)) return {type:'upi', value:text};
    const scheme = text.match(/^([a-z][a-z0-9+.\-]*):\/\//i);
    if(scheme) return {type:'deeplink', scheme:scheme[1], value:text};
    return {type:'other', value:text};
  }

  function parseQueryString(str){
    const out = {};
    str.split('&').forEach(pair=>{
      if(!pair) return;
      const eq = pair.indexOf('=');
      const k = eq>=0 ? pair.slice(0,eq) : pair;
      const v = eq>=0 ? pair.slice(eq+1) : '';
      try{ out[decodeURIComponent(k)] = decodeURIComponent(v.replace(/\+/g,' ')); }
      catch(e){ out[k] = v; }
    });
    return out;
  }

  const KNOWN_UPI_HANDLES = ['oksbi','okhdfcbank','okicici','okaxis','ybl','paytm','upi','axl','ibl',
    'apl','rbl','kmb','dbs','hsbc','sc','idfcbank','federal','kotak','boi','cnrb','pnb','unionbank',
    'indus','yesbank','freecharge','airtel','jio','icici','hdfcbank','sbi','axisbank','uco','idbi',
    'citi','citibank','waaxis','waicici','wasbi','yapl','jupiteraxis','fbl','psb','dbank'];
  const SCAM_BAIT_WORDS = ['refund','cashback','reward','prize','won','winner','gift','claim',
    'lottery','bonus','congratulations','giveaway'];

  function renderUpiVerdict(raw){
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.add('show');

    const qIdx = raw.indexOf('?');
    const params = qIdx >= 0 ? parseQueryString(raw.slice(qIdx+1)) : {};
    const pa = params.pa || '', pn = params.pn || '', am = params.am || '', cu = params.cu || 'INR', tn = params.tn || '';

    let score = 0;
    const findings = [];

    if(!pa){
      findings.push(['bad','No payee address (pa) found — this isn\u2019t a validly formed UPI payment link.']);
      score += 60;
    } else if(!/^[\w.\-]+@[\w.\-]+$/.test(pa)){
      findings.push(['bad','Payee address "'+pa+'" isn\u2019t a validly formatted VPA.']);
      score += 40;
    } else {
      const handle = pa.split('@')[1].toLowerCase();
      if(KNOWN_UPI_HANDLES.includes(handle)){
        findings.push(['ok','Payee handle "@'+handle+'" matches a recognized bank/PSP.']);
      } else {
        findings.push(['warn','Payee handle "@'+handle+'" isn\u2019t one we recognize — not necessarily fraudulent, just unfamiliar. Double-check the payee name before paying.']);
        score += 15;
      }
    }

    const baitHit = SCAM_BAIT_WORDS.find(w => (pn+' '+tn).toLowerCase().includes(w));
    if(baitHit){
      findings.push(['bad','Payee name or note mentions "'+baitHit+'" — a common lure in refund/cashback QR scams. Scanning and approving a UPI code only ever sends money out, never in.']);
      score += 40;
    }

    if(am){
      findings.push(['warn','Requests a fixed amount of '+cu+' '+am+' to '+(pn||pa)+'. Make sure that matches what you actually intend to pay.']);
    } else {
      findings.push(['ok','No amount is pre-filled — you\u2019ll enter it yourself in your UPI app.']);
    }

    const level = score>=50 ? 'danger' : (score>0 ? 'caution' : 'clear');
    const label = score>=50 ? 'FLAGGED<br>Verify before paying' : (score>0 ? 'CAUTION<br>Check payee first' : 'CLEARED<br>Looks like a standard request');
    els.stamp.className = 'stamp ' + level;
    els.stamp.innerHTML = label;

    els.ticket.innerHTML = `
      <div class="ticket-row"><span class="k">Payload type</span><span class="v">UPI payment link</span></div>
      <div class="ticket-row"><span class="k">Payee name</span><span class="v">${escapeHtml(pn||'—')}</span></div>
      <div class="ticket-row"><span class="k">VPA</span><span class="v">${escapeHtml(pa||'—')}</span></div>
      <div class="ticket-row"><span class="k">Amount</span><span class="v">${am ? escapeHtml(cu+' '+am) : 'not pre-filled'}</span></div>
      ${findings.map(([lvl,t])=>`<div class="ticket-row"><span class="k">${lvl==='bad'?'⚠ Risk':(lvl==='warn'?'! Note':'✓ OK')}</span><span class="v">${escapeHtml(t)}</span></div>`).join('')}
      <div class="ticket-row"><span class="k">Remember</span><span class="v">Your UPI PIN is only ever needed to send money. No genuine refund, cashback or "receive" flow ever asks for it.</span></div>
      <div class="ticket-actions"><button class="btn" id="copyLinkBtn">Copy raw link</button></div>
    `;
    document.getElementById('copyLinkBtn').onclick = ()=>{ navigator.clipboard && navigator.clipboard.writeText(raw); };
  }

  function renderDeepLinkVerdict(scheme, raw){
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.add('show');
    const baitHit = SCAM_BAIT_WORDS.find(w => raw.toLowerCase().includes(w));
    const level = baitHit ? 'caution' : 'info';
    els.stamp.className = 'stamp ' + level;
    els.stamp.innerHTML = (baitHit ? 'CAUTION<br>' : 'APP LINK<br>') + escapeHtml(scheme+'://');

    els.ticket.innerHTML = `
      <div class="ticket-row"><span class="k">Payload type</span><span class="v">App deep link (${escapeHtml(scheme)}://)</span></div>
      <div class="ticket-row"><span class="k">Decoded content</span><span class="v">${escapeHtml(raw)}</span></div>
      <div class="ticket-row"><span class="k">Note</span><span class="v">${baitHit ? 'Contains "'+escapeHtml(baitHit)+'" — a common scam lure. Be cautious before approving anything.' : 'DNS and threat-database checks only apply to web links, so Lanes 02\u201303 don\u2019t run here. Review the decoded content above before letting it open in the matching app.'}</span></div>
      <div class="ticket-actions"><button class="btn" id="copyLinkBtn">Copy content</button></div>
    `;
    document.getElementById('copyLinkBtn').onclick = ()=>{ navigator.clipboard && navigator.clipboard.writeText(raw); };
  }

  function nonUrlLabel(text){
    if(/^wifi:/i.test(text)) return {kind:'Wi-Fi network config', detail:'This code configures a Wi-Fi connection — it doesn\u2019t point anywhere, so there\u2019s no link to screen.'};
    if(/^begin:vcard/i.test(text)) return {kind:'Contact card (vCard)', detail:'This code stores a contact card — there\u2019s no URL destination to check.'};
    if(/^mailto:/i.test(text)) return {kind:'Email address', detail:'This code opens an email composer — there\u2019s no web destination to screen.'};
    if(/^tel:/i.test(text)) return {kind:'Phone number', detail:'This code dials a phone number — there\u2019s no web destination to screen.'};
    if(/^sms:/i.test(text)) return {kind:'SMS message', detail:'This code opens a text message — there\u2019s no web destination to screen.'};
    if(/^geo:/i.test(text)) return {kind:'Geographic coordinates', detail:'This code points to a map location — there\u2019s no web destination to screen.'};
    return {kind:'Plain text', detail:'No recognizable link or scheme was found in this code, so there\u2019s nothing to screen.'};
  }

  function renderNonUrlVerdict(text){
    const info = nonUrlLabel(text);
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.add('show');
    els.stamp.className = 'stamp info';
    els.stamp.innerHTML = 'NOT A LINK<br>' + escapeHtml(info.kind);
    els.ticket.innerHTML = `
      <div class="ticket-row"><span class="k">Payload type</span><span class="v">${escapeHtml(info.kind)}</span></div>
      <div class="ticket-row"><span class="k">Decoded content</span><span class="v">${escapeHtml(text)}</span></div>
      <div class="ticket-row"><span class="k">Note</span><span class="v">${escapeHtml(info.detail)}</span></div>
      <div class="ticket-actions">
        <button class="btn" id="copyLinkBtn">Copy content</button>
        <button class="btn" id="forceScreenBtn">Screen as link anyway</button>
      </div>
    `;
    document.getElementById('copyLinkBtn').onclick = ()=>{
      navigator.clipboard && navigator.clipboard.writeText(text);
    };
    document.getElementById('forceScreenBtn').onclick = ()=>{
      const forced = /^https?:\/\//i.test(text) ? text : 'https://' + text.replace(/^[a-z]+:\/*/i,'');
      inspect(forced).catch(showInspectionError);
    };
  }

  function handleDecodedText(text){
    els.decodeError.classList.remove('show');
    els.payloadStrip.classList.add('show');
    els.payloadVal.textContent = text;
    els.consoleStatus.textContent = '● INSPECTING';

    const payload = classifyPayload(text);
    if(payload.type === 'web'){
      inspect(payload.value).catch(showInspectionError);
      return;
    }
    if(payload.type === 'upi'){
      renderUpiVerdict(payload.value);
    } else if(payload.type === 'deeplink'){
      renderDeepLinkVerdict(payload.scheme, payload.value);
    } else {
      renderNonUrlVerdict(payload.value);
    }
    els.consoleStatus.textContent = '● INSPECTION COMPLETE';
  }

  function showInspectionError(e){
    els.consoleStatus.textContent = '● INSPECTION FAILED';
    els.verdictSection.classList.add('show');
    els.stamp.className = 'stamp caution';
    els.stamp.innerHTML = 'UNKNOWN<br>Check failed';
    els.ticket.innerHTML = `
      <div class="ticket-row"><span class="k">Status</span><span class="v">Something went wrong while screening this code.</span></div>
      <div class="ticket-row"><span class="k">Detail</span><span class="v">${escapeHtml((e && e.message) || String(e))}</span></div>
      <div class="ticket-row"><span class="k">Advice</span><span class="v">Treat this code as unverified. Try again, or don\u2019t open the link.</span></div>
    `;
  }

  function handleImageFile(file){
    stopCamera();
    els.decodeError.classList.remove('show');
    els.payloadStrip.classList.remove('show');
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.remove('show');

    const url = URL.createObjectURL(file);
    const img = new Image();
    img.onload = ()=>{
      els.mediaWrap.innerHTML = '';
      const shown = img.cloneNode();
      els.mediaWrap.appendChild(shown);
      const sl = document.createElement('div');
      sl.className = 'scanline';
      els.mediaWrap.appendChild(sl);
      els.scanStage.classList.add('active');
      els.scanCaption.innerHTML = 'SCANNING FOR CODE<span class="cursor">_</span>';

      setTimeout(()=>{
        const result = decodeImageElement(img);
        sl.remove();
        if(result && result.data){
          els.scanCaption.textContent = 'CODE ACQUIRED';
          handleDecodedText(result.data);
        } else {
          els.scanCaption.textContent = 'NO CODE FOUND';
          els.decodeError.textContent = 'Could not detect a QR code in this image. Try a clearer, more direct photo.';
          els.decodeError.classList.add('show');
        }
      }, 650);
    };
    img.onerror = ()=>{
      els.decodeError.textContent = 'Could not read this file as an image.';
      els.decodeError.classList.add('show');
    };
    img.src = url;
  }

  /* ---------------- camera ---------------- */
  async function startCamera(){
    els.decodeError.classList.remove('show');
    els.payloadStrip.classList.remove('show');
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.remove('show');
    try{
      stream = await navigator.mediaDevices.getUserMedia({video:{facingMode:'environment'}});
    }catch(e){
      els.decodeError.textContent = 'Camera unavailable or permission denied. Try uploading an image instead.';
      els.decodeError.classList.add('show');
      return;
    }
    els.mediaWrap.innerHTML = '';
    const video = document.createElement('video');
    video.setAttribute('playsinline','');
    video.autoplay = true;
    video.muted = true;
    video.srcObject = stream;
    els.mediaWrap.appendChild(video);
    const sl = document.createElement('div');
    sl.className = 'scanline';
    els.mediaWrap.appendChild(sl);
    els.scanStage.classList.add('active');
    els.scanCaption.innerHTML = 'LIVE — POINT AT A CODE<span class="cursor">_</span>';

    video.play();
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    function tick(){
      if(video.readyState === video.HAVE_ENOUGH_DATA){
        canvas.width = video.videoWidth;
        canvas.height = video.videoHeight;
        ctx.drawImage(video,0,0,canvas.width,canvas.height);
        const imgData = ctx.getImageData(0,0,canvas.width,canvas.height);
        const result = jsQR(imgData.data, canvas.width, canvas.height);
        if(result && result.data){
          els.scanCaption.textContent = 'CODE ACQUIRED';
          stopCamera();
          handleDecodedText(result.data);
          return;
        }
      }
      rafId = requestAnimationFrame(tick);
    }
    rafId = requestAnimationFrame(tick);
  }
  function stopCamera(){
    if(rafId) cancelAnimationFrame(rafId);
    rafId = null;
    if(stream){ stream.getTracks().forEach(t=>t.stop()); stream = null; }
  }

  /* ---------------- wiring ---------------- */
  els.uploadBtn.addEventListener('click', ()=> els.fileInput.click());
  els.dropzone.addEventListener('click', (e)=>{ if(e.target===els.dropzone) els.fileInput.click(); });
  els.fileInput.addEventListener('change', (e)=>{
    if(e.target.files && e.target.files[0]) handleImageFile(e.target.files[0]);
  });
  els.cameraBtn.addEventListener('click', startCamera);

  ['dragenter','dragover'].forEach(ev=>{
    els.dropzone.addEventListener(ev, e=>{ e.preventDefault(); els.dropzone.classList.add('drag'); });
  });
  ['dragleave','drop'].forEach(ev=>{
    els.dropzone.addEventListener(ev, e=>{ e.preventDefault(); els.dropzone.classList.remove('drag'); });
  });
  els.dropzone.addEventListener('drop', e=>{
    const f = e.dataTransfer.files && e.dataTransfer.files[0];
    if(f) handleImageFile(f);
  });

  els.rescanBtn.addEventListener('click', ()=>{
    stopCamera();
    els.scanStage.classList.remove('active');
    els.mediaWrap.innerHTML = '';
    els.payloadStrip.classList.remove('show');
    els.decodeError.classList.remove('show');
    els.lanesSection.classList.remove('show');
    els.verdictSection.classList.remove('show');
    els.consoleStatus.textContent = '● AWAITING SUBMISSION';
    els.fileInput.value = '';
  });

  els.saveKeyBtn.addEventListener('click', ()=>{
    apiKey = els.apiKeyInput.value.trim();
    els.saveKeyBtn.textContent = apiKey ? 'Saved ✓' : 'Save key';
    setTimeout(()=>{ els.saveKeyBtn.textContent = 'Save key'; }, 1500);
  });

})();
