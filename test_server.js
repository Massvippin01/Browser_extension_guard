/**
 * test_server.js - Verity Redirect Tracker Test Server
 *
 * Uses multiple ports to simulate genuine cross-domain redirect chains.
 * Each port = a different "domain" from Verity's perspective.
 *
 * PORT 3000 = URL Shortener hub (add "localhost:3000" to urlShorteners.json... 
 *             or just "localhost" and it will match all localhost entries)
 * PORT 3001 = Tracking / intermediate site
 * PORT 3002 = Second redirect hop
 * PORT 3003 = Final destination (fake bank or payment page)
 *
 * Run: node test_server.js
 * Open: http://localhost:3000
 */

const http = require('http');

// ─── PORT 3000: URL Shortener Hub ──────────────────────────────────────────
const hub = http.createServer((req, res) => {
  console.log(`[SHORTENER :3000] ${req.url}`);

  // Test A — Safe: shortener → Google (safe, trusted final domain)
  if (req.url === '/safe') {
    res.writeHead(302, { 'Location': 'https://www.google.com' });
    return res.end();
  }

  // Test B — Suspicious: shortener → unknown intermediate → lands on same server unknown page
  if (req.url === '/suspicious') {
    res.writeHead(302, { 'Location': 'http://localhost:3001/unknown-landing' });
    return res.end();
  }

  // Test C — Multi-hop scam: shortener → tracking → redirect → fake bank login
  if (req.url === '/multihop') {
    res.writeHead(302, { 'Location': 'http://localhost:3001/track' });
    return res.end();
  }

  // Test D — Payment scam: shortener → fake payment page with card fields
  if (req.url === '/payment-scam') {
    res.writeHead(302, { 'Location': 'http://localhost:3001/payment-hop' });
    return res.end();
  }

  // Test E — HTTPS Downgrade: (simulated — we start http so use a different header note)
  if (req.url === '/https-downgrade') {
    // Both are http here (localhost), but Verity will log the chain
    res.writeHead(302, { 'Location': 'http://localhost:3003/downgraded' });
    return res.end();
  }

  // Test F — Redirect Loop: shortener → A → B → A (loop, browser will ERR_TOO_MANY_REDIRECTS)
  if (req.url === '/loop') {
    res.writeHead(302, { 'Location': 'http://localhost:3001/loop-a' });
    return res.end();
  }

  // Test G — Real-world Malvertising simulation: mimics wb.omegatootler.rest pattern
  if (req.url === '/malvert') {
    // Redirect to a simulated ad-redirect URL with all the fingerprints
    const fakeBlob = 'A'.repeat(200) + '*' + 'B'.repeat(200) + '*' + 'C'.repeat(150);
    res.writeHead(302, { 'Location': `http://localhost:3001/cx/${fakeBlob}?md=eyJhcmNoaXRlY3R1cmUiOiJ4ODYifQ&pr=Kkme4Xg&fc=wRsUqusY&cd=ashfk_q1` });
    return res.end();
  }

  // Dashboard
  res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Verity Redirect Tracker – Test Dashboard</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;700&family=JetBrains+Mono:wght@400;600&display=swap');
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { 
      font-family: 'Outfit', system-ui, sans-serif; 
      background: radial-gradient(circle at top left, #0f172a 0%, #020617 100%);
      color: #f1f5f9; min-height: 100vh; padding: 60px 40px; 
    }
    h1 { font-size: 2.6rem; font-weight: 700; margin-bottom: 10px; letter-spacing: -0.5px; }
    h1 span { 
      background: linear-gradient(135deg, #38bdf8, #818cf8);
      -webkit-background-clip: text; -webkit-text-fill-color: transparent; 
    }
    .subtitle { color: #94a3b8; margin-bottom: 50px; font-size: 1.1rem; font-weight: 300; }
    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 28px; }
    .card {
      background: rgba(30, 41, 59, 0.4); 
      backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px);
      border: 1px solid rgba(255,255,255,0.05);
      border-radius: 20px; padding: 32px;
      display: flex; flex-direction: column; gap: 18px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
      position: relative; overflow: hidden;
    }
    .card::before {
      content: ""; position: absolute; top: 0; left: 0; right: 0; height: 3px;
      background: linear-gradient(90deg, rgba(255,255,255,0.1), rgba(255,255,255,0));
      opacity: 0; transition: opacity 0.3s;
    }
    .card:hover { transform: translateY(-6px); box-shadow: 0 20px 40px rgba(0,0,0,0.4); background: rgba(30, 41, 59, 0.7); }
    .card:hover::before { opacity: 1; }
    .card-head { display: flex; align-items: center; gap: 16px; }
    .badge {
      width: 44px; height: 44px; border-radius: 12px;
      display: flex; align-items: center; justify-content: center;
      font-size: 1.4rem; flex-shrink: 0;
      box-shadow: inset 0 2px 4px rgba(255,255,255,0.1);
    }
    .badge.green  { background: linear-gradient(135deg, #166534, #14532d); color: #4ade80; border: 1px solid #22c55e; }
    .badge.yellow { background: linear-gradient(135deg, #854d0e, #713f12); color: #fbbf24; border: 1px solid #eab308; }
    .badge.red    { background: linear-gradient(135deg, #991b1b, #7f1d1d); color: #f87171; border: 1px solid #ef4444; }
    .badge.blue   { background: linear-gradient(135deg, #1e40af, #1e3a8a); color: #60a5fa; border: 1px solid #3b82f6; }
    .badge.purple { background: linear-gradient(135deg, #6b21a8, #581c87); color: #c084fc; border: 1px solid #a855f7; }
    
    .card-title { font-weight: 700; font-size: 1.2rem; color: #f8fafc; letter-spacing: -0.3px; }
    .card-desc  { font-size: 0.95rem; color: #94a3b8; line-height: 1.6; font-weight: 300; }
    
    .chain { 
      background: rgba(15, 23, 42, 0.6); border: 1px solid rgba(255,255,255,0.05);
      border-radius: 12px; padding: 16px; 
      font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; 
      color: #7dd3fc; line-height: 2; margin-top: auto; 
    }
    .chain span { color: #64748b; font-size: 0.75rem; }
    
    .expected { display: inline-flex; padding: 6px 14px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; width: fit-content; }
    .e-safe   { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }
    .e-warn   { background: rgba(234, 179, 8, 0.15); color: #fbbf24; border: 1px solid rgba(234, 179, 8, 0.3); }
    .e-block  { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .e-loop   { background: rgba(168, 85, 247, 0.15); color: #c084fc; border: 1px solid rgba(168, 85, 247, 0.3); }
    
    .btn {
      display: inline-flex; align-items: center; justify-content: center;
      padding: 14px 24px; width: 100%;
      background: linear-gradient(135deg, #3b82f6, #2563eb); 
      color: white; text-decoration: none;
      border-radius: 12px; font-weight: 600; font-size: 1rem;
      transition: all 0.2s ease; box-shadow: 0 4px 15px rgba(37, 99, 235, 0.3);
      border: 1px solid rgba(255,255,255,0.1);
    }
    .btn:hover { background: linear-gradient(135deg, #60a5fa, #3b82f6); transform: scale(1.02); box-shadow: 0 8px 25px rgba(37, 99, 235, 0.5); }
    .btn:active { transform: scale(0.98); }
    
    .info-box { 
      background: rgba(30, 64, 175, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); 
      border-radius: 16px; padding: 20px 24px; margin-bottom: 40px; 
      font-size: 1rem; color: #93c5fd; line-height: 1.6;
      backdrop-filter: blur(8px); display: inline-block;
    }
    .info-box strong { color: #fff; font-weight: 600; }
    code { background: rgba(0,0,0,0.3); padding: 2px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 0.9em; }
  </style>
</head>
<body>
  <h1>🛡️ Verity <span>Redirect Tracker</span></h1>
  <p class="subtitle">Test Dashboard — Each test simulates a real redirect chain across different ports (domains).</p>

  <div class="info-box">
    <strong>⚙️ Setup Required:</strong> Make sure <code>"localhost"</code> is in your 
    <code>config/urlShorteners.json</code> shorteners list so Verity treats this server as a URL shortener.
    Then reload the extension at <code>chrome://extensions</code>.
  </div>

  <div class="grid">

    <div class="card">
      <div class="card-head">
        <div class="badge green">✓</div>
        <div class="card-title">Test A — Safe Shortener</div>
      </div>
      <div class="card-desc">Shortener → Google. Verity should detect the shortener but trust the final destination.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        www.google.com<span> (safe)</span>
      </div>
      <span class="expected e-safe">🟢 Expected: ALLOW</span>
      <a class="btn" href="/safe">▶ Run Test A</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge yellow">?</div>
        <div class="card-title">Test B — Suspicious Destination</div>
      </div>
      <div class="card-desc">Shortener → unknown page on unrecognized port. No malicious signals, but unknown.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3001<span> (unknown landing)</span>
      </div>
      <span class="expected e-warn">🟡 Expected: SUSPICIOUS</span>
      <a class="btn" href="/suspicious">▶ Run Test B</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge red">!</div>
        <div class="card-title">Test C — Multi-Hop Fake Bank</div>
      </div>
      <div class="card-desc">Shortener → tracking → redirect → fake HDFC login with password field.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3001<span> (tracking)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3002<span> (redirect hop)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3003<span> (fake bank login)</span>
      </div>
      <span class="expected e-block">🔴 Expected: BLOCK</span>
      <a class="btn" href="/multihop">▶ Run Test C</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge red">💳</div>
        <div class="card-title">Test D — Payment Scam</div>
      </div>
      <div class="card-desc">Shortener → intermediate → fake PayPal checkout with card/CVV/OTP fields.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3001<span> (hop)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3003<span> (fake payment page)</span>
      </div>
      <span class="expected e-block">🔴 Expected: BLOCK</span>
      <a class="btn" href="/payment-scam">▶ Run Test D</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge blue">↕</div>
        <div class="card-title">Test E — Chain Visualization</div>
      </div>
      <div class="card-desc">2-hop redirect. Tests that the badge shows redirect chain in the tooltip on hover.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3003<span> (destination)</span>
      </div>
      <span class="expected e-warn">🟡 Expected: Badge shows chain</span>
      <a class="btn" href="/https-downgrade">▶ Run Test E</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge purple">∞</div>
        <div class="card-title">Test F — Redirect Loop</div>
      </div>
      <div class="card-desc">Shortener → A → B → A... loops. Browser will ERR_TOO_MANY_REDIRECTS. Verity detects the loop internally.</div>
      <div class="chain">
        localhost:3000<span> (shortener)</span><br>
        &nbsp;&nbsp;↓<br>
        localhost:3001/loop-a<br>
        &nbsp;&nbsp;↓<br>
        localhost:3002/loop-b<br>
        &nbsp;&nbsp;↓<br>
        localhost:3001/loop-a<span> ← loop!</span>
      </div>
      <span class="expected e-loop">🟣 Expected: Loop detected</span>
      <a class="btn" href="/loop">▶ Run Test F</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge red">📲</div>
        <div class="card-title">Test H — UPI Cashback Scam Trap</div>
      </div>
      <div class="card-desc">Fake Paytm cashback page claiming "Receive ₹5,000", but button embeds a upi://pay DEBIT transaction.</div>
      <div class="chain">
        localhost:3000/upi-scam-demo<br>
        &nbsp;&nbsp;↓<br>
        upi://pay?pa=scammer@paytm<span> (debit trap)</span>
      </div>
      <span class="expected e-block">🔴 Expected: DIGITAL SCAM TRAP BLOCK</span>
      <a class="btn" href="/upi-scam-demo">▶ Run Test H</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge red">⚡</div>
        <div class="card-title">Test I — Digital Arrest & Bill Scam</div>
      </div>
      <div class="card-desc">Fake electricity disconnection threat demanding ₹10 verification fee via credit card.</div>
      <div class="chain">
        localhost:3000/utility-scam-demo<br>
        &nbsp;&nbsp;↓<br>
        unverified payment form<span> (scam trap)</span>
      </div>
      <span class="expected e-block">🔴 Expected: DIGITAL SCAM BLOCK</span>
      <a class="btn" href="/utility-scam-demo">▶ Run Test I</a>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="badge red">🛑</div>
        <div class="card-title">Test J — Fake Banking APK Download</div>
      </div>
      <div class="card-desc">Page hosting sbi_yono_rewards.apk on unverified domain. Verity cancels download in 0.1s.</div>
      <div class="chain">
        localhost:3000/fake-apk-demo<br>
        &nbsp;&nbsp;↓<br>
        sbi_yono_rewards.apk<span> (trojan cancel)</span>
      </div>
      <span class="expected e-block">🔴 Expected: AUTO-CANCEL DOWNLOAD</span>
      <a class="btn" href="/fake-apk-demo">▶ Run Test J</a>
    </div>

  </div>
</body>
</html>`);
});

// ─── PORT 3001: Tracking / Intermediate ──────────────────────────────────────
const tracker = http.createServer((req, res) => {
  console.log(`[TRACKER   :3001] ${req.url}`);

  if (req.url === '/unknown-landing') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end('<html><body><h1>Unknown Landing Page</h1><p>Nothing suspicious here.</p></body></html>');
  }
  if (req.url === '/track') {
    res.writeHead(302, { 'Location': 'http://localhost:3002/hop' });
    return res.end();
  }
  if (req.url === '/payment-hop') {
    res.writeHead(302, { 'Location': 'http://localhost:3003/fake-checkout' });
    return res.end();
  }
  // Loop A
  if (req.url === '/loop-a') {
    res.writeHead(302, { 'Location': 'http://localhost:3002/loop-b' });
    return res.end();
  }

  // Test H — UPI Cashback Scam Trap Demo
  if (req.url === '/upi-scam-demo') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>Paytm Cashback Reward</title></head>
<body style="font-family:sans-serif;max-width:480px;margin:60px auto;padding:24px;border:1.5px solid #22c55e;border-radius:12px;text-align:center;background:#f0fdf4;">
  <h1 style="color:#15803d;font-size:24px;">🎉 Congratulations!</h1>
  <h2 style="color:#166534;font-size:18px;">You Received ₹5,000 Paytm Cashback!</h2>
  <p style="color:#374151;font-size:14px;line-height:1.5;">Click below to claim your cashback directly to your bank account via UPI.</p>
  <a href="upi://pay?pa=scammer@paytm&am=5000&pn=PaytmCashback" style="display:inline-block;background:#22c55e;color:white;font-weight:700;padding:14px 28px;border-radius:8px;text-decoration:none;margin-top:16px;box-shadow:0 4px 12px rgba(34,197,94,0.3);">CLAIM CASHBACK NOW (UPI)</a>
</body></html>`);
  }

  // Test I — Digital Arrest & Utility Bill Scam Demo
  if (req.url === '/utility-scam-demo') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>Electricity Department Notice</title></head>
<body style="font-family:sans-serif;max-width:500px;margin:60px auto;padding:24px;border:2px solid #ef4444;border-radius:12px;background:#fef2f2;">
  <h2 style="color:#dc2626;margin-top:0;">⚡ URGENT: Electricity Connection Disconnection Notice</h2>
  <p style="color:#991b1b;font-weight:600;">Your electricity connection will be disconnected tonight at 9:30 PM due to pending bill update.</p>
  <p style="color:#374151;font-size:14px;">Pay ₹10 Verification Fee immediately to avoid TRAI / Police digital arrest & power cutoff.</p>
  <form action="/pay-fake-bill" method="POST" style="margin-top:20px;">
    <input type="text" name="consumer_no" placeholder="Consumer Number" style="width:100%;padding:10px;margin-bottom:12px;border:1px solid #ccc;border-radius:6px;">
    <input type="text" name="cardnumber" placeholder="Card / NetBanking Number" style="width:100%;padding:10px;margin-bottom:12px;border:1px solid #ccc;border-radius:6px;">
    <button type="submit" style="width:100%;background:#dc2626;color:white;font-weight:700;padding:12px;border:none;border-radius:6px;cursor:pointer;">PAY ₹10 VERIFICATION FEE NOW</button>
  </form>
</body></html>`);
  }

  // Test J — Fake Banking APK Trojan Download Demo
  if (req.url === '/fake-apk-demo') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>SBI YONO Reward Update</title></head>
<body style="font-family:sans-serif;max-width:450px;margin:60px auto;padding:24px;border:1px solid #0284c7;border-radius:12px;text-align:center;">
  <h2 style="color:#0369a1;">🏦 SBI YONO Rewards</h2>
  <p style="color:#334155;">Download the official SBI YONO Reward update (.apk) to claim your reward points.</p>
  <a href="/downloads/sbi_yono_rewards.apk" download style="display:inline-block;background:#0284c7;color:white;font-weight:700;padding:12px 24px;border-radius:8px;text-decoration:none;margin-top:16px;">Download sbi_yono_rewards.apk</a>
</body></html>`);
  }

  // Serves fake APK binary payload
  if (req.url === '/downloads/sbi_yono_rewards.apk') {
    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Disposition': 'attachment; filename="sbi_yono_rewards.apk"'
    });
    return res.end(Buffer.from('FAKEMALWAREBINARYPAYLOAD'));
  }

  // Malvertising landing (simulated ad-redirect network landing page)
  if (req.url.startsWith('/cx/')) {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>Ad Network Landing Page</title></head>
<body style="font-family:sans-serif;padding:40px;background:#111;color:#eee;">
  <h2>🎉 Congratulations! You've been selected!</h2>
  <p>Click below to claim your prize.</p>
  <button onclick="window.location='http://localhost:3003/fake-checkout'" style="padding:12px 24px;background:#e53e3e;color:white;border:none;border-radius:6px;cursor:pointer;font-size:16px;">
    Claim Now
  </button>
</body></html>`);
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>Intermediate/Tracking Server (port 3001)</h1></body></html>');
});

// ─── PORT 3002: Second Redirect Hop ──────────────────────────────────────────
const redirector = http.createServer((req, res) => {
  console.log(`[REDIRECTOR:3002] ${req.url}`);

  if (req.url === '/hop') {
    res.writeHead(302, { 'Location': 'http://localhost:3003/fake-bank' });
    return res.end();
  }
  // Loop B
  if (req.url === '/loop-b') {
    res.writeHead(302, { 'Location': 'http://localhost:3001/loop-a' });
    return res.end();
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>Redirector Server (port 3002)</h1></body></html>');
});

// ─── PORT 3003: Final Destination (Malicious / Payment) ──────────────────────
const destination = http.createServer((req, res) => {
  console.log(`[DEST      :3003] ${req.url}`);

  // Fake bank login — password + account fields
  if (req.url === '/fake-bank') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>HDFC Bank – Secure Login</title></head>
<body style="font-family:sans-serif;max-width:400px;margin:60px auto;padding:20px;border:1px solid #ccc;border-radius:8px;">
  <h2>🏦 HDFC Bank – NetBanking</h2>
  <p style="color:#666;font-size:0.9em;">Secure login to your account</p>
  <form action="/submit" method="POST" id="loginForm">
    <label>Account Number<br>
      <input type="text" name="account" id="account" placeholder="Account number" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <label>Password<br>
      <input type="password" name="password" id="password" placeholder="NetBanking password" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <button type="submit" style="background:#1a56db;color:white;padding:10px 24px;border:none;border-radius:6px;cursor:pointer;">Login</button>
  </form>
</body></html>`);
  }

  // Fake payment checkout — card + CVV + OTP
  if (req.url === '/fake-checkout') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><head><title>PayPal Checkout</title></head>
<body style="font-family:sans-serif;max-width:420px;margin:60px auto;padding:20px;border:1px solid #ccc;border-radius:8px;">
  <h2>💳 PayPal Secure Checkout</h2>
  <p style="color:#666;font-size:0.9em;">Complete your payment securely</p>
  <form action="/pay" method="POST" id="payForm">
    <label>Card Number<br>
      <input type="text" name="cardnumber" id="cardnumber" placeholder="1234 5678 9012 3456" autocomplete="cc-number" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <label>CVV<br>
      <input type="text" name="cvv" id="cvv" placeholder="CVV" autocomplete="cc-csc" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <label>OTP<br>
      <input type="text" name="otp" id="otp" placeholder="One-time password" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <label>Expiry<br>
      <input type="text" name="expiry" id="expiry" placeholder="MM/YY" autocomplete="cc-exp" style="width:100%;margin:8px 0;padding:8px;">
    </label><br>
    <button type="submit" style="background:#003087;color:white;padding:10px 24px;border:none;border-radius:6px;cursor:pointer;">Pay Now</button>
  </form>
</body></html>`);
  }

  // HTTPS downgrade landing
  if (req.url === '/downgraded') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return res.end(`<!DOCTYPE html>
<html><body style="font-family:sans-serif;padding:40px;">
  <h2>🌐 Destination Page</h2>
  <p>You arrived via a redirect chain. Hover the Verity badge (top-right) to see the chain.</p>
</body></html>`);
  }

  res.writeHead(200, { 'Content-Type': 'text/html' });
  res.end('<html><body><h1>Final Destination Server (port 3003)</h1></body></html>');
});

// ─── Start All Servers ────────────────────────────────────────────────────────
hub.listen(3000, () => console.log('✅ Shortener hub   → http://localhost:3000 (start here)'));
tracker.listen(3001, () => console.log('✅ Tracker         → http://localhost:3001'));
redirector.listen(3002, () => console.log('✅ Redirector      → http://localhost:3002'));
destination.listen(3003, () => console.log('✅ Destination     → http://localhost:3003'));
