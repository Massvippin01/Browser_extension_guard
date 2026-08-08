const http = require('http');

const PORT = 8080;

const server = http.createServer((req, res) => {
  console.log(`[DEMO :8080] ${req.url}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO A — Fake Bank Login (HDFC NetBanking credential harvester)
  // Triggers: content_brand_impersonation (+60), dom_analysis (+20),
  //           synergy_impersonation_credentials (+30)
  // Expected: BLOCK (score ~100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/bank') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>HDFC NetBanking - Secure Login</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);width:350px;text-align:center;border-top:5px solid #004c8f}
    .logo{font-size:24px;font-weight:bold;color:#004c8f;margin-bottom:20px}
    input{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
    button{width:100%;padding:12px;background:#004c8f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px}
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">HDFC Bank NetBanking</div>
    <p style="color:#666;font-size:14px">Welcome to HDFC Bank secure net banking login portal.</p>
    <form action="/steal" method="POST">
      <input type="text" name="customer_id" placeholder="Customer ID" required>
      <input type="password" name="password" placeholder="IPIN (Password)" required>
      <input type="text" name="otp" placeholder="OTP (One Time Password)">
      <button type="submit">SECURE LOGIN</button>
    </form>
    <p style="font-size:11px;color:#999;margin-top:15px">HDFC Bank Limited. Net banking with enhanced security.</p>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO B — Fake Payment Gateway (PayPal checkout with Card/CVV/OTP)
  // Triggers: payment_brand_impersonation (+50), payment_domain_mismatch (+25),
  //           payment_card_cvv_mismatch (+50), payment_otp_mismatch (+30),
  //           isCriticalPaymentPhishing → min 85
  // Expected: BLOCK (score 100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/payment') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>PayPal Secure Checkout</title>
  <style>
    body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.1);width:400px;text-align:center}
    .logo{font-size:28px;font-weight:bold;color:#003087;margin-bottom:10px;font-style:italic}
    .logo span{color:#009cde}
    .amount{font-size:32px;color:#333;font-weight:300;margin-bottom:30px}
    .group{text-align:left;margin-bottom:15px}
    label{font-size:13px;color:#666;font-weight:bold;display:block;margin-bottom:5px}
    input{width:100%;padding:12px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;font-size:14px}
    .row{display:flex;gap:15px}
    .row .group{flex:1}
    button{width:100%;padding:14px;background:#0070ba;color:#fff;border:none;border-radius:24px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:20px}
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">Pay<span>Pal</span></div>
    <p style="color:#666;margin-bottom:10px;font-size:14px">PayPal Secure Checkout — Complete your purchase</p>
    <div class="amount">$299.99 USD</div>
    <form id="payment" action="/pay" method="POST">
      <div class="group">
        <label for="cardnumber">Card Number</label>
        <input type="text" id="cardnumber" name="cardnumber" placeholder="1234 5678 9012 3456" autocomplete="cc-number">
      </div>
      <div class="row">
        <div class="group">
          <label for="expiry">Expiry</label>
          <input type="text" id="expiry" name="expiry" placeholder="MM/YY" autocomplete="cc-exp">
        </div>
        <div class="group">
          <label for="cvv">CVV</label>
          <input type="text" id="cvv" name="cvv" placeholder="123" autocomplete="cc-csc">
        </div>
      </div>
      <div class="group">
        <label for="otp">OTP Verification</label>
        <input type="text" id="otp" name="otp" placeholder="Enter OTP sent to your phone">
      </div>
      <button type="submit">Pay Now — PayPal</button>
    </form>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO C — UPI Cashback Scam (Paytm reward trap with hidden debit link)
  // Triggers: isUpiTrap (+85), isCriticalPaymentPhishing → min 85
  // Expected: BLOCK (score 100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/upi') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Paytm - Claim Your Cashback Reward</title>
  <style>
    body{font-family:Arial,sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .card{background:#1e293b;padding:40px;border-radius:16px;border:1px solid #334155;text-align:center;width:350px;box-shadow:0 15px 35px rgba(0,0,0,.5)}
    .amount{font-size:42px;font-weight:bold;color:#4ade80;margin:20px 0}
    .btn{display:inline-block;width:100%;padding:16px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:18px;margin-top:20px;box-sizing:border-box}
  </style>
</head>
<body>
  <div class="card">
    <h2 style="margin-top:0;color:#38bdf8">Paytm Rewards</h2>
    <p style="color:#94a3b8">Congratulations! You have won a cashback scratch card reward.</p>
    <div class="amount">₹5,000</div>
    <p style="font-size:13px;color:#64748b">Click below to instantly receive money directly to your linked bank account.</p>
    <a class="btn" href="upi://pay?pa=scammer@paytm&pn=Reward&am=5000&cu=INR">Claim ₹5,000 Cashback Now</a>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO D — Digital Arrest / Utility Scam (Electricity disconnection threat)
  // Triggers: isDigitalScam (+75), isCriticalPaymentPhishing → min 85
  // Expected: BLOCK (score 100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/utility') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Electricity Board — Urgent Disconnection Notice</title>
  <style>
    body{font-family:Arial,sans-serif;background:#fff1f2;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .card{background:#fff;padding:40px;border-radius:12px;border:2px solid #e11d48;text-align:center;width:400px;box-shadow:0 10px 25px rgba(225,29,72,.2)}
    h2{color:#e11d48;margin-top:0}
    button{display:inline-block;width:100%;padding:14px;background:#e11d48;color:#fff;border:none;border-radius:6px;font-weight:bold;font-size:16px;margin-top:20px;cursor:pointer}
    input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  </style>
</head>
<body>
  <div class="card">
    <h2>⚠️ URGENT: DISCONNECTION NOTICE</h2>
    <p style="color:#4c0519;font-weight:bold;font-size:15px">Your electricity connection will be disconnected tonight at 9:30 PM due to pending bill. Update KYC immediately.</p>
    <p style="color:#666;font-size:13px;margin-bottom:20px">Please update your KYC and pay the ₹11 processing fee immediately to avoid power cutoff. This is your final notice from the electricity board.</p>
    <form>
      <input type="text" name="consumer_no" placeholder="Consumer Number" required>
      <input type="text" name="mobile" placeholder="Mobile Number" required>
      <input type="text" name="otp" placeholder="OTP Verification">
      <button type="submit">Pay ₹11 & Update KYC Now</button>
    </form>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO E — Malicious APK Auto-Download (SBI YONO impersonation)
  // Triggers: installerDownload (+35), brandImpersonation (+65)
  // Download is chunked so chrome.downloads.cancel() can intercept it
  // Expected: Download CANCELLED + notification toast
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/download') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>SBI YONO Rewards App — Download</title>
  <style>
    body{font-family:Arial,sans-serif;background:#e0f2fe;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .card{background:#fff;padding:40px;border-radius:12px;text-align:center;width:350px;box-shadow:0 10px 30px rgba(0,0,0,.1)}
    .btn{display:inline-block;width:100%;padding:16px;background:#0284c7;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:16px;margin-top:20px;box-sizing:border-box}
  </style>
  <script>
    setTimeout(function(){ document.getElementById('dl').click(); }, 1500);
  </script>
</head>
<body>
  <div class="card">
    <h2 style="color:#0369a1;margin-top:0">SBI YONO Rewards</h2>
    <p style="color:#64748b;font-size:14px">Your download will begin automatically…</p>
    <a id="dl" class="btn" href="/sbi_yono_rewards.apk" download="sbi_yono_rewards.apk">Download APK</a>
  </div>
</body>
</html>`);
  }

  // Chunked APK download — stays in_progress long enough for cancel()
  if (req.url === '/sbi_yono_rewards.apk') {
    const totalBytes = 5 * 1024 * 1024;
    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Length': totalBytes,
      'Content-Disposition': 'attachment; filename="sbi_yono_rewards.apk"'
    });
    const chunk = Buffer.alloc(256 * 1024);
    let sent = 0;
    const iv = setInterval(() => {
      if (sent >= totalBytes || res.writableEnded) { clearInterval(iv); if (!res.writableEnded) res.end(); return; }
      try { res.write(chunk); } catch(e) { clearInterval(iv); }
      sent += chunk.length;
    }, 300);
    return;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO F — Multi-Hop Fake Bank (equivalent to old Test C)
  // This is a standalone page that simulates a fake ICICI bank with password+OTP
  // Triggers: content_brand_impersonation (+60), dom_analysis (+20),
  //           synergy_impersonation_credentials (+30)
  // Expected: BLOCK (score 100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/fake-bank-redirect') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>ICICI Bank — Internet Banking Login</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f8f8f8;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 16px rgba(0,0,0,.12);width:360px;text-align:center;border-top:4px solid #f37021}
    .logo{font-size:22px;font-weight:bold;color:#f37021;margin-bottom:20px}
    input{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
    button{width:100%;padding:12px;background:#f37021;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px}
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">ICICI Bank Internet Banking</div>
    <p style="color:#666;font-size:14px">Login to your ICICI Bank account securely.</p>
    <form action="/steal" method="POST">
      <input type="text" name="user_id" placeholder="User ID" required>
      <input type="password" name="password" placeholder="Password" required>
      <input type="text" name="otp" placeholder="OTP (Sent to registered mobile)">
      <button type="submit">LOGIN SECURELY</button>
    </form>
    <p style="font-size:11px;color:#999;margin-top:12px">ICICI Bank Limited. Secured by 256-bit encryption.</p>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO G — Multi-Hop Payment Scam (equivalent to old Test D)
  // Fake Razorpay checkout with card + CVV + OTP on unverified domain
  // Triggers: payment_brand_impersonation (+50), payment_card_cvv_mismatch (+50),
  //           payment_otp_mismatch (+30), isCriticalPaymentPhishing → min 85
  // Expected: BLOCK (score 100)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/fake-payment-redirect') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Razorpay Checkout — Complete Payment</title>
  <style>
    body{font-family:Arial,sans-serif;background:#f0f4ff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
    .box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.1);width:380px;text-align:center}
    .logo{font-size:24px;font-weight:bold;color:#3395ff;margin-bottom:10px}
    .amount{font-size:28px;color:#333;font-weight:300;margin-bottom:25px}
    .group{text-align:left;margin-bottom:14px}
    label{font-size:12px;color:#666;font-weight:bold;display:block;margin-bottom:4px}
    input{width:100%;padding:11px;border:1px solid #ddd;border-radius:6px;box-sizing:border-box;font-size:14px}
    .row{display:flex;gap:12px}
    .row .group{flex:1}
    button{width:100%;padding:14px;background:#3395ff;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:16px}
  </style>
</head>
<body>
  <div class="box">
    <div class="logo">Razorpay</div>
    <p style="color:#666;font-size:14px">Razorpay Secure Checkout — Merchant: TechStore India</p>
    <div class="amount">₹4,999.00</div>
    <form id="payment" action="/pay" method="POST">
      <div class="group">
        <label for="cardnumber">Credit/Debit Card Number</label>
        <input type="text" id="cardnumber" name="cardnumber" placeholder="4111 1111 1111 1111" autocomplete="cc-number">
      </div>
      <div class="row">
        <div class="group">
          <label for="expiry">Expiry Date</label>
          <input type="text" id="expiry" name="expiry" placeholder="MM/YY" autocomplete="cc-exp">
        </div>
        <div class="group">
          <label for="cvv">CVV Code</label>
          <input type="text" id="cvv" name="cvv" placeholder="***" autocomplete="cc-csc">
        </div>
      </div>
      <div class="group">
        <label for="otp">Bank OTP</label>
        <input type="text" id="otp" name="otp" placeholder="Enter OTP from your bank">
      </div>
      <button type="submit">Pay ₹4,999 via Razorpay</button>
    </form>
  </div>
</body>
</html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUB DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/' || req.url === '/favicon.ico') {
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html>
<html>
<head>
  <title>Verity Demo Server</title>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;700&display=swap" rel="stylesheet">
  <style>
    *{box-sizing:border-box;margin:0;padding:0}
    body{font-family:'Outfit',sans-serif;background:#020617;color:#f8fafc;min-height:100vh;padding:60px 40px;display:flex;flex-direction:column;align-items:center}
    h1{font-size:2.5rem;font-weight:700;margin-bottom:10px;text-align:center}
    h1 span{background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
    p.sub{color:#94a3b8;margin-bottom:40px;text-align:center;font-size:1.1rem}
    .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px;width:100%;max-width:1100px}
    .card{background:rgba(30,41,59,.5);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:28px;display:flex;flex-direction:column;gap:12px;transition:.3s;position:relative;overflow:hidden}
    .card:hover{transform:translateY(-4px);background:rgba(30,41,59,.8);border-color:rgba(255,255,255,.2);box-shadow:0 10px 30px rgba(0,0,0,.3)}
    .card-title{font-size:1.3rem;font-weight:700;display:flex;align-items:center;gap:10px}
    .card-desc{font-size:.95rem;color:#cbd5e1;line-height:1.5;font-weight:300;flex-grow:1}
    .expected{font-size:.8rem;color:#94a3b8;padding:6px 10px;background:rgba(255,255,255,.05);border-radius:6px;margin-top:4px}
    .expected b{color:#ef4444}
    .expected.safe b{color:#22c55e}
    .btn{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;padding:13px;text-align:center;text-decoration:none;border-radius:10px;font-weight:bold;font-size:1rem;transition:.2s;border:1px solid rgba(255,255,255,.1)}
    .btn:hover{background:linear-gradient(135deg,#60a5fa,#3b82f6);transform:scale(1.02)}
    .section-title{font-size:1.1rem;color:#64748b;text-transform:uppercase;letter-spacing:2px;margin:30px 0 10px;width:100%;max-width:1100px}
  </style>
</head>
<body>
  <h1>🛡️ Verity <span>Demo Environment</span></h1>
  <p class="sub">Each page below triggers a specific Verity protection module. Reload extension at chrome://extensions first.</p>

  <div class="section-title">Core Demos</div>
  <div class="grid">
    <div class="card">
      <div class="card-title">🏦 Fake Bank Login</div>
      <div class="card-desc">Realistic HDFC NetBanking login page harvesting Customer ID, Password, and OTP.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Red overlay blocks the page</div>
      <a class="btn" href="/demo/bank" target="_blank">Launch Demo A</a>
    </div>
    <div class="card">
      <div class="card-title">💳 Fake Payment Gateway</div>
      <div class="card-desc">PayPal checkout page stealing Card Number, CVV, and OTP on a fake domain.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Payment Phishing overlay</div>
      <a class="btn" href="/demo/payment" target="_blank">Launch Demo B</a>
    </div>
    <div class="card">
      <div class="card-title">📲 UPI Cashback Scam</div>
      <div class="card-desc">Paytm reward trap with a hidden UPI debit link that steals ₹5,000.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Digital Scam Trap detected</div>
      <a class="btn" href="/demo/upi" target="_blank">Launch Demo C</a>
    </div>
    <div class="card">
      <div class="card-title">⚡ Digital Arrest Scam</div>
      <div class="card-desc">Electricity disconnection scam with fake KYC update form.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Digital Arrest blocked</div>
      <a class="btn" href="/demo/utility" target="_blank">Launch Demo D</a>
    </div>
    <div class="card">
      <div class="card-title">📦 Malicious APK Download</div>
      <div class="card-desc">Auto-downloads fake "SBI YONO" APK. Verity should cancel it instantly.</div>
      <div class="expected">Expected: <b>🔴 CANCEL</b> — Download cancelled + toast popup</div>
      <a class="btn" href="/demo/download" target="_blank">Launch Demo E</a>
    </div>
  </div>

  <div class="section-title">Advanced Demos (Test C & D equivalents)</div>
  <div class="grid">
    <div class="card">
      <div class="card-title">🏦 Fake ICICI Bank (Test C)</div>
      <div class="card-desc">Simulates what Test C was supposed to do: credential harvesting on a fake ICICI bank portal.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Brand impersonation blocked</div>
      <a class="btn" href="/demo/fake-bank-redirect" target="_blank">Launch Demo F</a>
    </div>
    <div class="card">
      <div class="card-title">💳 Fake Razorpay (Test D)</div>
      <div class="card-desc">Simulates what Test D was supposed to do: fake Razorpay checkout with Card/CVV/OTP.</div>
      <div class="expected">Expected: <b>🔴 BLOCK</b> — Payment Phishing blocked</div>
      <a class="btn" href="/demo/fake-payment-redirect" target="_blank">Launch Demo G</a>
    </div>
  </div>
</body>
</html>`);
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n=======================================================`);
  console.log(`🚀 Verity Demo Server running at http://localhost:${PORT}`);
  console.log(`=======================================================\n`);
});
