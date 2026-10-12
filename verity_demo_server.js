const http = require('http');
const PORT = 8080;

const server = http.createServer((req, res) => {
  console.log(`[DEMO :8080] ${req.url}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // DOWNLOAD ENDPOINT — Malicious APK payload
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/download-file' || req.url === '/downloads/sbi_yono_rewards.apk') {
    res.writeHead(200, {
      'Content-Type': 'application/vnd.android.package-archive',
      'Content-Disposition': 'attachment; filename="sbi_yono_rewards.apk"',
      'Content-Length': 32
    });
    return res.end(Buffer.from('PK\x03\x04verity_test_payload_apk_binary'));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO A — Fake Bank Login (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/bank') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>HDFC NetBanking - Secure Login</title>
<style>
  body{font-family:Arial,sans-serif;background:#f4f6f9;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#fff;padding:40px;border-radius:8px;box-shadow:0 4px 12px rgba(0,0,0,.1);width:350px;text-align:center;border-top:5px solid #004c8f}
  .logo{font-size:24px;font-weight:bold;color:#004c8f;margin-bottom:20px}
  input{width:100%;padding:12px;margin:10px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
  button{width:100%;padding:12px;background:#004c8f;color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:10px}
</style></head><body>
<div class="box">
  <div class="logo">HDFC Bank NetBanking</div>
  <p style="color:#666;font-size:14px">Welcome to HDFC Bank secure net banking login.</p>
  <form><input type="text" placeholder="Customer ID"><input type="password" placeholder="IPIN (Password)"><input type="text" placeholder="OTP"><button type="button">SECURE LOGIN</button></form>
  <p style="font-size:11px;color:#999;margin-top:15px">HDFC Bank Limited.</p>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO B — Fake Payment Gateway (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/payment') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>PayPal Secure Checkout</title>
<style>
  body{font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;background:#f5f7fa;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .box{background:#fff;padding:40px;border-radius:12px;box-shadow:0 10px 30px rgba(0,0,0,.1);width:400px;text-align:center}
  .logo{font-size:28px;font-weight:bold;color:#003087;font-style:italic}.logo span{color:#009cde}
  .amount{font-size:32px;color:#333;font-weight:300;margin-bottom:30px}
  .grp{text-align:left;margin-bottom:15px}
  label{font-size:13px;color:#666;font-weight:bold;display:block;margin-bottom:5px}
  input{width:100%;padding:12px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box;font-size:14px}
  .row{display:flex;gap:15px}.row .grp{flex:1}
  button{width:100%;padding:14px;background:#0070ba;color:#fff;border:none;border-radius:24px;cursor:pointer;font-size:16px;font-weight:bold;margin-top:20px}
</style></head><body>
<div class="box">
  <div class="logo">Pay<span>Pal</span></div>
  <p style="color:#666;font-size:14px">Complete your purchase</p>
  <div class="amount">$299.99 USD</div>
  <form>
    <div class="grp"><label>Card Number</label><input placeholder="1234 5678 9012 3456"></div>
    <div class="row"><div class="grp"><label>Expiry</label><input placeholder="MM/YY"></div><div class="grp"><label>CVV</label><input placeholder="123"></div></div>
    <div class="grp"><label>OTP Verification</label><input placeholder="Enter OTP"></div>
    <button type="button">Pay Now</button>
  </form>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO C — UPI Cashback Scam (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/upi') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Paytm - Claim Your Cashback</title>
<style>
  body{font-family:Arial,sans-serif;background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#1e293b;padding:40px;border-radius:16px;border:1px solid #334155;text-align:center;width:350px;box-shadow:0 15px 35px rgba(0,0,0,.5)}
  .amount{font-size:42px;font-weight:bold;color:#4ade80;margin:20px 0}
  .btn{display:inline-block;width:100%;padding:16px;background:#0ea5e9;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:18px;margin-top:20px;box-sizing:border-box;text-align:center}
</style></head><body>
<div class="card">
  <h2 style="margin-top:0;color:#38bdf8">Paytm Rewards</h2>
  <p style="color:#94a3b8">Congratulations! You have won a cashback reward.</p>
  <div class="amount">₹5,000</div>
  <p style="font-size:13px;color:#64748b">Click below to receive money to your bank account.</p>
  <a class="btn" href="upi://pay?pa=claimreward@fakeupi&pn=PaytmReward&am=5000&cu=INR">Claim ₹5,000 Cashback Now</a>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO D — Digital Arrest / Utility Scam (Plain HTML, no embedded overlays)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/utility') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Electricity Board — Urgent Notice</title>
<style>
  body{font-family:Arial,sans-serif;background:#fff1f2;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:40px;border-radius:12px;border:2px solid #e11d48;text-align:center;width:400px;box-shadow:0 10px 25px rgba(225,29,72,.2)}
  h2{color:#e11d48;margin-top:0}
  button{width:100%;padding:14px;background:#e11d48;color:#fff;border:none;border-radius:6px;font-weight:bold;font-size:16px;margin-top:20px;cursor:pointer}
  input{width:100%;padding:12px;margin:8px 0;border:1px solid #ccc;border-radius:4px;box-sizing:border-box}
</style></head><body>
<div class="card">
  <h2>⚠️ URGENT: DISCONNECTION NOTICE</h2>
  <p style="color:#4c0519;font-weight:bold;font-size:15px">Your electricity connection will be disconnected tonight at 9:30 PM.</p>
  <p style="color:#666;font-size:13px;margin-bottom:20px">Update KYC and pay ₹11 processing fee immediately.</p>
  <form><input placeholder="Consumer Number"><input placeholder="Mobile Number"><input placeholder="OTP"><button type="button">Pay ₹11 & Update KYC</button></form>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO E — Malicious APK Download (Plain HTML, links to /download-file)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/download') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>SBI YONO Rewards — Download</title>
<style>
  body{font-family:Arial,sans-serif;background:#e0f2fe;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:40px;border-radius:12px;text-align:center;width:380px;box-shadow:0 10px 30px rgba(0,0,0,.1)}
  .btn{display:inline-block;width:100%;padding:16px;background:#0284c7;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:16px;margin-top:20px;box-sizing:border-box;text-align:center}
</style></head><body>
<div class="card">
  <h2 style="color:#0369a1;margin-top:0">SBI YONO Rewards</h2>
  <p style="color:#64748b;font-size:14px">Download your official rewards app update below.</p>
  <a class="btn" href="/downloads/sbi_yono_rewards.apk" id="dl-btn">Download APK</a>
</div>
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // HUB DASHBOARD
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/' || req.url === '/favicon.ico') {
    if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>Verity Demo Server</title>
<link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;700&display=swap" rel="stylesheet">
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Outfit',sans-serif;background:#020617;color:#f8fafc;min-height:100vh;padding:60px 40px;display:flex;flex-direction:column;align-items:center}
  h1{font-size:2.5rem;font-weight:700;margin-bottom:10px;text-align:center}
  h1 span{background:linear-gradient(135deg,#38bdf8,#818cf8);-webkit-background-clip:text;-webkit-text-fill-color:transparent}
  p.sub{color:#94a3b8;margin-bottom:40px;text-align:center;font-size:1.1rem;max-width:600px;line-height:1.6}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:24px;width:100%;max-width:1100px}
  .card{background:rgba(30,41,59,.5);border:1px solid rgba(255,255,255,.1);border-radius:16px;padding:28px;display:flex;flex-direction:column;gap:12px;transition:.3s}
  .card:hover{transform:translateY(-4px);background:rgba(30,41,59,.8);border-color:rgba(255,255,255,.2);box-shadow:0 10px 30px rgba(0,0,0,.3)}
  .card-title{font-size:1.3rem;font-weight:700}
  .card-desc{font-size:.95rem;color:#cbd5e1;line-height:1.5;font-weight:300;flex-grow:1}
  .expected{font-size:.8rem;color:#94a3b8;padding:6px 10px;background:rgba(255,255,255,.05);border-radius:6px;margin-top:4px}
  .expected b{color:#ef4444}
  .btn{background:linear-gradient(135deg,#3b82f6,#2563eb);color:#fff;padding:13px;text-align:center;text-decoration:none;border-radius:10px;font-weight:bold;font-size:1rem;transition:.2s;border:1px solid rgba(255,255,255,.1)}
  .btn:hover{background:linear-gradient(135deg,#60a5fa,#3b82f6);transform:scale(1.02)}
</style></head><body>
<h1>🛡️ Verity <span>Demo Environment</span></h1>
<p class="sub">These demo pages serve plain HTML test fixtures without any client-side simulated overlays or mock scripts. The real Verity browser extension analyzes each page and download stream to produce security verdicts.</p>
<div class="grid">
  <div class="card">
    <div class="card-title">🏦 Fake Bank Login</div>
    <div class="card-desc">Realistic HDFC NetBanking login harvesting Customer ID, Password, and OTP.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Verity extension blocks the page</div>
    <a class="btn" href="/demo/bank" target="_blank">Launch Demo A</a>
  </div>
  <div class="card">
    <div class="card-title">💳 Fake Payment Gateway</div>
    <div class="card-desc">PayPal checkout stealing Card Number, CVV, and OTP on a fake domain.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Payment Phishing overlay</div>
    <a class="btn" href="/demo/payment" target="_blank">Launch Demo B</a>
  </div>
  <div class="card">
    <div class="card-title">📲 UPI Cashback Scam</div>
    <div class="card-desc">Paytm reward trap hiding a UPI debit link (upi://pay).</div>
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
    <div class="card-desc">Serves "sbi_yono_rewards.apk". Verity download monitor analyzes and cancels it.</div>
    <div class="expected">Expected: <b>🔴 CANCEL</b> — Download cancelled + extension warning</div>
    <a class="btn" href="/demo/download" target="_blank">Launch Demo E</a>
  </div>
</div>
</body></html>`);
  }

  res.writeHead(404);
  res.end('Not found');
});

server.listen(PORT, () => {
  console.log(`\n=======================================================`);
  console.log(`🚀 Verity Demo Server running at http://localhost:${PORT}`);
  console.log(`=======================================================\n`);
});
