const http = require('http');
const PORT = 8080;

// ─────────────────────────────────────────────────────────────────────────────
// SHARED: Verity Block Overlay (injected into each demo page via JS)
// This is a pixel-perfect replica of Verity's real overlay.
// ─────────────────────────────────────────────────────────────────────────────
function verityOverlay({ title, riskScore, category, reasons, isPayment }) {
  const tagsHtml = reasons.map(r => `<span class="vtag">${r}</span>`).join('');
  const headerBadge = isPayment ? '💳 Payment Phishing Blocked' : '🛑 Threat Blocked';
  const stateColor = '#D32F2F';
  const message = isPayment
    ? 'This website is attempting to impersonate a payment gateway to steal your payment credentials. We strongly recommend you do not proceed.'
    : 'This site matches signatures of phishing, scams, or credential harvesting. Verity recommends returning to safety.';

  return `
  <div id="verity-overlay" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;z-index:2147483647;background:#FAFAFA;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;overflow-y:auto;">
    <style>
      .vo-header{display:flex;justify-content:space-between;align-items:center;padding:18px 32px;background:linear-gradient(135deg,#0f172a,#1e293b);color:#f8fafc}
      .vo-brand{display:flex;align-items:center;gap:12px}
      .vo-logo{width:36px;height:36px;border-radius:10px;background:linear-gradient(135deg,#3b82f6,#8b5cf6);display:flex;align-items:center;justify-content:center;font-weight:900;color:#fff;font-size:18px}
      .vo-title{font-size:15px;font-weight:700;letter-spacing:1px}
      .vo-badge{background:${stateColor};color:#fff;padding:6px 16px;border-radius:20px;font-size:12px;font-weight:700}
      .vo-body{max-width:620px;margin:40px auto;padding:0 24px}
      .vo-card{background:#fff;border-radius:16px;box-shadow:0 4px 24px rgba(0,0,0,.08);padding:36px;display:flex;gap:24px;align-items:flex-start}
      .vo-alert{width:56px;height:56px;border-radius:50%;background:${stateColor}22;display:flex;align-items:center;justify-content:center;flex-shrink:0}
      .vo-alert-icon{width:40px;height:40px;border-radius:50%;background:${stateColor};color:#fff;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:900}
      .vo-status{font-size:22px;font-weight:700;color:#1e293b;margin-bottom:8px}
      .vo-status span{color:${stateColor}}
      .vo-url{font-size:13px;color:#64748b;margin-bottom:12px;word-break:break-all}
      .vo-msg{font-size:14px;color:#475569;line-height:1.6;margin-bottom:16px}
      .vo-tags{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:20px}
      .vtag{background:#fef2f2;color:#b91c1c;padding:5px 12px;border-radius:8px;font-size:12px;font-weight:600;border:1px solid #fecaca}
      .vo-score{display:flex;align-items:center;gap:16px;padding:16px;background:#fef2f2;border-radius:12px;border:1px solid #fecaca;margin-bottom:24px}
      .vo-score-num{font-size:36px;font-weight:900;color:${stateColor}}
      .vo-score-label{font-size:13px;color:#64748b}
      .vo-score-cat{font-size:14px;font-weight:700;color:#1e293b}
      .vo-actions{display:flex;gap:12px;flex-wrap:wrap}
      .vo-btn{padding:12px 28px;border-radius:10px;font-size:14px;font-weight:700;cursor:pointer;border:none;transition:.2s}
      .vo-btn-safe{background:#1e293b;color:#fff}.vo-btn-safe:hover{background:#0f172a}
      .vo-btn-risk{background:#fff;color:#64748b;border:1px solid #e2e8f0}.vo-btn-risk:hover{background:#f8fafc}
      .vo-payment-warn{background:linear-gradient(135deg,#dc262622,#f8717122);border:2px solid #dc2626;border-radius:12px;padding:16px;margin-bottom:16px;display:flex;align-items:center;gap:12px}
      .vo-payment-warn span{font-size:28px}
      .vo-payment-warn div{font-size:13px;color:#991b1b;font-weight:600}
    </style>
    <div class="vo-header">
      <div class="vo-brand">
        <div class="vo-logo">V</div>
        <div class="vo-title">VERITY <span style="opacity:.4;margin:0 6px">|</span> <span style="font-weight:400;opacity:.7">Web Protection</span></div>
      </div>
      <div class="vo-badge">${headerBadge}</div>
    </div>
    <div class="vo-body">
      <div class="vo-card">
        <div class="vo-alert"><div class="vo-alert-icon">!</div></div>
        <div style="flex:1">
          <div class="vo-status">Website status: <span>${title}</span></div>
          <div class="vo-url">🌐 <span id="vo-url-display"></span></div>
          ${isPayment ? '<div class="vo-payment-warn"><span>💳</span><div>PAYMENT PHISHING DETECTED — This page is impersonating a trusted payment provider to steal your card details, CVV, and OTP.</div></div>' : ''}
          <div class="vo-msg">${message}</div>
          <div class="vo-tags">${tagsHtml}</div>
          <div class="vo-score">
            <div class="vo-score-num">${riskScore}</div>
            <div>
              <div class="vo-score-cat">${category}</div>
              <div class="vo-score-label">Risk Score / 100</div>
            </div>
          </div>
          <div class="vo-actions">
            <button class="vo-btn vo-btn-safe" onclick="history.back()">← Go Back to Safety</button>
            <button class="vo-btn vo-btn-risk" onclick="document.getElementById('verity-overlay').style.display='none'">I understand the risks, proceed anyway</button>
          </div>
        </div>
      </div>
    </div>
  </div>
  <script>
    // Show overlay after 1.2s so user briefly sees the scam page first
    setTimeout(function(){
      document.getElementById('vo-url-display').textContent = window.location.href;
      document.getElementById('verity-overlay').style.display = 'block';
    }, 1200);
  </script>`;
}

// ─────────────────────────────────────────────────────────────────────────────
// SHARED: Download Toast Notification (expand/shrink animation)
// ─────────────────────────────────────────────────────────────────────────────
const downloadToastHtml = `
<style>
  .dl-toast{position:fixed;top:16px;right:16px;z-index:2147483647;transform-origin:top right;animation:dlExpand 5s cubic-bezier(.16,1,.3,1) forwards;pointer-events:auto}
  @keyframes dlExpand{0%{transform:scale(.2) translateY(-20px);opacity:0}12%{transform:scale(1.08) translateY(0);opacity:1}18%{transform:scale(1) translateY(0);opacity:1}85%{transform:scale(1) translateY(0);opacity:1}100%{transform:scale(.2) translateY(-20px);opacity:0}}
  .dl-panel{background:rgba(15,23,42,.96);color:#f8fafc;border:2px solid #ef4444;border-radius:14px;padding:16px 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;display:flex;align-items:center;gap:14px;box-shadow:0 10px 30px rgba(0,0,0,.5),0 0 20px rgba(239,68,68,.3)}
  .dl-icon{font-size:24px}
  .dl-title{font-weight:800;color:#ef4444;font-size:12px;letter-spacing:.5px;margin-bottom:3px}
  .dl-sub{color:#cbd5e1;font-size:12px}
  .dl-file{color:#94a3b8;font-size:11px;margin-top:2px}
</style>
<div class="dl-toast" id="dl-toast">
  <div class="dl-panel">
    <div class="dl-icon">🛡️</div>
    <div>
      <div class="dl-title">VERITY — DOWNLOAD BLOCKED</div>
      <div class="dl-sub">Malicious APK cancelled & deleted</div>
      <div class="dl-file">sbi_yono_rewards.apk — Brand impersonation detected</div>
    </div>
  </div>
</div>
<script>setTimeout(function(){var t=document.getElementById('dl-toast');if(t)t.remove();},5500);</script>`;

const server = http.createServer((req, res) => {
  console.log(`[DEMO :8080] ${req.url}`);

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO A — Fake Bank Login
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
${verityOverlay({
  title: 'Dangerous',
  riskScore: 97,
  category: 'Phishing — Brand Impersonation',
  isPayment: false,
  reasons: ['Brand Impersonation: HDFC Bank', 'Credential Harvesting', 'Password + OTP Collection', 'Unverified Domain']
})}
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO B — Fake Payment Gateway
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
${verityOverlay({
  title: 'Payment Phishing Blocked',
  riskScore: 100,
  category: 'Payment Phishing',
  isPayment: true,
  reasons: ['Fake PayPal Domain', 'Card/CVV Collection', 'OTP Harvesting', 'Domain Mismatch: not paypal.com']
})}
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO C — UPI Cashback Scam
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
  <a class="btn" href="#">Claim ₹5,000 Cashback Now</a>
</div>
${verityOverlay({
  title: 'Digital Scam Blocked',
  riskScore: 100,
  category: 'UPI Debit Trap / Financial Scam',
  isPayment: true,
  reasons: ['UPI Debit Trap Detected', 'Fake Cashback Claim', 'Reverse Transaction: upi://pay', 'Paytm Brand Impersonation']
})}
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO D — Digital Arrest / Utility Scam
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
${verityOverlay({
  title: 'Digital Arrest Blocked',
  riskScore: 95,
  category: 'Scam / Social Engineering',
  isPayment: false,
  reasons: ['Digital Arrest Scam', 'Utility Disconnection Threat', 'Fake KYC Collection', 'High-Pressure Tactics']
})}
</body></html>`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DEMO E — Malicious APK Download (with animated toast)
  // ═══════════════════════════════════════════════════════════════════════════
  if (req.url === '/demo/download') {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    return res.end(`<!DOCTYPE html><html><head><title>SBI YONO Rewards — Download</title>
<style>
  body{font-family:Arial,sans-serif;background:#e0f2fe;display:flex;justify-content:center;align-items:center;height:100vh;margin:0}
  .card{background:#fff;padding:40px;border-radius:12px;text-align:center;width:380px;box-shadow:0 10px 30px rgba(0,0,0,.1)}
  .btn{display:inline-block;width:100%;padding:16px;background:#0284c7;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;font-size:16px;margin-top:20px;box-sizing:border-box;text-align:center}
  .progress{margin-top:20px;display:none}
  .bar-bg{height:8px;background:#e2e8f0;border-radius:4px;overflow:hidden}
  .bar-fill{height:100%;width:0%;background:linear-gradient(90deg,#0284c7,#ef4444);border-radius:4px;transition:width .3s}
  .status{font-size:13px;color:#64748b;margin-top:8px}
  .cancelled{color:#ef4444;font-weight:bold;font-size:15px;display:none;margin-top:16px}
</style></head><body>
<div class="card">
  <h2 style="color:#0369a1;margin-top:0">SBI YONO Rewards</h2>
  <p style="color:#64748b;font-size:14px">Your download will begin automatically…</p>
  <a class="btn" href="#" id="dl-btn">Download APK</a>
  <div class="progress" id="progress">
    <div class="bar-bg"><div class="bar-fill" id="bar"></div></div>
    <div class="status" id="dl-status">Downloading sbi_yono_rewards.apk…</div>
  </div>
  <div class="cancelled" id="cancelled">✕ Download cancelled by Verity</div>
</div>
${downloadToastHtml.replace('id="dl-toast"', 'id="dl-toast" style="display:none"')}
<script>
  // Simulate download → cancel after 2s
  setTimeout(function(){
    document.getElementById('progress').style.display = 'block';
    var bar = document.getElementById('bar');
    var pct = 0;
    var iv = setInterval(function(){
      pct += 8;
      bar.style.width = pct + '%';
      if (pct >= 35) {
        clearInterval(iv);
        bar.style.background = '#ef4444';
        bar.style.width = pct + '%';
        document.getElementById('dl-status').innerHTML = '<span style="color:#ef4444;font-weight:bold">⛔ BLOCKED — Verity cancelled this download</span>';
        document.getElementById('cancelled').style.display = 'block';
        document.getElementById('dl-btn').style.background = '#94a3b8';
        document.getElementById('dl-btn').textContent = 'Download Blocked';
        // Show toast
        var toast = document.getElementById('dl-toast');
        toast.style.display = 'block';
        setTimeout(function(){ toast.remove(); }, 5500);
      }
    }, 200);
  }, 1500);
</script>
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
<p class="sub">Each demo below shows a realistic scam page, then Verity's protection overlay automatically activates after 1 second — demonstrating real-time threat blocking.</p>
<div class="grid">
  <div class="card">
    <div class="card-title">🏦 Fake Bank Login</div>
    <div class="card-desc">Realistic HDFC NetBanking login harvesting Customer ID, Password, and OTP.</div>
    <div class="expected">Expected: <b>🔴 BLOCK</b> — Red overlay blocks the page</div>
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
    <div class="card-desc">Paytm reward trap hiding a UPI debit link that steals ₹5,000.</div>
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
    <div class="card-desc">Auto-downloads fake "SBI YONO" APK. Verity cancels it instantly with animated toast.</div>
    <div class="expected">Expected: <b>🔴 CANCEL</b> — Download cancelled + toast popup</div>
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
