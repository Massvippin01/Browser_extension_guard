const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = 8123;
const BRANDS_FILE = path.join(__dirname, '..', 'brands.json');

let brands = [];
try {
  const data = fs.readFileSync(BRANDS_FILE, 'utf8');
  brands = JSON.parse(data);
} catch (e) {
  console.error('Failed to load brands.json', e);
}

// Map variants/names to actual brand objects for quick lookup
const brandMap = new Map();
for (const b of brands) {
  brandMap.set(b.name.toLowerCase(), b);
  if (b.variants) {
    for (const v of b.variants) {
      brandMap.set(v.toLowerCase(), b);
    }
  }
}

// Generate a generic phishing login page
function generateLoginPage(brandName) {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>${brandName} - Secure Login</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
      background-color: #f3f4f6;
      margin: 0;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
    }
    .login-container {
      background: white;
      padding: 40px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.1);
      width: 100%;
      max-width: 400px;
      text-align: center;
    }
    .brand-logo {
      font-size: 28px;
      font-weight: 800;
      color: #1e3a8a;
      margin-bottom: 8px;
    }
    .subtitle {
      color: #64748b;
      margin-bottom: 32px;
      font-size: 14px;
    }
    .input-group {
      margin-bottom: 20px;
      text-align: left;
    }
    .input-group label {
      display: block;
      margin-bottom: 6px;
      font-size: 13px;
      font-weight: 600;
      color: #334155;
    }
    .input-group input {
      width: 100%;
      padding: 12px;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      box-sizing: border-box;
      font-size: 15px;
    }
    .input-group input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .submit-btn {
      width: 100%;
      padding: 12px;
      background-color: #2563eb;
      color: white;
      border: none;
      border-radius: 6px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      margin-top: 10px;
    }
    .submit-btn:hover {
      background-color: #1d4ed8;
    }
    .footer-links {
      margin-top: 24px;
      font-size: 13px;
      color: #3b82f6;
      display: flex;
      justify-content: space-between;
    }
    .footer-links span {
      cursor: pointer;
    }
  </style>
</head>
<body>
  <div class="login-container">
    <div class="brand-logo">${brandName}</div>
    <div class="subtitle">Sign in to your account to continue</div>
    
    <form action="/fake-submit" method="POST" onsubmit="event.preventDefault(); alert('Phishing payload submitted!');">
      <div class="input-group">
        <label>Email or Username</label>
        <input type="text" placeholder="Enter your email" required>
      </div>
      <div class="input-group">
        <label>Password</label>
        <input type="password" placeholder="Enter your password" required>
      </div>
      <button type="submit" class="submit-btn">Sign In</button>
    </form>
    
    <div class="footer-links">
      <span>Forgot password?</span>
      <span>Create an account</span>
    </div>
  </div>
</body>
</html>
  `;
}

// Demo 3: Financial Scam
function generateFinancialPage() {
  return generateLoginPage("Global Bank").replace(
    '<label>Password</label>',
    `<label>Account Number</label><input type="text" placeholder="Account Number"><br><br>
     <label>Credit Card Number</label><input type="text" placeholder="Card Number"><br><br>
     <label>CVV</label><input type="password" placeholder="CVV"><br><br>
     <label>OTP / PIN</label><input type="password" placeholder="Enter OTP">
     <div style="display:none;">UPI ID, KYC verification</div>`
  );
}

// Demo 5: Search Page
function generateSearchPage() {
  return `
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Google Search Mock</title>
  <style>
    body { font-family: Arial, sans-serif; padding: 40px; }
    .result { margin-bottom: 24px; max-width: 600px; }
    h3 { margin: 0 0 4px 0; color: #1a0dab; font-size: 20px; font-weight: normal; }
    .url { color: #006621; font-size: 14px; margin-bottom: 4px; }
    a { text-decoration: none; }
    a:hover { text-decoration: underline; }
  </style>
</head>
<body id="search">
  <div style="margin-bottom: 30px; font-size: 24px; font-weight: bold;">Google Search: SBI Net Banking</div>
  
  <div class="result">
    <a href="https://onlinesbi.sbi">
      <div class="url">https://onlinesbi.sbi</div>
      <h3>State Bank of India - Personal Banking</h3>
    </a>
    <div style="color: #4d5156; font-size: 14px;">Official online banking portal for State Bank of India.</div>
  </div>

  <div class="result">
    <a href="http://sbi-login-verification.localhost:8123">
      <div class="url">http://sbi-login-verification.localhost:8123</div>
      <h3>SBI Secure Login - Verify KYC Now</h3>
    </a>
    <div style="color: #4d5156; font-size: 14px;">Urgent: Verify your SBI account KYC immediately to prevent block.</div>
  </div>
</body>
</html>`;
}

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const urlPath = req.url;

  if (urlPath === '/safe') {
    res.writeHead(200);
    res.end('<html><body><h1>Safe Website</h1><p>This is a completely normal, safe website running on localhost.</p></body></html>');
    return;
  }
  
  if (urlPath === '/financial') {
    res.writeHead(200);
    res.end(generateFinancialPage());
    return;
  }

  if (urlPath.startsWith('/redirect')) {
    const step = parseInt(urlPath.split('-')[1] || '0');
    if (step < 3) {
      res.writeHead(302, { 'Location': `/redirect-${step + 1}` });
      res.end();
    } else {
      res.writeHead(302, { 'Location': `http://fake-bank-login.localhost:${PORT}` });
      res.end();
    }
    return;
  }

  if (urlPath === '/search') {
    res.writeHead(200);
    res.end(generateSearchPage());
    return;
  }

  const host = req.headers.host || '';
  let subdomain = host.split('.')[0].toLowerCase();
  
  let targetBrandName = 'Generic Service';
  if (brandMap.has(subdomain)) {
    targetBrandName = brandMap.get(subdomain).name;
  } else if (subdomain.includes('localhost') || subdomain.includes('127') || !subdomain) {
    targetBrandName = 'Generic Bank';
  } else {
    targetBrandName = subdomain.charAt(0).toUpperCase() + subdomain.slice(1);
  }

  res.writeHead(200);
  res.end(generateLoginPage(targetBrandName));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Verity Simulator] Server running on http://127.0.0.1:${PORT}`);
});
