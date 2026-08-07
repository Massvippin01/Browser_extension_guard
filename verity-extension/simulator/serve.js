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

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  
  // CORS for the simulator UI
  res.setHeader('Access-Control-Allow-Origin', '*');

  // Try to parse the host header
  // e.g. "paypal-secure.localhost:8123"
  const host = req.headers.host || '';
  
  let subdomain = host.split('.')[0].toLowerCase();
  
  // Find brand by subdomain
  let targetBrandName = 'Generic Service';
  
  if (brandMap.has(subdomain)) {
    targetBrandName = brandMap.get(subdomain).name;
  } else if (subdomain.includes('localhost') || subdomain.includes('127') || !subdomain) {
    // If just localhost:8123 or 127.0.0.1:8123, use default generic
    targetBrandName = 'Generic Bank';
  } else {
    // We didn't explicitly find it, but we can just use the subdomain string as the brand name
    // Capitalize first letter
    targetBrandName = subdomain.charAt(0).toUpperCase() + subdomain.slice(1);
  }

  res.writeHead(200);
  res.end(generateLoginPage(targetBrandName));
});

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[Verity Simulator] Fake phishing server running on http://127.0.0.1:${PORT}`);
  console.log(`To simulate an attack, visit e.g. http://paypal-secure.localhost:${PORT}`);
});
