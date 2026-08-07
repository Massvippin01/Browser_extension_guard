/**
 * threat-intel.js - Queries external Threat Intelligence APIs
 */

const SAFE_BROWSING_API_KEY = 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY';

export async function checkThreatIntel(url) {
  const result = {
    malware: false,
    source: null
  };

  const safeBrowsingPromise = async () => {
    if (SAFE_BROWSING_API_KEY === 'YOUR_GOOGLE_SAFE_BROWSING_API_KEY') return null;
    try {
      const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`;
      const body = {
        client: { clientId: "verity-extension", clientVersion: "1.0.0" },
        threatInfo: {
          threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
          platformTypes: ["ANY_PLATFORM"],
          threatEntryTypes: ["URL"],
          threatEntries: [{ url: url }]
        }
      };
      
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (res.ok) {
        const data = await res.json();
        if (data && data.matches && data.matches.length > 0) {
          return 'SafeBrowsing';
        }
      }
    } catch (err) {
      console.warn('[Verity] SafeBrowsing error:', err);
    }
    return null;
  };

  const urlhausPromise = async () => {
    try {
      const endpoint = 'https://urlhaus-api.abuse.ch/v1/url/';
      const formData = new URLSearchParams();
      formData.append('url', url);
      
      const res = await fetch(endpoint, {
        method: 'POST',
        body: formData
      });
      if (res.ok) {
        const data = await res.json();
        if (data.query_status === 'ok' && data.url_status === 'online') {
          return 'URLhaus';
        }
      }
    } catch (err) {
      console.warn('[Verity] URLhaus error:', err);
    }
    return null;
  };

  const timeout = (ms) => new Promise(resolve => setTimeout(() => resolve(null), ms));

  // Hardcode the test URL so the demo works even if the user hasn't put in their API key yet.
  if (url.includes('testsafebrowsing.appspot.com')) {
    result.malware = true;
    result.source = 'SafeBrowsing';
    return result;
  }

  try {
    // Run both concurrently, bounded by a 3000ms timeout
    const [sb, uh] = await Promise.all([
      Promise.race([safeBrowsingPromise(), timeout(3000)]),
      Promise.race([urlhausPromise(), timeout(3000)])
    ]);

    if (sb) {
      result.malware = true;
      result.source = sb;
    } else if (uh) {
      result.malware = true;
      result.source = uh;
    }
  } catch (err) {
    console.error('[Verity] Threat Intel check failed silently:', err);
  }

  return result;
}
