/**
 * reputation.js — Threat Intelligence with local caching
 *
 * Queries external reputation services and caches results
 * to reduce latency and API usage.
 * Fails safely when service is unavailable.
 */

// In-memory cache: hostname → { result, timestamp }
const cache = new Map();
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

function getCached(hostname) {
  const entry = cache.get(hostname);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
    cache.delete(hostname);
    return null;
  }
  return entry.result;
}

function setCached(hostname, result) {
  cache.set(hostname, { result, timestamp: Date.now() });
  // Limit cache size
  if (cache.size > 500) {
    const firstKey = cache.keys().next().value;
    cache.delete(firstKey);
  }
}

/**
 * Check URL reputation.
 * Returns: { malware: boolean, source: string|null }
 * 'unknown' result is returned if service is unavailable — never treated as malicious.
 */
export async function checkReputation(url) {
  let hostname = '';
  try {
    hostname = new URL(url).hostname.toLowerCase();
  } catch (e) {
    return { malware: false, source: null };
  }

  const cached = getCached(hostname);
  if (cached !== null) return cached;

  // Try local Verity Cloud (optional — gracefully fails if unavailable)
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 2000); // 2s timeout

    const res = await fetch('http://localhost:8000/threat-intel/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const result = { malware: !!data.malware, source: data.source || 'Verity Cloud' };
      setCached(hostname, result);
      return result;
    }
  } catch (e) {
    // Service unavailable — fail safe
  }

  const fallback = { malware: false, source: null };
  setCached(hostname, fallback);
  return fallback;
}
