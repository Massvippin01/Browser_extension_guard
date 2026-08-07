/**
 * ml-scorer.js - Refactored to proxy requests to the MV3 Offscreen Document.
 * This circumvents the limitations of loading WASM/Web Workers inside an ES Module Service Worker.
 */

/**
 * Initializes the ONNX model by ensuring the offscreen document is open.
 */
export async function initializeModel() {
  await setupOffscreenDocument();
  // Send an init message to preemptively load the model
  try {
    await chrome.runtime.sendMessage({ target: 'offscreen', action: 'init_model' });
  } catch (e) {
    console.warn('[Verity ML] Offscreen init failed:', e);
  }
}

/**
 * Sets up the offscreen document if it doesn't exist yet.
 */
async function setupOffscreenDocument() {
  const path = 'background/offscreen.html';
  const url = chrome.runtime.getURL(path);
  
  try {
    const existingContexts = await chrome.runtime.getContexts({
      contextTypes: ['OFFSCREEN_DOCUMENT'],
      documentUrls: [url]
    });

    if (existingContexts.length > 0) {
      return;
    }

    await chrome.offscreen.createDocument({
      url: path,
      reasons: ['WORKERS'], // Web Worker/WASM threading reason
      justification: 'Run ONNX ML Inference for phishing detection'
    });
  } catch (err) {
    if (err.message && err.message.includes('Only a single offscreen document may be created')) {
      // Ignored
    } else {
      console.error('[Verity ML] Error creating offscreen document:', err);
    }
  }
}

/**
 * Proxies the ML inference request to the offscreen document.
 * @param {string} url 
 * @param {Object} domSignals 
 * @returns {Promise<number|null>} Risk score 0-100, or null if failed/unavailable.
 */
export async function getMlScore(url, domSignals) {
  try {
    await setupOffscreenDocument();
    const response = await chrome.runtime.sendMessage({
      target: 'offscreen',
      action: 'run_inference',
      url: url,
      domSignals: domSignals
    });
    return response ? response.score : null;
  } catch (err) {
    console.warn('[Verity ML] Failed to communicate with offscreen doc:', err);
    return null;
  }
}
