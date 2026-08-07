// offscreen.js - Runs inside offscreen.html to handle ML execution

let session = null;
let featureOrder = [];
let isModelAvailable = false;

async function initModel() {
  if (isModelAvailable) return true;
  try {
    if (typeof ort === 'undefined') {
      throw new Error('ORT not defined in offscreen document.');
    }
    ort.env.wasm.wasmPaths = '../background/lib/';
    ort.env.wasm.numThreads = 1;

    const featureRes = await fetch('../background/model/feature_order.json');
    const featureData = await featureRes.json();
    featureOrder = featureData.features;

    const modelRes = await fetch('../background/model/phishing_model.onnx');
    const modelBuffer = await modelRes.arrayBuffer();

    session = await ort.InferenceSession.create(modelBuffer, { executionProviders: ['wasm'] });
    isModelAvailable = true;
    console.log('[Verity ML Offscreen] Model loaded successfully.');
    return true;
  } catch (err) {
    console.error('[Verity ML Offscreen] Initialization failed:', err);
    return false;
  }
}

// Parses URL safely
function parseUrlSafe(urlString) {
  try {
    return new URL(urlString);
  } catch (e) {
    return null;
  }
}

// Extract features
function extractFeatures(urlString, domSignals) {
  const url = parseUrlSafe(urlString);
  if (!url) return null;

  const featureMap = {};

  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  featureMap['having_IP_Address'] = ipv4Regex.test(url.hostname) ? -1 : 1;

  const len = urlString.length;
  if (len >= 75) featureMap['URL_Length'] = -1;
  else if (len >= 54) featureMap['URL_Length'] = 0;
  else featureMap['URL_Length'] = 1;

  const shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs'];
  featureMap['Shortining_Service'] = shorteners.includes(url.hostname) ? -1 : 1;

  featureMap['having_At_Symbol'] = urlString.includes('@') ? -1 : 1;

  const lastDoubleSlash = urlString.lastIndexOf('//');
  featureMap['double_slash_redirecting'] = (lastDoubleSlash > 7) ? -1 : 1;

  featureMap['Prefix_Suffix'] = url.hostname.includes('-') ? -1 : 1;

  let cleanHostname = url.hostname.replace(/^www\./, '');
  const dotCount = (cleanHostname.match(/\./g) || []).length;
  if (dotCount >= 3) featureMap['having_Sub_Domain'] = -1;
  else if (dotCount === 2) featureMap['having_Sub_Domain'] = 0;
  else featureMap['having_Sub_Domain'] = 1;

  featureMap['HTTPS_token'] = url.hostname.includes('https') ? -1 : 1;

  // domSignals logic can be used here if needed (e.g. login form presence)
  // Stage 2 model doesn't use domSignals directly, but it's passed down just in case

  const vector = [];
  for (const featureName of featureOrder) {
    const val = featureMap[featureName];
    if (val === undefined || isNaN(val) || val === null) return null;
    vector.push(val);
  }
  return vector;
}

// Run Inference
async function runInference(urlString, domSignals) {
  if (!isModelAvailable) {
    const ready = await initModel();
    if (!ready) return null;
  }

  try {
    const vector = extractFeatures(urlString, domSignals);
    if (!vector) return null;

    const inputTensor = new ort.Tensor('float32', Float32Array.from(vector), [1, vector.length]);
    const feeds = { float_input: inputTensor };

    const results = await session.run(feeds);
    
    let probTensor = results['output_probability'] || results['probabilities'];
    if (!probTensor && results['output_label']) {
      const keys = Object.keys(results);
      if (keys.length > 1) probTensor = results[keys[1]];
    }

    if (!probTensor) return null;

    const data = probTensor.data; 
    let phishingProb = (data.length >= 2) ? data[1] : data[0];

    let mlScore = Math.round(phishingProb * 100);
    return Math.min(Math.max(mlScore, 0), 100);
  } catch (err) {
    console.error('[Verity ML Offscreen] Inference error:', err);
    return null;
  }
}

// Listen for messages from service worker
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.target === 'offscreen') {
    if (msg.action === 'init_model') {
      initModel().then(success => sendResponse({ success }));
      return true;
    }
    if (msg.action === 'run_inference') {
      runInference(msg.url, msg.domSignals).then(score => {
        sendResponse({ score });
      });
      return true; // async
    }
  }
});
