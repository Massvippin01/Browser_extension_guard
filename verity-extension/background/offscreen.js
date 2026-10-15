// offscreen.js - Runs inside offscreen.html to handle ML execution
import { extractRichFeatures } from './rich-feature-extractor.js';

let session = null;
let isModelAvailable = false;

async function initModel() {
  if (isModelAvailable) return true;
  try {
    if (typeof ort === 'undefined') {
      throw new Error('ORT not defined in offscreen document.');
    }
    ort.env.wasm.wasmPaths = '/background/lib/';
    ort.env.wasm.numThreads = 1;
    ort.env.wasm.simd = false;

    const modelRes = await fetch('/background/model/phishing_model_v2.onnx');
    const modelBuffer = await modelRes.arrayBuffer();

    session = await ort.InferenceSession.create(modelBuffer, { executionProviders: ['wasm'] });
    isModelAvailable = true;
    console.log('[Verity ML Offscreen] Model v2 loaded successfully.');
    return true;
  } catch (err) {
    console.error('[Verity ML Offscreen] Initialization failed:', err);
    return false;
  }
}

// Run Inference
async function runInference(urlString, domSignals) {
  if (!isModelAvailable) {
    const ready = await initModel();
    if (!ready) return null;
  }

  try {
    const vector = extractRichFeatures(urlString);
    if (!vector) return null;

    const inputTensor = new ort.Tensor('float32', Float32Array.from(vector), [1, vector.length]);
    const feeds = { float_input: inputTensor };

    const results = await session.run(feeds);
    
    let probTensor = results['probabilities'] || results['output_probability'];
    if (!probTensor) {
      for (const [key, val] of Object.entries(results)) {
        if (key !== 'label' && key !== 'output_label' && val && val.data) {
          probTensor = val;
          break;
        }
      }
    }
    if (!probTensor) {
      const keys = Object.keys(results);
      if (keys.length > 1) probTensor = results[keys[1]];
      else if (keys.length === 1) probTensor = results[keys[0]];
    }

    if (!probTensor || !probTensor.data) return null;

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
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
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
}

export { extractRichFeatures, runInference };
