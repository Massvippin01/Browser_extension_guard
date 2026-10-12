import json
import os
import re
import math
from urllib.parse import urlparse
import numpy as np
import onnxruntime as ort

OLD_FEATURE_ORDER = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'HTTPS_token'
]

def extract_old_features(url_str):
    if not url_str.startswith('http'):
        url_str = 'http://' + url_str
    try:
        parsed = urlparse(url_str)
        hostname = (parsed.hostname or '').lower()
    except Exception:
        hostname = ''

    feature_map = {}
    ipv4_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    feature_map['having_IP_Address'] = -1 if ipv4_regex.match(hostname) else 1

    l = len(url_str)
    if l >= 75: feature_map['URL_Length'] = -1
    elif l >= 54: feature_map['URL_Length'] = 0
    else: feature_map['URL_Length'] = 1

    shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly', 'buff.ly']
    feature_map['Shortining_Service'] = -1 if any(s in hostname for s in shorteners) else 1
    feature_map['having_At_Symbol'] = -1 if '@' in url_str else 1

    last_double_slash = url_str.rfind('//')
    feature_map['double_slash_redirecting'] = -1 if last_double_slash > 7 else 1
    feature_map['Prefix_Suffix'] = -1 if '-' in hostname else 1

    clean_hostname = re.sub(r'^www\.', '', hostname)
    dot_count = clean_hostname.count('.')
    if dot_count >= 3: feature_map['having_Sub_Domain'] = -1
    elif dot_count == 2: feature_map['having_Sub_Domain'] = 0
    else: feature_map['having_Sub_Domain'] = 1

    feature_map['HTTPS_token'] = -1 if 'https' in hostname else 1

    return [float(feature_map[k]) for k in OLD_FEATURE_ORDER]

SUSPICIOUS_TLDS = {'.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.site', '.online', '.rest', '.click', '.fun', '.info', '.icu', '.sbs', '.cfd', '.monster'}
KEYWORDS = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'signin', 'wallet', 'claim', 'otp', 'support', 'auth', 'bill']

def calculate_entropy(text):
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log2(p) for p in prob)

def extract_v2_features(url_str):
    if not url_str.startswith('http'):
        url_str = 'http://' + url_str
    try:
        parsed = urlparse(url_str)
        hostname = (parsed.hostname or '').lower()
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = ''
        path = ''
        query = ''

    url_len = float(len(url_str))
    host_len = float(len(hostname))
    path_len = float(len(path))

    digits = sum(c.isdigit() for c in url_str)
    digit_ratio = digits / max(url_len, 1.0)
    host_digits = sum(c.isdigit() for c in hostname)
    host_digit_ratio = host_digits / max(host_len, 1.0)

    host_entropy = calculate_entropy(hostname)

    dot_count = float(url_str.count('.'))
    hyphen_count = float(url_str.count('-'))
    at_count = float(url_str.count('@'))
    slash_count = float(url_str.count('/'))
    query_count = float(url_str.count('?'))
    equal_count = float(url_str.count('='))

    host_tokens = float(len(re.split(r'[\.-]', hostname)))

    ipv4_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    is_ip = 1.0 if ipv4_regex.match(hostname) else 0.0
    is_https = 1.0 if url_str.startswith('https://') else 0.0

    last_double_slash = url_str.rfind('//')
    double_slash = 1.0 if last_double_slash > 7 else 0.0

    is_suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
    url_lower = url_str.lower()
    keyword_matches = float(sum(1 for kw in KEYWORDS if kw in url_lower))

    return [
        url_len, host_len, path_len, digit_ratio, host_digit_ratio,
        host_entropy, dot_count, hyphen_count, at_count, slash_count,
        query_count, equal_count, host_tokens, is_ip, is_https,
        double_slash, is_suspicious_tld, keyword_matches
    ]

def main():
    old_model_path = os.path.join(os.path.dirname(__file__), '..', 'background', 'model', 'phishing_model.onnx')
    v2_model_path = os.path.join(os.path.dirname(__file__), '..', 'background', 'model', 'phishing_model_v2.onnx')
    test_urls_path = os.path.join(os.path.dirname(__file__), '..', 'benchmark', 'test_urls.json')
    out_path = os.path.join(os.path.dirname(__file__), '..', 'benchmark', 'ml_scores.json')

    with open(test_urls_path, 'r', encoding='utf-8') as f:
        urls_data = json.load(f)

    old_session = ort.InferenceSession(old_model_path)
    old_input_name = old_session.get_inputs()[0].name

    v2_session = ort.InferenceSession(v2_model_path)
    v2_input_name = v2_session.get_inputs()[0].name

    results = {}
    for item in urls_data:
        u = item['url']
        # 1. Old model inference
        old_feats = extract_old_features(u)
        old_arr = np.array([old_feats], dtype=np.float32)
        old_outs = old_session.run(None, {old_input_name: old_arr})
        old_probs = old_outs[1]
        old_prob = float(old_probs[0][1]) if hasattr(old_probs, '__getitem__') else 0.0
        old_score = int(round(old_prob * 100))

        # 2. V2 model inference
        v2_feats = extract_v2_features(u)
        v2_arr = np.array([v2_feats], dtype=np.float32)
        v2_outs = v2_session.run(None, {v2_input_name: v2_arr})
        v2_probs = v2_outs[1]
        # v2 is GradientBoosting with zipmap=True or probability tensor
        if isinstance(v2_probs, list) and isinstance(v2_probs[0], dict):
            v2_prob = float(v2_probs[0].get(1, 0.0))
        elif hasattr(v2_probs, 'shape'):
            v2_prob = float(v2_probs[0][1])
        else:
            v2_prob = 0.0
        v2_score = int(round(v2_prob * 100))

        results[u] = {
            'old_score': old_score,
            'old_prob': old_prob,
            'v2_score': v2_score,
            'v2_prob': v2_prob
        }

    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=2)

    print(f'[ONNX Inference] Computed ML scores for {len(results)} URLs and saved to {out_path}')

if __name__ == '__main__':
    main()
