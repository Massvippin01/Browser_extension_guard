import json
import numpy as np
from sklearn.ensemble import GradientBoostingClassifier
from urllib.parse import urlparse
import math

def calculate_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    ent = 0.0
    for c, count in freq.items():
        p = count / len(text)
        ent -= p * math.log2(p)
    return ent

SUSPICIOUS_TLDS = {
    '.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
    '.site', '.online', '.rest', '.click', '.fun', '.info', '.icu', '.sbs', '.cfd', '.monster'
}

KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'banking', 'update',
    'signin', 'wallet', 'claim', 'otp', 'support', 'auth', 'bill'
]

def extract_features(url_str, mode='full'):
    url = url_str
    if not (url.startswith('http://') or url.startswith('https://')):
        url = 'http://' + url
    
    if mode == 'path_stripped':
        try:
            parsed = urlparse(url)
            url = f"{parsed.scheme}://{parsed.netloc}/"
        except:
            pass

    try:
        parsed = urlparse(url)
        hostname = (parsed.hostname or '').lower()
        pathname = parsed.path or ''
        search = parsed.query or ''
    except:
        hostname = ''
        pathname = ''
        search = ''

    url_len = len(url)
    host_len = len(hostname)
    path_len = len(pathname)

    digits = sum(1 for c in url if c.isdigit())
    digit_ratio = digits / max(url_len, 1)

    host_digits = sum(1 for c in hostname if c.isdigit())
    host_digit_ratio = host_digits / max(host_len, 1)

    host_entropy = calculate_entropy(hostname)

    dot_count = url.count('.')
    hyphen_count = url.count('-')
    at_count = url.count('@')
    slash_count = url.count('/')
    query_count = url.count('?')
    equal_count = url.count('=')

    host_tokens = len(hostname.replace('-', '.').split('.'))

    is_ip = 1.0 if hostname.replace('.', '').isdigit() and len(hostname.split('.')) == 4 else 0.0
    is_https = 1.0 if url.startswith('https://') else 0.0
    double_slash = 1.0 if url.rfind('//') > 7 else 0.0

    is_suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0

    url_lower = url.lower()
    keyword_matches = sum(1.0 for kw in KEYWORDS if kw in url_lower)

    if mode == 'host_only':
        # Drop: url_len, path_len, slash_count, query_count, equal_count, double_slash, is_https, is_ip
        return [
            host_len, digit_ratio, host_digit_ratio, host_entropy,
            dot_count, hyphen_count, at_count, host_tokens,
            is_suspicious_tld, keyword_matches
        ]
    else:
        return [
            url_len, host_len, path_len, digit_ratio, host_digit_ratio,
            host_entropy, dot_count, hyphen_count, at_count, slash_count,
            query_count, equal_count, host_tokens, is_ip, is_https,
            double_slash, is_suspicious_tld, keyword_matches
        ]

def run_evaluation():
    with open('benchmark/test_urls.json', 'r', encoding='utf-8') as f:
        data = json.load(f)

    dev_data = [d for d in data if d['split'] == 'dev']
    test_data = [d for d in data if d['split'] == 'test']

    modes = ['full', 'host_only', 'path_stripped']
    results = {}

    for mode in modes:
        print(f"\n=======================================================")
        print(f"Evaluating Mode: {mode.upper()}")
        print(f"=======================================================")

        # Featurize dev
        train_feat_mode = 'host_only' if mode == 'host_only' else 'full'
        X_train = np.array([extract_features(d['url'], mode=train_feat_mode) for d in dev_data])
        y_train = np.array([1 if d['label'] in ('phishing', 'malware') else 0 for d in dev_data])

        clf = GradientBoostingClassifier(n_estimators=100, learning_rate=0.1, max_depth=5, random_state=42)
        clf.fit(X_train, y_train)

        # Featurize test
        test_feat_mode = 'host_only' if mode == 'host_only' else ('path_stripped' if mode == 'path_stripped' else 'full')
        X_test = np.array([extract_features(d['url'], mode=test_feat_mode) for d in test_data])
        preds = clf.predict_proba(X_test)[:, 1]
        scores = np.round(preds * 100).astype(int)

        # Evaluate against Phishing vs Safe (and Malware vs Safe)
        safe_indices = [i for i, d in enumerate(test_data) if d['label'] == 'safe']
        phish_indices = [i for i, d in enumerate(test_data) if d['label'] == 'phishing']

        eval_indices = safe_indices + phish_indices
        y_true = np.array([1 if test_data[i]['label'] == 'phishing' else 0 for i in eval_indices])
        y_scores = scores[eval_indices]
        y_preds = (y_scores >= 35).astype(int)

        # 1000 Bootstrap resamples
        rng = np.random.default_rng(42)
        n = len(y_true)
        f1_boots, prec_boots, rec_boots, fpr_boots = [], [], [], []

        for _ in range(1000):
            idx = rng.integers(0, n, size=n)
            yt = y_true[idx]
            yp = y_preds[idx]

            tp = np.sum((yt == 1) & (yp == 1))
            fp = np.sum((yt == 0) & (yp == 1))
            fn = np.sum((yt == 1) & (yp == 0))
            tn = np.sum((yt == 0) & (yp == 0))

            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            f1_boots.append(f1)
            prec_boots.append(prec)
            rec_boots.append(rec)
            fpr_boots.append(fpr)

        f1_mean = np.mean(f1_boots)
        f1_ci = np.percentile(f1_boots, [2.5, 97.5])
        fpr_mean = np.mean(fpr_boots)
        fpr_ci = np.percentile(fpr_boots, [2.5, 97.5])
        prec_mean = np.mean(prec_boots)
        rec_mean = np.mean(rec_boots)

        print(f"Mode {mode} (Phishing vs Safe @ 35):")
        print(f"  F1: {f1_mean * 100:.2f}% (95% CI: [{f1_ci[0]*100:.2f}%, {f1_ci[1]*100:.2f}%])")
        print(f"  Precision: {prec_mean * 100:.2f}%")
        print(f"  Recall: {rec_mean * 100:.2f}%")
        print(f"  Benign FPR: {fpr_mean * 100:.2f}% (95% CI: [{fpr_ci[0]*100:.2f}%, {fpr_ci[1]*100:.2f}%])")

        results[mode] = {
            'f1': float(f1_mean),
            'f1_ci': [float(f1_ci[0]), float(f1_ci[1])],
            'precision': float(prec_mean),
            'recall': float(rec_mean),
            'benign_fpr': float(fpr_mean),
            'benign_fpr_ci': [float(fpr_ci[0]), float(fpr_ci[1])]
        }

    with open('benchmark/confound_modes_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    print("\nSaved confound modes results to benchmark/confound_modes_results.json")

if __name__ == '__main__':
    run_evaluation()
