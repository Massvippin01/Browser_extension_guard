import json
import os
import math
import re
from urllib.parse import urlparse
import numpy as np
from sklearn.model_selection import GroupKFold
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import skl2onnx
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

SUSPICIOUS_TLDS = {'.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.site', '.online', '.rest', '.click', '.fun', '.info', '.icu', '.sbs', '.cfd', '.monster'}
KEYWORDS = ['login', 'verify', 'secure', 'account', 'banking', 'update', 'signin', 'wallet', 'claim', 'otp', 'support', 'auth', 'bill']

def calculate_entropy(text):
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum(p * math.log2(p) for p in prob)

def extract_features_dict(url_str):
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

    # 1. Lengths
    url_len = float(len(url_str))
    host_len = float(len(hostname))
    path_len = float(len(path))

    # 2. Digit ratios
    digits = sum(c.isdigit() for c in url_str)
    digit_ratio = digits / max(url_len, 1.0)
    host_digits = sum(c.isdigit() for c in hostname)
    host_digit_ratio = host_digits / max(host_len, 1.0)

    # 3. Entropy
    host_entropy = calculate_entropy(hostname)

    # 4. Special character counts
    dot_count = float(url_str.count('.'))
    hyphen_count = float(url_str.count('-'))
    at_count = float(url_str.count('@'))
    slash_count = float(url_str.count('/'))
    query_count = float(url_str.count('?'))
    equal_count = float(url_str.count('='))

    # 5. Token counts
    host_tokens = float(len(re.split(r'[\.-]', hostname)))

    # 6. Structural flags
    ipv4_regex = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    is_ip = 1.0 if ipv4_regex.match(hostname) else 0.0
    is_https = 1.0 if url_str.startswith('https://') else 0.0

    last_double_slash = url_str.rfind('//')
    double_slash = 1.0 if last_double_slash > 7 else 0.0

    # 7. Suspicious TLD & Keywords
    is_suspicious_tld = 1.0 if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS) else 0.0
    url_lower = url_str.lower()
    keyword_matches = float(sum(1 for kw in KEYWORDS if kw in url_lower))

    return {
        'url_len': url_len,
        'host_len': host_len,
        'path_len': path_len,
        'digit_ratio': digit_ratio,
        'host_digit_ratio': host_digit_ratio,
        'host_entropy': host_entropy,
        'dot_count': dot_count,
        'hyphen_count': hyphen_count,
        'at_count': at_count,
        'slash_count': slash_count,
        'query_count': query_count,
        'equal_count': equal_count,
        'host_tokens': host_tokens,
        'is_ip': is_ip,
        'is_https': is_https,
        'double_slash': double_slash,
        'is_suspicious_tld': is_suspicious_tld,
        'keyword_matches': keyword_matches
    }

ALL_FEATURE_NAMES = [
    'url_len', 'host_len', 'path_len', 'digit_ratio', 'host_digit_ratio',
    'host_entropy', 'dot_count', 'hyphen_count', 'at_count', 'slash_count',
    'query_count', 'equal_count', 'host_tokens', 'is_ip', 'is_https',
    'double_slash', 'is_suspicious_tld', 'keyword_matches'
]

NO_HTTPS_NO_IP_NAMES = [
    'url_len', 'host_len', 'path_len', 'digit_ratio', 'host_digit_ratio',
    'host_entropy', 'dot_count', 'hyphen_count', 'at_count', 'slash_count',
    'query_count', 'equal_count', 'host_tokens',
    'double_slash', 'is_suspicious_tld', 'keyword_matches'
]

HOST_ONLY_FEATURE_NAMES = [
    'host_len', 'digit_ratio', 'host_digit_ratio', 'host_entropy',
    'dot_count', 'hyphen_count', 'at_count', 'host_tokens',
    'is_suspicious_tld', 'keyword_matches'
]

def run_group_cv(X, y, groups, model_builder, feature_set_name, n_splits=5):
    gkf = GroupKFold(n_splits=n_splits)
    metrics_35 = {'precision': [], 'recall': [], 'f1': [], 'fpr': []}
    metrics_70 = {'precision': [], 'recall': [], 'f1': [], 'fpr': []}

    for fold, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups=groups)):
        X_tr, y_tr = X[train_idx], y[train_idx]
        X_val, y_val = X[val_idx], y[val_idx]

        model = model_builder()
        model.fit(X_tr, y_tr)
        probs = model.predict_proba(X_val)[:, 1]

        for th, m_dict in [(0.35, metrics_35), (0.70, metrics_70)]:
            preds = (probs >= th).astype(int)
            p = precision_score(y_val, preds, zero_division=0)
            r = recall_score(y_val, preds, zero_division=0)
            f = f1_score(y_val, preds, zero_division=0)
            cm = confusion_matrix(y_val, preds, labels=[0, 1])
            tn, fp, fn, tp = cm.ravel()
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

            m_dict['precision'].append(p)
            m_dict['recall'].append(r)
            m_dict['f1'].append(f)
            m_dict['fpr'].append(fpr)

    print(f"\n--- 5-Fold Grouped-by-Domain CV Results: {feature_set_name} ---")
    for th, m_dict in [('0.35', metrics_35), ('0.70', metrics_70)]:
        p_mean, p_std = np.mean(m_dict['precision']), np.std(m_dict['precision'])
        r_mean, r_std = np.mean(m_dict['recall']), np.std(m_dict['recall'])
        f_mean, f_std = np.mean(m_dict['f1']), np.std(m_dict['f1'])
        fpr_mean, fpr_std = np.mean(m_dict['fpr']), np.std(m_dict['fpr'])
        print(f"  Threshold {th}:")
        print(f"    Precision: {p_mean*100:.2f}% +/- {p_std*100:.2f}%")
        print(f"    Recall:    {r_mean*100:.2f}% +/- {r_std*100:.2f}%")
        print(f"    F1 Score:  {f_mean*100:.2f}% +/- {f_std*100:.2f}%")
        print(f"    Benign FPR:{fpr_mean*100:.2f}% +/- {fpr_std*100:.2f}%")

    return {
        'th35': {k: (float(np.mean(v)), float(np.std(v))) for k, v in metrics_35.items()},
        'th70': {k: (float(np.mean(v)), float(np.std(v))) for k, v in metrics_70.items()}
    }

def main():
    print("======================================================================")
    print("[Retrain V2.1] HONEST RETRAIN & GROUPED CV (REAL BENCHMARK DATA)")
    print("======================================================================")

    data_path = os.path.join(os.path.dirname(__file__), '..', 'benchmark', 'test_urls.json')
    with open(data_path, 'r', encoding='utf-8') as f:
        all_data = json.load(f)

    # Dev split for training & CV
    dev_data = [d for d in all_data if d['split'] == 'dev']
    print(f"Dev data size: {len(dev_data)} (Safe: {sum(1 for d in dev_data if d['label']=='safe')}, Phish: {sum(1 for d in dev_data if d['label']=='phishing')}, Malware: {sum(1 for d in dev_data if d['label']=='malware')})")

    # Only train on binary Safe (0) vs Phishing/Malware (1)
    y_dev = np.array([1 if d['label'] != 'safe' else 0 for d in dev_data], dtype=np.int32)
    groups_dev = np.array([d['registeredDomain'] for d in dev_data])

    feat_dicts_dev = [extract_features_dict(d['url']) for d in dev_data]

    X_all_dev = np.array([[fd[f] for f in ALL_FEATURE_NAMES] for fd in feat_dicts_dev], dtype=np.float32)
    X_no_dev = np.array([[fd[f] for f in NO_HTTPS_NO_IP_NAMES] for fd in feat_dicts_dev], dtype=np.float32)
    X_host_dev = np.array([[fd[f] for f in HOST_ONLY_FEATURE_NAMES] for fd in feat_dicts_dev], dtype=np.float32)

    # 1. CV WITH is_https and is_ip features
    cv_with = run_group_cv(
        X_all_dev, y_dev, groups_dev,
        lambda: GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=42),
        "WITH is_https and is_ip (18 features)"
    )

    # 2. CV WITHOUT is_https and is_ip features
    cv_without = run_group_cv(
        X_no_dev, y_dev, groups_dev,
        lambda: GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=42),
        "WITHOUT is_https and is_ip (16 features)"
    )

    # 3. CV HOST-ONLY features
    cv_host = run_group_cv(
        X_host_dev, y_dev, groups_dev,
        lambda: GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=42),
        "HOST-ONLY features (10 features)"
    )

    # Train final candidate model on all Dev data
    chosen_features = ALL_FEATURE_NAMES
    X_train = X_all_dev
    gb_model = GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=42)
    gb_model.fit(X_train, y_dev)

    # Export ONNX model
    onnx_path = os.path.join(os.path.dirname(__file__), '..', 'background', 'model', 'phishing_model_v2.onnx')
    initial_type = [('float_input', FloatTensorType([None, len(chosen_features)]))]
    onnx_model = convert_sklearn(gb_model, initial_types=initial_type, target_opset=12)
    with open(onnx_path, 'wb') as f:
        f.write(onnx_model.SerializeToString())
    print(f"\n[ONNX] Saved candidate model v2 to {onnx_path} ({os.path.getsize(onnx_path)} bytes)")

    # Save schema
    schema_path = os.path.join(os.path.dirname(__file__), '..', 'background', 'model', 'rich_features.json')
    with open(schema_path, 'w', encoding='utf-8') as f:
        json.dump({
            "features": chosen_features,
            "cv_metrics_with_flags": cv_with,
            "cv_metrics_without_flags": cv_without
        }, f, indent=2)
    print(f"[Schema] Saved rich features schema to {schema_path}")

    # Generate parity fixtures for JavaScript engine parity test
    parity_urls = [
        "https://google.com/",
        "http://192.168.1.1/login.php",
        "https://netbanking.hdfcbank.com/netbanking/",
        "http://secure-login-paypal.com/auth",
        "https://bit.ly/3uG2yZx",
        "https://sub.domain.test-bank.xyz/portal/verify",
        "http://000webhostapp.com/yahoo/attverzon/login.php"
    ]
    fixtures = []
    for u in parity_urls:
        fd = extract_features_dict(u)
        vec = [fd[f] for f in chosen_features]
        fixtures.append({"url": u, "features": vec})

    fixture_path = os.path.join(os.path.dirname(__file__), '..', 'tests', 'parity_fixtures.json')
    with open(fixture_path, 'w', encoding='utf-8') as f:
        json.dump(fixtures, f, indent=2)
    print(f"[Fixtures] Saved {len(fixtures)} parity test fixtures to {fixture_path}")

if __name__ == '__main__':
    main()
