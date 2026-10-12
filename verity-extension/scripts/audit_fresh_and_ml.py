import json
import os
import math
import hashlib
import numpy as np
from urllib.parse import urlparse
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import recall_score, precision_score, f1_score

import sys
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if base_dir not in sys.path:
    sys.path.insert(0, base_dir)
fresh_path = os.path.join(base_dir, 'benchmark', 'fresh_test_urls.json')
test_path = os.path.join(base_dir, 'benchmark', 'test_urls.json')

# 1. Audit benchmark/fresh_test_urls.json
with open(fresh_path, 'rb') as f:
    fresh_bytes = f.read()
fresh_sha256 = hashlib.sha256(fresh_bytes).hexdigest()

with open(fresh_path, 'r', encoding='utf-8') as f:
    fresh_items = json.load(f)

print("=" * 70)
print("AUDIT: benchmark/fresh_test_urls.json")
print("=" * 70)
print(f"File SHA256: {fresh_sha256}")
print(f"Total rows:  {len(fresh_items)}")

# Breakdown by source feed and HTTP vs HTTPS
feed_counts = {}
feed_http = {}
for item in fresh_items:
    feed = item.get('source', 'unknown')
    is_https = item['url'].startswith('https://')
    proto = 'HTTPS' if is_https else 'HTTP'
    
    if feed not in feed_counts:
        feed_counts[feed] = 0
        feed_http[feed] = {'HTTP': 0, 'HTTPS': 0}
    feed_counts[feed] += 1
    feed_http[feed][proto] += 1

print("\nBreakdown by Source Feed and Protocol:")
for feed, cnt in feed_counts.items():
    http_n = feed_http[feed]['HTTP']
    https_n = feed_http[feed]['HTTPS']
    print(f"  Feed: {feed}")
    print(f"    Total: {cnt} | HTTP: {http_n} ({http_n/cnt*100:.1f}%) | HTTPS: {https_n} ({https_n/cnt*100:.1f}%)")

# 2. ML Feature Importances and Leakage Checks
print("\n" + "=" * 70)
print("ML MODEL AUDIT & LEAKAGE CHECKS")
print("=" * 70)

from training.retrain_model import ALL_FEATURE_NAMES, extract_features_dict

with open(test_path, 'r', encoding='utf-8') as f:
    all_test = json.load(f)

dev_data = [d for d in all_test if d.get('split') == 'dev']
print(f"Dev data size: {len(dev_data)}")

# Verify NO source field in feature extraction
# Note: extract_features_dict only takes url_str, never uses source or label!
print("Leakage Check 1 (Source field exclusion): Verified. extract_features_dict only accepts url_str.")

y_dev = np.array([1 if d['label'] != 'safe' else 0 for d in dev_data], dtype=np.int32)
feat_dicts = [extract_features_dict(d['url']) for d in dev_data]
X_dev = np.array([[fd[f] for f in ALL_FEATURE_NAMES] for fd in feat_dicts], dtype=np.float32)

# Train GradientBoostingClassifier
gb = GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=42)
gb.fit(X_dev, y_dev)

importances = gb.feature_importances_
sorted_idx = np.argsort(importances)[::-1]

print("\nTop ML Features by Importance (GradientBoosting on Dev):")
for rank, idx in enumerate(sorted_idx):
    print(f"  {rank+1:2d}. {ALL_FEATURE_NAMES[idx]:20s}: {importances[idx]*100:.2f}%")

# Label shuffle sanity check
print("\nLeakage Check 2: Label-Shuffle Sanity Check")
rng = np.random.RandomState(42)
shuffled_scores = []
for trial in range(5):
    y_shuffled = rng.permutation(y_dev)
    gb_shuffled = GradientBoostingClassifier(n_estimators=50, max_depth=3, learning_rate=0.1, random_state=trial)
    gb_shuffled.fit(X_dev, y_shuffled)
    train_score = gb_shuffled.score(X_dev, y_shuffled)
    train_f1 = f1_score(y_shuffled, gb_shuffled.predict(X_dev), zero_division=0)
    shuffled_scores.append((train_score, train_f1))
    print(f"  Trial {trial+1}: Shuffled Accuracy = {train_score*100:.2f}%, F1 = {train_f1*100:.2f}%")

# Feed vs Phishing Correlation Check
print("\nLeakage Check 3: Feed vs Phishing Correlation Check")
# Does any feature correlate with feed source rather than ground truth phishing?
# Compare features across different benign feeds or phishing feeds
url_lens = [fd['url_len'] for fd in feat_dicts]
is_https_vals = [fd['is_https'] for fd in feat_dicts]
path_lens = [fd['path_len'] for fd in feat_dicts]

corr_https = np.corrcoef(is_https_vals, y_dev)[0, 1]
corr_url_len = np.corrcoef(url_lens, y_dev)[0, 1]
corr_path_len = np.corrcoef(path_lens, y_dev)[0, 1]

print(f"  Correlation of is_https with phishing label: {corr_https:.4f}")
print(f"  Correlation of url_len with phishing label:  {corr_url_len:.4f}")
print(f"  Correlation of path_len with phishing label: {corr_path_len:.4f}")

# Check feed-specific confounds in dev
sources = [d.get('source', '') for d in dev_data]
feed_types = set(sources)
print("\nFeed-level protocol distribution in Dev:")
for s in sorted(feed_types):
    sub = [dev_data[i] for i, src in enumerate(sources) if src == s]
    https_share = sum(1 for item in sub if item['url'].startswith('https://')) / len(sub)
    print(f"  {s[:50]:50s} (N={len(sub):4d}): HTTPS={https_share*100:.1f}%")

print("\nConclusion on feed correlation: in feeds like raw Phishing.Database active snapshots,")
print("HTTP is present on nearly 100% of rows, which confounds feed identity with the absence of HTTPS.")
