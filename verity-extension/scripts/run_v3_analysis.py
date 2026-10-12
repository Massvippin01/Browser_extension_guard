import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold

with open('benchmark/evaluated_dataset.json', 'r', encoding='utf-8') as f:
    items = json.load(f)

dev_items = [i for i in items if i['split'] == 'dev']
test_items = [i for i in items if i['split'] == 'test']

print(f"Loaded: Dev={len(dev_items)}, Test={len(test_items)}")

# ---------------------------------------------------------------------------
# 1. FUSION COMPARISON ON DEV (5-Fold Grouped CV by registeredDomain)
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("[FUSION] FUSION STRATEGY COMPARISON ON DEV (5-FOLD GROUPED-BY-DOMAIN CV)")
print("="*70)

y_dev = np.array([1 if d['label'] != 'safe' else 0 for d in dev_items])
groups_dev = np.array([d['registeredDomain'] for d in dev_items])
rules_dev = np.array([d['rules_score'] for d in dev_items], dtype=float)
ml_prob_dev = np.array([d['ml_v2_prob'] for d in dev_items], dtype=float)
ml_score_dev = np.array([d['ml_v2_score'] for d in dev_items], dtype=float)

gkf = GroupKFold(n_splits=5)

fusion_metrics = {
    'additive': {'f1_35': [], 'fpr_35': [], 'f1_70': [], 'fpr_70': []},
    'max': {'f1_35': [], 'fpr_35': [], 'f1_70': [], 'fpr_70': []},
    'stacking': {'f1_35': [], 'fpr_35': [], 'f1_70': [], 'fpr_70': []}
}

for fold, (train_idx, val_idx) in enumerate(gkf.split(dev_items, y_dev, groups_dev)):
    y_val = y_dev[val_idx]
    
    # 1. Additive
    add_scores = np.array([dev_items[i]['additive_v2_score'] for i in val_idx])
    
    # 2. Max
    max_scores = np.array([dev_items[i]['max_fusion_score'] for i in val_idx])
    
    # 3. Logistic Stacking
    X_train_stack = np.column_stack([rules_dev[train_idx], ml_prob_dev[train_idx]])
    X_val_stack = np.column_stack([rules_dev[val_idx], ml_prob_dev[val_idx]])
    
    lr = LogisticRegression(random_state=42)
    lr.fit(X_train_stack, y_dev[train_idx])
    stack_scores = np.round(lr.predict_proba(X_val_stack)[:, 1] * 100).astype(int)

    def calc_metrics(scores):
        res = {}
        for th in [35, 70]:
            preds = (scores >= th).astype(int)
            tp = np.sum((y_val == 1) & (preds == 1))
            fp = np.sum((y_val == 0) & (preds == 1))
            fn = np.sum((y_val == 1) & (preds == 0))
            tn = np.sum((y_val == 0) & (preds == 0))
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
            f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
            res[f'f1_{th}'] = f1
            res[f'fpr_{th}'] = fpr
        return res

    for strat, sc in [('additive', add_scores), ('max', max_scores), ('stacking', stack_scores)]:
        m = calc_metrics(sc)
        for k in m:
            fusion_metrics[strat][k].append(m[k])

print("\nDev Grouped CV Results (Mean +/- Std):")
for strat in ['additive', 'max', 'stacking']:
    f1_35 = np.mean(fusion_metrics[strat]['f1_35']) * 100
    fpr_35 = np.mean(fusion_metrics[strat]['fpr_35']) * 100
    f1_70 = np.mean(fusion_metrics[strat]['f1_70']) * 100
    fpr_70 = np.mean(fusion_metrics[strat]['fpr_70']) * 100
    print(f"Strategy: {strat.upper():<10} | F1@35: {f1_35:.2f}% (FPR: {fpr_35:.2f}%) | F1@70: {f1_70:.2f}% (FPR: {fpr_70:.2f}%)")

# Fit final stacking model on all dev data to score test
X_all_dev = np.column_stack([rules_dev, ml_prob_dev])
lr_final = LogisticRegression(random_state=42)
lr_final.fit(X_all_dev, y_dev)

# ---------------------------------------------------------------------------
# 2. EVALUATION ON TEST SET (SCORED ONCE)
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("[TEST SET] HELD-OUT TEST EVALUATION (ALL THREE FUSION STRATEGIES + VARIANTS)")
print("="*70)

rules_test = np.array([d['rules_score'] for d in test_items], dtype=float)
ml_prob_test = np.array([d['ml_v2_prob'] for d in test_items], dtype=float)
X_test_stack = np.column_stack([rules_test, ml_prob_test])
stack_test_scores = np.round(lr_final.predict_proba(X_test_stack)[:, 1] * 100).astype(int)

for i, d in enumerate(test_items):
    d['stacking_score'] = int(stack_test_scores[i])

# Bootstrap CI function
def bootstrap_metrics(eval_subset, score_key, th=35, n_resamples=1000):
    y_true = np.array([1 if d['label'] in ('phishing', 'malware') else 0 for d in eval_subset])
    scores = np.array([d[score_key] for d in eval_subset])
    y_pred = (scores >= th).astype(int)

    rng = np.random.default_rng(42)
    n = len(y_true)
    f1s, precs, recs, fprs = [], [], [], []

    for _ in range(n_resamples):
        idx = rng.integers(0, n, size=n)
        yt = y_true[idx]
        yp = y_pred[idx]
        tp = np.sum((yt == 1) & (yp == 1))
        fp = np.sum((yt == 0) & (yp == 1))
        fn = np.sum((yt == 1) & (yp == 0))
        tn = np.sum((yt == 0) & (yp == 0))
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        f1s.append(f1)
        precs.append(prec)
        recs.append(rec)
        fprs.append(fpr)

    return {
        'f1': np.mean(f1s), 'f1_ci': np.percentile(f1s, [2.5, 97.5]),
        'prec': np.mean(precs), 'prec_ci': np.percentile(precs, [2.5, 97.5]),
        'rec': np.mean(recs), 'rec_ci': np.percentile(recs, [2.5, 97.5]),
        'fpr': np.mean(fprs), 'fpr_ci': np.percentile(fprs, [2.5, 97.5])
    }

# Compare Test results across Phishing (Overall & HTTPS-only)
phish_test = [d for d in test_items if d['label'] in ('safe', 'phishing')]
https_phish_test = [d for d in phish_test if d['url'].startswith('https://')]

strategies = [
    ('rules_only', 'rules_score'),
    ('rules_old_ml', 'old_ml_combined_score'),
    ('rules_v2_additive', 'additive_v2_score'),
    ('v2_ml_only', 'ml_v2_score'),
    ('fusion_max', 'max_fusion_score'),
    ('fusion_stacking', 'stacking_score')
]

test_ablation_results = {}

print("\n--- Test Set: Phishing Threat Metrics (@ Threshold 35) ---")
for name, key in strategies:
    m_all = bootstrap_metrics(phish_test, key, th=35)
    m_https = bootstrap_metrics(https_phish_test, key, th=35)
    test_ablation_results[name] = {'overall_35': m_all, 'https_35': m_https}
    print(f"{name:<20} | Overall F1: {m_all['f1']*100:.2f}% (FPR: {m_all['fpr']*100:.2f}%) | HTTPS-only F1: {m_https['f1']*100:.2f}%")

print("\n--- Test Set: Phishing Threat Metrics (@ Threshold 70) ---")
for name, key in strategies:
    m_all = bootstrap_metrics(phish_test, key, th=70)
    m_https = bootstrap_metrics(https_phish_test, key, th=70)
    test_ablation_results[name]['overall_70'] = m_all
    test_ablation_results[name]['https_70'] = m_https
    print(f"{name:<20} | Overall F1: {m_all['f1']*100:.2f}% (FPR: {m_all['fpr']*100:.2f}%) | HTTPS-only F1: {m_https['f1']*100:.2f}%")

# ---------------------------------------------------------------------------
# 3. BENIGN_BARE VS BENIGN_DEEP FPR BREAKDOWN
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("[FPR BREAKDOWN] BENIGN_BARE VS BENIGN_DEEP")
print("="*70)

safe_test = [d for d in test_items if d['label'] == 'safe']
bare_safe_test = [d for d in safe_test if d.get('benignType') == 'benign_bare']
deep_safe_test = [d for d in safe_test if d.get('benignType') == 'benign_deep']

fpr_breakdown = {}

for name, key in [('Rules Only', 'rules_score'), ('Rules + V2 Additive', 'additive_v2_score'), ('V2 ML Only', 'ml_v2_score')]:
    for th in [35, 70]:
        bare_fps = sum(1 for d in bare_safe_test if d[key] >= th)
        bare_fpr = (bare_fps / len(bare_safe_test)) * 100
        deep_fps = sum(1 for d in deep_safe_test if d[key] >= th)
        deep_fpr = (deep_fps / len(deep_safe_test)) * 100
        all_fps = bare_fps + deep_fps
        all_fpr = (all_fps / len(safe_test)) * 100
        print(f"{name} (@{th}):")
        print(f"  Benign Bare (N={len(bare_safe_test)}): FPR = {bare_fpr:.2f}% ({bare_fps} FPs)")
        print(f"  Benign Deep (N={len(deep_safe_test)}): FPR = {deep_fpr:.2f}% ({deep_fps} FPs)")
        print(f"  Combined Safe (N={len(safe_test)}): FPR = {all_fpr:.2f}% ({all_fps} FPs)")
        fpr_breakdown[f"{name}_th{th}"] = {
            'bare_fpr': bare_fpr, 'bare_fps': bare_fps,
            'deep_fpr': deep_fpr, 'deep_fps': deep_fps,
            'combined_fpr': all_fpr, 'combined_fps': all_fps
        }

# ---------------------------------------------------------------------------
# 4. ALLOWLISTED VS NON-ALLOWLISTED BENIGN FPR BREAKDOWN
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("[ALLOWLIST] ALLOWLISTED VS NON-ALLOWLISTED BENIGN FPR (HELD-OUT REAL BANK/GOV INCLUDED)")
print("="*70)

allowlisted_safe = [d for d in safe_test if d.get('isAllowlisted') is True]
non_allowlisted_safe = [d for d in safe_test if d.get('isAllowlisted') is not True]

allowlist_breakdown = {}

for name, key in [('Rules Only', 'rules_score'), ('Rules + V2 Additive', 'additive_v2_score'), ('V2 ML Only', 'ml_v2_score')]:
    for th in [35, 70]:
        al_fps = sum(1 for d in allowlisted_safe if d[key] >= th)
        al_fpr = (al_fps / len(allowlisted_safe)) * 100 if allowlisted_safe else 0.0
        non_al_fps = sum(1 for d in non_allowlisted_safe if d[key] >= th)
        non_al_fpr = (non_al_fps / len(non_allowlisted_safe)) * 100
        print(f"{name} (@{th}):")
        print(f"  Allowlisted Benign (N={len(allowlisted_safe)}): FPR = {al_fpr:.2f}% ({al_fps} FPs)")
        print(f"  Non-Allowlisted Benign (N={len(non_allowlisted_safe)}): FPR = {non_al_fpr:.2f}% ({non_al_fps} FPs)")
        allowlist_breakdown[f"{name}_th{th}"] = {
            'allowlisted_fpr': al_fpr, 'allowlisted_fps': al_fps,
            'non_allowlisted_fpr': non_al_fpr, 'non_allowlisted_fps': non_al_fps
        }

# ---------------------------------------------------------------------------
# 5. DIAGNOSTICS: WORST-20 FALSE POSITIVES AND WORST-20 MISSES
# ---------------------------------------------------------------------------
print("\n" + "="*70)
print("[DIAGNOSTICS] WORST-20 FALSE POSITIVES AND WORST-20 MISSES (TEST SET)")
print("="*70)

fps = [d for d in safe_test if d['additive_v2_score'] >= 35]
fps_sorted = sorted(fps, key=lambda x: x['additive_v2_score'], reverse=True)

print(f"\n[WORST-20 FALSE POSITIVES (Total FPs = {len(fps)})]")
for idx, fp in enumerate(fps_sorted[:20]):
    firing = ", ".join([f"{r['name']}(+{r['score']})" for r in fp.get('firing_rules', [])]) or "None"
    print(f"  {idx+1}. [{fp['source']}] Score={fp['additive_v2_score']} | URL: {fp['url']}")
    print(f"      Rules: {firing} | ML_Prob: {fp.get('ml_v2_prob', 0):.2f}")

misses = [d for d in test_items if d['label'] == 'phishing' and d['additive_v2_score'] < 35]
misses_sorted = sorted(misses, key=lambda x: x['additive_v2_score'])

print(f"\n[WORST-20 PHISHING MISSES (Total Misses = {len(misses)})]")
for idx, ms in enumerate(misses_sorted[:20]):
    firing = ", ".join([f"{r['name']}(+{r['score']})" for r in ms.get('firing_rules', [])]) or "None"
    print(f"  {idx+1}. [{ms['source']}] Score={ms['additive_v2_score']} | URL: {ms['url']}")
    print(f"      Rules: {firing} | ML_Prob: {ms.get('ml_v2_prob', 0):.2f}")

# Group remaining FPs by firing rule
print("\n[TEST SET FALSE POSITIVES GROUPED BY FIRING RULE]")
rule_fp_counts = {}
for fp in fps:
    fired = fp.get('firing_rules', [])
    if not fired:
        rule_fp_counts['ML_Only_Threshold_Elevation'] = rule_fp_counts.get('ML_Only_Threshold_Elevation', 0) + 1
    else:
        for r in fired:
            rule_fp_counts[r['name']] = rule_fp_counts.get(r['name'], 0) + 1

for rname, count in sorted(rule_fp_counts.items(), key=lambda x: x[1], reverse=True):
    print(f"  - {rname}: {count} FPs ({count / len(safe_test) * 100:.2f}% of test benign)")

# Save evaluation output
full_out = {
    'fusion_dev_cv': fusion_metrics,
    'test_ablation': test_ablation_results,
    'fpr_bare_vs_deep': fpr_breakdown,
    'fpr_allowlist': allowlist_breakdown,
    'fp_rule_distribution': rule_fp_counts
}
with open('benchmark/v3_analysis_results.json', 'w', encoding='utf-8') as f:
    json.dump(full_out, f, indent=2, default=str)

print("\nWrote full V3 analysis results to benchmark/v3_analysis_results.json")
