import json
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import GroupKFold
import math

# Load URLs and ML scores
with open('benchmark/test_urls.json', 'r', encoding='utf-8') as f:
    items = json.load(f)

with open('benchmark/ml_scores.json', 'r', encoding='utf-8') as f:
    ml_scores = json.load(f)

# Attach ml scores
for item in items:
    s = ml_scores.get(item['url'], {})
    item['v1_prob'] = s.get('v1_prob', 0.0)
    item['v2_prob'] = s.get('v2_prob', 0.0)
    item['v2_score'] = s.get('v2_score', 0)

dev_items = [i for i in items if i['split'] == 'dev']
test_items = [i for i in items if i['split'] == 'test']

print(f"Dataset Loaded: Dev={len(dev_items)}, Test={len(test_items)}")

# We will need the rules scores for each item.
# We can load the rules scores from a temporary evaluation run or compute them directly.
# Let's save a json of rule scores computed by Node or compute via subprocess/Node script.
