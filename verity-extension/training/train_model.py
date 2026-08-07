import json
import os
import numpy as np
import pandas as pd
from sklearn.datasets import fetch_openml
from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

# 1. Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), '..', 'background', 'model')
os.makedirs(MODEL_DIR, exist_ok=True)

# 2. Fetch Dataset
print("Fetching PhishingWebsites dataset from OpenML...")
# Dataset ID 4534 is PhishingWebsites on OpenML
data = fetch_openml('PhishingWebsites', version=1, as_frame=True, parser='auto')
df = data.frame

# The dataset features are typically -1 (phishing/bad), 0 (suspicious), 1 (legitimate).
# The target is 'Result' with values '-1' and '1'.

# 3. Select Reproducible Features
# We only select features that can be synchronously and 100% reliably calculated
# from a URL string inside a Chrome extension background worker.
# Deep network features (DNS, Traffic, SSL) are intentionally excluded.
REPRODUCIBLE_FEATURES = [
    'having_IP_Address',
    'URL_Length',
    'Shortining_Service',
    'having_At_Symbol',
    'double_slash_redirecting',
    'Prefix_Suffix',
    'having_Sub_Domain',
    'HTTPS_token'
]

print(f"Dataset loaded. Total rows: {len(df)}. Total columns: {len(df.columns)}")
print(f"Selecting {len(REPRODUCIBLE_FEATURES)} reproducible URL features for in-browser inference...")

# Ensure dataset has our columns
for col in REPRODUCIBLE_FEATURES:
    if col not in df.columns:
        raise ValueError(f"Expected feature '{col}' not found in dataset!")

X = df[REPRODUCIBLE_FEATURES].astype(float)
# Target 'Result' has strings '-1' and '1'. Map to 1 (phishing) and 0 (legitimate)
y = (df['Result'].astype(str) == '-1').astype(int)

# 4. Train/Test Split
print("Splitting dataset 80/20...")
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

# 5. Model Training
print("Training Logistic Regression model...")
model = LogisticRegression(random_state=42)
model.fit(X_train, y_train)

# 6. Evaluation
print("Evaluating on test set...")
y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

metrics = {
    "model": "LogisticRegression",
    "dataset": {
        "name": "UCI PhishingWebsites (OpenML)",
        "rows": len(df),
        "features": len(REPRODUCIBLE_FEATURES)
    },
    "split": {
        "train": len(X_train),
        "test": len(X_test)
    },
    "metrics": {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred)),
        "recall": float(recall_score(y_test, y_pred)),
        "f1": float(f1_score(y_test, y_pred)),
        "roc_auc": float(roc_auc_score(y_test, y_prob))
    },
    "confusion_matrix": confusion_matrix(y_test, y_pred).tolist()
}

metrics_path = os.path.join(os.path.dirname(__file__), 'model_metrics.json')
with open(metrics_path, 'w') as f:
    json.dump(metrics, f, indent=2)
print(f"Saved metrics to {metrics_path}")

# 7. ONNX Export
print("Exporting model to ONNX...")
initial_type = [('float_input', FloatTensorType([None, len(REPRODUCIBLE_FEATURES)]))]
onnx_model = convert_sklearn(model, initial_types=initial_type, target_opset=12)

onnx_path = os.path.join(MODEL_DIR, 'phishing_model.onnx')
with open(onnx_path, 'wb') as f:
    f.write(onnx_model.SerializeToString())
print(f"Saved ONNX model to {onnx_path}")

# 8. Feature Schemas
feature_order = {
    "features": REPRODUCIBLE_FEATURES
}
with open(os.path.join(MODEL_DIR, 'feature_order.json'), 'w') as f:
    json.dump(feature_order, f, indent=2)

feature_schema = {
    "features": {
        "having_IP_Address": {
            "meaning": "URL contains an IP address instead of a domain name.",
            "values": {"-1": "IP is used (Phishing)", "1": "IP is not used (Legit)"},
            "js_calculation": "Check if hostname matches IPv4 regex."
        },
        "URL_Length": {
            "meaning": "Length of the URL.",
            "values": {"-1": "URL >= 75 (Phishing)", "0": "54 <= URL < 75", "1": "URL < 54 (Legit)"},
            "js_calculation": "Check full URL length against thresholds."
        },
        "Shortining_Service": {
            "meaning": "Use of URL shortening services.",
            "values": {"-1": "Shortened (Phishing)", "1": "Not Shortened (Legit)"},
            "js_calculation": "Check if hostname matches known shorteners (bit.ly, tinyurl, etc.)."
        },
        "having_At_Symbol": {
            "meaning": "URL contains @ symbol.",
            "values": {"-1": "Contains @ (Phishing)", "1": "No @ (Legit)"},
            "js_calculation": "Check if URL string contains '@'."
        },
        "double_slash_redirecting": {
            "meaning": "Position of the last double slash.",
            "values": {"-1": "Position > 7 (Phishing)", "1": "Position <= 7 (Legit)"},
            "js_calculation": "Check if '//' appears after the protocol."
        },
        "Prefix_Suffix": {
            "meaning": "Domain name contains a dash/hyphen.",
            "values": {"-1": "Contains dash (Phishing)", "1": "No dash (Legit)"},
            "js_calculation": "Check if hostname contains '-'."
        },
        "having_Sub_Domain": {
            "meaning": "Number of dots in the domain.",
            "values": {"-1": ">= 3 dots (Phishing)", "0": "2 dots", "1": "1 dot (Legit)"},
            "js_calculation": "Count dots in hostname minus 'www'."
        },
        "HTTPS_token": {
            "meaning": "Domain name contains 'https'.",
            "values": {"-1": "Contains 'https' in domain (Phishing)", "1": "No 'https' in domain (Legit)"},
            "js_calculation": "Check if hostname includes 'https'."
        }
    }
}
with open(os.path.join(MODEL_DIR, 'feature_schema.json'), 'w') as f:
    json.dump(feature_schema, f, indent=2)

print("Training pipeline completed successfully.")
