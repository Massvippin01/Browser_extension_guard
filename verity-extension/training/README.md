# Verity Stage 2 Training Pipeline

This directory contains the pipeline to train a Logistic Regression model on a public Phishing Websites dataset and export it to ONNX for in-browser inference.

## Setup

1. Make sure you have Python 3.8+ installed.
2. Install the requirements:
   ```bash
   pip install -r requirements.txt
   ```

## Execution

Run the script to download the dataset, train the model, and generate the artifacts:
```bash
python train_model.py
```

## What This Does
1. Downloads the `PhishingWebsites` dataset from OpenML.
2. Selects 8 purely structural URL features that can be 100% reliably reproduced offline in a Chrome Extension without external API calls.
3. Drops non-reproducible features (like PageRank, DNS records, traffic).
4. Trains a Logistic Regression classifier.
5. Saves the ONNX model to `../background/model/phishing_model.onnx`.
6. Saves the `feature_order.json` and `feature_schema.json` to ensure JS and Python use identical representations.
7. Saves `model_metrics.json` containing the real evaluation metrics for the Model Card.
