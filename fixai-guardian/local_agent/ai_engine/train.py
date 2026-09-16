#!/usr/bin/env python3
"""
FixAI — Real Model Training Pipeline (AI4I 2020 Dataset)
========================================================

Trains:
  1. Isolation Forest — Unsupervised Anomaly Detection (trained on healthy-only rows)
  2. XGBoost Classifier — Supervised Failure Prediction & Multi-label root-cause diagnosis
     (with class-imbalance cost-sensitive weighting, scale_pos_weight)

Data Source:
  Real tabular data from data/ai4i2020.csv (10,000 instances, 3.39% failure rate).
  Zero synthetic/mock rows.

Outputs:
  - isolation_forest.joblib
  - xgboost_classifier.joblib
  - xgboost_multilabel.joblib
  - scaler.joblib
  - feature_names.json
  - training_report.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Tuple

# Ensure UTF-8 output on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier


# ─── Feature Definitions ──────────────────────────────────────────────────
BASE_FEATURE_NAMES = [
    "Type_encoded",
    "Air temperature [K]",
    "Process temperature [K]",
    "Rotational speed [rpm]",
    "Torque [Nm]",
    "Tool wear [min]",
    "Temp_diff",
    "Power_kW",
    "Overstrain",
]

TARGET_COL = "Machine failure"
FAILURE_MODES = ["TWF", "HDF", "PWF", "OSF", "RNF"]


def locate_dataset(provided_path: str | None = None) -> Path:
    """Find the real ai4i2020.csv in possible project data locations."""
    if provided_path and Path(provided_path).exists():
        return Path(provided_path)

    candidates = [
        Path("data/ai4i2020.csv"),
        Path("../data/ai4i2020.csv"),
        Path("../../data/ai4i2020.csv"),
        Path("C:/project/FixAI/fixai1/data/ai4i2020.csv"),
        Path("C:/project/FixAI/data/ai4i2020.csv"),
    ]

    for p in candidates:
        if p.exists():
            return p.resolve()

    raise FileNotFoundError(
        "Could not find 'ai4i2020.csv'. Please place the real AI4I 2020 dataset in data/ai4i2020.csv"
    )


def load_and_preprocess(csv_path: Path) -> Tuple[pd.DataFrame, List[str]]:
    """
    Load real AI4I 2020 dataset, engineer physical features,
    and encode categorical Type (L/M/H).
    """
    print(f"📖 Loading real dataset from: {csv_path}")
    df = pd.read_csv(csv_path)

    if len(df) == 0:
        raise ValueError(f"Dataset at {csv_path} is empty!")

    # 1. Clean column names / verify schema
    expected_cols = [
        "Type",
        "Air temperature [K]",
        "Process temperature [K]",
        "Rotational speed [rpm]",
        "Torque [Nm]",
        "Tool wear [min]",
        TARGET_COL,
    ]
    for col in expected_cols:
        if col not in df.columns:
            raise KeyError(f"Expected column '{col}' missing from {csv_path}")

    # 2. Encode categorical 'Type' (L: Low quality, M: Medium, H: High)
    type_map = {"L": 0, "M": 1, "H": 2}
    df["Type_encoded"] = df["Type"].map(type_map).fillna(0).astype(int)

    # 3. Domain feature engineering from physical laws
    # Temperature difference (Process - Air)
    df["Temp_diff"] = df["Process temperature [K]"] - df["Air temperature [K]"]
    # Power generated in kW (Torque * angular velocity)
    df["Power_kW"] = (df["Torque [Nm]"] * df["Rotational speed [rpm]"] * 2 * np.pi) / 60000.0
    # Overstrain product (Wear * Torque)
    df["Overstrain"] = df["Tool wear [min]"] * df["Torque [Nm]"]

    print(f"   ✓ Loaded {len(df)} total rows.")
    print(f"   ✓ Failure rate: {df[TARGET_COL].sum()} failures ({(df[TARGET_COL].mean() * 100):.2f}% imbalance)")
    for mode in FAILURE_MODES:
        if mode in df.columns:
            print(f"     - {mode}: {df[mode].sum()} occurrences")

    return df, BASE_FEATURE_NAMES


def train(
    data_path: str | None = None,
    out_dir: str = "models",
    test_size: float = 0.2,
    seed: int = 42,
) -> dict:
    """
    Train Isolation Forest and XGBoost classifiers on real data only.
    """
    csv_file = locate_dataset(data_path)
    df, feature_cols = load_and_preprocess(csv_file)

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    # ── 1. Stratified Train / Test Split ────────────────────────────────
    print(f"\n✂️  Splitting data (test_size={test_size}, random_state={seed})...")
    train_df, test_df = train_test_split(
        df,
        test_size=test_size,
        random_state=seed,
        stratify=df[TARGET_COL],
    )
    print(f"   Train set: {len(train_df)} rows ({train_df[TARGET_COL].sum()} failures)")
    print(f"   Test set:  {len(test_df)} rows ({test_df[TARGET_COL].sum()} failures)")

    # ── 2. Feature Scaling ──────────────────────────────────────────────
    scaler = StandardScaler()
    X_train = scaler.fit_transform(train_df[feature_cols])
    X_test = scaler.transform(test_df[feature_cols])

    # ── 3. Train Isolation Forest on Healthy-Only Data ──────────────────
    print("\n🌲 Training Isolation Forest on healthy baseline instances only...")
    healthy_mask = train_df[TARGET_COL] == 0
    X_train_healthy = X_train[healthy_mask]
    print(f"   Healthy baseline samples: {len(X_train_healthy)}")

    # Contamination set to empirical failure rate of dataset (~3.39%)
    contamination_rate = max(0.01, min(0.1, float(df[TARGET_COL].mean())))
    iso_forest = IsolationForest(
        n_estimators=150,
        contamination=contamination_rate,
        random_state=seed,
        n_jobs=-1,
    )
    iso_forest.fit(X_train_healthy)

    # Evaluate Isolation Forest on test set (-1 is anomaly, 1 is normal)
    if_test_pred = iso_forest.predict(X_test)
    if_binary_pred = (if_test_pred == -1).astype(int)
    if_f1 = f1_score(test_df[TARGET_COL], if_binary_pred, zero_division=0)
    if_recall = recall_score(test_df[TARGET_COL], if_binary_pred, zero_division=0)
    if_precision = precision_score(test_df[TARGET_COL], if_binary_pred, zero_division=0)
    print(f"   Isolation Forest -> F1: {if_f1:.3f} | Recall: {if_recall:.3f} | Precision: {if_precision:.3f}")

    # ── 4. Train Supervised XGBoost Binary Failure Predictor ────────────
    print("\n🚀 Training Cost-Sensitive XGBoost Binary Failure Predictor...")
    pos_count = int(train_df[TARGET_COL].sum())
    neg_count = len(train_df) - pos_count
    pos_weight = neg_count / max(1, pos_count)
    print(f"   Class weighting (scale_pos_weight): {pos_weight:.2f}")

    xgb_binary = XGBClassifier(
        n_estimators=150,
        max_depth=5,
        learning_rate=0.06,
        scale_pos_weight=pos_weight,
        eval_metric="logloss",
        random_state=seed,
        n_jobs=-1,
    )
    xgb_binary.fit(X_train, train_df[TARGET_COL])

    y_test_bin = test_df[TARGET_COL]
    y_pred_bin = xgb_binary.predict(X_test)
    y_prob_bin = xgb_binary.predict_proba(X_test)[:, 1]

    bin_f1 = f1_score(y_test_bin, y_pred_bin, zero_division=0)
    bin_recall = recall_score(y_test_bin, y_pred_bin, zero_division=0)
    bin_precision = precision_score(y_test_bin, y_pred_bin, zero_division=0)
    print(f"   XGBoost Binary -> F1: {bin_f1:.3f} | Recall: {bin_recall:.3f} | Precision: {bin_precision:.3f}")

    # ── 5. Train Multi-Label XGBoost for Failure Modes ──────────────────
    print("\n🎯 Training Multi-Label Failure Mode Classifiers (TWF, HDF, PWF, OSF, RNF)...")
    multilabel_models = {}
    mode_metrics = {}

    for mode in FAILURE_MODES:
        if mode not in train_df.columns:
            continue
        mode_pos = int(train_df[mode].sum())
        mode_neg = len(train_df) - mode_pos
        mode_weight = mode_neg / max(1, mode_pos)

        mode_xgb = XGBClassifier(
            n_estimators=100,
            max_depth=4,
            learning_rate=0.08,
            scale_pos_weight=mode_weight,
            eval_metric="logloss",
            random_state=seed,
            n_jobs=-1,
        )
        mode_xgb.fit(X_train, train_df[mode])
        mode_preds = mode_xgb.predict(X_test)

        m_f1 = f1_score(test_df[mode], mode_preds, zero_division=0)
        m_rec = recall_score(test_df[mode], mode_preds, zero_division=0)
        m_prec = precision_score(test_df[mode], mode_preds, zero_division=0)

        print(f"   Mode [{mode}] -> F1: {m_f1:.3f} | Recall: {m_rec:.3f} | Precision: {m_prec:.3f} (Weight: {mode_weight:.1f})")
        multilabel_models[mode] = mode_xgb
        mode_metrics[mode] = {"f1": m_f1, "recall": m_rec, "precision": m_prec, "pos_count": mode_pos}

    # ── 6. Save Artifacts ───────────────────────────────────────────────
    print(f"\n💾 Saving real AI4I model artifacts to: {out}")
    # Namespaced AI4I models
    joblib.dump(scaler, out / "ai4i_scaler.joblib")
    joblib.dump(iso_forest, out / "ai4i_isolation_forest.joblib")
    joblib.dump(xgb_binary, out / "ai4i_xgboost_classifier.joblib")
    joblib.dump(multilabel_models, out / "ai4i_xgboost_multilabel.joblib")
    joblib.dump(multilabel_models, out / "xgboost_multilabel.joblib")

    with open(out / "ai4i_feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, indent=2)

    report = {
        "dataset": str(csv_file),
        "total_samples": len(df),
        "train_samples": len(train_df),
        "test_samples": len(test_df),
        "features": feature_cols,
        "isolation_forest": {
            "f1": float(if_f1),
            "recall": float(if_recall),
            "precision": float(if_precision),
            "healthy_train_samples": len(X_train_healthy),
        },
        "xgboost_binary": {
            "f1": float(bin_f1),
            "recall": float(bin_recall),
            "precision": float(bin_precision),
            "scale_pos_weight": float(pos_weight),
        },
        "multilabel_failure_modes": {
            k: {
                "f1": float(v["f1"]),
                "recall": float(v["recall"]),
                "precision": float(v["precision"]),
                "pos_count": int(v["pos_count"]),
            }
            for k, v in mode_metrics.items()
        },
    }

    with open(out / "training_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    with open(out / "ai4i_training_report.json", "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    print("   ✓ All artifacts saved successfully.")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="FixAI Real Model Training Pipeline")
    parser.add_argument("--data", type=str, default=None, help="Path to ai4i2020.csv")
    parser.add_argument("--out-dir", type=str, default="models", help="Output directory for .joblib models")
    parser.add_argument("--with-rul", action="store_true", help="Also run NASA C-MAPSS RUL training pipeline")
    parser.add_argument("--with-telemetry", action="store_true", help="Also run local host telemetry baseline adaptation pass")
    parser.add_argument("--all", action="store_true", help="Train all models (AI4I + NASA C-MAPSS + Telemetry)")
    args = parser.parse_args()

    train(data_path=args.data, out_dir=args.out_dir)

    if args.with_rul or args.all:
        try:
            try:
                from ai_engine.train_rul import train_rul_pipeline
            except ModuleNotFoundError:
                from train_rul import train_rul_pipeline

            print("\n" + "=" * 65)
            print("  Starting NASA C-MAPSS RUL Pipeline (--with-rul)")
            print("=" * 65)
            train_rul_pipeline(out_dir=args.out_dir)
        except Exception as e:
            print(f"⚠️  RUL training encountered an error: {e}")

    if args.with_telemetry or args.all:
        try:
            try:
                from ai_engine.train_telemetry import adapt_telemetry_pipeline
            except ModuleNotFoundError:
                from train_telemetry import adapt_telemetry_pipeline

            print("\n" + "=" * 65)
            print("  Starting Real Telemetry Baseline Adaptation (--with-telemetry)")
            print("=" * 65)
            adapt_telemetry_pipeline(out_dir=args.out_dir)
        except Exception as e:
            print(f"⚠️  Telemetry baseline adaptation encountered an error: {e}")


