#!/usr/bin/env python3
"""
FixAI — NASA C-MAPSS Remaining Useful Life (RUL) Training Pipeline
==================================================================

Trains an XGBoost Regressor to predict Remaining Useful Life (RUL)
using the NASA Turbofan Engine Degradation Simulation Dataset (C-MAPSS).

Data Schema (26 columns, space-delimited):
  - unit_nr:       Engine unit ID (1..100)
  - time_cycles:   Time in operational cycles (1..N)
  - setting_1..3:  Operational settings
  - s_1..s_21:     21 sensor channels (temperatures, pressures, speeds, ratios)

Ground Truth RUL:
  RUL_i = max(cycle_unit) - current_cycle
  (with optional piecewise linear clipping at 125 cycles, standard benchmark)

Feature Engineering:
  - Rolling mean (window = 5) per engine unit
  - Rolling standard deviation (window = 5) per engine unit
  - Cycle-to-cycle delta per engine unit

Evaluation:
  Evaluated on official held-out test units (test_FD001.txt against RUL_FD001.txt).
  Metrics: RMSE, MAE, R², and the NASA asymmetric exponential score.

Outputs:
  - local_agent/models/rul_model.joblib
  - local_agent/models/rul_scaler.joblib
  - local_agent/models/rul_feature_names.json
  - local_agent/models/rul_report.json
"""

from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Ensure UTF-8 on Windows terminals
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import mean_absolute_error, r2_score, root_mean_squared_error
from sklearn.preprocessing import StandardScaler
from xgboost import XGBRegressor

# ─── Dataset Column Specifications ─────────────────────────────────────────
RAW_COLUMNS = (
    ["unit_nr", "time_cycles", "setting_1", "setting_2", "setting_3"]
    + [f"s_{i}" for i in range(1, 22)]
)


def locate_cmapss_dir(provided_path: str | None = None) -> Path:
    """Locate the directory containing NASA C-MAPSS files."""
    if provided_path and Path(provided_path).exists():
        return Path(provided_path).resolve()

    candidates = [
        Path("data/cmapss"),
        Path("../data/cmapss"),
        Path("../../data/cmapss"),
        Path("C:/project/FixAI/fixai1/data/cmapss"),
        Path("C:/project/FixAI/data/cmapss"),
        Path("data"),
        Path("../data"),
    ]

    for c in candidates:
        if (c / "train_FD001.txt").exists():
            return c.resolve()

    raise FileNotFoundError(
        "Could not find NASA C-MAPSS dataset ('train_FD001.txt'). "
        "Please ensure data files are located in data/cmapss/"
    )


def load_cmapss_subset(
    data_dir: Path,
    subset: str = "FD001",
    clip_rul: Optional[int] = 125,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """
    Load raw space-delimited C-MAPSS data for a specific subset (e.g. FD001).

    Returns:
      train_df: Full run-to-failure time series with ground-truth RUL
      test_df:  Truncated time series for test units
      rul_df:   Ground truth remaining cycles at the last recorded test cycle
    """
    train_path = data_dir / f"train_{subset}.txt"
    test_path = data_dir / f"test_{subset}.txt"
    rul_path = data_dir / f"RUL_{subset}.txt"

    for p in [train_path, test_path, rul_path]:
        if not p.exists():
            raise FileNotFoundError(f"Missing required NASA file: {p}")

    print(f"📖 Loading NASA C-MAPSS [{subset}] from: {data_dir}")
    train_df = pd.read_csv(train_path, sep=r"\s+", header=None, names=RAW_COLUMNS)
    test_df = pd.read_csv(test_path, sep=r"\s+", header=None, names=RAW_COLUMNS)
    rul_df = pd.read_csv(rul_path, sep=r"\s+", header=None, names=["true_rul"])

    print(f"   ✓ Train rows: {len(train_df):,} across {train_df['unit_nr'].nunique()} engines")
    print(f"   ✓ Test rows:  {len(test_df):,} across {test_df['unit_nr'].nunique()} engines")
    print(f"   ✓ Ground-truth test RUL records: {len(rul_df)}")

    # 1. Compute ground-truth RUL for training data: RUL = max(cycle_unit) - current_cycle
    max_cycle_train = train_df.groupby("unit_nr")["time_cycles"].transform("max")
    train_df["RUL_raw"] = max_cycle_train - train_df["time_cycles"]

    if clip_rul is not None and clip_rul > 0:
        # Standard literature benchmark: piecewise linear degradation model
        train_df["RUL"] = np.minimum(train_df["RUL_raw"], float(clip_rul))
        print(f"   ✓ RUL piecewise linear clipped at {clip_rul} cycles (max raw = {train_df['RUL_raw'].max()})")
    else:
        train_df["RUL"] = train_df["RUL_raw"]

    # 2. Compute ground-truth RUL for test units
    # For each test engine u, failure_cycle = max_observed_cycle + rul_df[u-1]
    max_cycle_test = test_df.groupby("unit_nr")["time_cycles"].transform("max")
    rul_mapping = {u: float(rul_df.iloc[u - 1]["true_rul"]) for u in range(1, len(rul_df) + 1)}
    test_df["max_cycle"] = max_cycle_test
    test_df["RUL_last_true"] = test_df["unit_nr"].map(rul_mapping)
    test_df["RUL_raw"] = test_df["RUL_last_true"] + (test_df["max_cycle"] - test_df["time_cycles"])

    if clip_rul is not None and clip_rul > 0:
        test_df["RUL"] = np.minimum(test_df["RUL_raw"], float(clip_rul))
    else:
        test_df["RUL"] = test_df["RUL_raw"]

    return train_df, test_df, rul_df


def engineer_features(
    df: pd.DataFrame,
    sensor_cols: List[str],
    window: int = 5,
) -> Tuple[pd.DataFrame, List[str]]:
    """
    Apply domain time-series feature engineering per engine unit:
      1. Rolling window mean
      2. Rolling window standard deviation
      3. Cycle-to-cycle delta
    """
    engineered_cols: List[str] = []
    df_out = df.copy()

    for col in sensor_cols:
        # 1. Raw sensor
        engineered_cols.append(col)

        # 2. Rolling mean (grouped by unit_nr)
        mean_col = f"{col}_roll_mean"
        df_out[mean_col] = (
            df_out.groupby("unit_nr")[col]
            .rolling(window, min_periods=1)
            .mean()
            .reset_index(level=0, drop=True)
        )
        engineered_cols.append(mean_col)

        # 3. Rolling std (grouped by unit_nr)
        std_col = f"{col}_roll_std"
        df_out[std_col] = (
            df_out.groupby("unit_nr")[col]
            .rolling(window, min_periods=1)
            .std()
            .fillna(0.0)
            .reset_index(level=0, drop=True)
        )
        engineered_cols.append(std_col)

        # 4. Cycle-to-cycle delta
        delta_col = f"{col}_delta"
        df_out[delta_col] = df_out.groupby("unit_nr")[col].diff().fillna(0.0)
        engineered_cols.append(delta_col)

    return df_out, engineered_cols


def compute_nasa_score(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """
    Compute official NASA PHM scoring metric (asymmetric penalty):
      d = y_pred - y_true
      d < 0 (early prediction / safe):     score += exp(-d / 13) - 1
      d >= 0 (late prediction / dangerous): score += exp(d / 10) - 1
    """
    d = y_pred - y_true
    score = 0.0
    for diff in d:
        if diff < 0:
            score += math.exp(-diff / 13.0) - 1.0
        else:
            score += math.exp(diff / 10.0) - 1.0
    return float(score)


def train_rul_pipeline(
    data_dir: str | None = None,
    out_dir: str = "models",
    subset: str = "FD001",
    clip_rul: int = 125,
    window: int = 5,
    seed: int = 42,
) -> dict:
    """
    Run complete end-to-end RUL regression pipeline on NASA C-MAPSS data.
    """
    start_time = time.time()
    c_dir = locate_cmapss_dir(data_dir)
    train_raw, test_raw, rul_raw = load_cmapss_subset(c_dir, subset=subset, clip_rul=clip_rul)

    # Determine informative sensors
    # Filter out any column with zero standard deviation
    std_series = train_raw[[f"s_{i}" for i in range(1, 22)] + ["setting_1", "setting_2", "setting_3"]].std()
    active_sensors = [col for col in std_series.index if std_series[col] > 1e-4]
    print(f"   ✓ Identified {len(active_sensors)} active sensor/setting channels (excluded {len(std_series) - len(active_sensors)} constant channels)")

    # ── Feature Engineering ───────────────────────────────────────────
    print(f"\n⚙️  Engineering temporal features (window={window}, rolling mean/std + cycle deltas)...")
    train_fe, feature_names = engineer_features(train_raw, active_sensors, window=window)
    test_fe, _ = engineer_features(test_raw, active_sensors, window=window)
    print(f"   ✓ Engineered feature matrix: {len(feature_names)} features per cycle record")

    X_train = train_fe[feature_names].values
    y_train = train_fe["RUL"].values

    # ── Fit StandardScaler ────────────────────────────────────────────
    print("\n📏 Fitting StandardScaler on training cycles...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)

    # ── Train XGBoost Regressor ───────────────────────────────────────
    print("🚀 Training XGBoost Regressor on NASA turbofan run-to-failure cycles...")
    model = XGBRegressor(
        n_estimators=120,
        max_depth=5,
        learning_rate=0.07,
        subsample=0.85,
        colsample_bytree=0.85,
        random_state=seed,
        n_jobs=-1,
    )
    model.fit(X_train_scaled, y_train)

    # ── Evaluate on Held-Out Test Engines ─────────────────────────────
    # Official NASA benchmark: evaluate the last recorded cycle of each test engine against RUL_FDxxx
    print("\n📊 Evaluating on held-out test engines (NASA benchmark protocol)...")
    test_last_records = test_fe.groupby("unit_nr").last().reset_index()
    X_test_last = test_last_records[feature_names].values
    X_test_last_scaled = scaler.transform(X_test_last)

    y_test_last_clipped = test_last_records["RUL"].values
    y_test_last_raw = test_last_records["RUL_last_true"].values

    preds_last = model.predict(X_test_last_scaled)
    # Clip negative predictions to 0
    preds_last = np.maximum(0.0, preds_last)

    # Also evaluate across ALL test rows
    X_test_all = test_fe[feature_names].values
    X_test_all_scaled = scaler.transform(X_test_all)
    y_test_all = test_fe["RUL"].values
    preds_all = np.maximum(0.0, model.predict(X_test_all_scaled))

    # Metrics on Last Cycle (Benchmark standard)
    rmse_last_clipped = float(root_mean_squared_error(y_test_last_clipped, preds_last))
    mae_last_clipped = float(mean_absolute_error(y_test_last_clipped, preds_last))
    r2_last_clipped = float(r2_score(y_test_last_clipped, preds_last))

    rmse_last_raw = float(root_mean_squared_error(y_test_last_raw, preds_last))
    mae_last_raw = float(mean_absolute_error(y_test_last_raw, preds_last))
    nasa_score_last = compute_nasa_score(y_test_last_raw, preds_last)

    # Metrics on All Test Cycles
    rmse_all = float(root_mean_squared_error(y_test_all, preds_all))
    mae_all = float(mean_absolute_error(y_test_all, preds_all))
    r2_all = float(r2_score(y_test_all, preds_all))

    print(f"   ╔══════════════════════════════════════════════════════════════╗")
    print(f"   ║  NASA C-MAPSS [{subset}] Test Benchmark Results              ║")
    print(f"   ╠══════════════════════════════════════════════════════════════╣")
    print(f"   ║  Last-Cycle Benchmark RMSE (clipped target):  {rmse_last_clipped:>6.2f} cycles ║")
    print(f"   ║  Last-Cycle Benchmark MAE   (clipped target):  {mae_last_clipped:>6.2f} cycles ║")
    print(f"   ║  Last-Cycle Benchmark R²    (clipped target):  {r2_last_clipped:>6.3f}        ║")
    print(f"   ║  Last-Cycle Benchmark RMSE (unclipped target):{rmse_last_raw:>6.2f} cycles ║")
    print(f"   ║  Last-Cycle Benchmark MAE   (unclipped target):{mae_last_raw:>6.2f} cycles ║")
    print(f"   ║  NASA Asymmetric Score:                       {nasa_score_last:>8.1f}        ║")
    print(f"   ║  All-Cycles Test RMSE:                         {rmse_all:>6.2f} cycles ║")
    print(f"   ║  All-Cycles Test MAE:                          {mae_all:>6.2f} cycles ║")
    print(f"   ╚══════════════════════════════════════════════════════════════╝")

    # ── Feature Importance ────────────────────────────────────────────
    importances = model.feature_importances_
    top_indices = np.argsort(importances)[::-1][:10]
    print("\n🔍 Top 10 Most Predictive Degradation Features:")
    top_features = []
    for rank, idx in enumerate(top_indices, start=1):
        feat_name = feature_names[idx]
        imp_val = float(importances[idx])
        top_features.append({"rank": rank, "feature": feat_name, "importance": round(imp_val, 4)})
        print(f"   {rank:2d}. {feat_name:<20} {imp_val:.4f}")

    # ── Save Artifacts ────────────────────────────────────────────────
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    model_path = out / "rul_model.joblib"
    scaler_path = out / "rul_scaler.joblib"
    features_path = out / "rul_feature_names.json"
    report_path = out / "rul_report.json"

    print(f"\n💾 Saving real RUL artifacts to: {out.resolve()}...")
    joblib.dump(model, model_path)
    joblib.dump(scaler, scaler_path)

    with open(features_path, "w", encoding="utf-8") as f:
        json.dump(feature_names, f, indent=2)

    report_data = {
        "dataset": f"NASA C-MAPSS ({subset})",
        "train_rows": len(train_raw),
        "test_rows": len(test_raw),
        "train_units": int(train_raw["unit_nr"].nunique()),
        "test_units": int(test_raw["unit_nr"].nunique()),
        "num_features": len(feature_names),
        "hyperparameters": {
            "n_estimators": 120,
            "max_depth": 5,
            "learning_rate": 0.07,
            "subsample": 0.85,
            "colsample_bytree": 0.85,
            "clip_rul": clip_rul,
            "window": window,
        },
        "metrics": {
            "last_cycle_benchmark": {
                "rmse_clipped": round(rmse_last_clipped, 3),
                "mae_clipped": round(mae_last_clipped, 3),
                "r2_clipped": round(r2_last_clipped, 4),
                "rmse_unclipped": round(rmse_last_raw, 3),
                "mae_unclipped": round(mae_last_raw, 3),
                "nasa_score": round(nasa_score_last, 2),
            },
            "all_cycles": {
                "rmse": round(rmse_all, 3),
                "mae": round(mae_all, 3),
                "r2": round(r2_all, 4),
            },
        },
        "top_features": top_features,
        "training_duration_seconds": round(time.time() - start_time, 2),
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"   ✓ {model_path.name} ({model_path.stat().st_size / 1024:.1f} KB)")
    print(f"   ✓ {scaler_path.name} ({scaler_path.stat().st_size / 1024:.1f} KB)")
    print(f"   ✓ {features_path.name}")
    print(f"   ✓ {report_path.name}")
    print(f"\n🎉 NASA C-MAPSS RUL training complete in {report_data['training_duration_seconds']}s!")

    return report_data


def main() -> None:
    parser = argparse.ArgumentParser(description="FixAI NASA C-MAPSS RUL Training Pipeline")
    parser.add_argument("--data-dir", type=str, default=None, help="Directory containing NASA txt files")
    parser.add_argument("--out-dir", type=str, default="models", help="Output directory for joblib models")
    parser.add_argument("--subset", type=str, default="FD001", choices=["FD001", "FD002", "FD003", "FD004"], help="Dataset subset")
    parser.add_argument("--clip-rul", type=int, default=125, help="Piecewise linear RUL clipping threshold")
    parser.add_argument("--window", type=int, default=5, help="Rolling window size in cycles")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")

    args = parser.parse_args()
    train_rul_pipeline(
        data_dir=args.data_dir,
        out_dir=args.out_dir,
        subset=args.subset,
        clip_rul=args.clip_rul,
        window=args.window,
        seed=args.seed,
    )


if __name__ == "__main__":
    main()
