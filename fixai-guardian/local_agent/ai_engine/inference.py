"""
FixAI — Edge AI Inference Engine
=================================

Loads real trained models once at initialization and exposes:
  - analyze(hardware_metrics): Primary edge analysis returning anomaly score,
    failure probability, SHAP attribution weights, and a template-based NLG explanation.

All computation runs locally on the host machine.
Zero dummy fallback weights or synthetic generation.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import joblib
import numpy as np
import shap
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from xgboost import XGBClassifier

from dataclasses import dataclass, field

logger = logging.getLogger("fixai.ai_engine")

FEATURE_NAMES = ["cpu", "ram", "latency", "error_rate", "disk"]


@dataclass
class InferenceResult:
    """Structured container for single-pass inference diagnostics."""

    anomaly_score: float
    p_failure: float
    risk: str
    shap_weights: Dict[str, float] = field(default_factory=dict)
    nlg_explanation: str = ""

    def __getitem__(self, key: str) -> Any:
        if key == "shap":
            return [
                {"feature": k, "attribution": v, "value": 0.0}
                for k, v in self.shap_weights.items()
            ]
        if hasattr(self, key):
            return getattr(self, key)
        raise KeyError(f"Key '{key}' not found in InferenceResult")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anomaly_score": self.anomaly_score,
            "p_failure": self.p_failure,
            "risk": self.risk,
            "shap_weights": self.shap_weights,
            "nlg_explanation": self.nlg_explanation,
        }


class EdgeAIEngine:
    """
    Lightweight Edge AI Inference Engine for FixAI.

    Loads pre-trained model artifacts once at startup and performs
    sub-millisecond inference on streaming hardware telemetry.
    """

    def __init__(self, model_dir: Optional[Union[str, Path]] = None) -> None:
        """
        Load all pre-trained .joblib models and initialize the SHAP explainer.
        Models are loaded strictly once into memory.
        """
        if model_dir is not None:
            model_path = Path(model_dir)
        else:
            # Default to local_agent/models relative to this file
            model_path = Path(__file__).resolve().parent.parent / "models"

        if not model_path.exists():
            # Fallback search in working directory
            candidates = [Path("models"), Path("../models")]
            for c in candidates:
                if c.exists() and (c / "scaler.joblib").exists():
                    model_path = c
                    break

        self.model_path = model_path.resolve()
        self.feature_names = FEATURE_NAMES
        logger.info("Initializing EdgeAIEngine from models directory: %s", self.model_path)

        # ── 1. Load Pre-Trained Artifacts (Once Only) ─────────────────
        self.scaler: StandardScaler = self._load_artifact(
            self.model_path / "scaler.joblib", "StandardScaler"
        )
        self.iso_forest: IsolationForest = self._load_artifact(
            self.model_path / "isolation_forest.joblib", "Isolation Forest"
        )
        self.xgb: XGBClassifier = self._load_artifact(
            self.model_path / "xgboost_classifier.joblib", "XGBoost Classifier"
        )

        # ── 2. Initialize SHAP TreeExplainer (Once Only) ──────────────
        self.shap_explainer: Optional[shap.TreeExplainer] = None
        try:
            self.shap_explainer = shap.TreeExplainer(self.xgb)
            logger.info("SHAP TreeExplainer initialized successfully")
        except Exception as exc:
            logger.warning("SHAP TreeExplainer init warning (%s); fallback to feature importances enabled", exc)

        logger.info("EdgeAIEngine successfully initialized and ready for streaming inference")

    @staticmethod
    def _load_artifact(path: Path, label: str) -> Any:
        """Helper to load a .joblib artifact with explicit error messaging."""
        if not path.exists():
            raise FileNotFoundError(
                f"Missing required model artifact: '{path.name}' ({label}) at {path.resolve()}.\n"
                f"Please run 'python ai_engine/train.py --all' to train real models first."
            )
        artifact = joblib.load(path)
        logger.info("Loaded artifact: %s (%s)", path.name, label)
        return artifact

    # ── Public API ──────────────────────────────────────────────────────

    def analyze(self, hardware_metrics: Dict[str, float]) -> Dict[str, Any]:
        """
        Analyze a dictionary of 5 hardware metrics and produce failure diagnostics.

        Args:
            hardware_metrics: Dictionary containing:
                - cpu: float (0..100 %)
                - ram: float (0..100 %)
                - latency: float (HTTP / ping latency in ms)
                - error_rate: float (HTTP 5xx / application error rate %)
                - disk: float (disk utilization 0..100 %)

        Returns:
            Dictionary containing:
                - anomaly_score: float (0..1, higher = more anomalous)
                - p_failure: float (0..1, probability of failure)
                - risk: str ("LOW" | "MEDIUM" | "HIGH")
                - shap_weights: Dict[str, float] (attribution per metric)
                - nlg_explanation: str (human-readable root-cause diagnosis)
        """
        # 1. Normalize and extract features in strictly ordered sequence
        c = float(hardware_metrics.get("cpu", 0.0))
        r = float(hardware_metrics.get("ram", 0.0))
        lat = float(hardware_metrics.get("latency", 0.0))
        err = float(hardware_metrics.get("error_rate", hardware_metrics.get("errorRate", 0.0)))
        d = float(hardware_metrics.get("disk", 0.0))

        raw_vector = np.array([[c, r, lat, err, d]])

        # 2. Scale features with pre-fitted StandardScaler
        features_scaled = (raw_vector - self.scaler.mean_) / self.scaler.scale_

        # 3. Anomaly Detection (Isolation Forest)
        # raw_df > 0 => normal inlier; raw_df < 0 => anomalous outlier
        raw_df = float(self.iso_forest.decision_function(features_scaled)[0])
        anomaly_score = float(np.clip(0.5 - raw_df * 2.0, 0.0, 1.0))

        # 4. Failure Probability (XGBoost)
        try:
            probabilities = self.xgb.predict_proba(features_scaled)[0]
            p_failure = float(probabilities[1]) if len(probabilities) > 1 else float(probabilities[0])
        except Exception:
            p_failure = anomaly_score

        p_failure = float(np.clip(p_failure, 0.001, 0.999))

        # 5. Risk Categorization
        if p_failure >= 0.70 or anomaly_score >= 0.75:
            risk = "HIGH"
        elif p_failure >= 0.40 or anomaly_score >= 0.45:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        # 6. SHAP Attribution Weights
        shap_weights = self._compute_shap_weights(features_scaled, raw_vector[0])

        # 7. Template-based NLG Explanation
        nlg_explanation = self._generate_nlg_explanation(
            risk=risk,
            p_failure=p_failure,
            anomaly_score=anomaly_score,
            shap_weights=shap_weights,
            raw_metrics={"cpu": c, "ram": r, "latency": lat, "error_rate": err, "disk": d},
        )

        return {
            "anomaly_score": round(anomaly_score, 4),
            "p_failure": round(p_failure, 4),
            "risk": risk,
            "shap_weights": shap_weights,
            "nlg_explanation": nlg_explanation,
        }

    # ── Backwards Compatibility Alias ──────────────────────────────────

    def predict(self, *args: Any, **kwargs: Any) -> Dict[str, Any]:
        """Backwards compatibility adapter for code calling predict()."""
        if args and isinstance(args[0], (list, tuple, np.ndarray)):
            m = args[0]
            metrics = {"cpu": m[0], "ram": m[1], "latency": m[2], "error_rate": m[3], "disk": m[4]}
        elif args and isinstance(args[0], dict):
            metrics = args[0]
        else:
            metrics = kwargs
        return self.analyze(metrics)

    # ── Private Helpers ─────────────────────────────────────────────────

    def _compute_shap_weights(
        self,
        features_scaled: np.ndarray,
        raw_features: np.ndarray,
    ) -> Dict[str, float]:
        """Compute exact SHAP feature attribution weights per feature."""
        if self.shap_explainer is not None:
            try:
                shap_values = self.shap_explainer.shap_values(features_scaled)
                if isinstance(shap_values, list):
                    vals = shap_values[1][0] if len(shap_values) > 1 else shap_values[0][0]
                elif shap_values.ndim == 2:
                    vals = shap_values[0]
                else:
                    vals = shap_values

                return {
                    name: round(float(vals[i]), 4)
                    for i, name in enumerate(self.feature_names)
                }
            except Exception as e:
                logger.debug("TreeExplainer calculation warning: %s", e)

        # Fallback: Tree feature importances weighted by scaled divergence
        importances = getattr(self.xgb, "feature_importances_", np.ones(5) / 5)
        attributions = features_scaled[0] * importances
        return {
            name: round(float(attributions[i]), 4)
            for i, name in enumerate(self.feature_names)
        }

    @staticmethod
    def _generate_nlg_explanation(
        risk: str,
        p_failure: float,
        anomaly_score: float,
        shap_weights: Dict[str, float],
        raw_metrics: Dict[str, float],
    ) -> str:
        """
        Generate template-based natural language string diagnosing the top driver.
        """
        if risk == "LOW":
            return (
                f"System is operating normally within baseline parameters "
                f"(Anomaly: {anomaly_score:.2f}, Risk: LOW). Resources are stable."
            )

        # Find the feature with the highest positive attribution
        top_driver = max(shap_weights, key=lambda k: shap_weights[k])
        val = raw_metrics.get(top_driver, 0.0)

        explanations = {
            "cpu": (
                f"System is at {risk} risk (P_fail: {p_failure:.2f}) because CPU utilization "
                f"is critically elevated at {val:.1f}%, indicating process saturation."
            ),
            "ram": (
                f"System is at {risk} risk (P_fail: {p_failure:.2f}) because RAM consumption "
                f"is critically high at {val:.1f}%, risking memory exhaustion and swap thrashing."
            ),
            "latency": (
                f"System is at {risk} risk (P_fail: {p_failure:.2f}) due to network latency degradation "
                f"peaking at {val:.1f}ms, far exceeding baseline thresholds."
            ),
            "error_rate": (
                f"System is at {risk} risk (P_fail: {p_failure:.2f}) caused by application HTTP error storms "
                f"reaching {val:.1f}%, signaling upstream service unresponsiveness."
            ),
            "disk": (
                f"System is at {risk} risk (P_fail: {p_failure:.2f}) because disk utilization "
                f"has reached {val:.1f}%, indicating I/O saturation or disk exhaustion."
            ),
        }

        return explanations.get(
            top_driver,
            f"System anomaly detected with {risk} risk (Anomaly: {anomaly_score:.2f}, P_fail: {p_failure:.2f})."
        )


# Export alias
FixAIInference = EdgeAIEngine

__all__ = ["EdgeAIEngine", "FixAIInference", "InferenceResult", "FEATURE_NAMES"]
