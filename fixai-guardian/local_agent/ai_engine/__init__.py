"""FixAI Edge AI Engine — anomaly detection, failure prediction, SHAP attribution, and RUL hardware life prediction."""

from .inference import EdgeAIEngine, InferenceResult
from .rul_predictor import (
    RULPredictor,
    BatteryHealth,
    StorageHealth,
    RULPredictionResult,
)

__all__ = [
    "EdgeAIEngine",
    "InferenceResult",
    "RULPredictor",
    "BatteryHealth",
    "StorageHealth",
    "RULPredictionResult",
]

