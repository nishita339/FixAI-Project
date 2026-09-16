from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TelemetryData(BaseModel):
    cpu: float
    ram: float
    latency: float = 0.0
    errorRate: float = Field(default=0.0, alias="error_rate")
    disk: float = 0.0

    class Config:
        populate_by_name = True


class AiVerdict(BaseModel):
    anomalyScore: float = Field(default=0.0, alias="anomaly_score")
    pFailure: float = Field(default=0.0, alias="p_failure")
    risk: str = "LOW"
    confidence: float = 1.0

    class Config:
        populate_by_name = True


class ShapItem(BaseModel):
    feature: str
    value: float = 0.0
    attribution: float = 0.0


class IngestPayload(BaseModel):
    device_name: Optional[str] = None
    device_id: Optional[str] = None
    timestamp: Optional[int] = None
    specs: Optional[Dict[str, Any]] = None
    telemetry: Optional[TelemetryData] = None
    metrics: Optional[TelemetryData] = None
    ai_verdict: Optional[AiVerdict] = None
    ai_results: Optional[AiVerdict] = None
    shap: Optional[Any] = None
    shap_weights: Optional[Dict[str, float]] = None
    nlg_explanation: Optional[str] = None
    incident: Optional[Dict[str, Any]] = None
    audit: Optional[Dict[str, Any]] = None

    def get_telemetry(self) -> TelemetryData:
        """Resolve telemetry from either 'telemetry' or 'metrics' key."""
        if self.telemetry:
            return self.telemetry
        if self.metrics:
            return self.metrics
        return TelemetryData(cpu=0.0, ram=0.0)

    def get_verdict(self) -> AiVerdict:
        """Resolve AI verdict from either 'ai_verdict' or 'ai_results' key."""
        if self.ai_verdict:
            return self.ai_verdict
        if self.ai_results:
            return self.ai_results
        return AiVerdict()


class ResolvePayload(BaseModel):
    incident_id: Optional[str] = None
    action_id: Optional[str] = None
    status: str
    is_health_restored: Optional[bool] = False
    mode: Optional[str] = "AUTOMATED"
    playbook_name: Optional[str] = "Unknown"
    action_name: Optional[str] = None
    post_fix_note: Optional[str] = "Resolved by agent"
    note: Optional[str] = None
    soak_seconds: Optional[int] = 15
    post_fix_metrics: Optional[Dict[str, Any]] = None
    post_fix_anomaly_score: Optional[float] = None
    post_fix_p_failure: Optional[float] = None


class ClaimPayload(BaseModel):
    incident_id: str
    agent_name: Optional[str] = "fixai-agent"
