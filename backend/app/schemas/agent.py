from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TelemetryData(BaseModel):
    cpu: float
    ram: float
    latency: float = 0.0
    errorRate: float = Field(default=0.0, alias="error_rate")
    disk: float = 0.0
    battery: Optional[float] = None
    battery_available: Optional[bool] = Field(default=None, alias="batteryAvailable")
    is_plugged: Optional[bool] = Field(default=None, alias="isPlugged")
    temp: Optional[float] = None
    temp_available: Optional[bool] = Field(default=None, alias="tempAvailable")

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
    osquery_data: Optional[Dict[str, Any]] = None
    edr_telemetry: Optional[Dict[str, Any]] = None
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


class BatchIngestPayload(BaseModel):
    batch: List[IngestPayload]
    device_id: Optional[str] = None


class DeviceStatusResponse(BaseModel):
    device_id: str
    name: str
    is_online: bool
    mode: str
    status: str
    health_score: float
    last_heartbeat: Optional[str] = None
    seconds_since_heartbeat: Optional[float] = None
    websocket_clients: int = 0
    server_time: str


class ProcessTreeNode(BaseModel):
    id: str
    name: str
    pid: int
    ppid: int
    cmdline: str = ""
    user: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    create_time: float = 0.0
    status: str = "RUNNING"  # RUNNING, SUSPENDED, TERMINATED, FLAGGED
    is_attacker: bool = False
    mitre_techniques: List[Dict[str, str]] = []
    evasion_flags: List[str] = []
    sha256: Optional[str] = None
    children: List["ProcessTreeNode"] = []


class TerminateProcessPayload(BaseModel):
    pid: int
    device_id: Optional[str] = None
    reason: Optional[str] = "Malicious process terminated via FixAI Process Tree Visualizer"


class CopilotMessage(BaseModel):
    role: str  # "user", "assistant", "system"
    content: str
    timestamp: Optional[str] = None


class CopilotChatPayload(BaseModel):
    message: str
    history: List[CopilotMessage] = []
    device_id: Optional[str] = None
    telemetry_context: Optional[Dict[str, Any]] = None
    incident_context: Optional[Dict[str, Any]] = None


class CopilotChatResponse(BaseModel):
    reply: str
    suggested_actions: List[str] = []
    playbook_recommendations: List[str] = []
    mitre_references: List[str] = []
