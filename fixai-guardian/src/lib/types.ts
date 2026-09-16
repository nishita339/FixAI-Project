/**
 * FixAI — Core domain models.
 *
 * Mirrors the research blueprint's data strategy: live telemetry samples are
 * streamed (never uploaded as CSV), scored by an anomaly detector + failure
 * predictor, explained via SHAP-style feature attributions, and resolved via
 * risk-tiered recovery playbooks with post-fix validation.
 */

export type MetricKey = "cpu" | "ram" | "latency" | "errorRate" | "disk" | "temp" | "battery";

/** One streaming telemetry sample from the connected target system. */
export interface TelemetrySample {
  t: number; // epoch ms
  cpu: number; // %
  ram: number; // %
  latency: number; // ms
  errorRate: number; // %
  disk: number; // %
  temp?: number; // CPU Core Temperature in °C (Hardware)
  battery?: number; // Laptop Battery level in % (Hardware)
}

export type HealthStatus = "HEALTHY" | "DEGRADED" | "CRITICAL";
export type RiskTier = "LOW" | "MEDIUM" | "HIGH";
export type IncidentStatus =
  | "OPEN"
  | "PENDING_APPROVAL"
  | "EXECUTING"
  | "RESOLVED"
  | "ESCALATED"
  | "FAILED";
export type RecoveryMode = "MANUAL" | "AUTOMATED";
export type PolicyDecision = "ALLOWED" | "DENIED" | "BLOCKED";
export type ExecutionStatus = "SUCCESS" | "FAILED" | "BLOCKED";

/** Conformal Remaining Useful Life (RUL) & Time-to-Failure (TTF) Forecast */
export interface RulForecast {
  /** Expected Remaining Useful Life in minutes until system crash/OOM */
  rulMinutes: number;
  /** Conformal prediction lower bound (95% coverage) */
  confidenceLowerMinutes: number;
  /** Conformal prediction upper bound (95% coverage) */
  confidenceUpperMinutes: number;
  /** Conformal coverage guarantee, e.g. 0.95 */
  coverageGuarantee: number;
  /** Rate of metric degradation per minute (%/min or ms/min) */
  degradationRate: number;
  /** Critical metric driving the burnout timeline */
  limitingResource: string;
}

/** Output of the AI analytics pipeline for a telemetry window. */
export interface AiVerdict {
  /** Isolation Forest anomaly score, normalised 0..1 (higher = more anomalous). */
  anomalyScore: number;
  /** XGBoost P(Failure) in [0,1] over the next lead window. */
  failureProbability: number;
  risk: RiskTier;
  /** Model confidence band (uncertainty quantification). */
  confidence: number;
  /** Conformal Remaining Useful Life (RUL) estimation */
  rul: RulForecast;
}

/** SHAP-style feature attribution for the current prediction. */
export interface ShapAttribution {
  feature: string;
  value: number; // raw metric value
  attribution: number; // signed weight pushing risk up/down
}

/** Actionable what-if changes (DiCE) to lower risk. */
export interface Counterfactual {
  feature: string;
  currentValue: number;
  targetValue: number;
  action: "DECREASE" | "INCREASE";
  riskReduction: number;
}

/** Causal AI Node representing an observability variable in the DAG */
export interface CausalNode {
  id: string;
  label: string;
  metric: string;
  value: number;
  unit: string;
  isRootCause: boolean;
  severity: "NORMAL" | "ELEVATED" | "CRITICAL";
}

/** Causal Directed Edge representing Pearl's Do-Calculus influence */
export interface CausalEdge {
  source: string;
  target: string;
  causalStrength: number; // 0..1 weight of causal link
  relationship: string; // e.g. "causes memory pressure"
}

/** Do-Calculus Intervention Outcome Simulation */
export interface CausalIntervention {
  playbookId: string;
  playbookName: string;
  doVariable: string;
  expectedRulGainMinutes: number;
  pSuccessGivenDo: number; // P(Healthy | do(Action))
}

/** Directed Acyclic Graph (DAG) for Root Cause Discovery */
export interface CausalGraph {
  nodes: CausalNode[];
  edges: CausalEdge[];
  interventions: CausalIntervention[];
  rootDriverId: string;
}

/** Identified failure mode plus its evidence trail. */
export interface RootCause {
  id: string;
  primaryCause: string;
  explanation: string; // plain-English diagnostic
  shap: ShapAttribution[];
  counterfactuals?: Counterfactual[];
  causalGraph?: CausalGraph;
  logEvidence: string[];
}

/** A pre-audited recovery playbook (command whitelist, never raw shell). */
export interface Playbook {
  id: string;
  name: string;
  description: string;
  riskTier: RiskTier;
  /** Manual steps rendered in the guide view. */
  manualSteps: string[];
  /** Copyable terminal command for the manual path. */
  command: string;
  /** Whether the policy engine may auto-execute without confirmation. */
  autoAllowed: boolean;
  /** Rough success probability used by the utility ranking. */
  successProbability: number;
  downtimeSeconds: number;
  /** Playbook-specific soak window for validation. */
  verificationWindowSeconds: number;
}

export interface RecoveryOption extends Playbook {
  utilityScore: number;
}

/** A full incident episode: detection → diagnosis → recovery → validation. */
export interface Incident {
  id: string;
  systemId: string;
  systemName: string;
  detectedAt: number;
  resolvedAt?: number;
  status: IncidentStatus;
  failureProbability: number;
  anomalyScore: number;
  risk: RiskTier;
  rootCause: RootCause;
  preFixMetrics: TelemetrySample;
  postFixMetrics?: TelemetrySample;
  mode?: RecoveryMode;
  playbookName?: string;
  policyDecision?: PolicyDecision;
  policyReason?: string;
  executedBy?: "AUTO_AGENT" | "USER";
  isHealthRestored?: boolean;
  soakSeconds?: number;
  scenarioKey?: string; // which fault injection produced this
}

/** One entry of the append-only audit log. */
export interface AuditEntry {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  decision: PolicyDecision | "EXECUTED" | "VALIDATED";
  reason: string;
}

/** Per-action permission configuration managed by the user. */
export interface ActionPermission {
  playbookId: string;
  riskTier: RiskTier;
  isAutoApproved: boolean;
  maxExecPerDay: number;
}

/** Aggregated device state shown on cards / headers. */
export interface SystemSnapshot {
  systemId: string;
  systemName: string;
  status: HealthStatus;
  healthScore: number; // 0..100
  failureRisk: number; // 0..1
  anomalyScore: number;
  current: TelemetrySample;
  lastIncident?: Incident;
  agentOnline: boolean;
  lastSeenAt: number;
  specs: {
    os: string;
    cpuModel: string;
    cores: number;
    ramGb: number;
  };
}

/** Payload used to stream a telemetry batch into the Convex backend. */
export interface TelemetryBatchPayload {
  systemId: string;
  status: HealthStatus;
  healthScore: number;
  failureRisk: number;
  anomalyScore: number;
  samples: TelemetrySample[];
  incident?: SerializedIncident | null;
  audit?: SerializedAuditEntry | null;
  agentOnline: boolean;
}

/** Incident shape with numbers only (Convex-safe serialisation). */
export interface SerializedIncident {
  id: string;
  detectedAt: number;
  resolvedAt: number | null;
  status: IncidentStatus;
  failureProbability: number;
  anomalyScore: number;
  risk: RiskTier;
  rootCauseId: string;
  primaryCause: string;
  explanation: string;
  shap: { feature: string; value: number; attribution: number }[];
  counterfactuals?: { feature: string; currentValue: number; targetValue: number; action: string; riskReduction: number }[];
  logEvidence: string[];
  mode: RecoveryMode | null;
  playbookName: string | null;
  policyDecision: PolicyDecision | null;
  executedBy: string | null;
  isHealthRestored: boolean | null;
  soakSeconds: number | null;
  scenarioKey: string | null;
}

/** Audit entry shape with numbers only (Convex-safe serialisation). */
export interface SerializedAuditEntry {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  decision: string;
  reason: string;
}

/** Row returned by the backend for history/audit views. */
export interface StoredIncident extends SerializedIncident {
  systemName: string;
}

export interface StoredAuditEntry {
  id: string;
  timestamp: number;
  actor: string;
  action: string;
  decision: string;
  reason: string;
}

export interface StoredTelemetrySample {
  t: number;
  cpu: number;
  ram: number;
  latency: number;
  errorRate: number;
  disk: number;
}
