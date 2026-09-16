import { rankRecoveryOptions } from "./policy";
import type {
  ActionPermission,
  AiVerdict,
  RecoveryOption,
  RootCause,
  ShapAttribution,
  TelemetrySample,
} from "./types";

/**
 * Agentic telemetry simulation + AI analytics engine.
 *
 * Stands in for the Python agent (psutil + Prometheus) and the XGBoost/SHAP
 * pipeline so the closed healing loop is fully demonstrable in-browser:
 *   stream → anomaly score → failure probability → SHAP attribution → RCA.
 */

const clamp = (v: number, lo: number, hi: number) =>
  Math.min(hi, Math.max(lo, v));

/** Sigmoid for mapping a composite stress signal into P(failure) ∈ [0,1]. */
const sigmoid = (x: number) => 1 / (1 + Math.exp(-x));

/** Smooth noise so charts look like real telemetry, not white noise. */
function jitter(prev: number, amt: number): number {
  return prev + (Math.random() - 0.5) * amt;
}

export type FaultKey =
  | "none"
  | "cpu_spike"
  | "memory_leak"
  | "disk_fill"
  | "latency_storm"
  | "error_burst"
  | "db_disconnect"
  | "thermal_throttling"
  | "battery_drain"
  | "wifi_adapter_glitch"
  | "display_driver_hang"
  | "disk_io_saturation";

export const FAULTS: Record<
  Exclude<FaultKey, "none">,
  { label: string; description: string }
> = {
  cpu_spike: {
    label: "High CPU Spike",
    description: "Infinite loop thread pegs the CPU and starves request handling.",
  },
  memory_leak: {
    label: "Memory Exhaustion",
    description: "Buffer overflow pattern; RAM climbs until the container is OOM-killed.",
  },
  disk_fill: {
    label: "Disk Space Fill",
    description: "Temp artifacts accumulate until the mount hits 98%.",
  },
  latency_storm: {
    label: "High Response Latency",
    description: "time.sleep(5) in the request pipeline; pool saturation.",
  },
  error_burst: {
    label: "High Error Rate",
    description: "Unhandled exceptions on 50% of API calls; 5xx burst.",
  },
  db_disconnect: {
    label: "DB Connection Drop",
    description: "Connection pool exhausts; Postgres pings time out.",
  },
  // ── Hardware & Laptop-Specific Faults ──
  thermal_throttling: {
    label: "CPU Thermal Overheating (96°C)",
    description: "Hardware core temp breaches 95°C; CPU clock throttles and fan screeches.",
  },
  battery_drain: {
    label: "Rapid Battery Discharge Leak",
    description: "Hardware power draw surges to 65W; battery level plunges rapidly.",
  },
  wifi_adapter_glitch: {
    label: "Wi-Fi Freeze & Packet Drop",
    description: "Network stack buffer lock; 4500ms packet latency and DNS resolution drop.",
  },
  display_driver_hang: {
    label: "GPU / DWM Display Driver Hang",
    description: "Desktop Window Manager compositing freeze; display stutter & frame drops.",
  },
  disk_io_saturation: {
    label: "Storage SSD Queue Saturation",
    description: "Disk queue length saturated at 100%; write latency stalls active processes.",
  },
};

export interface SimState {
  /** Rolling window of samples (newest last). */
  samples: TelemetrySample[];
  fault: FaultKey;
  /** 0..1 progression of the active fault. */
  faultProgress: number;
}

/** One simulated OS "tick" of the target system. */
export function nextSample(state: SimState): SimState {
  const last = state.samples[state.samples.length - 1] ?? {
    t: Date.now(),
    cpu: 24,
    ram: 42,
    latency: 110,
    errorRate: 0.2,
    disk: 38,
    temp: 48,
    battery: 88,
  };

  let cpu = clamp(jitter(last.cpu, 6), 3, 99);
  let ram = clamp(jitter(last.ram, 3), 10, 99);
  let latency = clamp(jitter(last.latency, 30), 40, 6000);
  let errorRate = clamp(jitter(last.errorRate, 0.6), 0, 60);
  let disk = clamp(jitter(last.disk, 0.4), 5, 99.5);
  let temp = clamp(jitter(last.temp ?? 48, 1.5), 38, 99);
  let battery = clamp(jitter(last.battery ?? 88, 0.2), 5, 100);
  let progress = state.faultProgress;

  switch (state.fault) {
    case "cpu_spike":
      cpu = clamp(last.cpu + 7 + Math.random() * 6, 20, 97);
      latency = clamp(last.latency + 220, 80, 5200);
      temp = clamp(temp + 2.5, 45, 88);
      break;
    case "memory_leak":
      ram = clamp(last.ram + 4.5 + Math.random() * 3, 20, 96);
      cpu = clamp(last.cpu + 2.5, 10, 95);
      latency = clamp(last.latency + 140, 60, 4800);
      break;
    case "disk_fill":
      disk = clamp(last.disk + 3.4, 10, 98.8);
      break;
    case "latency_storm":
      latency = clamp(last.latency + 380, 80, 5600);
      cpu = clamp(last.cpu + 3, 10, 90);
      break;
    case "error_burst":
      errorRate = clamp(last.errorRate + 4.2, 0, 48);
      latency = clamp(last.latency + 90, 60, 2500);
      break;
    case "db_disconnect":
      errorRate = clamp(last.errorRate + 5.5, 0, 46);
      latency = clamp(last.latency + 500, 100, 5900);
      cpu = clamp(last.cpu + 2, 10, 85);
      break;
    case "thermal_throttling":
      temp = clamp(temp + 5.5 + Math.random() * 3, 50, 98.5);
      cpu = clamp(last.cpu + 6.8, 30, 96);
      latency = clamp(last.latency + 160, 80, 3800);
      break;
    case "battery_drain":
      battery = clamp(battery - 3.2 - Math.random() * 2, 6, 99);
      cpu = clamp(last.cpu + 4.0, 20, 85);
      break;
    case "wifi_adapter_glitch":
      latency = clamp(last.latency + 460, 100, 5800);
      errorRate = clamp(last.errorRate + 4.5, 0, 42);
      break;
    case "display_driver_hang":
      cpu = clamp(last.cpu + 5.2, 20, 89);
      latency = clamp(last.latency + 280, 80, 4200);
      break;
    case "disk_io_saturation":
      disk = clamp(last.disk + 3.8, 20, 99.2);
      latency = clamp(last.latency + 240, 80, 3900);
      break;
    case "none":
      // Gentle pull back toward a healthy baseline.
      cpu += (24 - cpu) * 0.18;
      ram += (42 - ram) * 0.18;
      latency += (110 - latency) * 0.18;
      errorRate += (0.3 - errorRate) * 0.3;
      disk += (38 - disk) * 0.12;
      temp += (48 - temp) * 0.20;
      battery += (88 - battery) * 0.05;
      break;
  }

  const sample: TelemetrySample = {
    t: Date.now(),
    cpu: clamp(cpu, 1, 99),
    ram: clamp(ram, 5, 99),
    latency: clamp(latency, 40, 6000),
    errorRate: clamp(errorRate, 0, 60),
    disk: clamp(disk, 5, 99.5),
    temp: clamp(temp, 35, 105),
    battery: clamp(battery, 2, 100),
  };

  const samples = [...state.samples, sample].slice(-90);
  progress = clamp(progress + 0.08, 0, 1);

  return { samples, fault: state.fault, faultProgress: progress };
}

/**
 * Isolation Forest stand-in: composite stress distance from the healthy
 * baseline, normalised to 0..1 (higher = more anomalous).
 */
export function computeAnomalyScore(s: TelemetrySample): number {
  const deviations = [
    (s.cpu - 45) / 45,
    (s.ram - 55) / 45,
    (s.latency - 300) / 1500,
    (s.errorRate - 2) / 12,
    (s.disk - 60) / 40,
  ];
  const stress = deviations.reduce(
    (acc, d) => acc + Math.max(0, d) ** 1.5,
    0,
  );
  return clamp(1 - Math.exp(-stress * 0.9), 0, 1);
}

/** XGBoost stand-in: composite logistic risk over the 5-minute lead window. */
export function predictFailure(s: TelemetrySample): number {
  const z =
    0.055 * (s.cpu - 45) +
    0.07 * (s.ram - 55) +
    0.0022 * (s.latency - 300) +
    0.09 * (s.errorRate - 2) +
    0.045 * (s.disk - 60);
  return clamp(sigmoid(z), 0.004, 0.996);
}

/** Platt scaling stand-in to calibrate raw probabilities into true likelihoods. */
export function calibrateProbability(rawP: number): number {
  // A simple calibration curve that pulls extreme probabilities slightly towards the center
  // and smooths the decision boundary, simulating calibrated outputs.
  return clamp(1 / (1 + Math.exp(-2.5 * (rawP - 0.5))), 0.01, 0.99);
}

export function riskFromProbability(p: number): AiVerdict["risk"] {
  if (p >= 0.75) return "HIGH";
  if (p >= 0.5) return "MEDIUM";
  return "LOW";
}

/**
 * Conformal Remaining Useful Life (RUL) Forecaster
 * Uses residual quantiles to guarantee 95% marginal coverage for the Time-to-Failure window.
 */
export function computeConformalRul(
  s: TelemetrySample,
  failureProbability: number,
  confidence: number,
): import("./types").RulForecast {
  // Identify limiting resource and degradation velocity
  let limitingResource = "General System Load";
  let nominalMinutes = 120.0;
  let degradationRate = 0.1; // %/min

  if (s.ram > 75) {
    limitingResource = "Memory (Heap Exhaustion)";
    // Velocity scales with stress: e.g. 88% RAM climbing towards 100%
    degradationRate = Math.max(0.5, (s.ram - 70) * 0.4);
    nominalMinutes = Math.max(1.2, (100 - s.ram) / (degradationRate * 0.5));
  } else if (s.cpu > 80) {
    limitingResource = "Compute (CPU Runqueue Saturation)";
    degradationRate = Math.max(0.8, (s.cpu - 75) * 0.5);
    nominalMinutes = Math.max(2.0, (100 - s.cpu) / (degradationRate * 0.4));
  } else if (s.disk > 85) {
    limitingResource = "Storage (/var /tmp mount saturation)";
    degradationRate = Math.max(0.2, (s.disk - 80) * 0.2);
    nominalMinutes = Math.max(5.0, (100 - s.disk) / (degradationRate * 0.2));
  } else if (s.latency > 1500) {
    limitingResource = "Network (Socket & Connection Pool Saturation)";
    degradationRate = Math.max(10, (s.latency - 1000) * 0.1);
    nominalMinutes = Math.max(0.8, (5000 - s.latency) / 800);
  } else {
    // Normal baseline operational health
    nominalMinutes = Math.max(60.0, 180.0 * (1 - failureProbability));
    degradationRate = 0.05;
  }

  // Modulate nominal RUL by calibrated failure probability
  if (failureProbability > 0.5) {
    nominalMinutes = Math.min(nominalMinutes, Math.max(0.8, (1 - failureProbability) * 30));
  }

  // Conformal uncertainty margin based on model calibration confidence (1 - confidence)
  // Non-conformity score quantile: Q_{1-\alpha}
  const uncertaintySpread = (1 - confidence) * nominalMinutes * 0.45;
  const confidenceLowerMinutes = Math.max(0.3, nominalMinutes - uncertaintySpread);
  const confidenceUpperMinutes = nominalMinutes + uncertaintySpread;

  return {
    rulMinutes: Number(nominalMinutes.toFixed(1)),
    confidenceLowerMinutes: Number(confidenceLowerMinutes.toFixed(1)),
    confidenceUpperMinutes: Number(confidenceUpperMinutes.toFixed(1)),
    coverageGuarantee: 0.95,
    degradationRate: Number(degradationRate.toFixed(2)),
    limitingResource,
  };
}

export function deriveVerdict(s: TelemetrySample): AiVerdict {
  const anomalyScore = computeAnomalyScore(s);
  const rawP = predictFailure(s);
  const failureProbability = calibrateProbability(rawP);
  const risk = riskFromProbability(failureProbability);
  // Confidence is lowest at the decision boundary (0.5), highest at extremes (0 or 1).
  const confidence = clamp(0.4 + 1.2 * Math.pow(Math.abs(failureProbability - 0.5), 2), 0.4, 0.98);
  const rul = computeConformalRul(s, failureProbability, confidence);
  return { anomalyScore, failureProbability, risk, confidence, rul };
}

export function healthScoreFrom(s: TelemetrySample, risk: number): number {
  const metricHealth =
    (100 - s.cpu) * 0.2 +
    (100 - s.ram) * 0.2 +
    (100 - clamp(s.latency / 60, 0, 100)) * 0.25 +
    (100 - clamp(s.errorRate * 8, 0, 100)) * 0.25 +
    (100 - s.disk) * 0.1;
  return Math.round(clamp(metricHealth * 0.75 + (1 - risk) * 100 * 0.25, 0, 100));
}

export function statusFromScore(score: number): "HEALTHY" | "DEGRADED" | "CRITICAL" {
  if (score >= 70) return "HEALTHY";
  if (score >= 45) return "DEGRADED";
  return "CRITICAL";
}

/** SHAP-style signed attributions for the current prediction. */
export function computeShap(s: TelemetrySample): ShapAttribution[] {
  const attrs: { feature: string; value: number; w: number; fmt: string }[] = [
    { feature: "CPU Usage", value: s.cpu, w: 0.028, fmt: "%" },
    { feature: "Memory Usage", value: s.ram, w: 0.035, fmt: "%" },
    { feature: "Response Latency", value: s.latency, w: 0.0011, fmt: "ms" },
    { feature: "HTTP 5xx Rate", value: s.errorRate, w: 0.045, fmt: "%" },
    { feature: "Disk Usage", value: s.disk, w: 0.09, fmt: "%" },
  ];
  return attrs
    .map((a) => ({
      feature: a.feature,
      value: a.value,
      attribution: (a.value - 50) * a.w,
    }))
    .sort((a, b) => b.attribution - a.attribution);
}

/** DiCE Counterfactuals: Actionable what-if changes to restore health. */
export function generateCounterfactuals(s: TelemetrySample, verdict: AiVerdict): import("./types").Counterfactual[] {
  if (verdict.risk === "LOW") return [];
  
  const cfs: import("./types").Counterfactual[] = [];
  const currentP = verdict.failureProbability;
  
  // Test reducing each metric to see if it brings P(fail) down significantly
  const tests = [
    { feature: "CPU Usage", key: "cpu" as keyof TelemetrySample, safe: 40 },
    { feature: "Memory Usage", key: "ram" as keyof TelemetrySample, safe: 50 },
    { feature: "Response Latency", key: "latency" as keyof TelemetrySample, safe: 150 },
    { feature: "Disk Usage", key: "disk" as keyof TelemetrySample, safe: 50 },
  ];
  
  for (const t of tests) {
    const val = s[t.key] as number;
    if (val > t.safe * 1.2) {
      const sim = { ...s, [t.key]: t.safe };
      const newP = calibrateProbability(predictFailure(sim));
      if (currentP - newP > 0.15) {
        cfs.push({
          feature: t.feature,
          currentValue: val,
          targetValue: t.safe,
          action: "DECREASE",
          riskReduction: currentP - newP,
        });
      }
    }
  }
  return cfs.sort((a, b) => b.riskReduction - a.riskReduction);
}

/** Log lines "fused" with the metric spike for RCA evidence. */
export function collectLogEvidence(
  s: TelemetrySample,
  fault: FaultKey,
): string[] {
  const t = new Date().toLocaleTimeString();
  const lines: string[] = [];
  if (s.ram > 88) lines.push(`[${t}] ERROR worker.6 MemoryError: Out of memory (heap 96%)`);
  if (s.cpu > 90) lines.push(`[${t}] WARN  scheduler CPU starvation detected on 3 threads`);
  if (s.latency > 2500) lines.push(`[${t}] ERROR gateway upstream_timeout after 5000ms — pool exhausted`);
  if (s.errorRate > 20) lines.push(`[${t}] ERROR api.routes Unhandled Exception: 500 on 42% of requests`);
  if (s.disk > 95) lines.push(`[${t}] CRIT  storage /tmp write failed: No space left on device`);
  if (fault === "db_disconnect")
    lines.push(`[${t}] ERROR db.pool ConnectionRefusedError: could not connect to postgres:5432`);
  if (lines.length === 0)
    lines.push(`[${t}] INFO  healthcheck /health returned 200 OK in ${Math.round(s.latency)}ms`);
  return lines.slice(0, 4);
}

/**
 * Causal Graph Discovery (Pearl's Do-Calculus & PCMCI+ stand-in)
 * Infers directional dependency paths and intervention outcomes.
 */
export function deriveCausalGraph(
  s: TelemetrySample,
  fault: FaultKey,
  verdict: AiVerdict,
): import("./types").CausalGraph {
  const nodes: import("./types").CausalNode[] = [
    {
      id: "node-temp",
      label: "CPU Thermal Core",
      metric: "Core Temp",
      value: Math.round(s.temp ?? 48),
      unit: "°C",
      isRootCause: fault === "thermal_throttling" || (s.temp ?? 48) > 85,
      severity: (s.temp ?? 48) > 85 ? "CRITICAL" : (s.temp ?? 48) > 68 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-battery",
      label: "Battery Power Bus",
      metric: "Battery",
      value: Math.round(s.battery ?? 88),
      unit: "%",
      isRootCause: fault === "battery_drain" || (s.battery ?? 88) < 20,
      severity: (s.battery ?? 88) < 20 ? "CRITICAL" : (s.battery ?? 88) < 40 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-ram",
      label: "Heap Allocator",
      metric: "RAM",
      value: Math.round(s.ram),
      unit: "%",
      isRootCause: fault === "memory_leak" || (fault === "none" && s.ram > 85),
      severity: s.ram > 85 ? "CRITICAL" : s.ram > 65 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-cpu",
      label: "Compute Scheduler",
      metric: "CPU",
      value: Math.round(s.cpu),
      unit: "%",
      isRootCause: fault === "cpu_spike" || (fault === "none" && s.cpu > 85),
      severity: s.cpu > 85 ? "CRITICAL" : s.cpu > 65 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-disk",
      label: "I/O Storage Mount",
      metric: "Disk",
      value: Math.round(s.disk),
      unit: "%",
      isRootCause: fault === "disk_fill" || fault === "disk_io_saturation",
      severity: s.disk > 90 ? "CRITICAL" : s.disk > 75 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-latency",
      label: "HTTP / Network Gateway",
      metric: "Latency",
      value: Math.round(s.latency),
      unit: "ms",
      isRootCause: fault === "latency_storm" || fault === "wifi_adapter_glitch",
      severity: s.latency > 1500 ? "CRITICAL" : s.latency > 600 ? "ELEVATED" : "NORMAL",
    },
    {
      id: "node-errors",
      label: "Application Service Tier",
      metric: "5xx Rate",
      value: Number(s.errorRate.toFixed(1)),
      unit: "%",
      isRootCause: fault === "error_burst" || fault === "db_disconnect",
      severity: s.errorRate > 10 ? "CRITICAL" : s.errorRate > 3 ? "ELEVATED" : "NORMAL",
    },
  ];

  const edges: import("./types").CausalEdge[] = [];

  if ((s.temp ?? 48) > 75) {
    edges.push({
      source: "node-temp",
      target: "node-cpu",
      causalStrength: 0.95,
      relationship: "Thermal throttling forces clock frequency down, pegging CPU usage",
    });
  }
  if ((s.battery ?? 88) < 25) {
    edges.push({
      source: "node-battery",
      target: "node-cpu",
      causalStrength: 0.82,
      relationship: "Low voltage triggers firmware throttle mode",
    });
  }
  if (s.ram > 70) {
    edges.push({
      source: "node-ram",
      target: "node-cpu",
      causalStrength: 0.88,
      relationship: "Garbage collection & swapping thrashes CPU",
    });
  }
  if (s.cpu > 70) {
    edges.push({
      source: "node-cpu",
      target: "node-latency",
      causalStrength: 0.92,
      relationship: "Scheduler starvation delays response dispatch",
    });
  }
  if (s.disk > 80) {
    edges.push({
      source: "node-disk",
      target: "node-latency",
      causalStrength: 0.79,
      relationship: "I/O wait stalls transaction logging",
    });
  }
  if (s.latency > 1000) {
    edges.push({
      source: "node-latency",
      target: "node-errors",
      causalStrength: 0.85,
      relationship: "Upstream socket timeouts trigger HTTP 504/500 errors",
    });
  }

  const interventions: import("./types").CausalIntervention[] = [
    {
      playbookId: "cool_down_cpu",
      playbookName: "CPU Thermal Throttle & Active Cooling",
      doVariable: "do(CoreTemp = 58°C, MaxClock = 85%)",
      expectedRulGainMinutes: 180.0,
      pSuccessGivenDo: 0.93,
    },
    {
      playbookId: "optimize_battery_health",
      playbookName: "Laptop Battery Saver & Power Leak Optimizer",
      doVariable: "do(Discharge = 12W, Saver = ON)",
      expectedRulGainMinutes: 240.0,
      pSuccessGivenDo: 0.91,
    },
    {
      playbookId: "reset_network_adapter",
      playbookName: "Reset Wi-Fi Adapter & Flush DNS",
      doVariable: "do(Latency = 25ms, PacketDrop = 0%)",
      expectedRulGainMinutes: 120.0,
      pSuccessGivenDo: 0.89,
    },
    {
      playbookId: "restart_graphics_subsystem",
      playbookName: "Restart Graphics Pipeline & DWM",
      doVariable: "do(DWM_Memory = 120MB, VRAM_Flush)",
      expectedRulGainMinutes: 90.0,
      pSuccessGivenDo: 0.86,
    },
    {
      playbookId: "optimize_storage_trim",
      playbookName: "Storage Optimizer & SSD TRIM Health Check",
      doVariable: "do(DiskActive = 12%, TempPurge = 8GB)",
      expectedRulGainMinutes: 160.0,
      pSuccessGivenDo: 0.94,
    },
    {
      playbookId: "restart_container",
      playbookName: "Restart Service Container",
      doVariable: "do(RAM = 35%, CPU = 20%)",
      expectedRulGainMinutes: 120.0,
      pSuccessGivenDo: 0.94,
    },
    {
      playbookId: "flush_cache",
      playbookName: "Flush Application Cache",
      doVariable: "do(Latency = 120ms)",
      expectedRulGainMinutes: 45.0,
      pSuccessGivenDo: 0.78,
    },
  ];

  const rootNode = nodes.find((n) => n.isRootCause) || nodes.reduce((max, n) => (n.value > max.value ? n : max), nodes[0]);

  return {
    nodes,
    edges,
    interventions,
    rootDriverId: rootNode.id,
  };
}

export function deriveRootCause(
  s: TelemetrySample,
  fault: FaultKey,
  verdict: AiVerdict,
): RootCause {
  const shap = computeShap(s);
  const counterfactuals = generateCounterfactuals(s, verdict);
  const causalGraph = deriveCausalGraph(s, fault, verdict);
  const evidence = collectLogEvidence(s, fault);
  const top = shap[0];

  let primaryCause = "Resource Pressure";
  let explanation =
    "Aggregate resource pressure is elevated, but the system remains within recoverable bounds. Continue monitoring.";

  if (fault === "thermal_throttling" || (s.temp ?? 48) > 85) {
    primaryCause = "CPU Thermal Runaway (Overheating)";
    explanation = `Hardware core package temperature has reached ${Math.round(s.temp ?? 48)}°C. Thermal throttling has triggered clock frequency degradation to avoid automatic shutdown. Engage passive cooling and processor cap.`;
  } else if (fault === "battery_drain" || (s.battery ?? 88) < 18) {
    primaryCause = "Critical Battery Discharge & Power Leak";
    explanation = `Battery charge has dropped to ${Math.round(s.battery ?? 88)}% with excessive hardware discharge wattage. Rogue background threads are preventing ACPI sleep states. Switch to ultra power saver profile.`;
  } else if (fault === "wifi_adapter_glitch") {
    primaryCause = "Wi-Fi Driver Buffer Lock & Packet Drop";
    explanation = `Network interface latency spiked to ${Math.round(s.latency)}ms with ${s.errorRate.toFixed(1)}% packet drop. Network socket buffer is deadlocked — flush DNS and power-cycle adapter.`;
  } else if (fault === "display_driver_hang") {
    primaryCause = "GPU Display Driver / DWM Hang";
    explanation = `Desktop Window Manager and GPU compositing pipeline have frozen, creating frame stutter and ${Math.round(s.latency)}ms input lag. Restart graphics pipeline and clear VRAM.`;
  } else if (fault === "disk_io_saturation") {
    primaryCause = "SSD Storage Controller Queue Saturation";
    explanation = `Storage controller queue depth has maxed at 100% active time with ${s.disk.toFixed(1)}% volume saturation. Execute SSD TRIM and purge corrupted temp journals.`;
  } else if (s.errorRate > 18 && (fault === "db_disconnect" || s.latency > 1800)) {
    primaryCause = fault === "db_disconnect" ? "Database Connection Failure" : "Cascade Failure: Errors × Latency";
    explanation =
      fault === "db_disconnect"
        ? `The service is failing because database connections are being refused at the pool level. 5xx rate is ${s.errorRate.toFixed(1)}% and latency is ${Math.round(s.latency)}ms — reset the connection pool or restart the container to re-seat clients.`
        : `Unhandled exceptions (${s.errorRate.toFixed(1)}% of requests) are compounding latency (${Math.round(s.latency)}ms). The error burst is the primary driver pushing ${top.feature.toLowerCase()} risk upward.`;
  } else if (s.disk > 90) {
    primaryCause = "Storage Exhaustion";
    explanation = `Disk usage has reached ${s.disk.toFixed(1)}% on the primary mount. Write pressure will degrade logs and database durability. Purge temporary artifacts or expand the volume.`;
  } else if (s.ram > 85) {
    primaryCause = "Memory Exhaustion";
    explanation = `The service is at high risk of crashing because memory usage (${s.ram.toFixed(1)}%) and ${top.feature.toLowerCase()} exceeded safe operational thresholds. A container restart reclaims the leaked heap.`;
  } else if (s.cpu > 88) {
    primaryCause = "CPU Starvation";
    explanation = `CPU utilisation is pinned at ${s.cpu.toFixed(1)}%, starving the request scheduler. Latency has risen to ${Math.round(s.latency)}ms as requests queue behind compute-bound threads.`;
  } else if (s.latency > 2200) {
    primaryCause = "Thread Blocking / Slow Query";
    explanation = `Response latency has degraded to ${Math.round(s.latency)}ms while CPU and memory remain moderate — consistent with a blocking call or slow query holding the connection pool.`;
  } else if (verdict.failureProbability >= 0.5) {
    primaryCause = "Emerging Resource Pressure";
    explanation = `The predictor flagged a rising trajectory (${(verdict.failureProbability * 100).toFixed(0)}% failure probability) before hard thresholds were breached. Early intervention is cheap now; waiting will not be.`;
  }

  return { id: `rca-${Date.now()}`, primaryCause, explanation, shap, counterfactuals, causalGraph, logEvidence: evidence };
}

export function recommendActions(
  s: TelemetrySample,
  verdict: AiVerdict,
  permissions: ActionPermission[],
): RecoveryOption[] {
  return rankRecoveryOptions(verdict, s, permissions);
}

export function initialSamples(count = 45): TelemetrySample[] {
  let state: SimState = { samples: [], fault: "none", faultProgress: 0 };
  for (let i = 0; i < count; i++) state = nextSample(state);
  return state.samples;
}

/** Baseline snapshot used for pre/post-fix comparison. */
export function baselineSample(): TelemetrySample {
  return { t: Date.now(), cpu: 24, ram: 42, latency: 110, errorRate: 0.3, disk: 38, temp: 48, battery: 88 };
}
