import type { TelemetrySample } from "./types";

/**
 * Historical Incident Episode in Vector Memory.
 * Represents a past incident, its telemetry feature vector, the applied playbook, and the outcome.
 */
export interface IncidentMemoryRecord {
  id: string;
  timestamp: number;
  featureVector: number[]; // [cpu/100, ram/100, latency/5000, errorRate/100, disk/100]
  primaryCause: string;
  playbookId: string;
  resolved: boolean;
  downtimeObservedSeconds: number;
  postFixHealthScore: number;
}

/** Pre-seeded historical cases based on real operational patterns */
export const SEED_INCIDENT_MEMORY: IncidentMemoryRecord[] = [
  {
    id: "hist-001",
    timestamp: Date.now() - 86400000 * 3,
    featureVector: [0.94, 0.45, 0.48, 0.02, 0.40],
    primaryCause: "CPU Starvation",
    playbookId: "restart_worker",
    resolved: true,
    downtimeObservedSeconds: 3,
    postFixHealthScore: 94,
  },
  {
    id: "hist-002",
    timestamp: Date.now() - 86400000 * 2,
    featureVector: [0.35, 0.92, 0.32, 0.05, 0.42],
    primaryCause: "Memory Exhaustion",
    playbookId: "restart_container",
    resolved: true,
    downtimeObservedSeconds: 11,
    postFixHealthScore: 96,
  },
  {
    id: "hist-003",
    timestamp: Date.now() - 86400000 * 2,
    featureVector: [0.30, 0.50, 0.85, 0.35, 0.38],
    primaryCause: "Cascade Failure: Errors × Latency",
    playbookId: "flush_cache",
    resolved: true,
    downtimeObservedSeconds: 1,
    postFixHealthScore: 91,
  },
  {
    id: "hist-004",
    timestamp: Date.now() - 86400000 * 1,
    featureVector: [0.25, 0.40, 0.10, 0.01, 0.96],
    primaryCause: "Storage Exhaustion",
    playbookId: "purge_tmp",
    resolved: true,
    downtimeObservedSeconds: 2,
    postFixHealthScore: 98,
  },
  {
    id: "hist-005",
    timestamp: Date.now() - 43200000,
    featureVector: [0.88, 0.82, 0.65, 0.20, 0.45],
    primaryCause: "High CPU Spike",
    playbookId: "scale_instances",
    resolved: true,
    downtimeObservedSeconds: 8,
    postFixHealthScore: 95,
  },
];

/**
 * Normalizes a TelemetrySample into a 5-dimensional feature vector in [0, 1].
 */
export function extractFeatureVector(s: TelemetrySample): number[] {
  return [
    Math.min(1, Math.max(0, s.cpu / 100)),
    Math.min(1, Math.max(0, s.ram / 100)),
    Math.min(1, Math.max(0, s.latency / 5000)),
    Math.min(1, Math.max(0, s.errorRate / 100)),
    Math.min(1, Math.max(0, s.disk / 100)),
  ];
}

/**
 * Computes Cosine Similarity between two N-dimensional vectors.
 */
export function cosineSimilarity(a: number[], b: number[]): number {
  if (a.length !== b.length) return 0;
  let dotProduct = 0;
  let normA = 0;
  let normB = 0;
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }
  if (normA === 0 || normB === 0) return 0;
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
}

export interface MatchPrecedent {
  record: IncidentMemoryRecord;
  similarity: number;
}

/**
 * Vector Search: Retrieves the top-K most similar historical incidents from memory.
 */
export function findSimilarIncidents(
  sample: TelemetrySample,
  memory: IncidentMemoryRecord[] = SEED_INCIDENT_MEMORY,
  topK: number = 3,
): MatchPrecedent[] {
  const queryVector = extractFeatureVector(sample);
  const scored = memory.map((rec) => ({
    record: rec,
    similarity: cosineSimilarity(queryVector, rec.featureVector),
  }));

  return scored
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, topK);
}

/**
 * Outcome Calibration: Adjusts a playbook's estimated success probability
 * based on similarity-weighted historical outcomes.
 */
export function getHistoricalSuccessAdjustment(
  playbookId: string,
  sample: TelemetrySample,
  memory: IncidentMemoryRecord[] = SEED_INCIDENT_MEMORY,
): number {
  const matches = findSimilarIncidents(sample, memory, 5);
  const relevant = matches.filter((m) => m.record.playbookId === playbookId);

  if (relevant.length === 0) return 0;

  let totalWeight = 0;
  let weightedSuccess = 0;

  for (const m of relevant) {
    totalWeight += m.similarity;
    weightedSuccess += m.similarity * (m.record.resolved ? 0.15 : -0.25);
  }

  return totalWeight > 0 ? weightedSuccess / totalWeight : 0;
}
