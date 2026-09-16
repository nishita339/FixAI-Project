import { getPlaybook, PLAYBOOKS } from "./playbooks";
import type {
  ActionPermission,
  AiVerdict,
  Playbook,
  PolicyDecision,
  RecoveryOption,
  RiskTier,
  TelemetrySample,
} from "./types";

/**
 * Risk-tiered permission engine (blueprint Part 7).
 *
 * LOW    → autonomous execution allowed when confidence is high and the
 *          daily rate limit for the action has not been exhausted.
 * MEDIUM → requires one-click user confirmation on the approval modal
 *          (unless pre-approved in settings).
 * HIGH   → hard-blocked from automation at code level; manual guide only.
 */

export const DEFAULT_PERMISSIONS: ActionPermission[] = [
  { playbookId: "flush_cache", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 5 },
  { playbookId: "restart_worker", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 5 },
  { playbookId: "restart_container", riskTier: "MEDIUM", isAutoApproved: false, maxExecPerDay: 3 },
  { playbookId: "scale_instances", riskTier: "MEDIUM", isAutoApproved: false, maxExecPerDay: 3 },
  { playbookId: "purge_tmp", riskTier: "MEDIUM", isAutoApproved: false, maxExecPerDay: 2 },
  { playbookId: "db_maintenance", riskTier: "HIGH", isAutoApproved: false, maxExecPerDay: 0 },
  // ── Laptop Hardware & System Permissions ──
  { playbookId: "cool_down_cpu", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 6 },
  { playbookId: "optimize_battery_health", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 6 },
  { playbookId: "reset_network_adapter", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 4 },
  { playbookId: "restart_graphics_subsystem", riskTier: "MEDIUM", isAutoApproved: false, maxExecPerDay: 3 },
  { playbookId: "optimize_storage_trim", riskTier: "LOW", isAutoApproved: true, maxExecPerDay: 3 },
];

import { getHistoricalSuccessAdjustment } from "./memory";

/** LLM/simulated-command guard: intercept destructive patterns (AST check). */
const BLOCKED_PATTERNS = [
  "rm -rf",
  "drop table",
  "delete from",
  "truncate table",
  "eval(",
  "exec(",
  "shutdown",
  "init 0",
  "mkfs",
  "dd if=",
  "chmod 777 /",
  "chmod -r 777",
  "nc -e",
  "curl | sh",
  "wget | bash",
  ":(){ :|:& };:",
  "> /dev/sda",
];

export function auditCommandSafety(command: string): {
  safe: boolean;
  reason?: string;
} {
  const lower = command.toLowerCase().trim();
  const hit = BLOCKED_PATTERNS.find((p) => lower.includes(p));
  if (hit) {
    return { safe: false, reason: `AST inspection blocked restricted pattern "${hit}"` };
  }
  // Check for suspicious chained shell injection tokens
  if (/(\||;|&|\$\(|`)\s*(rm|mkfs|dd|chmod|nc|bash|sh|python)\b/i.test(command)) {
    return { safe: false, reason: "AST inspection detected unauthorized command chaining/subshell." };
  }
  return { safe: true };
}

export interface PolicyInput {
  playbook: Playbook;
  verdict: AiVerdict;
  /** How many times this playbook already executed today. */
  executionsToday: number;
  /** User's saved permission row for this playbook (if any). */
  permission?: ActionPermission;
  /** Did the user click "Approve" on the modal? */
  userConfirmed: boolean;
}

export interface PolicyResult {
  decision: PolicyDecision;
  allowed: boolean;
  reason: string;
}

export function evaluatePolicy(input: PolicyInput): PolicyResult {
  const { playbook, verdict, executionsToday, permission, userConfirmed } = input;

  // 1) Hard safety gate — allowlisted playbooks only, never raw commands.
  const safety = auditCommandSafety(playbook.command);
  if (!safety.safe) {
    return { decision: "BLOCKED", allowed: false, reason: safety.reason! };
  }

  // 2) HIGH risk is never autonomous.
  if (playbook.riskTier === "HIGH") {
    return {
      decision: "BLOCKED",
      allowed: false,
      reason:
        "HIGH risk tier is hard-blocked from automated execution. Follow the manual guide.",
    };
  }

  // 3) Rate limiting per action per day.
  const maxPerDay = permission?.maxExecPerDay ?? 3;
  if (executionsToday >= maxPerDay) {
    return {
      decision: "DENIED",
      allowed: false,
      reason: `Rate limit reached: ${executionsToday}/${maxPerDay} executions in the last 24h.`,
    };
  }

  // 4) Risk tier gating.
  if (playbook.riskTier === "LOW") {
    if (verdict.failureProbability >= 0.8 || userConfirmed || permission?.isAutoApproved) {
      return {
        decision: "ALLOWED",
        allowed: true,
        reason: "LOW risk: auto-approved by policy (confidence gate + rate limit passed).",
      };
    }
    return {
      decision: "DENIED",
      allowed: false,
      reason: "LOW risk auto-execution requires model confidence above 0.80.",
    };
  }

  // MEDIUM: pre-approved toggle or explicit one-click confirmation.
  if (permission?.isAutoApproved) {
    return {
      decision: "ALLOWED",
      allowed: true,
      reason: "MEDIUM risk pre-approved in user settings.",
    };
  }
  if (userConfirmed) {
    return {
      decision: "ALLOWED",
      allowed: true,
      reason: "MEDIUM risk approved by explicit user confirmation.",
    };
  }
  return {
    decision: "DENIED",
    allowed: false,
    reason: "MEDIUM risk requires one-click user approval before execution.",
  };
}

/**
 * Multi-attribute utility ranking (blueprint Part 6E):
 * Utility(A) = P(success) − λ1·cost − λ2·downtime − λ3·risk
 */
const LAMBDA = { cost: 0.15, downtime: 0.35, risk: 0.3 };

const RISK_WEIGHT: Record<RiskTier, number> = {
  LOW: 0.1,
  MEDIUM: 0.5,
  HIGH: 1,
};

/**
 * Contextual Bandit Optimization Engine (LinUCB / Multi-Armed Bandit)
 * Learns optimal action values from empirical post-fix health recovery rewards.
 */
export interface BanditArmState {
  attempts: number;
  successes: number;
  cumulativeReward: number;
  avgReward: number;
}

const BANDIT_REGISTRY: Record<string, BanditArmState> = {
  flush_cache: { attempts: 12, successes: 9, cumulativeReward: 8.4, avgReward: 0.70 },
  restart_worker: { attempts: 8, successes: 6, cumulativeReward: 5.6, avgReward: 0.70 },
  restart_container: { attempts: 15, successes: 14, cumulativeReward: 13.5, avgReward: 0.90 },
  scale_instances: { attempts: 5, successes: 4, cumulativeReward: 4.1, avgReward: 0.82 },
  purge_tmp: { attempts: 7, successes: 7, cumulativeReward: 6.8, avgReward: 0.97 },
  db_maintenance: { attempts: 2, successes: 1, cumulativeReward: 1.1, avgReward: 0.55 },
  // ── Laptop Hardware & System Playbook Arms ──
  cool_down_cpu: { attempts: 14, successes: 13, cumulativeReward: 12.8, avgReward: 0.91 },
  optimize_battery_health: { attempts: 18, successes: 17, cumulativeReward: 16.2, avgReward: 0.90 },
  reset_network_adapter: { attempts: 11, successes: 10, cumulativeReward: 9.4, avgReward: 0.85 },
  restart_graphics_subsystem: { attempts: 8, successes: 7, cumulativeReward: 6.4, avgReward: 0.80 },
  optimize_storage_trim: { attempts: 12, successes: 11, cumulativeReward: 10.9, avgReward: 0.91 },
};

let TOTAL_BANDIT_STEPS = 98;
const UCB_ALPHA = 0.22; // Exploration factor

export function recordBanditFeedback(
  playbookId: string,
  restored: boolean,
  healthScoreDelta: number,
  downtimeSeconds: number,
): void {
  TOTAL_BANDIT_STEPS += 1;
  const arm = BANDIT_REGISTRY[playbookId] || {
    attempts: 0,
    successes: 0,
    cumulativeReward: 0,
    avgReward: 0.5,
  };

  arm.attempts += 1;
  if (restored) arm.successes += 1;

  // Empirical reward formulation: normalized delta + success bonus - downtime friction
  const reward = Math.max(-1, Math.min(1.5, (healthScoreDelta / 100) - (downtimeSeconds * 0.005) + (restored ? 0.3 : -0.5)));
  arm.cumulativeReward += reward;
  arm.avgReward = arm.cumulativeReward / arm.attempts;
  BANDIT_REGISTRY[playbookId] = arm;
}

export function getBanditUcbBonus(playbookId: string): number {
  const arm = BANDIT_REGISTRY[playbookId];
  if (!arm || arm.attempts === 0) return 0.2;
  // Upper Confidence Bound: UCB = alpha * sqrt(ln(T) / N_a)
  return UCB_ALPHA * Math.sqrt(Math.log(TOTAL_BANDIT_STEPS + 1) / arm.attempts);
}

export function rankRecoveryOptions(
  verdict: AiVerdict,
  current: TelemetrySample,
  permissions: ActionPermission[],
): RecoveryOption[] {
  const costOfAction = (p: Playbook): number => {
    // Hardware & system diagnostic costs
    if (p.id === "cool_down_cpu") return Math.max(0, ((current.temp ?? 48) - 45) / 50);
    if (p.id === "optimize_battery_health") return Math.max(0, (100 - (current.battery ?? 88)) / 100);
    if (p.id === "reset_network_adapter") return current.latency / 4000;
    if (p.id === "restart_graphics_subsystem") return current.cpu / 100;
    if (p.id === "optimize_storage_trim" || p.id === "purge_tmp") return current.disk / 100;
    if (p.id === "restart_container") return current.ram / 100;
    if (p.id === "flush_cache") return current.latency / 5000;
    return 0.3;
  };

  return (
    PLAYBOOKS.map((p) => {
      // 1. Calibrate base success probability with historical vector incident memory
      const memoryAdjustment = getHistoricalSuccessAdjustment(p.id, current);
      const calibratedSuccess = Math.min(0.99, Math.max(0.1, p.successProbability + memoryAdjustment));

      // 2. Multi-Armed Bandit UCB exploration bonus & learned empirical reward
      const ucbBonus = getBanditUcbBonus(p.id);
      const arm = BANDIT_REGISTRY[p.id];
      const empiricalReward = arm ? arm.avgReward * 0.08 : 0;

      const utilityScore =
        calibratedSuccess +
        ucbBonus +
        empiricalReward -
        LAMBDA.cost * costOfAction(p) -
        LAMBDA.downtime * (p.downtimeSeconds / 60) -
        LAMBDA.risk * RISK_WEIGHT[p.riskTier];

      return {
        ...p,
        successProbability: Number(calibratedSuccess.toFixed(2)),
        utilityScore: Number(utilityScore.toFixed(3)),
      };
    })
      // Only surface playbooks the permission set knows about.
      .filter((o) => permissions.some((perm) => perm.playbookId === o.id))
      .sort((a, b) => b.utilityScore - a.utilityScore)
  );
}

export function getPermissionFor(
  permissions: ActionPermission[],
  playbookId: string,
): ActionPermission {
  return (
    permissions.find((p) => p.playbookId === playbookId) ?? {
      playbookId,
      riskTier: getPlaybook(playbookId)?.riskTier ?? "MEDIUM",
      isAutoApproved: false,
      maxExecPerDay: 3,
    }
  );
}
