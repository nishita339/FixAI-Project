import { RiskGauge, HealthRing } from "@/components/fixai/RiskGauge";
import { IncidentStatusBadge, RiskTierBadge, StatusBadge } from "@/components/fixai/badges";
import { MetricCard } from "@/components/fixai/MetricCard";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useAgent } from "@/hooks/use-agent-context";
import { FAULTS } from "@/lib/telemetry";
import type { FaultKey } from "@/lib/telemetry";
import type { RecoveryOption } from "@/lib/types";
import {
  Activity,
  ArrowRight,
  BatteryMedium,
  Bug,
  Cpu,
  HardDrive,
  ListChecks,
  MemoryStick,
  MonitorSmartphone,
  RadioTower,
  ShieldCheck,
  Thermometer,
  Timer,
  Wand2,
  Wrench,
  Zap,
  Sparkles,
  Laptop,
  Volume2,
  RotateCcw,
  RefreshCw,
} from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";
import { executeLiveRepair } from "@/lib/history-store";

const DEVICE_SPECS_HINT = "Streaming via local agent · no CSV upload";

export default function Dashboard() {
  const agent = useAgent();
  const {
    current,
    verdict,
    healthScore,
    status,
    episode,
    validationResult,
    fault,
    injectFault,
    clearFault,
    executeAutomated,
    isExecuting,
    isLiveHardware,
    setIsLiveHardware,
    hardwareOnline,
  } = agent;

  const openEpisode = episode;
  const recommended: RecoveryOption | undefined = openEpisode?.options[0];

  return (
    <div className="mx-auto flex w-full max-w-6xl flex-col gap-6">
      {/* ── Header row ─────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">System Health & Live Monitoring</h1>
          <p className="mt-1 flex items-center gap-1.5 text-sm text-muted-foreground">
            <MonitorSmartphone className="size-4" />
            Host Laptop · Windows Real-Time psutil telemetry
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-1.5 text-xs">
            <Link to="/dashboard/hardware">
              <Laptop className="size-3.5 text-primary" /> Laptop Doctor
            </Link>
          </Button>
          <Button asChild variant="outline" size="sm" className="gap-1.5 text-xs">
            <Link to="/dashboard/history">
              <Timer className="size-3.5 text-primary" /> Solved History
            </Link>
          </Button>
          <StatusBadge status={status} className="h-7 px-3 text-xs" />
        </div>
      </div>

      {/* ── Live Telemetry Data Stream Status & Mode Toggle ─────────────── */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-border/80 bg-card/70 p-3 shadow-xs">
        <div className="flex items-center gap-3">
          {isLiveHardware && hardwareOnline ? (
            <>
              <span className="relative flex h-3.5 w-3.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-emerald-500"></span>
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-emerald-600 dark:text-emerald-400">
                    Real-Time Laptop Hardware Telemetry Active
                  </span>
                  <span className="rounded bg-emerald-500/10 px-1.5 py-0.5 text-[10px] font-mono font-medium text-emerald-600 dark:text-emerald-400">
                    HOST PSUTIL LIVE
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Streaming actual CPU, RAM, Disk, Temperature, and Battery from your machine into the self-healing engine.
                </p>
              </div>
            </>
          ) : isLiveHardware && !hardwareOnline ? (
            <>
              <span className="relative flex h-3.5 w-3.5">
                <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-amber-500"></span>
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-amber-600 dark:text-amber-400">
                    Connecting to Host Hardware Agent...
                  </span>
                  <span className="rounded bg-amber-500/10 px-1.5 py-0.5 text-[10px] font-mono font-medium text-amber-600 dark:text-amber-400">
                    CONNECTING
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Waiting for FastAPI telemetry server on http://localhost:8000. Fallback simulation running in interim.
                </p>
              </div>
            </>
          ) : (
            <>
              <span className="relative flex h-3.5 w-3.5">
                <span className="relative inline-flex h-3.5 w-3.5 rounded-full bg-blue-500"></span>
              </span>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold uppercase tracking-wider text-blue-600 dark:text-blue-400">
                    Simulation & Fault Testing Lab Active
                  </span>
                  <span className="rounded bg-blue-500/10 px-1.5 py-0.5 text-[10px] font-mono font-medium text-blue-600 dark:text-blue-400">
                    SIMULATION
                  </span>
                </div>
                <p className="text-xs text-muted-foreground">
                  Testing synthetic hardware and software anomalies for self-healing playbook verification.
                </p>
              </div>
            </>
          )}
        </div>

        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant={isLiveHardware ? "default" : "outline"}
            className="text-xs font-medium"
            onClick={() => {
              setIsLiveHardware(true);
              if (fault !== "none") clearFault();
              toast.info("Switched to Real-Time Host Laptop Telemetry");
            }}
          >
            <RadioTower className="mr-1.5 size-3.5" />
            Live Laptop Data
          </Button>
          <Button
            size="sm"
            variant={!isLiveHardware ? "default" : "outline"}
            className="text-xs font-medium"
            onClick={() => {
              setIsLiveHardware(false);
              toast.info("Switched to Simulation Fault Testing Lab");
            }}
          >
            <Sparkles className="mr-1.5 size-3.5" />
            Simulation Lab
          </Button>
        </div>
      </div>

      {/* ── Hero: health + risk ────────────────────────────────────────── */}
      <Card className="overflow-hidden border-border/70 shadow-soft">
        <CardContent className="grid gap-6 p-6 lg:grid-cols-[1fr_auto]">
          <div className="flex flex-col justify-between gap-5">
            <div>
              <CardTitle className="text-lg">Current health assessment</CardTitle>
              <CardDescription className="mt-1">
                Composite score from CPU, memory, latency, error rate, and disk
                signals — weighted with the model's failure probability.
              </CardDescription>
            </div>
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <MiniStat label="CPU" value={`${current.cpu.toFixed(0)}%`} />
              <MiniStat label="Memory" value={`${current.ram.toFixed(0)}%`} />
              <MiniStat label="Latency" value={`${Math.round(current.latency)}ms`} />
              <MiniStat label="5xx rate" value={`${current.errorRate.toFixed(1)}%`} />
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link to="/dashboard/monitor">
                  <Activity className="size-4" /> Live charts
                </Link>
              </Button>
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link to="/dashboard/incidents">
                  <ListChecks className="size-4" /> Incidents
                </Link>
              </Button>
            </div>
          </div>

          <div className="flex flex-row items-center justify-center gap-6 lg:flex-col lg:gap-4">
            <HealthRing score={healthScore} />
            <RiskGauge probability={verdict.failureProbability} tier={verdict.risk} confidence={verdict.confidence} rul={verdict.rul} size={170} />
          </div>
        </CardContent>
      </Card>

      {/* ── Metric cards ───────────────────────────────────────────────── */}
      <div className="grid gap-4 sm:grid-cols-2 md:grid-cols-3 xl:grid-cols-6">
        <MetricCard
          icon={Cpu}
          label="CPU usage"
          value={current.cpu.toFixed(0)}
          unit="%"
          progress={current.cpu}
          tone={current.cpu > 85 ? "bad" : current.cpu > 65 ? "warn" : "good"}
          hint={current.cpu > 85 ? "starved" : "nominal"}
        />
        <MetricCard
          icon={Thermometer}
          label="Core Temp"
          value={(current.temp ?? 48).toFixed(0)}
          unit="°C"
          progress={Math.min(100, ((current.temp ?? 48) / 100) * 100)}
          tone={(current.temp ?? 48) > 85 ? "bad" : (current.temp ?? 48) > 70 ? "warn" : "good"}
          hint={(current.temp ?? 48) > 85 ? "throttling" : (current.temp ?? 48) > 70 ? "warm" : "cool"}
        />
        <MetricCard
          icon={BatteryMedium}
          label="Battery"
          value={(current.battery ?? 88).toFixed(0)}
          unit="%"
          progress={current.battery ?? 88}
          tone={(current.battery ?? 88) < 20 ? "bad" : (current.battery ?? 88) < 40 ? "warn" : "good"}
          hint={(current.battery ?? 88) < 20 ? "critical" : (current.battery ?? 88) < 40 ? "discharging" : "optimal"}
        />
        <MetricCard
          icon={MemoryStick}
          label="Memory"
          value={current.ram.toFixed(0)}
          unit="%"
          progress={current.ram}
          tone={current.ram > 85 ? "bad" : current.ram > 65 ? "warn" : "good"}
          hint={current.ram > 85 ? "pressure" : "nominal"}
        />
        <MetricCard
          icon={Zap}
          label="Latency p95"
          value={Math.round(current.latency).toString()}
          unit="ms"
          progress={Math.min(100, current.latency / 50)}
          tone={current.latency > 2000 ? "bad" : current.latency > 800 ? "warn" : "good"}
          hint={current.latency > 2000 ? "degraded" : "healthy"}
        />
        <MetricCard
          icon={HardDrive}
          label="Disk"
          value={current.disk.toFixed(0)}
          unit="%"
          progress={current.disk}
          tone={current.disk > 90 ? "bad" : current.disk > 75 ? "warn" : "good"}
          hint={current.disk > 90 ? "nearly full" : "nominal"}
        />
      </div>

      {/* ── Active episode banner ──────────────────────────────────────── */}
      {openEpisode ? (
        <Card className="border-red-500/30 bg-red-500/[0.04] shadow-soft-lg">
          <CardHeader className="pb-3">
            <div className="flex flex-wrap items-center gap-2">
              <IncidentStatusBadge status={openEpisode.incident.status} />
              <RiskTierBadge tier={openEpisode.incident.risk} />
              <span className="text-xs text-muted-foreground">
                detected {new Date(openEpisode.incident.detectedAt).toLocaleTimeString()}
              </span>
            </div>
            <CardTitle className="mt-2 text-lg">
              {openEpisode.incident.rootCause.primaryCause}
            </CardTitle>
            <CardDescription className="mt-1 max-w-3xl text-sm leading-relaxed">
              {openEpisode.incident.rootCause.explanation}
            </CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <p className="flex-1 text-sm text-muted-foreground">
              Recommended: <span className="font-medium text-foreground">{recommended?.name}</span>{" "}
              · <RiskTierBadge tier={recommended?.riskTier ?? "MEDIUM"} className="align-middle" />
            </p>
            <div className="flex gap-2">
              <Button asChild variant="outline" size="sm" className="gap-1.5">
                <Link to="/dashboard/recovery">
                  <Wrench className="size-4" /> Manual guide
                </Link>
              </Button>
              <Button
                size="sm"
                className="gap-1.5"
                disabled={isExecuting}
                onClick={() => {
                  if (!recommended) return;
                  void executeAutomated(recommended).then(() =>
                    toast.success("Automated recovery finished — see Recovery page."),
                  );
                }}
              >
                <Wand2 className="size-4" />
                {isExecuting ? "Executing…" : "Auto-fix"}
              </Button>
            </div>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-emerald-500/25 bg-emerald-500/[0.04] shadow-soft">
          <CardContent className="flex items-center gap-3 p-5">
            <ShieldCheck className="size-5 shrink-0 text-emerald-600 dark:text-emerald-400" />
            <p className="text-sm text-muted-foreground">
              <span className="font-medium text-foreground">No active incidents.</span>{" "}
              The agent is streaming telemetry and evaluating predictions every 2 seconds.
            </p>
          </CardContent>
        </Card>
      )}

      {/* ── Real-World Laptop Hardware & Software Self-Healing Suite ───── */}
      <Card className="border-border/70 shadow-soft">
        <CardHeader className="pb-3">
          <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-2">
            <div className="flex items-center gap-2">
              <Wrench className="size-4.5 text-primary" />
              <CardTitle className="text-base">Real-World Laptop Self-Healing Suite</CardTitle>
            </div>
            <Button asChild size="sm" variant="ghost" className="h-7 text-xs text-primary gap-1">
              <Link to="/dashboard/hardware">
                Open Laptop Doctor <ArrowRight className="size-3.5" />
              </Link>
            </Button>
          </div>
          <CardDescription>
            One-click automated remediations for physical hardware (Battery, SSD, Thermal) and Windows software (Wi-Fi, Audio, Updates).
          </CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2">
          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Running CPU Thermal Throttling Mitigation...");
              const res = await executeLiveRepair("cool_down_cpu", "CPU Thermal Throttling Mitigation", "Hardware");
              toast.success(res.logs[res.logs.length - 1] || "CPU cooling enforced!");
            }}
          >
            <Thermometer className="size-3.5 text-red-500" />
            Cool Down CPU
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Calibrating Battery ACPI & Power Saver...");
              const res = await executeLiveRepair("optimize_battery_health", "Battery ACPI & Power Calibration", "Hardware");
              toast.success(res.logs[res.logs.length - 1] || "Battery calibrated!");
            }}
          >
            <BatteryMedium className="size-3.5 text-amber-500" />
            Calibrate Battery
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Flushing DNS and recycling Winsock stack...");
              const res = await executeLiveRepair("reset_network_adapter", "Wi-Fi DNS Flush & Winsock Stack Reset", "Hardware");
              toast.success(res.logs[res.logs.length - 1] || "Network stack reset!");
            }}
          >
            <RotateCcw className="size-3.5 text-emerald-500" />
            Reset Wi-Fi / DNS
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Executing SSD TRIM and cleaning temp files...");
              const res = await executeLiveRepair("optimize_storage_trim", "SSD Hardware TRIM & Sector Clean", "Hardware");
              toast.success(res.logs[res.logs.length - 1] || "SSD trimmed!");
            }}
          >
            <HardDrive className="size-3.5 text-blue-500" />
            SSD TRIM & Clean
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Recycling Windows Audio Services...");
              const res = await executeLiveRepair("restart_audio_service", "Restart Windows Audio & Endpoint Services", "Software");
              toast.success(res.logs[res.logs.length - 1] || "Audio services restarted!");
            }}
          >
            <Volume2 className="size-3.5 text-indigo-500" />
            Restart Audio
          </Button>

          <Button
            variant="outline"
            size="sm"
            className="gap-1.5 text-xs"
            onClick={async () => {
              toast.info("Purging Windows Update download cache...");
              const res = await executeLiveRepair("fix_windows_update", "Reset Windows Update Cache & BITS", "Software");
              toast.success(res.logs[res.logs.length - 1] || "Update cache cleared!");
            }}
          >
            <RefreshCw className="size-3.5 text-purple-500" />
            Fix Windows Update
          </Button>
        </CardContent>
      </Card>

      {/* ── Collapsed Developer Test Sandbox (Optional) ────────────────── */}
      <details className="rounded-lg border border-border/50 bg-muted/20 p-3 text-xs">
        <summary className="cursor-pointer font-medium text-muted-foreground hover:text-foreground">
          Developer Test Sandbox (Optional Synthetic Anomaly Testing)
        </summary>
        <div className="mt-3 flex flex-wrap gap-2">
          {(Object.keys(FAULTS) as Exclude<FaultKey, "none">[]).map((key) => (
            <Button
              key={key}
              variant={fault === key ? "default" : "outline"}
              size="sm"
              className="gap-1.5 text-xs"
              onClick={() => injectFault(key)}
            >
              <Zap className="size-3.5" />
              {FAULTS[key].label}
            </Button>
          ))}
          {fault !== "none" && (
            <Button variant="ghost" size="sm" onClick={clearFault} className="text-xs">
              Clear fault
            </Button>
          )}
        </div>
      </details>

      {/* ── Validation proof ───────────────────────────────────────────── */}
      {validationResult ? (
        <Card className="border-border/70 shadow-soft">
          <CardHeader className="pb-3">
            <div className="flex items-center gap-2">
              <ShieldCheck
                className={
                  validationResult.restored
                    ? "size-4.5 text-emerald-600 dark:text-emerald-400"
                    : "size-4.5 text-red-600 dark:text-red-400"
                }
              />
              <CardTitle className="text-base">
                Post-fix validation · {validationResult.restored ? "PASSED" : "FAILED"}
              </CardTitle>
            </div>
            <CardDescription>
              15-second telemetry soak comparing pre-fix vs post-fix signals.
            </CardDescription>
          </CardHeader>
          <CardContent className="grid gap-3 sm:grid-cols-5">
            <CompareChip label="CPU" pre={validationResult.pre.cpu} post={validationResult.post.cpu} unit="%" />
            <CompareChip label="Memory" pre={validationResult.pre.ram} post={validationResult.post.ram} unit="%" />
            <CompareChip label="Latency" pre={validationResult.pre.latency} post={validationResult.post.latency} unit="ms" />
            <CompareChip label="5xx" pre={validationResult.pre.errorRate} post={validationResult.post.errorRate} unit="%" />
            <CompareChip label="Disk" pre={validationResult.pre.disk} post={validationResult.post.disk} unit="%" />
          </CardContent>
        </Card>
      ) : null}

      {/* ── Quick links ────────────────────────────────────────────────── */}
      <div className="grid gap-4 sm:grid-cols-3">
        <QuickLink
          to="/dashboard/history"
          icon={Timer}
          title="History & audit"
          body="Every incident, execution, and policy decision — append-only."
        />
        <QuickLink
          to="/dashboard/permissions"
          icon={RadioTower}
          title="Permissions & risk"
          body="Tune which playbooks the agent may run autonomously."
        />
        <QuickLink
          to="/dashboard/recovery"
          icon={ArrowRight}
          title="Recovery center"
          body="Manual playbooks and guarded automated execution."
        />
      </div>
    </div>
  );
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-border/60 bg-muted/40 px-3 py-2.5">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums">{value}</p>
    </div>
  );
}

function CompareChip({
  label,
  pre,
  post,
  unit,
}: {
  label: string;
  pre: number;
  post: number;
  unit: string;
}) {
  const better = post <= pre;
  return (
    <div className="rounded-lg border border-border/60 bg-muted/40 p-3">
      <p className="text-xs font-medium text-muted-foreground">{label}</p>
      <p className="mt-1 flex items-baseline gap-1.5 text-sm tabular-nums">
        <span className="text-muted-foreground line-through decoration-red-400/60">
          {pre.toFixed(0)}
          {unit}
        </span>
        <ArrowRight className="size-3 text-muted-foreground" />
        <span
          className={
            better
              ? "font-semibold text-emerald-600 dark:text-emerald-400"
              : "font-semibold text-red-600 dark:text-red-400"
          }
        >
          {post.toFixed(0)}
          {unit}
        </span>
      </p>
    </div>
  );
}

function QuickLink({
  to,
  icon: Icon,
  title,
  body,
}: {
  to: string;
  icon: typeof Timer;
  title: string;
  body: string;
}) {
  return (
    <Link
      to={to}
      className="group rounded-xl border border-border/70 bg-card p-5 shadow-soft transition-all hover:-translate-y-0.5 hover:shadow-soft-lg"
    >
      <div className="flex items-center justify-between">
        <Icon className="size-5 text-primary" />
        <ArrowRight className="size-4 text-muted-foreground transition-transform group-hover:translate-x-0.5" />
      </div>
      <p className="mt-3 font-semibold tracking-tight">{title}</p>
      <p className="mt-1 text-sm text-muted-foreground">{body}</p>
    </Link>
  );
}
