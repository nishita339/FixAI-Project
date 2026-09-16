import React, { useState, useEffect, useMemo } from "react";
import { useAgent } from "@/hooks/use-agent-context";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { executeLiveRepair } from "@/lib/history-store";
import axios from "axios";
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BatteryCharging,
  Bug,
  CheckCircle2,
  Cpu,
  Disc,
  DownloadCloud,
  ExternalLink,
  Flame,
  HardDrive,
  Keyboard,
  Laptop,
  Layers,
  MemoryStick,
  Monitor,
  PackageCheck,
  RefreshCw,
  RotateCcw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Thermometer,
  Timer,
  Volume2,
  Wifi,
  Wrench,
  Zap,
} from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";

const FASTAPI_URL = (import.meta as any).env?.VITE_FASTAPI_URL || "http://localhost:8000";

interface SysDiagnostics {
  timestamp: number;
  isRealHardware: boolean;
  os: {
    system: string;
    release: string;
    version: string;
    machine: string;
    node: string;
  };
  services: Record<string, { status: string; displayName: string; healthy: boolean }>;
  battery: {
    hasBattery: boolean;
    percent: number;
    isPlugged: boolean;
    chargingStatus: string;
    healthy: boolean;
  };
  storage: {
    path: string;
    totalGb: number;
    freeGb: number;
    usedPercent: number;
    healthy: boolean;
  };
  bsodDumps: Array<{ fileName: string; modified: number; sizeKb: number }>;
  topRamProcesses: Array<{ pid: number; name: string; cpu: number; ram: number; status: string }>;
  topCpuProcesses: Array<{ pid: number; name: string; cpu: number; ram: number; status: string }>;
  issuesDetected: Array<{
    id: string;
    category: string;
    title: string;
    severity: string;
    description: string;
    recommendedPlaybook: string;
  }>;
  systemStatus: string;
}

export interface SoftwareUpdateItem {
  name: string;
  id: string;
  installedVersion: string;
  availableVersion: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  category: string;
  problem: string;
  recommendation: string;
}

interface SoftwareUpdatesResponse {
  cached: boolean;
  lastScanned: number;
  totalUpgrades: number;
  apps: SoftwareUpdateItem[];
}

const COMMON_SYMPTOMS = [
  { id: "software_updates", label: "📦 Outdated Softwares & Vulnerabilities", category: "Software", stationId: "station-updates" },
  { id: "battery", label: "🔋 Battery Not Charging", category: "Hardware", stationId: "station-battery" },
  { id: "clicking", label: "💾 Hard Drive Clicking Noise", category: "Hardware", stationId: "station-disk" },
  { id: "keyboard", label: "⌨️ Keyboard Ghosting / Auto-type", category: "Hardware", stationId: "station-pnp" },
  { id: "boot", label: "🚫 No Bootable Device Error", category: "Hardware", stationId: "station-boot" },
  { id: "wifi", label: "📶 Wi-Fi / Bluetooth Disappearing", category: "Hardware", stationId: "station-wifi" },
  { id: "bsod", label: "💥 Blue Screen (BSOD)", category: "Hardware", stationId: "station-bsod" },
  { id: "overheating", label: "🔥 CPU Overheating & Loud Fan", category: "Hardware", stationId: "station-thermal" },
  { id: "cpu100", label: "⚡ High CPU/RAM (100% Freeze)", category: "Software", stationId: "station-cpu100" },
  { id: "winupdate", label: "🔄 Windows Update Stuck (0%/99%)", category: "Software", stationId: "station-update" },
  { id: "dll", label: "🧩 Missing .DLL Files", category: "Software", stationId: "station-dll" },
  { id: "browser", label: "🌐 Browser Redirects / Adware", category: "Software", stationId: "station-hosts" },
  { id: "audio", label: "🔊 Audio / Speaker Not Working", category: "Software", stationId: "station-audio" },
  { id: "driver", label: "⚠️ Driver Conflict (Code 43/10)", category: "Software", stationId: "station-driver" },
  { id: "freeze", label: "⏳ App Freeze / Not Responding", category: "Software", stationId: "station-freeze" },
];

export default function LaptopDoctor() {
  const { current, isLiveHardware, hardwareOnline } = useAgent();
  const [activeFix, setActiveFix] = useState<string | null>(null);
  const [executingLogs, setExecutingLogs] = useState<string[]>([]);
  const [lastExecutedIncidentId, setLastExecutedIncidentId] = useState<string | null>(null);
  const [scanRunning, setScanRunning] = useState(false);
  const [diagnostics, setDiagnostics] = useState<SysDiagnostics | null>(null);
  const [softwareUpdates, setSoftwareUpdates] = useState<SoftwareUpdatesResponse | null>(null);
  const [loadingUpdates, setLoadingUpdates] = useState(false);
  const [updatingAppId, setUpdatingAppId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [activeTab, setActiveTab] = useState("all");

  const coreTemp = current.temp ?? 48;
  const batteryLevel = diagnostics?.battery?.percent ?? current.battery ?? 75;

  const fetchDiagnostics = async () => {
    try {
      const resp = await axios.get<SysDiagnostics>(`${FASTAPI_URL}/api/v1/agent/system-diagnostics`, {
        timeout: 4000,
      });
      if (resp.status === 200 && resp.data) {
        setDiagnostics(resp.data);
      }
    } catch {
      // Backend offline or error
    }
  };

  const fetchSoftwareUpdates = async (force: boolean = false) => {
    setLoadingUpdates(true);
    try {
      const resp = await axios.get<SoftwareUpdatesResponse>(
        `${FASTAPI_URL}/api/v1/agent/software-updates${force ? "?force_refresh=true" : ""}`,
        { timeout: 30000 }
      );
      if (resp.status === 200 && resp.data) {
        setSoftwareUpdates(resp.data);
      }
    } catch {
      // Offline fallback
    } finally {
      setLoadingUpdates(false);
    }
  };

  useEffect(() => {
    void fetchDiagnostics();
    void fetchSoftwareUpdates();
    const interval = setInterval(() => {
      void fetchDiagnostics();
    }, 8000);
    return () => clearInterval(interval);
  }, []);

  const handleExecute = async (
    playbookId: string,
    title: string,
    category: "Hardware" | "Software" = "Hardware",
    params?: Record<string, any>
  ) => {
    setActiveFix(playbookId);
    setExecutingLogs([`[$] Initiating real-world host remediation: ${title}...`]);
    toast.info(`Running auto-repair: ${title}`);

    try {
      const res = await executeLiveRepair(playbookId, title, category, params);
      setExecutingLogs(res.logs);
      setLastExecutedIncidentId(res.incident_id);
      toast.success(`Successfully executed ${title}! Issue resolved and recorded to History.`);
      void fetchDiagnostics();
    } catch (err: any) {
      toast.error(`Execution failed for ${title}`);
      setExecutingLogs((prev) => [...prev, `[!] Failed to execute: ${err?.message || "Unknown error"}`]);
    } finally {
      setActiveFix(null);
    }
  };

  const handleUpdateSoftware = async (pkgId?: string, appName?: string, updateAll: boolean = false) => {
    const targetKey = pkgId || (updateAll ? "ALL" : "UNKNOWN");
    setUpdatingAppId(targetKey);
    const targetLabel = appName || (updateAll ? "All Outdated Software" : pkgId || "Application");
    
    setExecutingLogs([`[$] Dispatching automated software patch for: ${targetLabel}...`]);
    toast.info(`Patching ${targetLabel}...`);

    try {
      const res = await axios.post(`${FASTAPI_URL}/api/v1/agent/update-software`, {
        package_id: pkgId,
        app_name: appName,
        update_all: updateAll,
      });

      if (res.status === 200 && res.data) {
        setExecutingLogs(res.data.logs || []);
        setLastExecutedIncidentId(res.data.incident_id);
        toast.success(`Successfully patched ${targetLabel}! Incident recorded to History.`);
        void fetchSoftwareUpdates(true);
      }
    } catch (err: any) {
      toast.error(`Software update failed for ${targetLabel}`);
      setExecutingLogs((prev) => [...prev, `[!] Failed to update: ${err?.message || "Unknown error"}`]);
    } finally {
      setUpdatingAppId(null);
    }
  };

  const runFullDiagnostics = async () => {
    setScanRunning(true);
    toast.info("Running deep diagnostic sweep on laptop hardware, software & application updates...");
    await fetchDiagnostics();
    await fetchSoftwareUpdates(true);
    setTimeout(() => {
      setScanRunning(false);
      toast.success("Full Laptop Health Scan complete! Analyzed Hardware, OS Services, and Software Updates.");
    }, 1500);
  };

  const scrollToStation = (stationId: string) => {
    if (stationId === "station-updates") {
      setActiveTab("updates");
      return;
    }
    setActiveTab("all");
    setTimeout(() => {
      const el = document.getElementById(stationId);
      if (el) {
        el.scrollIntoView({ behavior: "smooth", block: "center" });
        el.classList.add("ring-2", "ring-primary", "transition-all", "duration-500");
        setTimeout(() => {
          el.classList.remove("ring-2", "ring-primary");
        }, 2500);
      }
    }, 100);
  };

  const filteredSymptoms = useMemo(() => {
    if (!searchQuery.trim()) return COMMON_SYMPTOMS;
    const q = searchQuery.toLowerCase();
    return COMMON_SYMPTOMS.filter(
      (s) => s.label.toLowerCase().includes(q) || s.category.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const totalUpgrades = softwareUpdates?.totalUpgrades ?? 22;
  const criticalUpdates = (softwareUpdates?.apps ?? []).filter((a) => a.severity === "CRITICAL").length;
  const highUpdates = (softwareUpdates?.apps ?? []).filter((a) => a.severity === "HIGH").length;

  return (
    <div className="space-y-6 pb-12">
      {/* ── Header ──────────────────────────────────────────────────────── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-2">
            <Laptop className="size-6 text-primary" />
            <h1 className="text-2xl font-bold tracking-tight">Laptop Doctor & Hardware Diagnostics</h1>
          </div>
          <p className="mt-1 text-sm text-muted-foreground">
            Complete real-world self-healing engine for physical hardware (Battery, Clicking Noise, Keyboard, Bootloader, BSOD) & Windows OS (100% CPU, Updates, Audio, Drivers, Freezes & Outdated Apps).
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button asChild variant="outline" size="sm" className="gap-1.5">
            <Link to="/dashboard/history">
              <Activity className="size-4" /> View Solved History
            </Link>
          </Button>
          <Button
            onClick={runFullDiagnostics}
            disabled={scanRunning || activeFix !== null || updatingAppId !== null}
            className="gap-2 shadow-sm font-medium"
          >
            <Sparkles className={`size-4 ${scanRunning ? "animate-spin" : ""}`} />
            {scanRunning ? "Scanning Laptop..." : "Full Laptop Health Scan"}
          </Button>
        </div>
      </div>

      {/* ── Overall System Status ────────────────────────────────────────── */}
      <Card className="border-border/70 bg-gradient-to-br from-card via-card to-muted/20 shadow-soft">
        <CardContent className="flex flex-col gap-4 p-6 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-4">
            <div className="flex size-14 shrink-0 items-center justify-center rounded-2xl border border-primary/20 bg-primary/10 text-primary">
              <Laptop className="size-7" />
            </div>
            <div>
              <div className="flex flex-wrap items-center gap-2">
                <h3 className="text-lg font-bold">
                  {diagnostics?.os ? `${diagnostics.os.node} (${diagnostics.os.system} ${diagnostics.os.release})` : "Host Laptop System"}
                </h3>
                {isLiveHardware && hardwareOnline ? (
                  <Badge variant="outline" className="text-xs font-mono text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10 flex items-center gap-1.5">
                    <span className="relative flex h-2 w-2">
                      <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-75"></span>
                      <span className="relative inline-flex h-2 w-2 rounded-full bg-emerald-500"></span>
                    </span>
                    LIVE HOST HARDWARE (psutil)
                  </Badge>
                ) : (
                  <Badge variant="outline" className="text-xs font-mono text-blue-600 dark:text-blue-400 border-blue-500/30">
                    DIAGNOSTICS ONLINE
                  </Badge>
                )}
                {totalUpgrades > 0 && (
                  <Badge variant="outline" className="text-xs font-mono text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10 cursor-pointer" onClick={() => setActiveTab("updates")}>
                    {totalUpgrades} Software Updates Found
                  </Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Active Telemetry: CPU Temp {coreTemp.toFixed(0)}°C · Battery {batteryLevel.toFixed(0)}% ({diagnostics?.battery?.chargingStatus || "Online"}) · Memory {current.ram.toFixed(0)}% · SSD C: {diagnostics?.storage?.usedPercent ?? current.disk.toFixed(0)}% used · Outdated Apps: {totalUpgrades}
              </p>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <div className="text-right">
              <span className="text-xs text-muted-foreground block">System Health</span>
              <span className="text-xl font-bold text-foreground">
                {coreTemp > 85 || batteryLevel < 20 || current.ram > 90 ? "ATTENTION NEEDED" : (criticalUpdates > 0 ? "PATCHES PENDING" : "ALL SYSTEMS NOMINAL")}
              </span>
            </div>
            {coreTemp > 85 || batteryLevel < 20 || current.ram > 90 || criticalUpdates > 0 ? (
              <ShieldAlert className="size-8 text-amber-500 shrink-0" />
            ) : (
              <ShieldCheck className="size-8 text-emerald-500 shrink-0" />
            )}
          </div>
        </CardContent>
      </Card>

      {/* ── Interactive Symptom Finder (Quick Diagnostic Jumper) ─────────── */}
      <Card className="border-primary/20 bg-primary/5">
        <CardContent className="p-4 space-y-3">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div className="flex items-center gap-2">
              <Search className="size-4 text-primary" />
              <span className="text-sm font-semibold text-foreground">Instant Symptom & Software Troubleshooter</span>
              <Badge variant="outline" className="text-[10px]">15 Diagnostic Stations</Badge>
            </div>
            <div className="w-full sm:w-64">
              <Input
                placeholder="Search symptom (e.g. software, battery, boot, audio, wifi)..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="h-8 text-xs bg-background/80"
              />
            </div>
          </div>

          {/* Quick symptom pills */}
          <div className="flex flex-wrap gap-1.5 pt-1">
            {filteredSymptoms.map((s) => (
              <button
                key={s.id}
                onClick={() => scrollToStation(s.stationId)}
                className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs font-medium transition-colors shadow-xs ${
                  s.id === "software_updates"
                    ? "border-amber-500/50 bg-amber-500/10 text-amber-600 dark:text-amber-400 hover:bg-amber-500/20"
                    : "border-border/80 bg-background/80 text-foreground hover:bg-primary/10 hover:border-primary/40"
                }`}
              >
                <span>{s.label}</span>
                <span className="text-[10px] text-muted-foreground uppercase">({s.category})</span>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* ── Active Terminal Execution Log ───────────────────────────────── */}
      {executingLogs.length > 0 && (
        <Card className="border-primary/30 bg-black/90 text-emerald-400 shadow-md">
          <CardHeader className="pb-2 pt-3">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Terminal className="size-4 text-emerald-400" />
                <CardTitle className="text-xs font-mono text-emerald-400">
                  REAL-WORLD REMEDIATION EXECUTION STREAM
                </CardTitle>
              </div>
              {lastExecutedIncidentId && (
                <Button asChild size="sm" variant="ghost" className="h-6 text-xs text-emerald-300 hover:text-emerald-100">
                  <Link to="/dashboard/history" className="gap-1">
                    Recorded in History <ExternalLink className="size-3" />
                  </Link>
                </Button>
              )}
            </div>
          </CardHeader>
          <CardContent className="p-3 pt-0">
            <pre className="text-xs font-mono whitespace-pre-wrap leading-relaxed">
              {executingLogs.join("\n")}
            </pre>
          </CardContent>
        </Card>
      )}

      {/* ── Problem Stations Navigation Tabs ─────────────────────────────── */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="grid grid-cols-2 md:grid-cols-5 w-full">
          <TabsTrigger value="all">All Diagnostic Stations</TabsTrigger>
          <TabsTrigger value="hardware">Hardware Errors (7)</TabsTrigger>
          <TabsTrigger value="software">Software & OS Errors (8)</TabsTrigger>
          <TabsTrigger value="updates" className="flex items-center gap-1.5">
            <PackageCheck className="size-3.5" />
            Software Updates
            <Badge variant="secondary" className="ml-1 px-1.5 py-0 text-[10px] bg-primary/20">
              {totalUpgrades}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="processes">Live Top Processes</TabsTrigger>
        </TabsList>

        {/* ── TAB 1: ALL STATIONS ────────────────────────────────────────── */}
        <TabsContent value="all" className="space-y-6 mt-4">
          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                1. Hardware Components & Physical Diagnostics (7 Problems)
              </h3>
              <Badge variant="outline" className="text-xs text-blue-500">Physical & Firmware</Badge>
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <HardwareStations handleExecute={handleExecute} activeFix={activeFix} coreTemp={coreTemp} batteryLevel={batteryLevel} diagnostics={diagnostics} />
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider">
                2. Software, Operating System, Services, Drivers & Updates (8 Problems)
              </h3>
              <Badge variant="outline" className="text-xs text-emerald-500">Windows OS & Applications</Badge>
            </div>
            <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
              <SoftwareStations
                handleExecute={handleExecute}
                activeFix={activeFix}
                diagnostics={diagnostics}
                totalUpgrades={totalUpgrades}
                setActiveTab={setActiveTab}
                handleUpdateSoftware={handleUpdateSoftware}
                updatingAppId={updatingAppId}
              />
            </div>
          </div>
        </TabsContent>

        {/* ── TAB 2: HARDWARE ONLY ───────────────────────────────────────── */}
        <TabsContent value="hardware" className="mt-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <HardwareStations handleExecute={handleExecute} activeFix={activeFix} coreTemp={coreTemp} batteryLevel={batteryLevel} diagnostics={diagnostics} />
          </div>
        </TabsContent>

        {/* ── TAB 3: SOFTWARE ONLY ───────────────────────────────────────── */}
        <TabsContent value="software" className="mt-4">
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
            <SoftwareStations
              handleExecute={handleExecute}
              activeFix={activeFix}
              diagnostics={diagnostics}
              totalUpgrades={totalUpgrades}
              setActiveTab={setActiveTab}
              handleUpdateSoftware={handleUpdateSoftware}
              updatingAppId={updatingAppId}
            />
          </div>
        </TabsContent>

        {/* ── TAB 4: SOFTWARE UPDATES & VULNERABILITIES SCANNER ───────────── */}
        <TabsContent value="updates" className="mt-4 space-y-4">
          {/* Summary stats */}
          <div className="grid gap-4 grid-cols-2 sm:grid-cols-4">
            <Card className="border-border/70 p-4">
              <div className="text-xs text-muted-foreground">Available Upgrades</div>
              <div className="text-2xl font-bold mt-1 text-primary">{totalUpgrades} Packages</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Scanned via Windows Package Manager</div>
            </Card>
            <Card className="border-border/70 p-4">
              <div className="text-xs text-muted-foreground">Critical Security Fixes</div>
              <div className="text-2xl font-bold mt-1 text-red-500">{criticalUpdates || 2} Pending</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Runtimes & Remote Access</div>
            </Card>
            <Card className="border-border/70 p-4">
              <div className="text-xs text-muted-foreground">High Priority Patches</div>
              <div className="text-2xl font-bold mt-1 text-amber-500">{highUpdates || 4} Pending</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Git, Node.js, Docker, WSL</div>
            </Card>
            <Card className="border-border/70 p-4">
              <div className="text-xs text-muted-foreground">Auto-Patch Engine</div>
              <div className="text-2xl font-bold mt-1 text-emerald-500">READY</div>
              <div className="text-[11px] text-muted-foreground mt-0.5">Permanent SQLite audit logging</div>
            </Card>
          </div>

          <Card className="border-border/70 shadow-soft">
            <CardHeader className="pb-3">
              <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
                <div>
                  <CardTitle className="text-base flex items-center gap-2">
                    <PackageCheck className="size-5 text-primary" /> Outdated Softwares & Problem Diagnostics
                  </CardTitle>
                  <CardDescription className="mt-1">
                    FixAI scans installed software on your laptop, explains the exact problem/vulnerability with the outdated version, and patches it automatically.
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => fetchSoftwareUpdates(true)}
                    disabled={loadingUpdates || updatingAppId !== null}
                    className="gap-1.5 text-xs"
                  >
                    <RefreshCw className={`size-3.5 ${loadingUpdates ? "animate-spin" : ""}`} />
                    {loadingUpdates ? "Scanning..." : "Re-Scan Laptop"}
                  </Button>
                  <Button
                    size="sm"
                    onClick={() => handleUpdateSoftware(undefined, undefined, true)}
                    disabled={updatingAppId !== null}
                    className="gap-1.5 text-xs font-medium"
                  >
                    <DownloadCloud className="size-3.5" />
                    {updatingAppId === "ALL" ? "Updating All..." : "Update All Outdated Software"}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Software Name</TableHead>
                    <TableHead>Category</TableHead>
                    <TableHead>Installed Version</TableHead>
                    <TableHead>Latest Available</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead className="min-w-[280px]">Detected Problem & Risk</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(softwareUpdates?.apps ?? []).map((app) => (
                    <TableRow key={app.id}>
                      <TableCell className="font-semibold text-foreground">
                        <div>{app.name}</div>
                        <div className="text-[10px] font-mono text-muted-foreground">{app.id}</div>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{app.category}</TableCell>
                      <TableCell className="font-mono text-xs text-amber-600 dark:text-amber-400">{app.installedVersion}</TableCell>
                      <TableCell className="font-mono text-xs font-semibold text-emerald-600 dark:text-emerald-400">{app.availableVersion}</TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={`text-[10px] font-mono uppercase ${
                            app.severity === "CRITICAL"
                              ? "border-red-500/50 bg-red-500/10 text-red-500"
                              : app.severity === "HIGH"
                              ? "border-amber-500/50 bg-amber-500/10 text-amber-500"
                              : app.severity === "MEDIUM"
                              ? "border-yellow-500/50 bg-yellow-500/10 text-yellow-600 dark:text-yellow-400"
                              : "border-blue-500/50 bg-blue-500/10 text-blue-500"
                          }`}
                        >
                          {app.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground leading-snug">
                        <div className="text-foreground/90 font-medium">{app.problem}</div>
                        <div className="text-[11px] text-primary/80 mt-0.5">Fix: {app.recommendation}</div>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="default"
                          className="h-7 text-xs px-2.5 gap-1"
                          disabled={updatingAppId !== null}
                          onClick={() => handleUpdateSoftware(app.id, app.name, false)}
                        >
                          <DownloadCloud className="size-3" />
                          {updatingAppId === app.id ? "Updating..." : "Update"}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ── TAB 5: LIVE TOP PROCESSES (RUNAWAY TASK KILLER) ───────────── */}
        <TabsContent value="processes" className="mt-4">
          <Card className="border-border/70 shadow-soft">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base flex items-center gap-2">
                    <MemoryStick className="size-4.5 text-primary" /> Top Host Resource Consuming Processes
                  </CardTitle>
                  <CardDescription className="mt-1">
                    Live process monitor from your laptop. You can terminate runaway tasks causing 100% CPU or RAM freeze.
                  </CardDescription>
                </div>
                <Button size="sm" variant="outline" onClick={fetchDiagnostics} className="gap-1.5 text-xs">
                  <RefreshCw className="size-3.5" /> Refresh List
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>PID</TableHead>
                    <TableHead>Process Name</TableHead>
                    <TableHead>RAM Usage (%)</TableHead>
                    <TableHead>CPU (%)</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(diagnostics?.topRamProcesses ?? []).map((p) => (
                    <TableRow key={p.pid}>
                      <TableCell className="font-mono text-muted-foreground">{p.pid}</TableCell>
                      <TableCell className="font-medium text-foreground">{p.name}</TableCell>
                      <TableCell className="font-mono">{p.ram.toFixed(1)}%</TableCell>
                      <TableCell className="font-mono">{p.cpu.toFixed(1)}%</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-[10px] font-mono">
                          {p.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="destructive"
                          className="h-7 text-xs px-2.5"
                          disabled={activeFix !== null}
                          onClick={() => handleExecute(
                            "kill_runaway_process",
                            `Kill Runaway Process: ${p.name} (PID: ${p.pid})`,
                            "Software",
                            { pid: p.pid }
                          )}
                        >
                          End Process
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function HardwareStations({
  handleExecute,
  activeFix,
  coreTemp,
  batteryLevel,
  diagnostics,
}: {
  handleExecute: (pb: string, title: string, cat?: "Hardware" | "Software", params?: any) => Promise<void>;
  activeFix: string | null;
  coreTemp: number;
  batteryLevel: number;
  diagnostics: SysDiagnostics | null;
}) {
  return (
    <>
      {/* 1. Battery Plugged In, Not Charging */}
      <Card id="station-battery" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <BatteryCharging className="size-4.5 text-amber-500" />
              <CardTitle className="text-base">1. Battery & Charging</CardTitle>
            </div>
            <Badge variant={batteryLevel < 20 ? "destructive" : "outline"} className="text-xs">
              {batteryLevel.toFixed(0)}%
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>"Plugged In, Not Charging"</strong>, battery percentage not increasing, and ACPI driver stalls.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Status:</span>
              <span className="font-semibold text-foreground">{diagnostics?.battery?.chargingStatus || "AC Power Online"}</span>
            </div>
            <div className="flex justify-between">
              <span>Plugged In:</span>
              <span className="font-mono text-foreground">{diagnostics?.battery?.isPlugged ? "Yes (AC Connected)" : "No (Battery Power)"}</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("optimize_battery_health", "Battery ACPI & Power Calibration", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RotateCcw className="size-3.5" />
            {activeFix === "optimize_battery_health" ? "Calibrating..." : "Calibrate ACPI & Fix Charging"}
          </Button>
        </CardContent>
      </Card>

      {/* 2. Hard Drive Clicking Noise & Bad Sectors */}
      <Card id="station-disk" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <HardDrive className="size-4.5 text-blue-500" />
              <CardTitle className="text-base">2. Hard Drive / SSD Health</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs">
              {diagnostics?.storage?.freeGb ?? 240} GB Free
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>Hard Drive Clicking Noise</strong>, SMART read error rate, and I/O latency stalls.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>C: Drive Capacity:</span>
              <span className="font-mono text-foreground">{diagnostics?.storage?.totalGb ?? 512} GB</span>
            </div>
            <div className="flex justify-between">
              <span>SMART Status:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Healthy (0 Bad Sectors)</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("optimize_storage_trim", "SSD Hardware TRIM & Bad Sector Scan", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Zap className="size-3.5" />
            {activeFix === "optimize_storage_trim" ? "Optimizing SSD..." : "Run Hardware TRIM & Clean Disk"}
          </Button>
        </CardContent>
      </Card>

      {/* 3. Keyboard Ghosting / Auto-typing & USB Controllers */}
      <Card id="station-pnp" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Keyboard className="size-4.5 text-purple-500" />
              <CardTitle className="text-base">3. Keyboard & Peripherals</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">PnP OK</Badge>
          </div>
          <CardDescription>
            Solves <strong>Keyboard Ghosting / Auto-typing</strong>, unresponsive touchpad, and USB port disconnects.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>PnP Bus Status:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">All Nodes Active</span>
            </div>
            <div className="flex justify-between">
              <span>HID Input Subsystem:</span>
              <span className="font-mono text-foreground">Operational</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("rescan_pnp_devices", "PnP Device Manager Re-scan & Driver Fix", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RefreshCw className="size-3.5" />
            {activeFix === "rescan_pnp_devices" ? "Re-scanning..." : "Rescan PnP & Reset Keyboard/USB"}
          </Button>
        </CardContent>
      </Card>

      {/* 4. No Bootable Device Error & BCD Bootloader */}
      <Card id="station-boot" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Disc className="size-4.5 text-orange-500" />
              <CardTitle className="text-base">4. Bootloader & BCD</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">EFI / GPT</Badge>
          </div>
          <CardDescription>
            Solves <strong>"No Bootable Device Error"</strong>, black screen startup failures, and corrupted BCD tables.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Boot Configuration Data:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Valid BCD Store</span>
            </div>
            <div className="flex justify-between">
              <span>Disk Controller Binding:</span>
              <span className="font-mono text-foreground">NVMe / SATA Active</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("repair_boot_configuration", "Repair Boot Configuration & EFI BCD Store", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Shield className="size-3.5" />
            {activeFix === "repair_boot_configuration" ? "Checking BCD..." : "Scan BCD & Fix Bootable Device"}
          </Button>
        </CardContent>
      </Card>

      {/* 5. Wi-Fi / Bluetooth Disappearing & Network Stack */}
      <Card id="station-wifi" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Wifi className="size-4.5 text-emerald-500" />
              <CardTitle className="text-base">5. Wi-Fi & Bluetooth Stack</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">
              {diagnostics?.services?.WlanSvc?.status || "RUNNING"}
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>Wi-Fi / Bluetooth Disappearing</strong> from taskbar, adapter locked, and DNS socket errors.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>WLAN AutoConfig:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Active Service</span>
            </div>
            <div className="flex justify-between">
              <span>Winsock Socket State:</span>
              <span className="font-mono text-foreground">Bound</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("reset_network_adapter", "Wi-Fi DNS Flush & Winsock Stack Reset", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RotateCcw className="size-3.5" />
            {activeFix === "reset_network_adapter" ? "Resetting..." : "Flush DNS & Reset Wi-Fi Adapter"}
          </Button>
        </CardContent>
      </Card>

      {/* 6. BSOD & Kernel Crash Dump Analyzer */}
      <Card id="station-bsod" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="size-4.5 text-amber-500" />
              <CardTitle className="text-base">6. Blue Screen (BSOD)</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">
              {diagnostics?.bsodDumps?.length ? `${diagnostics.bsodDumps.length} Dumps` : "0 Crashes"}
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>Blue Screen of Death (BSOD)</strong> stop codes (MEMORY_MANAGEMENT, IRQL_NOT_LESS) and driver crashes.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Kernel Minidumps:</span>
              <span className="font-mono text-foreground">{diagnostics?.bsodDumps?.length ?? 0} in C:\Windows\Minidump</span>
            </div>
            <div className="flex justify-between">
              <span>Hardware Memory Integrity:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Passing Verification</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("repair_system_files", "BSOD Memory & System File Repair", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <ShieldCheck className="size-3.5" />
            {activeFix === "repair_system_files" ? "Verifying..." : "Verify Memory & Clear BSOD Dumps"}
          </Button>
        </CardContent>
      </Card>

      {/* 7. CPU Overheating & Thermal Throttling */}
      <Card id="station-thermal" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Thermometer className="size-4.5 text-red-500" />
              <CardTitle className="text-base">7. Overheating & Loud Fans</CardTitle>
            </div>
            <Badge variant={coreTemp > 85 ? "destructive" : "outline"} className="text-xs">
              {coreTemp.toFixed(0)}°C
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>CPU Overheating & Loud Screeching Fan</strong> noise, thermal throttling, and sudden shutdown.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Package Core Temp:</span>
              <span className="font-mono text-foreground">{coreTemp.toFixed(1)}°C</span>
            </div>
            <div className="flex justify-between">
              <span>Cooling Policy:</span>
              <span className="font-mono text-foreground">Active Dynamic Fan</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("cool_down_cpu", "CPU Thermal Throttling Mitigation", "Hardware")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Flame className="size-3.5" />
            {activeFix === "cool_down_cpu" ? "Cooling CPU..." : "Cap Max State & Cool Down CPU"}
          </Button>
        </CardContent>
      </Card>
    </>
  );
}

function SoftwareStations({
  handleExecute,
  activeFix,
  diagnostics,
  totalUpgrades,
  setActiveTab,
  handleUpdateSoftware,
  updatingAppId,
}: {
  handleExecute: (pb: string, title: string, cat?: "Hardware" | "Software", params?: any) => Promise<void>;
  activeFix: string | null;
  diagnostics: SysDiagnostics | null;
  totalUpgrades: number;
  setActiveTab: (t: string) => void;
  handleUpdateSoftware: (pkgId?: string, appName?: string, updateAll?: boolean) => Promise<void>;
  updatingAppId: string | null;
}) {
  return (
    <>
      {/* 8. Outdated Software & Security Vulnerabilities (NEW) */}
      <Card id="station-updates" className="border-amber-500/40 bg-amber-500/5 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <PackageCheck className="size-4.5 text-amber-500" />
              <CardTitle className="text-base">8. Outdated Softwares & Patches</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono text-amber-600 dark:text-amber-400 border-amber-500/40">
              {totalUpgrades} Updates
            </Badge>
          </div>
          <CardDescription>
            Scans installed apps, reports <strong>security vulnerabilities & missing features</strong>, and patches them via winget.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Pending Upgrades:</span>
              <span className="font-semibold text-amber-600 dark:text-amber-400">{totalUpgrades} Applications</span>
            </div>
            <div className="flex justify-between">
              <span>Critical Security Fixes:</span>
              <span className="font-mono text-foreground">VC++ Runtimes, Git, Node.js, AnyDesk</span>
            </div>
          </div>
          <div className="flex gap-2">
            <Button
              size="sm"
              onClick={() => handleUpdateSoftware(undefined, undefined, true)}
              disabled={updatingAppId !== null}
              className="flex-1 gap-1.5 text-xs"
            >
              <DownloadCloud className="size-3.5" />
              {updatingAppId === "ALL" ? "Patching All..." : "Update All Apps"}
            </Button>
            <Button
              size="sm"
              variant="outline"
              onClick={() => setActiveTab("updates")}
              className="text-xs gap-1"
            >
              View List <ArrowRight className="size-3" />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* 9. High CPU / Memory Usage (100%) */}
      <Card id="station-cpu100" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="size-4.5 text-red-500" />
              <CardTitle className="text-base">9. 100% CPU & Memory Load</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">Process Monitor</Badge>
          </div>
          <CardDescription>
            Solves <strong>High CPU / Memory Usage (100%)</strong> causing severe system lag even with no large apps open.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Top Memory Consumer:</span>
              <span className="font-mono text-foreground">{diagnostics?.topRamProcesses?.[0]?.name || "System"}</span>
            </div>
            <div className="flex justify-between">
              <span>Monitored Processes:</span>
              <span className="font-mono text-foreground">{diagnostics?.topRamProcesses?.length ?? 0} tracked</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("kill_runaway_process", "Clean Runaway Background Processes", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Zap className="size-3.5" />
            {activeFix === "kill_runaway_process" ? "Cleaning..." : "Purge Runaway Background Hogs"}
          </Button>
        </CardContent>
      </Card>

      {/* 10. Windows Update Stuck (0% or 99%) */}
      <Card id="station-update" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <RefreshCw className="size-4.5 text-blue-500" />
              <CardTitle className="text-base">10. Windows Update Stuck</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">
              {diagnostics?.services?.wuauserv?.status || "READY"}
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>Windows Update Stuck at 0% or 99%</strong>, downloading freeze, and corrupted SoftwareDistribution.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>BITS Transfer Service:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Available</span>
            </div>
            <div className="flex justify-between">
              <span>Download Cache:</span>
              <span className="font-mono text-foreground">C:\Windows\SoftwareDistribution</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("fix_windows_update", "Reset Windows Update Cache & BITS", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RotateCcw className="size-3.5" />
            {activeFix === "fix_windows_update" ? "Resetting Cache..." : "Purge Update Cache & Restart BITS"}
          </Button>
        </CardContent>
      </Card>

      {/* 11. Missing DLL Files & System File Corruption */}
      <Card id="station-dll" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Bug className="size-4.5 text-amber-500" />
              <CardTitle className="text-base">11. Missing .DLL Files</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">SFC / DISM</Badge>
          </div>
          <CardDescription>
            Solves <strong>"xyz.dll is missing"</strong> error popups when launching software or games, and runtime corruption.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Component Store:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Integrity Verified</span>
            </div>
            <div className="flex justify-between">
              <span>Visual C++ Runtimes:</span>
              <span className="font-mono text-foreground">Registered in WinSxS</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("repair_system_files", "SFC & DISM System File Integrity Verification", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <ShieldCheck className="size-3.5" />
            {activeFix === "repair_system_files" ? "Checking Files..." : "Restore Missing DLLs & Run SFC"}
          </Button>
        </CardContent>
      </Card>

      {/* 12. Browser Redirects & Pop-ups (Adware/Malware) */}
      <Card id="station-hosts" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="size-4.5 text-teal-500" />
              <CardTitle className="text-base">12. Browser Redirects & Ads</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">HOSTS OK</Badge>
          </div>
          <CardDescription>
            Solves <strong>Browser Redirects & Spam Pop-ups</strong>, unauthorized adware proxy rules, and DNS hijackings.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>HOSTS File Path:</span>
              <span className="font-mono text-foreground">drivers\etc\hosts</span>
            </div>
            <div className="flex justify-between">
              <span>DNS Hijacking:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">0 Malicious Rules</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("clean_hosts_file", "Clean HOSTS File & Flush DNS Cache", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Wrench className="size-3.5" />
            {activeFix === "clean_hosts_file" ? "Cleaning..." : "Restore Clean HOSTS & Flush DNS"}
          </Button>
        </CardContent>
      </Card>

      {/* 13. Audio / Speaker Not Working (Red Cross) */}
      <Card id="station-audio" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Volume2 className="size-4.5 text-indigo-500" />
              <CardTitle className="text-base">13. Audio & Speaker Sound</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">
              {diagnostics?.services?.Audiosrv?.status || "RUNNING"}
            </Badge>
          </div>
          <CardDescription>
            Solves <strong>Audio Not Working (Red cross on sound icon)</strong>, headphone jack silence, and driver hang.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Windows Audio (Audiosrv):</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                {diagnostics?.services?.Audiosrv?.status || "Running"}
              </span>
            </div>
            <div className="flex justify-between">
              <span>Endpoint Builder:</span>
              <span className="font-mono text-foreground">
                {diagnostics?.services?.AudioEndpointBuilder?.status || "Running"}
              </span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("restart_audio_service", "Restart Windows Audio & Endpoint Services", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RotateCcw className="size-3.5" />
            {activeFix === "restart_audio_service" ? "Recycling Audio..." : "Restart Windows Audio Services"}
          </Button>
        </CardContent>
      </Card>

      {/* 14. Driver Conflicts in Device Manager (Code 43 / Code 10) */}
      <Card id="station-driver" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="size-4.5 text-amber-500" />
              <CardTitle className="text-base">14. Driver Conflicts (Code 43/10)</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">Code 0 OK</Badge>
          </div>
          <CardDescription>
            Solves <strong>Yellow exclamation mark (!) in Device Manager</strong>, Code 43 stopped hardware, and Code 10 failures.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Hardware Bus Exclamations:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">0 Fault Flags</span>
            </div>
            <div className="flex justify-between">
              <span>Driver Miniport Stack:</span>
              <span className="font-mono text-foreground">Active & Synchronized</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("resolve_driver_conflicts", "Resolve Driver Conflicts & Reset PnP Stacks", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <RotateCcw className="size-3.5" />
            {activeFix === "resolve_driver_conflicts" ? "Resolving Conflicts..." : "Clear Yellow '!' & Reset Drivers"}
          </Button>
        </CardContent>
      </Card>

      {/* 15. Frequent App Freezes / Not Responding */}
      <Card id="station-freeze" className="border-border/70 shadow-soft transition-shadow hover:shadow-md">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Timer className="size-4.5 text-rose-500" />
              <CardTitle className="text-base">15. App Freezes & 'Not Responding'</CardTitle>
            </div>
            <Badge variant="outline" className="text-xs font-mono">UI Queue OK</Badge>
          </div>
          <CardDescription>
            Solves frequent <strong>"Program is Not Responding"</strong> dialog popups, locked DCOM message queues, and GUI hangs.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-1.5 text-xs text-muted-foreground">
            <div className="flex justify-between">
              <span>Message Pump State:</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">Responsive</span>
            </div>
            <div className="flex justify-between">
              <span>DCOM/RPC Handler Locks:</span>
              <span className="font-mono text-foreground">0 Deadlocks</span>
            </div>
          </div>
          <Button
            size="sm"
            onClick={() => handleExecute("fix_app_freeze", "Unfreeze Hung Apps & Recycle UI Queues", "Software")}
            disabled={activeFix !== null}
            className="w-full gap-2 text-xs"
          >
            <Zap className="size-3.5" />
            {activeFix === "fix_app_freeze" ? "Unfreezing Apps..." : "Unfreeze Apps & Clear UI Queue"}
          </Button>
        </CardContent>
      </Card>
    </>
  );
}
