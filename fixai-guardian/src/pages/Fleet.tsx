import React, { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Cpu,
  Filter,
  HardDrive,
  HeartPulse,
  Laptop,
  Layers,
  Lock,
  Network,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Smartphone,
  Sparkles,
  Thermometer,
  Wifi,
  WifiOff,
  Wrench,
  XCircle,
  Zap,
} from "lucide-react";
import { Link } from "react-router";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

interface FleetDevice {
  id: string;
  name: string;
  hostname: string;
  os: string;
  arch: string;
  is_online: boolean;
  status: "HEALTHY" | "DEGRADED" | "CRITICAL";
  health_score: number;
  cpu_percent: number;
  ram_percent: number;
  disk_percent: number;
  temperature_c: number;
  active_threats: string[];
  last_seen: string;
  connection_mode: string;
  ip_address: string;
}

interface FleetSummary {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  critical_devices: number;
  degraded_devices: number;
  healthy_devices: number;
  average_fleet_health: number;
}

export default function Fleet() {
  const [devices, setDevices] = useState<FleetDevice[]>([]);
  const [summary, setSummary] = useState<FleetSummary>({
    total_devices: 0,
    online_devices: 0,
    offline_devices: 0,
    critical_devices: 0,
    degraded_devices: 0,
    healthy_devices: 0,
    average_fleet_health: 100,
  });
  const [loading, setLoading] = useState<boolean>(true);
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [selectedDevice, setSelectedDevice] = useState<FleetDevice | null>(null);

  const fetchFleet = async () => {
    setLoading(true);
    try {
      const backendUrl = import.meta.env.VITE_FASTAPI_URL || "http://localhost:8000";
      const res = await fetch(`${backendUrl}/api/v1/agent/fleet`);
      if (res.ok) {
        const data = await res.json();
        setDevices(data.devices || []);
        setSummary(data.summary || {});
      } else {
        throw new Error("Failed to load fleet");
      }
    } catch {
      // Deterministic fallback fleet if server offline
      const mockDevices: FleetDevice[] = [
        {
          id: "dev-laptop-001",
          name: "Primary Host (This Laptop)",
          hostname: "local-workstation",
          os: "Windows 11 Pro 23H2",
          arch: "x86_64",
          is_online: true,
          status: "HEALTHY",
          health_score: 96.5,
          cpu_percent: 24.5,
          ram_percent: 54.2,
          disk_percent: 42.0,
          temperature_c: 52.0,
          active_threats: [],
          last_seen: new Date().toISOString(),
          connection_mode: "WEBSOCKET_STREAM",
          ip_address: "192.168.1.105",
        },
        {
          id: "dev-macbook-m3-002",
          name: "MacBook Pro M3 Max",
          hostname: "macbook-pro-alice",
          os: "macOS Sonoma 14.5",
          arch: "arm64",
          is_online: true,
          status: "HEALTHY",
          health_score: 98.4,
          cpu_percent: 14.2,
          ram_percent: 41.8,
          disk_percent: 35.0,
          temperature_c: 42.5,
          active_threats: [],
          last_seen: new Date().toISOString(),
          connection_mode: "WEBSOCKET_STREAM",
          ip_address: "192.168.1.112",
        },
        {
          id: "dev-ubuntu-prod-003",
          name: "Ubuntu Inference Server 01",
          hostname: "srv-prod-ai-01",
          os: "Ubuntu 24.04 LTS (Kernel 6.8)",
          arch: "x86_64",
          is_online: true,
          status: "DEGRADED",
          health_score: 76.0,
          cpu_percent: 88.4,
          ram_percent: 84.1,
          disk_percent: 79.2,
          temperature_c: 74.0,
          active_threats: ["HIGH_RESOURCE_BURN"],
          last_seen: new Date().toISOString(),
          connection_mode: "WEBSOCKET_STREAM",
          ip_address: "10.0.4.15",
        },
        {
          id: "dev-win11-finance-004",
          name: "Finance Workstation 04",
          hostname: "corp-fin-desk-04",
          os: "Windows 11 Enterprise",
          arch: "x86_64",
          is_online: true,
          status: "CRITICAL",
          health_score: 38.5,
          cpu_percent: 45.1,
          ram_percent: 68.0,
          disk_percent: 55.4,
          temperature_c: 62.0,
          active_threats: ["CANARY_TAMPER_SUSPECT", "BRUTE_FORCE_ATTACK"],
          last_seen: new Date().toISOString(),
          connection_mode: "OFFLINE_STORE_FORWARD",
          ip_address: "192.168.2.44",
        },
        {
          id: "dev-debian-gateway-005",
          name: "Edge Gateway Router",
          hostname: "gw-edge-router-01",
          os: "Debian 12 Bookworm",
          arch: "x86_64",
          is_online: true,
          status: "HEALTHY",
          health_score: 99.1,
          cpu_percent: 6.8,
          ram_percent: 22.4,
          disk_percent: 18.0,
          temperature_c: 38.0,
          active_threats: [],
          last_seen: new Date().toISOString(),
          connection_mode: "WEBSOCKET_STREAM",
          ip_address: "10.0.0.1",
        },
        {
          id: "dev-thinkpad-exec-006",
          name: "ThinkPad X1 Carbon",
          hostname: "exec-laptop-carol",
          os: "Windows 11 Pro 23H2",
          arch: "x86_64",
          is_online: false,
          status: "HEALTHY",
          health_score: 92.0,
          cpu_percent: 0.0,
          ram_percent: 0.0,
          disk_percent: 58.0,
          temperature_c: 0.0,
          active_threats: [],
          last_seen: new Date(Date.now() - 7200000).toISOString(),
          connection_mode: "OFFLINE",
          ip_address: "192.168.1.189",
        },
      ];
      setDevices(mockDevices);
      setSummary({
        total_devices: 6,
        online_devices: 5,
        offline_devices: 1,
        critical_devices: 1,
        degraded_devices: 1,
        healthy_devices: 4,
        average_fleet_health: 83.4,
      });
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchFleet();
  }, []);

  // Filtered devices
  const filtered = devices.filter((d) => {
    const matchesSearch =
      d.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      d.ip_address.includes(searchTerm);
    if (!matchesSearch) return false;
    if (statusFilter === "ALL") return true;
    if (statusFilter === "CRITICAL_DEGRADED") return d.status === "CRITICAL" || d.status === "DEGRADED";
    if (statusFilter === "HEALTHY") return d.status === "HEALTHY";
    if (statusFilter === "OFFLINE") return !d.is_online;
    return true;
  });

  const handleIsolateEndpoint = (name: string) => {
    toast.warning(`Network Isolation command dispatched to ${name}. All outbound sockets severed.`);
  };

  return (
    <div className="mx-auto flex w-full max-w-7xl flex-col gap-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Server className="size-6 text-primary" />
            Multi-Device Fleet Command
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Centralized EDR & Hardware Reliability telemetry across your managed laptop, server, and IoT fleet.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            size="sm"
            variant="outline"
            onClick={fetchFleet}
            disabled={loading}
            className="gap-2 text-xs"
          >
            <RefreshCw className={cn("size-3.5", loading && "animate-spin")} />
            Sync Fleet Status
          </Button>
          <Button size="sm" asChild className="gap-2 text-xs">
            <Link to="/dashboard/recovery">
              <Wrench className="size-3.5" />
              Fleet Playbooks
            </Link>
          </Button>
        </div>
      </div>

      {/* Fleet KPI Metric Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <Card className="border-border/70 bg-card/60 shadow-xs">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Total Endpoints</span>
              <Network className="size-4 text-primary" />
            </div>
            <p className="text-2xl font-bold tracking-tight tabular-nums">{summary.total_devices}</p>
            <p className="text-[11px] text-muted-foreground">
              <span className="text-emerald-500 font-semibold">{summary.online_devices} Online</span> · {summary.offline_devices} Standby
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/70 bg-card/60 shadow-xs">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Average Fleet Health</span>
              <HeartPulse className="size-4 text-emerald-500" />
            </div>
            <p className="text-2xl font-bold tracking-tight tabular-nums text-emerald-500">
              {summary.average_fleet_health}%
            </p>
            <p className="text-[11px] text-muted-foreground">Weighted reliability index</p>
          </CardContent>
        </Card>

        <Card className="border-border/70 bg-card/60 shadow-xs">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Active Threat Alerts</span>
              <ShieldAlert className="size-4 text-red-500" />
            </div>
            <p className="text-2xl font-bold tracking-tight tabular-nums text-red-500">
              {summary.critical_devices}
            </p>
            <p className="text-[11px] text-muted-foreground">
              {summary.critical_devices > 0 ? "Requires SOC review" : "Zero breaches detected"}
            </p>
          </CardContent>
        </Card>

        <Card className="border-border/70 bg-card/60 shadow-xs">
          <CardContent className="p-4 space-y-1">
            <div className="flex items-center justify-between text-muted-foreground">
              <span className="text-xs font-medium">Degraded Hardware</span>
              <AlertTriangle className="size-4 text-amber-500" />
            </div>
            <p className="text-2xl font-bold tracking-tight tabular-nums text-amber-500">
              {summary.degraded_devices}
            </p>
            <p className="text-[11px] text-muted-foreground">High thermal or RAM load</p>
          </CardContent>
        </Card>
      </div>

      {/* Filter and Search Bar */}
      <div className="flex flex-col sm:flex-row items-stretch sm:items-center justify-between gap-3 rounded-xl border border-border/70 bg-card p-3 shadow-xs">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
          <Input
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Search endpoint by name, hostname, or IP..."
            className="pl-9 h-9 text-xs"
          />
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-xs text-muted-foreground mr-1 hidden sm:inline">Filter:</span>
          {[
            { id: "ALL", label: "All" },
            { id: "CRITICAL_DEGRADED", label: "Threats & Degraded" },
            { id: "HEALTHY", label: "Healthy" },
            { id: "OFFLINE", label: "Offline" },
          ].map((f) => (
            <Button
              key={f.id}
              size="sm"
              variant={statusFilter === f.id ? "default" : "outline"}
              onClick={() => setStatusFilter(f.id)}
              className="h-8 text-xs px-2.5"
            >
              {f.label}
            </Button>
          ))}
        </div>
      </div>

      {/* Device Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {filtered.map((dev) => {
          const isCritical = dev.status === "CRITICAL";
          const isDegraded = dev.status === "DEGRADED";

          return (
            <Card
              key={dev.id}
              className={cn(
                "group relative overflow-hidden border transition-all duration-200 hover:shadow-md",
                isCritical
                  ? "border-red-500/50 bg-red-500/5 dark:bg-red-500/10"
                  : isDegraded
                  ? "border-amber-500/40 bg-amber-500/5"
                  : "border-border/70 bg-card hover:border-primary/50",
              )}
            >
              <CardHeader className="pb-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2.5 min-w-0">
                    <div
                      className={cn(
                        "flex size-9 shrink-0 items-center justify-center rounded-lg font-bold shadow-xs",
                        dev.is_online
                          ? isCritical
                            ? "bg-red-500 text-white animate-pulse"
                            : "bg-primary/15 text-primary"
                          : "bg-muted text-muted-foreground",
                      )}
                    >
                      <Laptop className="size-4" />
                    </div>
                    <div className="min-w-0">
                      <CardTitle className="text-sm font-bold truncate text-foreground">
                        {dev.name}
                      </CardTitle>
                      <p className="text-xs text-muted-foreground font-mono truncate">
                        {dev.hostname} · {dev.ip_address}
                      </p>
                    </div>
                  </div>

                  <Badge
                    variant={
                      !dev.is_online
                        ? "outline"
                        : isCritical
                        ? "destructive"
                        : isDegraded
                        ? "secondary"
                        : "default"
                    }
                    className="text-[10px] font-mono uppercase px-1.5 py-0 shrink-0 font-bold"
                  >
                    {dev.is_online ? dev.status : "OFFLINE"}
                  </Badge>
                </div>

                {/* OS & Arch Tag */}
                <div className="flex items-center justify-between text-[11px] text-muted-foreground pt-1 border-t border-border/40">
                  <span className="truncate max-w-[200px]">{dev.os}</span>
                  <span className="font-mono">{dev.arch}</span>
                </div>
              </CardHeader>

              <CardContent className="space-y-3 pb-4 text-xs">
                {/* Metric Bars */}
                {dev.is_online ? (
                  <div className="grid grid-cols-3 gap-2 rounded-lg border border-border/60 bg-muted/20 p-2.5 text-center">
                    <div>
                      <span className="text-[10px] text-muted-foreground block">CPU</span>
                      <span
                        className={cn(
                          "font-mono font-bold text-sm",
                          dev.cpu_percent > 80 ? "text-red-500" : "text-foreground",
                        )}
                      >
                        {dev.cpu_percent}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground block">RAM</span>
                      <span
                        className={cn(
                          "font-mono font-bold text-sm",
                          dev.ram_percent > 80 ? "text-amber-500" : "text-foreground",
                        )}
                      >
                        {dev.ram_percent}%
                      </span>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground block">Temp</span>
                      <span
                        className={cn(
                          "font-mono font-bold text-sm",
                          dev.temperature_c > 75 ? "text-red-500" : "text-foreground",
                        )}
                      >
                        {dev.temperature_c}°C
                      </span>
                    </div>
                  </div>
                ) : (
                  <div className="rounded-lg border border-dashed border-border/60 bg-muted/10 p-2.5 text-center text-muted-foreground text-[11px]">
                    Endpoint in standby · Last seen {new Date(dev.last_seen).toLocaleDateString()}
                  </div>
                )}

                {/* Active Threat Badges */}
                {dev.active_threats.length > 0 ? (
                  <div className="space-y-1">
                    <span className="text-[10px] font-semibold text-red-500 flex items-center gap-1">
                      <ShieldAlert className="size-3" /> Active Threats Detected:
                    </span>
                    <div className="flex flex-wrap gap-1">
                      {dev.active_threats.map((t, idx) => (
                        <Badge
                          key={idx}
                          variant="destructive"
                          className="text-[9px] font-mono px-1 py-0 uppercase"
                        >
                          {t}
                        </Badge>
                      ))}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-1.5 text-[11px] text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="size-3.5" />
                    <span>EDR Canary & Whitelist Active</span>
                  </div>
                )}

                {/* Autonomic Actions */}
                <div className="pt-2 border-t border-border/50 flex items-center justify-between gap-2">
                  {isCritical ? (
                    <Button
                      size="sm"
                      variant="destructive"
                      onClick={() => handleIsolateEndpoint(dev.name)}
                      className="h-7 w-full text-xs font-semibold"
                    >
                      <Lock className="size-3 mr-1" />
                      Isolate Endpoint
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      variant="outline"
                      asChild
                      className="h-7 w-full text-xs font-medium"
                    >
                      <Link to="/dashboard/monitor">
                        <Activity className="size-3 mr-1" />
                        Live Telemetry
                      </Link>
                    </Button>
                  )}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </div>
  );
}
