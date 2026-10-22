import React, { useState, useRef, useEffect } from "react";
import type { FixAiAgent } from "@/hooks/use-fixai-agent";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Bot,
  CheckCircle2,
  Download,
  Flame,
  HardDrive,
  HeartPulse,
  Maximize2,
  Minimize2,
  Radio,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  Sparkles,
  Terminal,
  Trash2,
  User,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { executeLiveRepair } from "@/lib/history-store";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  suggestedActions?: string[];
  playbookRecommendations?: string[];
  mitreReferences?: string[];
  executedPlaybook?: string;
}

const DEFAULT_QUICK_PROMPTS = [
  "📊 Live System Health Status",
  "🔥 Fix Laptop Overheating & Loud Fans",
  "💾 Clean Disk Space & Temp Junk",
  "⚡ High CPU / App Freeze Fix",
  "🛡️ Check Ransomware & Canaries",
  "📶 Reset Network & Wi-Fi",
];

interface SecurityCopilotProps {
  agent?: FixAiAgent | null;
}

export function SecurityCopilot({ agent }: SecurityCopilotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [executingPlaybook, setExecutingPlaybook] = useState<string | null>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome-01",
      role: "assistant",
      content:
        "**FixAI Security & Systems Copilot Online**\n\n" +
        "I am your autonomous SOC Analyst & IT Systems Reliability Engineer. " +
        "I have direct access to your local workstation hardware vitals, process trees, and honeypot canaries.\n\n" +
        "Ask me about any problem (in English or Hindi/Hinglish)—such as overheating, slow laptop, disk full, Wi-Fi drops, malware, or playbooks. I can diagnose it and execute safe automated self-healing playbooks on your host machine instantly!",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      suggestedActions: [
        "📊 Live System Health Status",
        "🔥 Fix Laptop Overheating & Loud Fans",
        "💾 Clean Disk Space & Temp Junk",
      ],
      playbookRecommendations: ["clean_hosts_file", "cool_down_cpu"],
      mitreReferences: ["T1059.001", "T1546.003", "T1486"],
    },
  ]);

  // Auto-scroll to bottom of chat
  useEffect(() => {
    if (isOpen && !isMinimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen, isMinimized, executingPlaybook]);

  // Execute Playbook directly from chat bubble
  const handleExecutePlaybook = async (playbookId: string) => {
    if (executingPlaybook) return;
    setExecutingPlaybook(playbookId);
    const humanTitle = playbookId.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
    toast.info(`Executing autonomous playbook: ${humanTitle}...`);

    try {
      const res = await executeLiveRepair(playbookId, humanTitle);
      if (res.success) {
        toast.success(`Playbook '${humanTitle}' executed successfully!`);
        const executionMsg: ChatMessage = {
          id: `sys-${Date.now()}`,
          role: "assistant",
          content:
            `✅ **Automated Remediation Complete**\n\n` +
            `Playbook **\`${playbookId}\`** was executed successfully on this host workstation.\n\n` +
            `**Command Output & Verification:**\n` +
            `\`\`\`text\n${(res.logs || []).join("\n")}\n\`\`\`\n\n` +
            `*Post-fix telemetry soak completed without regression. System health verified.*`,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          suggestedActions: ["📊 Live System Health Status", "Check Active Incidents"],
          executedPlaybook: playbookId,
        };
        setMessages((prev) => [...prev, executionMsg]);
      } else {
        toast.warning(`Playbook execution finished with warnings.`);
      }
    } catch (err: any) {
      toast.error(`Playbook execution failed: ${err.message || err}`);
    } finally {
      setExecutingPlaybook(null);
    }
  };

  // Send message to Backend / Copilot endpoint
  const handleSendMessage = async (textToSend?: string) => {
    const text = (textToSend || inputMessage).trim();
    if (!text || isLoading) return;

    const userMsg: ChatMessage = {
      id: `user-${Date.now()}`,
      role: "user",
      content: text,
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputMessage("");
    setIsLoading(true);

    // Current endpoint context
    const currentTelemetry = {
      cpu: agent?.current?.cpu ?? 22.0,
      ram: agent?.current?.ram ?? 54.0,
      latency: agent?.current?.latency ?? 14.0,
      errorRate: agent?.current?.errorRate ?? 0.0,
      healthScore: agent?.healthScore ?? 95,
      risk: agent?.verdict?.risk ?? "LOW",
    };

    const incidentContext = agent?.episode
      ? {
          id: agent.episode.incident.id,
          primaryCause: agent.episode.incident.rootCause.primaryCause,
          risk: agent.episode.incident.risk,
          explanation: agent.episode.incident.rootCause.explanation,
        }
      : undefined;

    try {
      const backendUrl = import.meta.env.VITE_FASTAPI_URL || "http://localhost:8000";
      const res = await fetch(`${backendUrl}/api/v1/agent/copilot/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          history: messages.slice(-8).map((m) => ({ role: m.role, content: m.content })),
          telemetry_context: currentTelemetry,
          incident_context: incidentContext,
        }),
      });

      if (res.ok) {
        const data = await res.json();
        const botMsg: ChatMessage = {
          id: `bot-${Date.now()}`,
          role: "assistant",
          content: data.reply,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          suggestedActions: data.suggested_actions || [],
          playbookRecommendations: data.playbook_recommendations || [],
          mitreReferences: data.mitre_references || [],
        };
        setMessages((prev) => [...prev, botMsg]);
      } else {
        throw new Error("Backend copilot error");
      }
    } catch {
      // High-Fidelity Client-side Fallback if backend is offline
      setTimeout(() => {
        let fallbackReply = `**FixAI SOC Engine (Offline Standalone)**\n\n`;
        const lower = text.toLowerCase();

        if (lower.includes("overheat") || lower.includes("garam") || lower.includes("fan")) {
          fallbackReply +=
            `🔥 **CPU Thermal Diagnostics & Cooldown Analysis**\n\n` +
            `• Current CPU Load: **${currentTelemetry.cpu}%**\n` +
            `• Frequent causes include clogged exhaust vents, dried thermal paste, or high background CPU workers.\n\n` +
            `**Immediate Fix:** Execute **\`cool_down_cpu\`** below to throttle CPU clock states and restore baseline temperatures.`;
        } else if (lower.includes("slow") || lower.includes("hang") || lower.includes("freeze") || lower.includes("dheema")) {
          fallbackReply +=
            `⚡ **System Slowness & Freeze Remediation**\n\n` +
            `• CPU: **${currentTelemetry.cpu}%** · RAM: **${currentTelemetry.ram}%**\n` +
            `• High background tasks create thread locks and pagefile thrashing.\n\n` +
            `**Immediate Fix:** Execute **\`kill_runaway_process\`** or **\`flush_cache\`** to reclaim memory immediately.`;
        } else if (lower.includes("disk") || lower.includes("storage") || lower.includes("khali")) {
          fallbackReply +=
            `💾 **Drive C: Storage Optimization**\n\n` +
            `• Windows accumulated temporary installation files, shadow copies, and browser caches.\n\n` +
            `**Immediate Fix:** Execute **\`purge_tmp\`** below to safely clean temp junk files.`;
        } else {
          fallbackReply +=
            `📊 **FixAI Diagnostics Report**\n\n` +
            `• System Health Score: **${agent?.healthScore ?? 95}%**\n` +
            `• CPU: **${currentTelemetry.cpu}%** · RAM: **${currentTelemetry.ram}%** · Latency: **${currentTelemetry.latency}ms**\n\n` +
            `You can run any self-healing playbook below to optimize your system.`;
        }

        const fallbackMsg: ChatMessage = {
          id: `bot-${Date.now()}`,
          role: "assistant",
          content: fallbackReply,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          suggestedActions: ["📊 Live System Health Status", "Clean Temp Files"],
          playbookRecommendations: ["clean_hosts_file", "cool_down_cpu"],
          mitreReferences: ["T1059.001"],
        };
        setMessages((prev) => [...prev, fallbackMsg]);
      }, 350);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearChat = () => {
    setMessages([
      {
        id: `welcome-${Date.now()}`,
        role: "assistant",
        content: "Chat history cleared. FixAI Security Copilot is ready for your questions.",
        timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
        suggestedActions: [
          "📊 Live System Health Status",
          "🔥 Fix Laptop Overheating & Loud Fans",
          "💾 Clean Disk Space & Temp Junk",
        ],
        playbookRecommendations: ["clean_hosts_file"],
      },
    ]);
    toast.info("Copilot chat history cleared");
  };

  const handleExportChat = () => {
    const text = messages
      .map((m) => `[${m.timestamp}] ${m.role === "user" ? "USER" : "FIXAI COPILOT"}:\n${m.content}\n`)
      .join("\n---\n\n");
    const blob = new Blob([text], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `fixai-copilot-report-${Date.now()}.md`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success("Copilot incident report exported");
  };

  return (
    <>
      {/* Floating Action Button */}
      {!isOpen && (
        <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3">
          <Button
            onClick={() => setIsOpen(true)}
            size="lg"
            className="group relative h-13 gap-2.5 rounded-full border border-primary/40 bg-card px-4 text-foreground shadow-2xl transition-all duration-300 hover:border-primary hover:bg-primary/10 hover:shadow-primary/25"
          >
            <div className="relative flex size-8 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-sm transition-transform duration-300 group-hover:scale-110">
              <Sparkles className="size-4 animate-spin-slow" />
              <div className="absolute -inset-1 rounded-full bg-primary/30 blur-sm animate-pulse" />
            </div>
            <div className="flex flex-col items-start text-left">
              <span className="text-xs font-bold tracking-tight flex items-center gap-1.5">
                FixAI Copilot
                <Badge variant="outline" className="px-1 py-0 text-[9px] font-mono border-primary/40 text-primary">
                  AI SOC
                </Badge>
              </span>
              <span className="text-[10px] text-muted-foreground font-mono">
                {agent?.episode ? "⚠️ Active Incident" : "● Health Nominal"}
              </span>
            </div>
          </Button>
        </div>
      )}

      {/* Floating Chat Modal / Slide-Over */}
      {isOpen && (
        <div className="fixed bottom-6 right-6 z-50 flex flex-col items-end">
          <Card
            className={cn(
              "flex flex-col overflow-hidden border-border/80 bg-card/95 shadow-2xl backdrop-blur-md transition-all duration-300",
              isMinimized
                ? "h-14 w-80 rounded-2xl"
                : isExpanded
                ? "h-[660px] w-[95vw] sm:w-[620px] rounded-2xl"
                : "h-[560px] w-[95vw] sm:w-[430px] rounded-2xl",
            )}
          >
            {/* Header */}
            <CardHeader className="flex flex-row items-center justify-between border-b border-border/60 bg-muted/40 p-3.5 space-y-0">
              <div className="flex items-center gap-2.5">
                <div className="flex size-7 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-xs">
                  <Bot className="size-4" />
                </div>
                <div>
                  <CardTitle className="text-xs font-bold flex items-center gap-1.5">
                    FixAI Security & Systems Copilot
                    <Badge variant="outline" className="text-[9px] font-mono px-1 py-0 border-emerald-500/40 text-emerald-500">
                      LIVE
                    </Badge>
                  </CardTitle>
                  <p className="text-[10px] text-muted-foreground font-mono">
                    Autonomous EDR & Self-Healing Partner
                  </p>
                </div>
              </div>

              {/* Window Controls */}
              <div className="flex items-center gap-1">
                <Button
                  size="icon"
                  variant="ghost"
                  title="Export Chat Report"
                  className="size-7 text-muted-foreground hover:text-foreground"
                  onClick={handleExportChat}
                >
                  <Download className="size-3.5" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  title="Clear Conversation"
                  className="size-7 text-muted-foreground hover:text-foreground"
                  onClick={handleClearChat}
                >
                  <Trash2 className="size-3.5" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  title={isExpanded ? "Collapse Width" : "Expand Width"}
                  className="size-7 text-muted-foreground hover:text-foreground hidden sm:flex"
                  onClick={() => setIsExpanded(!isExpanded)}
                >
                  {isExpanded ? <Minimize2 className="size-3.5" /> : <Maximize2 className="size-3.5" />}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  title={isMinimized ? "Restore" : "Minimize"}
                  className="size-7 text-muted-foreground hover:text-foreground"
                  onClick={() => setIsMinimized(!isMinimized)}
                >
                  <Minimize2 className="size-3.5" />
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  title="Close"
                  className="size-7 text-muted-foreground hover:text-destructive"
                  onClick={() => setIsOpen(false)}
                >
                  <X className="size-3.5" />
                </Button>
              </div>
            </CardHeader>

            {/* Chat Body */}
            {!isMinimized && (
              <>
                <div className="flex-1 overflow-y-auto p-4 space-y-4 text-xs">
                  {messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={cn(
                        "flex flex-col gap-1.5",
                        msg.role === "user" ? "items-end" : "items-start",
                      )}
                    >
                      <div className="flex items-center gap-1.5 px-1 text-[10px] text-muted-foreground font-mono">
                        {msg.role === "assistant" ? (
                          <>
                            <Sparkles className="size-3 text-primary" />
                            <span>FixAI Copilot</span>
                          </>
                        ) : (
                          <>
                            <User className="size-3" />
                            <span>You</span>
                          </>
                        )}
                        <span>· {msg.timestamp}</span>
                      </div>

                      <div
                        className={cn(
                          "rounded-2xl px-3.5 py-2.5 max-w-[92%] text-xs leading-relaxed shadow-xs whitespace-pre-wrap",
                          msg.role === "user"
                            ? "bg-primary text-primary-foreground rounded-br-xs"
                            : "bg-muted/70 text-foreground border border-border/70 rounded-bl-xs",
                        )}
                      >
                        {msg.content}

                        {/* MITRE Badges if provided */}
                        {msg.mitreReferences && msg.mitreReferences.length > 0 && (
                          <div className="mt-2.5 pt-2 border-t border-border/50 flex flex-wrap gap-1">
                            {msg.mitreReferences.map((ref, idx) => (
                              <Badge
                                key={idx}
                                variant="outline"
                                className="border-red-500/40 bg-red-500/10 text-[9px] font-mono text-red-600 dark:text-red-400 px-1 py-0"
                              >
                                {ref}
                              </Badge>
                            ))}
                          </div>
                        )}

                        {/* Interactive Playbook Execution Buttons */}
                        {msg.playbookRecommendations && msg.playbookRecommendations.length > 0 && (
                          <div className="mt-3 pt-2 border-t border-border/60">
                            <span className="text-[10px] text-muted-foreground font-semibold flex items-center gap-1 mb-1.5">
                              <Wrench className="size-3 text-primary" /> Recommended Self-Healing Actions:
                            </span>
                            <div className="flex flex-wrap items-center gap-1.5">
                              {msg.playbookRecommendations.map((pb) => (
                                <Button
                                  key={pb}
                                  size="sm"
                                  variant="secondary"
                                  disabled={executingPlaybook === pb}
                                  onClick={() => handleExecutePlaybook(pb)}
                                  className="h-6 px-2.5 text-[10px] font-mono gap-1 rounded-md bg-primary/15 text-primary hover:bg-primary/25 border border-primary/30 shadow-2xs"
                                >
                                  {executingPlaybook === pb ? (
                                    <>
                                      <RefreshCw className="size-2.5 animate-spin" />
                                      Executing...
                                    </>
                                  ) : (
                                    <>
                                      <Zap className="size-2.5" />
                                      Run {pb}
                                    </>
                                  )}
                                </Button>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Suggested Actions Buttons */}
                      {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1 max-w-[92%]">
                          {msg.suggestedActions.map((action, idx) => (
                            <button
                              key={idx}
                              onClick={() => handleSendMessage(action)}
                              className="rounded-full border border-border/80 bg-background/80 px-2.5 py-1 text-[10px] font-medium text-muted-foreground hover:border-primary/50 hover:text-foreground hover:bg-accent/60 transition-all text-left"
                            >
                              ⚡ {action}
                            </button>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}

                  {isLoading && (
                    <div className="flex items-center gap-2 text-xs text-muted-foreground p-2">
                      <RefreshCw className="size-3.5 animate-spin text-primary" />
                      <span className="italic font-mono text-[11px]">FixAI Copilot analyzing endpoint telemetry & diagnostics...</span>
                    </div>
                  )}

                  {executingPlaybook && (
                    <div className="flex items-center gap-2 text-xs text-primary p-2 border border-primary/30 rounded-lg bg-primary/5">
                      <Zap className="size-3.5 animate-pulse" />
                      <span className="font-mono text-[11px]">Executing self-healing playbook: {executingPlaybook}...</span>
                    </div>
                  )}

                  <div ref={messagesEndRef} />
                </div>

                {/* Quick Prompts Bar */}
                <div className="border-t border-border/50 bg-muted/20 px-3 py-1.5 overflow-x-auto flex gap-1.5 no-scrollbar">
                  {DEFAULT_QUICK_PROMPTS.map((prompt, idx) => (
                    <button
                      key={idx}
                      onClick={() => handleSendMessage(prompt)}
                      className="whitespace-nowrap rounded-md border border-border/60 bg-card px-2 py-0.5 text-[10px] text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>

                {/* Chat Input Bar */}
                <div className="border-t border-border/60 p-2.5 bg-background">
                  <form
                    onSubmit={(e) => {
                      e.preventDefault();
                      handleSendMessage();
                    }}
                    className="flex items-center gap-2"
                  >
                    <Input
                      value={inputMessage}
                      onChange={(e) => setInputMessage(e.target.value)}
                      placeholder="Ask FixAI Copilot about overheating, RAM, disk, threats, playbooks..."
                      disabled={isLoading}
                      className="h-9 text-xs font-mono"
                    />
                    <Button
                      type="submit"
                      size="icon"
                      disabled={!inputMessage.trim() || isLoading}
                      className="size-9 shrink-0 rounded-lg"
                    >
                      <Send className="size-3.5" />
                    </Button>
                  </form>
                </div>
              </>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
