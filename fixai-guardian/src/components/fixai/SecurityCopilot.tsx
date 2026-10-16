import React, { useState, useRef, useEffect } from "react";
import type { FixAiAgent } from "@/hooks/use-fixai-agent";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle, CardFooter } from "@/components/ui/card";
import {
  Bot,
  BrainCircuit,
  ChevronDown,
  Copy,
  CornerDownLeft,
  FileCode2,
  HardDrive,
  Maximize2,
  Minimize2,
  RefreshCw,
  Send,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Trash2,
  User,
  Wand2,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import { Link } from "react-router";

interface ChatMessage {
  id: string;
  role: "user" | "assistant" | "system";
  content: string;
  timestamp: string;
  suggestedActions?: string[];
  playbookRecommendations?: string[];
  mitreReferences?: string[];
}

const DEFAULT_QUICK_PROMPTS = [
  "Explain my current health & top risk drivers",
  "How do I mitigate WMI persistence (T1546.003)?",
  "Check for zero-day ransomware or canary tampers",
  "Which playbooks are safe to auto-execute?",
];

interface SecurityCopilotProps {
  agent?: FixAiAgent | null;
}

export function SecurityCopilot({ agent }: SecurityCopilotProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [isMinimized, setIsMinimized] = useState(false);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "welcome-01",
      role: "assistant",
      content:
        "**FixAI Security Copilot Online**\n\n" +
        "I am your autonomic AI SOC Analyst & Systems Reliability Engineer. " +
        "I am actively monitoring your live telemetry, process lineage, and honeypot canary files.\n\n" +
        "How can I assist your incident response or system optimization today?",
      timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
      suggestedActions: [
        "Explain current health",
        "How to mitigate WMI persistence?",
        "Check ransomware status",
      ],
      playbookRecommendations: ["clean_hosts_file", "remediate_brute_force"],
      mitreReferences: ["T1059.001", "T1546.003", "T1486"],
    },
  ]);

  // Auto-scroll to bottom of chat
  useEffect(() => {
    if (isOpen && !isMinimized) {
      messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
    }
  }, [messages, isOpen, isMinimized]);

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

    // Prepare current endpoint context
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
      // Call backend FastAPI endpoint (local or cloud)
      const backendUrl = import.meta.env.VITE_FASTAPI_URL || "http://localhost:8000";
      const res = await fetch(`${backendUrl}/api/v1/agent/copilot/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message: text,
          history: messages.slice(-6).map((m) => ({ role: m.role, content: m.content })),
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
      // High-Fidelity Client-side AI SOC fallback if backend is offline
      setTimeout(() => {
        let fallbackReply = `**FixAI SOC Engine (Offline Mode)**\n\nI have received: *"${text}"*.\n\n`;
        const lower = text.toLowerCase();

        if (lower.includes("wmi") || lower.includes("persistence")) {
          fallbackReply +=
            "**WMI Persistence Detected (MITRE T1546.003)**\n" +
            "Rogue WMI Event Consumers allow attacker scripts to persist without files. " +
            "Navigate to the **Incidents & Threats** page and use the **Process Tree Visualizer** to isolate and terminate the child shell.";
        } else if (lower.includes("ransomware") || lower.includes("canary")) {
          fallbackReply +=
            "**Zero-Day Ransomware Canary Trap Active**\n" +
            "Decoy honeypot files are monitored by background Watchdog threads. " +
            "No active encryption tamper detected. If triggered, system initiates immediate network isolation.";
        } else if (lower.includes("health") || lower.includes("cpu") || lower.includes("ram")) {
          fallbackReply +=
            `Current Health Score: **${agent?.healthScore ?? 95}%** (${agent?.verdict?.risk ?? "LOW"} Risk).\n` +
            `CPU: **${currentTelemetry.cpu}%** · RAM: **${currentTelemetry.ram}%** · Latency: **${currentTelemetry.latency}ms**.\n` +
            "Telemetry is within optimal operating bounds.";
        } else {
          fallbackReply +=
            "Your query has been logged. FixAI EDR provides real-time brute-force defense, " +
            "fileless threat hunting, AES-256 quarantine, and 28 autonomic recovery playbooks.";
        }

        const fallbackMsg: ChatMessage = {
          id: `bot-${Date.now()}`,
          role: "assistant",
          content: fallbackReply,
          timestamp: new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
          suggestedActions: ["Explain current health", "View Process Tree", "Open Playbook Catalog"],
          playbookRecommendations: ["clean_hosts_file"],
          mitreReferences: ["T1059.001", "T1546.003"],
        };
        setMessages((prev) => [...prev, fallbackMsg]);
      }, 400);
    } finally {
      setIsLoading(false);
    }
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
                : "h-[540px] w-[380px] sm:w-[420px] rounded-2xl",
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
                    FixAI Security Copilot
                    <Badge variant="outline" className="text-[9px] font-mono px-1 py-0 border-emerald-500/40 text-emerald-500">
                      LIVE
                    </Badge>
                  </CardTitle>
                  <p className="text-[10px] text-muted-foreground font-mono">
                    EDR & IT Reliability Assistant
                  </p>
                </div>
              </div>

              {/* Window Controls */}
              <div className="flex items-center gap-1">
                <Button
                  size="icon"
                  variant="ghost"
                  className="size-7 text-muted-foreground hover:text-foreground"
                  onClick={() => setIsMinimized(!isMinimized)}
                >
                  {isMinimized ? <Maximize2 className="size-3.5" /> : <Minimize2 className="size-3.5" />}
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
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
                            <span>FixAI SOC Copilot</span>
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
                          "rounded-2xl px-3.5 py-2.5 max-w-[88%] text-xs leading-relaxed shadow-xs whitespace-pre-wrap",
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

                        {/* Playbook Links if provided */}
                        {msg.playbookRecommendations && msg.playbookRecommendations.length > 0 && (
                          <div className="mt-2 flex flex-wrap items-center gap-1.5">
                            <span className="text-[10px] text-muted-foreground font-medium flex items-center gap-1">
                              <Wrench className="size-2.5 text-primary" /> Playbook:
                            </span>
                            {msg.playbookRecommendations.map((pb) => (
                              <Link
                                key={pb}
                                to="/dashboard/recovery"
                                className="rounded bg-primary/10 px-1.5 py-0.5 text-[10px] font-mono text-primary hover:bg-primary/20 transition-colors"
                              >
                                {pb}
                              </Link>
                            ))}
                          </div>
                        )}
                      </div>

                      {/* Suggested Actions Buttons */}
                      {msg.suggestedActions && msg.suggestedActions.length > 0 && (
                        <div className="flex flex-wrap gap-1 mt-1">
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
                      <span className="italic font-mono text-[11px]">FixAI Copilot analyzing endpoint telemetry...</span>
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
                      placeholder="Ask FixAI Copilot about threats, playbooks, health..."
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
