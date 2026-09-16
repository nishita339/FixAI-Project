import React from "react";
import type { CausalGraph } from "@/lib/types";
import { Badge } from "@/components/ui/badge";
import { ArrowRight, GitFork, ShieldCheck, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";

interface CausalGraphViewProps {
  graph: CausalGraph;
  className?: string;
}

export function CausalGraphView({ graph, className }: CausalGraphViewProps) {
  if (!graph || !graph.nodes || graph.nodes.length === 0) return null;

  return (
    <div className={cn("space-y-4 rounded-xl border border-border/70 bg-card p-4 shadow-sm", className)}>
      {/* Header */}
      <div className="flex items-center justify-between border-b border-border/50 pb-3">
        <div className="flex items-center gap-2">
          <GitFork className="size-4 text-primary" />
          <h4 className="text-sm font-semibold tracking-tight">
            Causal Discovery DAG & Pearl's Do-Calculus
          </h4>
        </div>
        <Badge variant="outline" className="text-[10px] font-mono tracking-wide uppercase text-muted-foreground">
          PCMCI+ Causal Inference
        </Badge>
      </div>

      {/* Causal Node Topology */}
      <div>
        <p className="text-xs font-medium text-muted-foreground mb-2.5">
          Propagation Graph (Root Driver → Cascade Path):
        </p>
        <div className="grid grid-cols-1 sm:grid-cols-5 gap-2">
          {graph.nodes.map((node) => {
            const isRoot = node.id === graph.rootDriverId;
            return (
              <div
                key={node.id}
                className={cn(
                  "relative flex flex-col justify-between rounded-lg border p-2.5 transition-all",
                  isRoot
                    ? "border-red-500/50 bg-red-500/10 shadow-sm dark:border-red-500/40"
                    : node.severity === "CRITICAL"
                    ? "border-amber-500/40 bg-amber-500/5"
                    : "border-border/60 bg-muted/20"
                )}
              >
                <div className="flex items-center justify-between gap-1">
                  <span className="text-[11px] font-semibold text-foreground truncate">
                    {node.metric}
                  </span>
                  {isRoot && (
                    <Badge variant="destructive" className="px-1 py-0 text-[9px] font-bold tracking-wider">
                      ROOT
                    </Badge>
                  )}
                </div>

                <div className="my-1">
                  <span className="text-lg font-bold tabular-nums">
                    {node.value}
                    <span className="text-xs font-normal text-muted-foreground ml-0.5">{node.unit}</span>
                  </span>
                </div>

                <span className="text-[10px] text-muted-foreground truncate" title={node.label}>
                  {node.label}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Causal Chains */}
      {graph.edges.length > 0 && (
        <div className="rounded-lg border border-border/40 bg-muted/15 p-3">
          <p className="text-xs font-semibold text-foreground/80 mb-2">
            Identified Causal Links (P(Target | Source)):
          </p>
          <div className="space-y-1.5">
            {graph.edges.map((edge, idx) => {
              const srcNode = graph.nodes.find((n) => n.id === edge.source);
              const tgtNode = graph.nodes.find((n) => n.id === edge.target);
              return (
                <div key={idx} className="flex flex-wrap items-center gap-2 text-xs">
                  <span className="font-mono font-medium text-foreground">{srcNode?.metric ?? edge.source}</span>
                  <ArrowRight className="size-3 text-muted-foreground shrink-0" />
                  <span className="font-mono font-medium text-foreground">{tgtNode?.metric ?? edge.target}</span>
                  <Badge variant="secondary" className="text-[10px] px-1 py-0 font-mono">
                    weight {(edge.causalStrength * 100).toFixed(0)}%
                  </Badge>
                  <span className="text-muted-foreground text-[11px] italic">
                    — {edge.relationship}
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Do-Calculus Interventions */}
      {graph.interventions && graph.interventions.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-1.5">
            <Sparkles className="size-3.5 text-primary" />
            <p className="text-xs font-semibold text-foreground">
              Do-Calculus Interventional Outcomes: P(Healthy | do(Action))
            </p>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {graph.interventions.map((inv) => (
              <div
                key={inv.playbookId}
                className="flex items-center justify-between rounded-lg border border-border/60 bg-muted/20 p-2.5 text-xs"
              >
                <div>
                  <p className="font-medium text-foreground">{inv.playbookName}</p>
                  <p className="font-mono text-[10px] text-muted-foreground mt-0.5">{inv.doVariable}</p>
                </div>
                <div className="text-right">
                  <span className="font-bold text-emerald-600 dark:text-emerald-400">
                    {(inv.pSuccessGivenDo * 100).toFixed(0)}% P(fix)
                  </span>
                  <p className="text-[10px] text-muted-foreground">+{inv.expectedRulGainMinutes}m RUL</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
