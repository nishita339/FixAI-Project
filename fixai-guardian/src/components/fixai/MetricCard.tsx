import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import type { LucideIcon } from "lucide-react";
import type { ReactNode } from "react";

export function MetricCard({
  icon: Icon,
  label,
  value,
  unit,
  hint,
  tone = "default",
  progress,
  children,
  className,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  unit?: string;
  hint?: string;
  tone?: "default" | "good" | "warn" | "bad";
  /** Optional 0..100 bar under the value. */
  progress?: number;
  children?: ReactNode;
  className?: string;
}) {
  const toneCls = {
    default: "text-primary",
    good: "text-emerald-500",
    warn: "text-amber-500",
    bad: "text-rose-500",
  }[tone];

  const iconBg = {
    default: "bg-primary/10 border-primary/20",
    good: "bg-emerald-500/10 border-emerald-500/20",
    warn: "bg-amber-500/10 border-amber-500/20",
    bad: "bg-rose-500/10 border-rose-500/20",
  }[tone];

  const hintBadge = {
    default: "bg-muted text-muted-foreground border-border/60",
    good: "bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 border-emerald-500/20",
    warn: "bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/20",
    bad: "bg-rose-500/10 text-rose-600 dark:text-rose-400 border-rose-500/20",
  }[tone];

  const progressColor = {
    default: "bg-primary",
    good: "bg-emerald-500",
    warn: "bg-amber-500",
    bad: "bg-rose-500",
  }[tone];

  return (
    <Card
      className={cn(
        "group relative overflow-hidden rounded-2xl border border-border/80 bg-card/70 p-0 shadow-soft backdrop-blur-md transition-all duration-300 hover:-translate-y-1 hover:border-primary/40 hover:shadow-soft-lg",
        className,
      )}
    >
      <div className="absolute top-0 right-0 h-16 w-16 bg-primary/5 rounded-full blur-xl pointer-events-none group-hover:bg-primary/10 transition-colors" />

      <CardContent className="flex flex-col justify-between gap-3 p-4 sm:p-5">
        <div className="flex items-center justify-between gap-2">
          <div
            className={cn(
              "flex size-9 items-center justify-center rounded-xl border transition-transform duration-200 group-hover:scale-105",
              iconBg,
              toneCls,
            )}
          >
            <Icon className="size-4.5" />
          </div>
          {hint ? (
            <span
              className={cn(
                "rounded-full border px-2 py-0.5 text-[10px] font-semibold tracking-wide capitalize shadow-2xs",
                hintBadge,
              )}
            >
              {hint}
            </span>
          ) : null}
        </div>

        <div>
          <p className="text-[11px] font-semibold uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="mt-1 flex items-baseline gap-1 font-bold tabular-nums text-foreground">
            <span className="text-2xl sm:text-3xl tracking-tight">{value}</span>
            {unit ? <span className="text-xs font-semibold text-muted-foreground">{unit}</span> : null}
          </p>
        </div>

        {progress !== undefined ? (
          <div className="space-y-1">
            <div className="h-1.5 w-full rounded-full bg-muted/80 overflow-hidden">
              <div
                className={cn("h-full rounded-full transition-all duration-500", progressColor)}
                style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
              />
            </div>
          </div>
        ) : null}

        {children}
      </CardContent>
    </Card>
  );
}
