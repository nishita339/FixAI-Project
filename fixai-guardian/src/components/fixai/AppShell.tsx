import { StatusBadge } from "@/components/fixai/badges";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Sheet, SheetContent, SheetTitle, SheetTrigger } from "@/components/ui/sheet";
import { useAuth } from "@/hooks/use-auth";
import { useFixAiAgent, type FixAiAgent } from "@/hooks/use-fixai-agent";
import { useTheme } from "@/hooks/use-theme";
import { cn } from "@/lib/utils";
import {
  Activity,
  ChevronDown,
  Cpu,
  Gauge,
  HeartPulse,
  History,
  Laptop,
  LayoutDashboard,
  LogOut,
  MemoryStick,
  Menu,
  Monitor,
  Moon,
  RadioTower,
  Settings,
  ShieldCheck,
  Sun,
  Wrench,
  Zap,
} from "lucide-react";
import { useState } from "react";
import { Link, NavLink, Outlet, useNavigate } from "react-router";

const NAV = [
  { to: "/dashboard", label: "Overview", icon: LayoutDashboard },
  { to: "/dashboard/hardware", label: "Laptop Doctor", icon: Laptop },
  { to: "/dashboard/monitor", label: "Live Telemetry", icon: Activity },
  { to: "/dashboard/incidents", label: "Incidents & Threats", icon: Monitor },
  { to: "/dashboard/recovery", label: "Self-Healing Playbooks", icon: Wrench },
  { to: "/dashboard/history", label: "Audit & Solved Logs", icon: History },
  { to: "/dashboard/permissions", label: "Policy & Sandbox", icon: ShieldCheck },
];

function NavLinks({ onNavigate }: { onNavigate?: () => void }) {
  return (
    <nav className="flex flex-col gap-1.5">
      {NAV.map((item) => (
        <NavLink
          key={item.to}
          to={item.to}
          onClick={onNavigate}
          className={({ isActive }) =>
            cn(
              "group flex items-center gap-3 rounded-xl px-3.5 py-2.5 text-sm font-medium transition-all duration-200",
              isActive
                ? "bg-primary/15 text-primary shadow-xs font-semibold dark:bg-primary/20"
                : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
            )
          }
        >
          {({ isActive }) => (
            <>
              <div
                className={cn(
                  "flex size-7 items-center justify-center rounded-lg transition-colors",
                  isActive
                    ? "bg-primary text-primary-foreground shadow-xs"
                    : "bg-muted/60 text-muted-foreground group-hover:bg-primary/15 group-hover:text-primary",
                )}
              >
                <item.icon className="size-4 shrink-0" />
              </div>
              <span className="truncate">{item.label}</span>
              {isActive && (
                <span className="ml-auto size-1.5 rounded-full bg-primary animate-pulse" />
              )}
            </>
          )}
        </NavLink>
      ))}
    </nav>
  );
}

function Brand() {
  return (
    <Link to="/" className="group flex items-center gap-3">
      <div className="flex size-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary via-emerald-500 to-cyan-500 text-primary-foreground shadow-md shadow-primary/20 transition-transform group-hover:scale-105">
        <HeartPulse className="size-5 animate-pulse" />
      </div>
      <div>
        <div className="flex items-center gap-1.5">
          <span className="text-base font-bold tracking-tight text-foreground">
            Fix<span className="text-gradient-cyan">AI</span>
          </span>
          <span className="rounded-full bg-primary/10 px-1.5 py-0.2 text-[10px] font-semibold text-primary dark:bg-primary/20">
            PRO
          </span>
        </div>
        <p className="text-[11px] font-medium text-muted-foreground">Autonomous AIOps & EDR</p>
      </div>
    </Link>
  );
}

export default function AppShell() {
  const { user, signOut } = useAuth();
  const { theme, setTheme, isDark } = useTheme();
  const navigate = useNavigate();
  const [mobileOpen, setMobileOpen] = useState(false);
  const agent: FixAiAgent = useFixAiAgent();

  const handleSignOut = async () => {
    await signOut();
    navigate("/");
  };

  const displayName = user?.name || user?.email?.split("@")[0] || "SecOps Lead";

  return (
    <div className="flex min-h-screen bg-background">
      {/* Desktop sidebar */}
      <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-border/70 bg-sidebar/80 px-4 py-5 backdrop-blur-xl lg:flex">
        <div className="px-1 pb-6">
          <Brand />
        </div>
        
        <NavLinks />

        {/* Live Mini Telemetry Meter in Sidebar Footer */}
        <div className="mt-auto space-y-3 pt-4">
          <div className="rounded-xl border border-border/80 bg-card/60 p-3.5 shadow-xs backdrop-blur-md">
            <div className="flex items-center justify-between pb-2">
              <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
                Live Host Vitals
              </span>
              <span className="flex items-center gap-1 text-[11px] font-medium text-emerald-500">
                <span className="size-1.5 rounded-full bg-emerald-500 animate-ping" />
                Synced
              </span>
            </div>

            <div className="space-y-2">
              <div>
                <div className="flex items-center justify-between text-xs mb-1 font-medium">
                  <span className="flex items-center gap-1 text-muted-foreground">
                    <Cpu className="size-3" /> CPU Load
                  </span>
                  <span className="tabular-nums font-semibold">{agent.current.cpu}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-500",
                      agent.current.cpu > 80
                        ? "bg-rose-500"
                        : agent.current.cpu > 50
                          ? "bg-amber-500"
                          : "bg-emerald-500",
                    )}
                    style={{ width: `${Math.min(100, Math.max(0, agent.current.cpu))}%` }}
                  />
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between text-xs mb-1 font-medium">
                  <span className="flex items-center gap-1 text-muted-foreground">
                    <MemoryStick className="size-3" /> RAM Memory
                  </span>
                  <span className="tabular-nums font-semibold">{agent.current.ram}%</span>
                </div>
                <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
                  <div
                    className={cn(
                      "h-full rounded-full transition-all duration-500",
                      agent.current.ram > 85
                        ? "bg-rose-500"
                        : agent.current.ram > 65
                          ? "bg-amber-500"
                          : "bg-cyan-500",
                    )}
                    style={{ width: `${Math.min(100, Math.max(0, agent.current.ram))}%` }}
                  />
                </div>
              </div>
            </div>

            <div className="mt-2.5 pt-2 border-t border-border/60 flex items-center justify-between text-[11px] text-muted-foreground">
              <span>Predictive Lead</span>
              <span className="font-semibold text-foreground">5 min · UCB Bandit</span>
            </div>
          </div>

          <Button
            variant="ghost"
            size="sm"
            className="w-full justify-start gap-2 text-muted-foreground hover:bg-destructive/10 hover:text-destructive transition-colors text-xs"
            onClick={handleSignOut}
          >
            <LogOut className="size-3.5" /> Sign out
          </Button>
        </div>
      </aside>

      {/* Main content column */}
      <div className="flex min-w-0 flex-1 flex-col">
        {/* Header */}
        <header className="sticky top-0 z-30 border-b border-border/70 bg-background/80 backdrop-blur-xl">
          <div className="flex h-15 items-center gap-3 px-4 sm:px-6">
            <div className="lg:hidden">
              <Sheet open={mobileOpen} onOpenChange={setMobileOpen}>
                <SheetTrigger asChild>
                  <Button variant="ghost" size="icon" aria-label="Open navigation">
                    <Menu className="size-5" />
                  </Button>
                </SheetTrigger>
                <SheetContent side="left" className="w-68 p-4">
                  <SheetTitle className="sr-only">Navigation</SheetTitle>
                  <div className="pb-5">
                    <Brand />
                  </div>
                  <NavLinks onNavigate={() => setMobileOpen(false)} />
                </SheetContent>
              </Sheet>
            </div>

            {/* Live Operational Status Pills */}
            <div className="flex min-w-0 items-center gap-2 sm:gap-3">
              <StatusBadge status={agent.status} className="h-7 px-3 text-xs shadow-xs" />

              {/* EDR Shield Active Pill */}
              <div className="hidden sm:flex items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-medium text-emerald-600 dark:text-emerald-400 shadow-xs">
                <ShieldCheck className="size-3.5 shrink-0 animate-pulse text-emerald-500" />
                <span>EDR Shield: Active</span>
              </div>

              {/* Host Telemetry Link Pill */}
              <div className="hidden md:flex items-center gap-1.5 rounded-full border border-border/80 bg-card/60 px-3 py-1 text-xs text-muted-foreground shadow-xs">
                <RadioTower className="size-3.5 shrink-0 text-primary animate-pulse" />
                <span>Host Telemetry Live</span>
              </div>
            </div>

            {/* Right side controls: Health Score, Theme Switcher, User Menu */}
            <div className="ml-auto flex items-center gap-2.5 sm:gap-3">
              {/* Overall Health Pill */}
              <div className="flex items-center gap-1.5 rounded-lg border border-border/80 bg-card/70 px-3 py-1.5 text-xs font-semibold shadow-xs">
                <Gauge className="size-3.5 text-primary" />
                <span className="text-muted-foreground font-normal">Health</span>
                <span
                  className={cn(
                    "tabular-nums font-bold",
                    agent.healthScore >= 90
                      ? "text-emerald-500"
                      : agent.healthScore >= 70
                        ? "text-amber-500"
                        : "text-rose-500",
                  )}
                >
                  {agent.healthScore}%
                </span>
              </div>

              {/* Dark/Light Theme Switcher */}
              <Button
                variant="ghost"
                size="icon"
                onClick={() => setTheme(isDark ? "light" : "dark")}
                className="size-9 rounded-xl border border-border/70 hover:bg-accent hover:border-primary/40 transition-colors"
                title={`Switch to ${isDark ? "Light" : "Dark"} mode`}
                aria-label="Toggle theme"
              >
                {isDark ? (
                  <Sun className="size-4.5 text-amber-400 transition-transform duration-300 hover:rotate-45" />
                ) : (
                  <Moon className="size-4.5 text-slate-700 transition-transform duration-300 hover:-rotate-12" />
                )}
              </Button>

              {/* User profile menu */}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="ghost" className="gap-2 rounded-xl px-2 hover:bg-accent/60">
                    <div className="flex size-7.5 items-center justify-center rounded-lg bg-gradient-to-br from-primary to-cyan-500 text-xs font-bold text-primary-foreground shadow-xs uppercase">
                      {displayName.slice(0, 2)}
                    </div>
                    <span className="hidden text-xs font-semibold md:inline">{displayName}</span>
                    <ChevronDown className="size-3 text-muted-foreground" />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end" className="w-56 p-1.5 shadow-lg">
                  <DropdownMenuLabel className="px-2 py-1.5 text-xs text-muted-foreground font-normal">
                    Signed in as <strong className="font-semibold text-foreground">{user?.email || displayName}</strong>
                  </DropdownMenuLabel>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={() => navigate("/dashboard/hardware")}>
                    <Laptop className="size-4 mr-2" /> Laptop Doctor
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => navigate("/dashboard/recovery")}>
                    <Wrench className="size-4 mr-2" /> Self-Healing Playbooks
                  </DropdownMenuItem>
                  <DropdownMenuItem onClick={() => navigate("/dashboard/permissions")}>
                    <Settings className="size-4 mr-2" /> Policy & Risk Rules
                  </DropdownMenuItem>
                  <DropdownMenuSeparator />
                  <DropdownMenuItem onClick={handleSignOut} className="text-destructive focus:text-destructive">
                    <LogOut className="size-4 mr-2" /> Sign out
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </div>
          </div>
        </header>

        <main className="flex-1 px-4 py-6 sm:px-6 lg:px-8">
          <Outlet context={agent} />
        </main>
      </div>
    </div>
  );
}
