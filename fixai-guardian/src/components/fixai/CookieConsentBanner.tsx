import { useState, useEffect } from "react";
import { ShieldCheck, Cookie, Lock, EyeOff, Cpu, Info, Check, X, Sliders } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";

const STORAGE_KEY = "fixai_cookie_consent_v1";

export interface ConsentSettings {
  necessary: boolean;
  telemetry: boolean;
  diagnostics: boolean;
  timestamp: string;
}

const DEFAULT_SETTINGS: ConsentSettings = {
  necessary: true,
  telemetry: true,
  diagnostics: true,
  timestamp: new Date().toISOString(),
};

export function CookieConsentBanner() {
  const [isVisible, setIsVisible] = useState(false);
  const [modalOpen, setModalOpen] = useState(false);
  const [activeTab, setActiveTab] = useState<"preferences" | "policy">("preferences");
  const [settings, setSettings] = useState<ConsentSettings>(DEFAULT_SETTINGS);

  useEffect(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        setSettings(JSON.parse(stored));
      } else {
        // Show banner after brief delay for smooth UX
        const timer = setTimeout(() => setIsVisible(true), 800);
        return () => clearTimeout(timer);
      }
    } catch {
      setIsVisible(true);
    }

    // Global event listener so buttons/footers can reopen privacy modal anytime
    const handleOpen = () => {
      setModalOpen(true);
    };
    window.addEventListener("fixai-open-privacy-consent", handleOpen);
    return () => window.removeEventListener("fixai-open-privacy-consent", handleOpen);
  }, []);

  const saveSettings = (newSettings: ConsentSettings) => {
    setSettings(newSettings);
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(newSettings));
    } catch (e) {
      console.warn("Could not save consent preferences to localStorage", e);
    }
    setIsVisible(false);
    setModalOpen(false);
  };

  const handleAcceptAll = () => {
    saveSettings({
      necessary: true,
      telemetry: true,
      diagnostics: true,
      timestamp: new Date().toISOString(),
    });
  };

  const handleEssentialOnly = () => {
    saveSettings({
      necessary: true,
      telemetry: false,
      diagnostics: false,
      timestamp: new Date().toISOString(),
    });
  };

  const handleCustomSave = () => {
    saveSettings({
      ...settings,
      necessary: true,
      timestamp: new Date().toISOString(),
    });
  };

  return (
    <>
      {/* ── Floating Cookie & Telemetry Privacy Banner ── */}
      {isVisible && (
        <aside
          role="region"
          aria-label="Cookie and Privacy Consent Banner"
          className="fixed bottom-4 left-4 right-4 z-50 mx-auto max-w-4xl animate-in fade-in slide-in-from-bottom-5 duration-300 sm:bottom-6"
        >
          <div className="relative overflow-hidden rounded-2xl border border-primary/20 bg-background/95 p-4 shadow-2xl backdrop-blur-xl sm:p-5">
            <div className="absolute inset-x-0 -top-px h-px bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
            
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
              <div className="flex items-start gap-3.5">
                <div className="flex size-10 shrink-0 items-center justify-center rounded-xl bg-primary/10 text-primary border border-primary/20">
                  <Cookie className="size-5" />
                </div>
                <div className="space-y-1">
                  <div className="flex items-center gap-2">
                    <h4 className="text-sm font-semibold text-foreground">
                      Telemetry & Privacy Notice
                    </h4>
                    <Badge variant="outline" className="border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-[10px] px-1.5 py-0 font-medium">
                      Zero-Knowledge Privacy
                    </Badge>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed max-w-2xl">
                    FixAI samples local hardware metrics (CPU, RAM, Disk, System thermals) strictly for real-time anomaly detection and autonomic self-healing.
                    <strong> We never inspect personal files, passwords, webcam, or private browser history.</strong>
                  </p>
                </div>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2 sm:shrink-0">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setActiveTab("preferences");
                    setModalOpen(true);
                  }}
                  className="h-8 gap-1.5 text-xs text-muted-foreground hover:text-foreground"
                >
                  <Sliders className="size-3.5" />
                  Preferences
                </Button>
                <Button
                  size="sm"
                  variant="secondary"
                  onClick={handleEssentialOnly}
                  className="h-8 text-xs font-medium"
                >
                  Essential Only
                </Button>
                <Button
                  size="sm"
                  onClick={handleAcceptAll}
                  className="h-8 text-xs font-semibold bg-primary text-primary-foreground hover:bg-primary/90 shadow-xs"
                >
                  Accept All
                </Button>
              </div>
            </div>
          </div>
        </aside>
      )}

      {/* ── Privacy & Cookie Preferences Modal ── */}
      <Dialog open={modalOpen} onOpenChange={setModalOpen}>
        <DialogContent className="max-w-2xl sm:max-h-[85vh] flex flex-col p-0 gap-0 overflow-hidden border-border/80">
          <DialogHeader className="p-6 pb-4 border-b border-border/60">
            <div className="flex items-center gap-2.5">
              <div className="flex size-9 items-center justify-center rounded-lg bg-primary/10 text-primary border border-primary/20">
                <ShieldCheck className="size-5" />
              </div>
              <div>
                <DialogTitle className="text-lg font-bold">Privacy & Data Governance</DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground mt-0.5">
                  Manage how FixAI processes telemetry, local metrics, and system security data.
                </DialogDescription>
              </div>
            </div>
          </DialogHeader>

          <Tabs
            value={activeTab}
            onValueChange={(val) => setActiveTab(val as "preferences" | "policy")}
            className="flex-1 overflow-hidden flex flex-col"
          >
            <div className="px-6 pt-3 border-b border-border/40 bg-muted/20">
              <TabsList className="grid w-full grid-cols-2 max-w-xs h-9">
                <TabsTrigger value="preferences" className="text-xs font-medium">Consent Controls</TabsTrigger>
                <TabsTrigger value="policy" className="text-xs font-medium">Privacy Policy</TabsTrigger>
              </TabsList>
            </div>

            <div className="p-6 overflow-y-auto max-h-[50vh] space-y-4">
              {/* TAB 1: Granular Preferences */}
              <TabsContent value="preferences" className="space-y-4 mt-0">
                {/* 1. Necessary */}
                <div className="flex items-start justify-between gap-4 rounded-xl border border-border/60 bg-muted/20 p-4">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground">Strictly Necessary Storage</span>
                      <Badge variant="outline" className="text-[10px] uppercase font-bold text-muted-foreground">Always Required</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Essential for application authentication tokens, security state validation, and theme preferences. Cannot be disabled.
                    </p>
                  </div>
                  <Switch checked={true} disabled className="opacity-70" />
                </div>

                {/* 2. Hardware Telemetry */}
                <div className="flex items-start justify-between gap-4 rounded-xl border border-border/60 bg-card p-4 transition-colors hover:border-primary/40">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground">Host Hardware Telemetry</span>
                      <Badge variant="outline" className="text-[10px] text-primary border-primary/30">Live Diagnostics</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Collects non-identifiable host statistics (CPU % load, RAM usage, storage trim counters, temperature sensors) to power Edge ML anomaly scoring and predict hardware failure before it occurs.
                    </p>
                  </div>
                  <Switch
                    checked={settings.telemetry}
                    onCheckedChange={(val) => setSettings({ ...settings, telemetry: val })}
                  />
                </div>

                {/* 3. Diagnostic & Threat Logs */}
                <div className="flex items-start justify-between gap-4 rounded-xl border border-border/60 bg-card p-4 transition-colors hover:border-primary/40">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground">Diagnostic & Threat Audit Trails</span>
                      <Badge variant="outline" className="text-[10px] text-amber-500 border-amber-500/30">Cyber Protection</Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      Stores local recovery execution logs, file entropy anomaly flags, and post-remediation validation proofs to verify system health was restored.
                    </p>
                  </div>
                  <Switch
                    checked={settings.diagnostics}
                    onCheckedChange={(val) => setSettings({ ...settings, diagnostics: val })}
                  />
                </div>
              </TabsContent>

              {/* TAB 2: Privacy Policy */}
              <TabsContent value="policy" className="space-y-4 text-xs text-muted-foreground leading-relaxed mt-0">
                <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-4 text-foreground">
                  <h5 className="font-semibold text-emerald-400 flex items-center gap-1.5 mb-1">
                    <ShieldCheck className="size-4" /> Zero-Trust Privacy Guarantee
                  </h5>
                  <p className="text-xs text-muted-foreground">
                    FixAI operates strictly as a system reliability and hardware guardian. We adhere to privacy-by-design principles:
                  </p>
                </div>

                <div className="space-y-3">
                  <div className="rounded-lg border border-border/50 p-3.5 space-y-1">
                    <strong className="text-foreground text-xs flex items-center gap-1.5">
                      <Cpu className="size-3.5 text-primary" /> 1. What FixAI Collects & Analyzes
                    </strong>
                    <ul className="list-disc pl-5 space-y-0.5 text-[11px]">
                      <li>Real-time CPU load, memory utilization, disk queue length, and host temperature.</li>
                      <li>Process IDs and resource percentages to isolate runaway tasks.</li>
                      <li>Cryptographic file entropy signatures to detect unauthorized encryption (ransomware indicators).</li>
                      <li>Operating system release, core count, and network adapter latency.</li>
                    </ul>
                  </div>

                  <div className="rounded-lg border border-rose-500/20 bg-rose-500/5 p-3.5 space-y-1">
                    <strong className="text-foreground text-xs flex items-center gap-1.5 text-rose-400">
                      <EyeOff className="size-3.5" /> 2. What FixAI NEVER Collects
                    </strong>
                    <ul className="list-disc pl-5 space-y-0.5 text-[11px] text-muted-foreground">
                      <li>We NEVER access personal documents, spreadsheets, photos, or emails.</li>
                      <li>We NEVER log user keystrokes, clipboard data, or active screens.</li>
                      <li>We NEVER track browser history or search engine queries.</li>
                      <li>We NEVER sell, trade, or share your data with advertisers or 3rd parties.</li>
                    </ul>
                  </div>

                  <div className="rounded-lg border border-border/50 p-3.5 space-y-1">
                    <strong className="text-foreground text-xs flex items-center gap-1.5">
                      <Lock className="size-3.5 text-primary" /> 3. Local-First & Compliance Standards
                    </strong>
                    <p className="text-[11px]">
                      Machine learning inference runs locally on your edge device via Isolation Forest and XGBoost models.
                      Data retention is fully under your control. In accordance with GDPR and DPDP Act standards, you have the right to inspect, export, or immediately purge all telemetry history directly from the Audit & History page.
                    </p>
                  </div>
                </div>
              </TabsContent>
            </div>

            <DialogFooter className="p-4 border-t border-border/60 bg-muted/20 flex flex-row items-center justify-between sm:justify-between">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setModalOpen(false)}
                className="text-xs"
              >
                Close
              </Button>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCustomSave}
                  className="text-xs"
                >
                  Save Choices
                </Button>
                <Button
                  size="sm"
                  onClick={handleAcceptAll}
                  className="text-xs bg-primary text-primary-foreground font-semibold hover:bg-primary/90"
                >
                  Accept All
                </Button>
              </div>
            </DialogFooter>
          </Tabs>
        </DialogContent>
      </Dialog>
    </>
  );
}

/** Helper function to open the Privacy Preferences modal from anywhere in the app */
export function openPrivacyConsentModal() {
  window.dispatchEvent(new Event("fixai-open-privacy-consent"));
}
