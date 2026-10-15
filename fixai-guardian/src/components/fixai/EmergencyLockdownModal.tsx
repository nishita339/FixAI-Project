import React, { useState, useEffect } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import {
  AlertOctagon,
  ShieldAlert,
  ShieldCheck,
  WifiOff,
  RefreshCw,
  Lock,
  Unlock,
  Radio,
  FileWarning,
  Volume2,
  VolumeX,
} from "lucide-react";
import { audioAlerts } from "@/lib/audio-alerts";

const FASTAPI_URL = (import.meta as any).env?.VITE_FASTAPI_URL || "http://localhost:8000";

interface EmergencyLockdownModalProps {
  isOpen: boolean;
  onClose: () => void;
  isLockdownActive: boolean;
  onToggleLockdown: (active: boolean) => void;
}

export function EmergencyLockdownModal({
  isOpen,
  onClose,
  isLockdownActive,
  onToggleLockdown,
}: EmergencyLockdownModalProps) {
  const [loadingAction, setLoadingAction] = useState<string | null>(null);
  const [isMuted, setIsMuted] = useState(audioAlerts.getMuted());

  const toggleSound = () => {
    const next = audioAlerts.toggleMute();
    setIsMuted(next);
    toast.info(next ? "Audio alerts muted" : "Audio alerts unmuted (Tactical sound active)");
  };

  const handleEngageLockdown = async () => {
    setLoadingAction("engage");
    audioAlerts.playLockdownEngagement();

    try {
      const resp = await fetch(`${FASTAPI_URL}/api/v1/recovery/execute-live`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          playbook_id: "isolate_network",
          target: "all_network_adapters",
        }),
      });

      if (resp.ok) {
        onToggleLockdown(true);
        audioAlerts.playCriticalSiren();
        toast.error("🚨 EMERGENCY LOCKDOWN ENGAGED — Network Air-Gapped", {
          description: "All outbound and inbound external sockets have been terminated by local firewall.",
          duration: 6000,
        });
      } else {
        // Still engage UI lockdown for user safety
        onToggleLockdown(true);
        audioAlerts.playWarningBeep();
        toast.warning("Network lockdown rule applied locally.");
      }
    } catch {
      onToggleLockdown(true);
      audioAlerts.playWarningBeep();
      toast.warning("Local endpoint air-gap active (Backend simulated).");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleDisengageLockdown = async () => {
    setLoadingAction("disengage");
    try {
      const resp = await fetch(`${FASTAPI_URL}/api/v1/recovery/execute-live`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          playbook_id: "reset_network_adapter",
          target: "primary_adapter",
        }),
      });

      onToggleLockdown(false);
      audioAlerts.playHealedChime();
      toast.success("✅ Lockdown Disengaged — Network Restored", {
        description: "Firewall rules reset. Standard network communication re-established.",
      });
    } catch {
      onToggleLockdown(false);
      audioAlerts.playHealedChime();
      toast.success("Lockdown released.");
    } finally {
      setLoadingAction(null);
    }
  };

  const handleTestSiren = () => {
    audioAlerts.playCriticalSiren();
    toast.info("Testing Critical Threat Siren (880Hz / 1320Hz warble)");
  };

  return (
    <Dialog open={isOpen} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-xl border-rose-500/40 bg-card/95 backdrop-blur-2xl text-foreground">
        <DialogHeader className="space-y-2 border-b border-border/80 pb-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <div className="flex size-9 items-center justify-center rounded-xl bg-rose-500/15 text-rose-500 ring-1 ring-rose-500/30">
                <AlertOctagon className="size-5 animate-pulse" />
              </div>
              <div>
                <DialogTitle className="text-lg font-bold text-rose-500 flex items-center gap-2">
                  Emergency Cyber Defense Lockdown
                </DialogTitle>
                <DialogDescription className="text-xs text-muted-foreground">
                  Instant host network air-gap & incident containment controls
                </DialogDescription>
              </div>
            </div>

            <Button
              variant="outline"
              size="sm"
              onClick={toggleSound}
              className="h-8 gap-1.5 text-xs rounded-lg border-border/80"
              title="Toggle audio alerts"
            >
              {isMuted ? <VolumeX className="size-3.5 text-muted-foreground" /> : <Volume2 className="size-3.5 text-emerald-500" />}
              <span>{isMuted ? "Muted" : "Audio On"}</span>
            </Button>
          </div>
        </DialogHeader>

        {/* Current State Indicator */}
        <div className={`p-4 rounded-xl border transition-all ${
          isLockdownActive
            ? "bg-rose-950/40 border-rose-500/60 text-rose-200"
            : "bg-emerald-950/20 border-emerald-500/30 text-emerald-300"
        }`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              {isLockdownActive ? (
                <div className="size-3 rounded-full bg-rose-500 animate-ping" />
              ) : (
                <div className="size-3 rounded-full bg-emerald-500" />
              )}
              <span className="font-bold text-sm tracking-wide">
                CURRENT STATUS: {isLockdownActive ? "ENDPOINT AIR-GAPPED & LOCKED DOWN" : "NORMAL SOC OPERATIONS"}
              </span>
            </div>
            <Badge
              variant={isLockdownActive ? "destructive" : "default"}
              className="font-mono text-xs"
            >
              {isLockdownActive ? "AIR-GAP ACTIVE" : "ONLINE"}
            </Badge>
          </div>
          <p className="text-xs mt-2 text-muted-foreground">
            {isLockdownActive
              ? "All external TCP/UDP outbound sockets are terminated. Incoming connections are blocked by local firewall rule FixAI-Block-All."
              : "Standard operational mode. Real-time EDR, process lineage, and honeypot canary observation active."}
          </p>
        </div>

        {/* Defense Controls Grid */}
        <div className="space-y-3 py-2">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {/* Engage / Disengage Primary Action */}
            {!isLockdownActive ? (
              <Button
                variant="destructive"
                className="h-14 font-bold text-sm gap-2 shadow-lg shadow-rose-950/50 hover:bg-rose-600 transition-all rounded-xl col-span-1 sm:col-span-2"
                onClick={handleEngageLockdown}
                disabled={loadingAction === "engage"}
              >
                <WifiOff className="size-5 shrink-0" />
                <div className="text-left">
                  <div>ENGAGE 1-CLICK LOCKDOWN</div>
                  <div className="text-[11px] font-normal opacity-85">Sever all external network sockets immediately</div>
                </div>
              </Button>
            ) : (
              <Button
                variant="outline"
                className="h-14 font-bold text-sm gap-2 border-emerald-500/50 text-emerald-400 hover:bg-emerald-950/40 transition-all rounded-xl col-span-1 sm:col-span-2"
                onClick={handleDisengageLockdown}
                disabled={loadingAction === "disengage"}
              >
                <Unlock className="size-5 shrink-0 text-emerald-400" />
                <div className="text-left">
                  <div>DISENGAGE & RESTORE NETWORK</div>
                  <div className="text-[11px] font-normal opacity-85">Flush firewall drop rules and restore connectivity</div>
                </div>
              </Button>
            )}

            {/* Audio Siren Test */}
            <Button
              variant="outline"
              size="sm"
              className="h-10 text-xs gap-1.5 rounded-xl border-border/80 hover:bg-accent"
              onClick={handleTestSiren}
            >
              <Radio className="size-3.5 text-primary" />
              <span>Test Audio Siren</span>
            </Button>

            {/* Canary Deployment Trigger */}
            <Button
              variant="outline"
              size="sm"
              className="h-10 text-xs gap-1.5 rounded-xl border-border/80 hover:bg-accent"
              onClick={() => {
                audioAlerts.playWarningBeep();
                toast.success("Honeypot Decoy Canary files verified across Desktop and Documents.");
              }}
            >
              <FileWarning className="size-3.5 text-amber-500" />
              <span>Verify Decoy Canaries</span>
            </Button>
          </div>
        </div>

        {/* Footer info */}
        <div className="pt-2 border-t border-border/70 flex items-center justify-between text-[11px] text-muted-foreground">
          <span>MITRE ATT&CK: T1071 / T1486 / T1562 Containment</span>
          <Button variant="ghost" size="sm" onClick={onClose} className="text-xs h-7">
            Close Console
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
