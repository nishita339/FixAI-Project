import type { Playbook, RiskTier } from "./types";

/**
 * Pre-audited playbook catalogue.
 *
 * The execution runtime only ever fires these allowlisted playbooks — the AI
 * layer passes parameters, never raw shell strings (blueprint Part 22).
 * HIGH risk actions are hard-blocked from automation at code level.
 */
export const PLAYBOOKS: Playbook[] = [
  {
    id: "flush_cache",
    name: "Flush Application Cache",
    description:
      "Clears stale cache entries and re-primes the hot path. Zero downtime.",
    riskTier: "LOW",
    manualSteps: [
      "Open the service console and confirm cache hit-rate is degraded",
      "Run the cache flush command below",
      "Watch cache hit-rate recover above 80% within 60 seconds",
    ],
    command: "fixai cache flush --service app_service",
    autoAllowed: true,
    successProbability: 0.62,
    downtimeSeconds: 0,
    verificationWindowSeconds: 10,
  },
  {
    id: "restart_worker",
    name: "Restart Background Worker",
    description:
      "Recycles the background worker process to release leaked handles.",
    riskTier: "LOW",
    manualSteps: [
      "Identify the worker PID from the process table",
      "Gracefully stop the worker, then start it again",
      "Confirm the worker re-registers with the queue within 30s",
    ],
    command: "fixai worker restart --graceful",
    autoAllowed: true,
    successProbability: 0.58,
    downtimeSeconds: 3,
    verificationWindowSeconds: 20,
  },
  {
    id: "restart_container",
    name: "Restart Service Container",
    description:
      "Restarts the target container to reclaim memory and reset stuck threads.",
    riskTier: "MEDIUM",
    manualSteps: [
      "Open a terminal on the host running Docker",
      "Run the restart command below",
      "Wait for the /health endpoint to return 200 OK",
      "Verify RAM drops below 50% within 15 seconds",
    ],
    command: "docker restart app_service",
    autoAllowed: false,
    successProbability: 0.88,
    downtimeSeconds: 12,
    verificationWindowSeconds: 30,
  },
  {
    id: "scale_instances",
    name: "Scale Service Instances",
    description:
      "Adds a service replica to absorb load and lower per-instance pressure.",
    riskTier: "MEDIUM",
    manualSteps: [
      "Check current replica count and host capacity headroom",
      "Run the scale command below",
      "Confirm the new replica passes health checks",
      "Watch CPU/RAM per instance fall back under baseline",
    ],
    command: "docker compose up -d --scale app_service=2",
    autoAllowed: false,
    successProbability: 0.74,
    downtimeSeconds: 8,
    verificationWindowSeconds: 40,
  },
  {
    id: "purge_tmp",
    name: "Purge Temporary Files",
    description:
      "Safely removes stale temp artifacts blocking the disk (allowlisted paths).",
    riskTier: "MEDIUM",
    manualSteps: [
      "Run df -h to confirm the mount is above the safe threshold",
      "Run the purge command below (scoped to /tmp only)",
      "Confirm disk usage falls below 50%",
    ],
    command: "fixai disk purge --path /tmp --older-than 24h",
    autoAllowed: false,
    successProbability: 0.81,
    downtimeSeconds: 2,
    verificationWindowSeconds: 15,
  },
  {
    id: "db_maintenance",
    name: "Database Maintenance Window",
    description:
      "Runs VACUUM/ANALYZE and re-seats the connection pool. Can interrupt traffic.",
    riskTier: "HIGH",
    manualSteps: [
      "Announce a maintenance window to downstream teams",
      "Enable connection draining, then run the maintenance command",
      "Verify connection pool saturation returns under 60%",
      "Re-enable traffic and watch error rates",
    ],
    command: "fixai db maintenance --vacuum --reseat-pool",
    autoAllowed: false,
    successProbability: 0.69,
    downtimeSeconds: 45,
    verificationWindowSeconds: 60,
  },
  // ── Hardware & Laptop-Specific Playbooks ──────────────────────────────
  {
    id: "cool_down_cpu",
    name: "CPU Thermal Throttle & Active Cooling",
    description:
      "Engages active cooling policy, caps maximum processor clock state to 85%, and terminates thermal runaways to drop core temp below 65°C.",
    riskTier: "LOW",
    manualSteps: [
      "Check CPU package temperature with core sensors",
      "Set maximum processor state to 85% in system power plan",
      "Switch thermal cooling policy to Active",
      "Verify CPU temperature falls below 65°C within 15s",
    ],
    command: "fixai hardware thermal --cool-down --cap-state 85",
    autoAllowed: true,
    successProbability: 0.92,
    downtimeSeconds: 0,
    verificationWindowSeconds: 15,
  },
  {
    id: "optimize_battery_health",
    name: "Laptop Battery Saver & Power Leak Optimizer",
    description:
      "Suspends power-hogging background telemetry, dims display refresh, and switches ACPI power profile to ultra-efficiency.",
    riskTier: "LOW",
    manualSteps: [
      "Inspect battery discharge rate in system energy report",
      "Enable Windows/Linux battery saver mode",
      "Suspend non-critical indexing and telemetry daemons",
      "Confirm discharge wattage stabilizes under 15W",
    ],
    command: "fixai hardware power --optimize-battery --kill-drains",
    autoAllowed: true,
    successProbability: 0.89,
    downtimeSeconds: 0,
    verificationWindowSeconds: 10,
  },
  {
    id: "reset_network_adapter",
    name: "Reset Wi-Fi Adapter & Flush DNS",
    description:
      "Flushes DNS resolver cache, resets Winsock/TCP-IP stack, and power-cycles the Wi-Fi/Ethernet interface to eliminate packet drop.",
    riskTier: "LOW",
    manualSteps: [
      "Run ipconfig /flushdns to clear poisoned cache",
      "Reset TCP/IP stack via netsh int ip reset",
      "Cycle network adapter power to unfreeze driver buffer",
      "Verify ping latency returns to <30ms",
    ],
    command: "fixai hardware net --flushdns --reset-adapter",
    autoAllowed: true,
    successProbability: 0.87,
    downtimeSeconds: 2,
    verificationWindowSeconds: 12,
  },
  {
    id: "restart_graphics_subsystem",
    name: "Restart Graphics Pipeline & DWM",
    description:
      "Reinitializes the Desktop Window Manager (DWM) and display driver subsystem to clear screen stutter and GPU driver hangs.",
    riskTier: "MEDIUM",
    manualSteps: [
      "Trigger graphics pipeline reload (Win+Ctrl+Shift+B equivalent)",
      "Recycle DWM process to reclaim leaked GPU video memory",
      "Verify display refresh rate stabilizes at 60Hz+",
    ],
    command: "fixai hardware display --restart-dwm --clear-vram",
    autoAllowed: false,
    successProbability: 0.84,
    downtimeSeconds: 1,
    verificationWindowSeconds: 15,
  },
  {
    id: "optimize_storage_trim",
    name: "Storage Optimizer & SSD TRIM Health Check",
    description:
      "Executes SSD TRIM, cleans system temp & error logs, and runs SMART sector verification.",
    riskTier: "LOW",
    manualSteps: [
      "Run defrag /O (TRIM) on SSD volumes",
      "Purge temporary Windows error logs and crash dumps",
      "Verify disk active time drops below 20%",
    ],
    command: "fixai hardware disk --trim --clean-system-temp",
    autoAllowed: true,
    successProbability: 0.91,
    downtimeSeconds: 1,
    verificationWindowSeconds: 15,
  },
  {
    id: "restart_audio_service",
    name: "Restart Windows Audio & Endpoint Services",
    description:
      "Recycles Windows Audio (Audiosrv) and AudioEndpointBuilder hardware pipes to fix missing sound or headphone jack silence.",
    riskTier: "LOW",
    manualSteps: [
      "Open PowerShell as Administrator",
      "Run Restart-Service -Name Audiosrv, AudioEndpointBuilder -Force",
      "Verify audio playback device is restored",
    ],
    command: "fixai software audio --restart-services",
    autoAllowed: true,
    successProbability: 0.92,
    downtimeSeconds: 1,
    verificationWindowSeconds: 10,
  },
  {
    id: "fix_windows_update",
    name: "Purge Update Download Cache & Restart BITS",
    description:
      "Clears corrupt SoftwareDistribution download cache and restarts BITS & Windows Update services to resolve 0% or 99% stuck updates.",
    riskTier: "MEDIUM",
    manualSteps: [
      "Stop Windows Update and BITS services",
      "Clear C:\\Windows\\SoftwareDistribution\\Download directory",
      "Restart BITS and check for updates cleanly",
    ],
    command: "fixai software winupdate --purge-cache --restart-bits",
    autoAllowed: false,
    successProbability: 0.89,
    downtimeSeconds: 2,
    verificationWindowSeconds: 20,
  },
  {
    id: "rescan_pnp_devices",
    name: "Rescan PnP Devices & Recover Driver Tree",
    description:
      "Runs pnputil /scan-devices to resolve Device Manager Code 40/43 and re-enumerate missing keyboard, touchpad, or USB controllers.",
    riskTier: "LOW",
    manualSteps: [
      "Open Device Manager",
      "Run pnputil /scan-devices",
      "Confirm missing peripheral is re-attached without yellow exclamation error",
    ],
    command: "fixai hardware pnp --rescan-devices",
    autoAllowed: true,
    successProbability: 0.86,
    downtimeSeconds: 1,
    verificationWindowSeconds: 10,
  },
  {
    id: "repair_system_files",
    name: "SFC & DISM System File Integrity Verification",
    description:
      "Verifies Windows Component Store and repairs corrupt DLLs and system binaries to prevent BSOD crashes.",
    riskTier: "MEDIUM",
    manualSteps: [
      "Run DISM /Online /Cleanup-Image /RestoreHealth",
      "Run sfc /scannow",
      "Verify zero integrity violations found",
    ],
    command: "fixai software sfc --verify-and-repair",
    autoAllowed: false,
    successProbability: 0.88,
    downtimeSeconds: 5,
    verificationWindowSeconds: 30,
  },
  {
    id: "clean_hosts_file",
    name: "Restore Default HOSTS File & Flush DNS",
    description:
      "Removes malicious adware redirect rules from drivers/etc/hosts and restores clean DNS resolving.",
    riskTier: "LOW",
    manualSteps: [
      "Inspect C:\\Windows\\System32\\drivers\\etc\\hosts",
      "Remove unauthorized IP domain redirect entries",
      "Flush DNS resolver cache",
    ],
    command: "fixai software hosts --clean-default-hosts",
    autoAllowed: true,
    successProbability: 0.95,
    downtimeSeconds: 0,
    verificationWindowSeconds: 5,
  },
  {
    id: "repair_boot_configuration",
    name: "Repair Boot Configuration & EFI BCD Store",
    description:
      "Scans BCD store, EFI system partition, and SATA/NVMe controller binding to fix 'No bootable device found' errors.",
    riskTier: "LOW",
    manualSteps: [
      "Scan BCD entries with bcdedit /enum",
      "Verify EFI partition file structure",
      "Ensure primary SSD controller is registered in Windows boot table",
    ],
    command: "fixai hardware boot --scan-and-repair-bcd",
    autoAllowed: true,
    successProbability: 0.91,
    downtimeSeconds: 2,
    verificationWindowSeconds: 15,
  },
  {
    id: "resolve_driver_conflicts",
    name: "Resolve Driver Conflicts & Reset PnP Stacks",
    description:
      "Detects Device Manager Code 43 / Code 10 exclamation errors, cycles hardware bus power state, and clears conflicting drivers.",
    riskTier: "LOW",
    manualSteps: [
      "Enumerate devices with error codes in Device Manager",
      "Cycle device power bus and reload kernel miniport driver",
      "Confirm device returns to functional state (Code 0)",
    ],
    command: "fixai hardware drivers --resolve-conflicts",
    autoAllowed: true,
    successProbability: 0.87,
    downtimeSeconds: 1,
    verificationWindowSeconds: 10,
  },
  {
    id: "fix_app_freeze",
    name: "Unfreeze Hung Apps & Recycle UI Queues",
    description:
      "Detects unresponsive window threads, frees frozen DCOM/RPC handles, and terminates hanging background task threads.",
    riskTier: "LOW",
    manualSteps: [
      "Inspect UI thread message queue for frozen window handles",
      "Release locked RPC endpoints and worker threads",
      "Restore desktop responsiveness without reboot",
    ],
    command: "fixai software process --unfreeze-ui-queues",
    autoAllowed: true,
    successProbability: 0.94,
    downtimeSeconds: 0,
    verificationWindowSeconds: 5,
  },
  {
    id: "restart_graphics_subsystem",
    name: "Restart Desktop Window Manager & Graphics Pipe",
    description:
      "Refreshes DWM display compositor thread and clears DirectX swapchain buffer to resolve screen flickering and stutter.",
    riskTier: "LOW",
    manualSteps: [
      "Flush DirectX swapchain buffer",
      "Soft reload Desktop Window Manager (dwm.exe)",
      "Verify display synchronization at 60Hz+",
    ],
    command: "fixai software display --restart-dwm",
    autoAllowed: true,
    successProbability: 0.93,
    downtimeSeconds: 1,
    verificationWindowSeconds: 5,
  },
];

export function getPlaybook(id: string): Playbook | undefined {
  return PLAYBOOKS.find((p) => p.id === id);
}

export function riskTierColor(tier: RiskTier): string {
  switch (tier) {
    case "LOW":
      return "text-emerald-600 dark:text-emerald-400";
    case "MEDIUM":
      return "text-amber-600 dark:text-amber-400";
    case "HIGH":
      return "text-red-600 dark:text-red-400";
  }
}
