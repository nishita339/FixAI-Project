"""
FixAI Security Subsystem — Endpoint Detection & Response (EDR)
==============================================================

Unified cybersecurity modules:
- Phase 1: Security Event Harvesting (Brute-Force Detection via Event ID 4625)
- Phase 2: Real-Time Malware Detection (Shannon Entropy & YARA Signatures)
- Phase 3: Fileless Threat Hunting (WMI Persistence & LotL Process Tree Lineage)
- Phase 4: Guarded Quarantine & Network Isolation (AES-256 Vault & Firewall)
- Phase 5: Plain-English Security Alerts & Desktop Notifications (IPC Bridge)
- Improvement #1: Telegram / Discord / Slack Webhook Alerts
- Improvement #2: Ransomware Canary / Honeypot Decoy Files
- Improvement #7: Network Socket & C2 Beaconing Monitor
"""

from .event_monitor import EventMonitor, BruteForceAlert
from .file_monitor import FileMonitor, MaliciousFileAlert, calculate_shannon_entropy
from .threat_hunter import ThreatHunter, FilelessThreatAlert
from .quarantine import (
    QuarantineVault,
    QuarantineRecord,
    FirewallManager,
    calculate_sha256,
    is_os_protected_file,
)
from .alert_bridge import (
    AlertBridge,
    SecurityAlertMessage,
    SecurityNLGEngine,
    DesktopNotifier,
)
from .webhook_notifier import (
    WebhookNotifier,
    WebhookConfig,
)
from .ransomware_canary import (
    RansomwareCanary,
    RansomwareCanaryAlert,
    CanaryRecord,
    CANARY_MAGIC,
)
from .network_monitor import (
    NetworkMonitor,
    NetworkConnection,
    C2BeaconAlert,
    calculate_domain_entropy,
    is_private_or_loopback_ip,
)

__all__ = [
    # Phase 1
    "EventMonitor",
    "BruteForceAlert",
    # Phase 2
    "FileMonitor",
    "MaliciousFileAlert",
    "calculate_shannon_entropy",
    # Phase 3
    "ThreatHunter",
    "FilelessThreatAlert",
    # Phase 4
    "QuarantineVault",
    "QuarantineRecord",
    "FirewallManager",
    "calculate_sha256",
    "is_os_protected_file",
    # Phase 5
    "AlertBridge",
    "SecurityAlertMessage",
    "SecurityNLGEngine",
    "DesktopNotifier",
    # Improvement #1
    "WebhookNotifier",
    "WebhookConfig",
    # Improvement #2
    "RansomwareCanary",
    "RansomwareCanaryAlert",
    "CanaryRecord",
    "CANARY_MAGIC",
    # Improvement #7
    "NetworkMonitor",
    "NetworkConnection",
    "C2BeaconAlert",
    "calculate_domain_entropy",
    "is_private_or_loopback_ip",
]

