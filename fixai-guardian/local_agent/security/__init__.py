"""
FixAI Security Subsystem — Endpoint Detection & Response (EDR)
==============================================================

Unified cybersecurity modules:
- Phase 1: Security Event Harvesting (Brute-Force Detection via Event ID 4625)
- Phase 2: Real-Time Malware Detection (Shannon Entropy & YARA Signatures)
- Phase 3: Fileless Threat Hunting (WMI Persistence & LotL Process Tree Lineage)
- Phase 4: Guarded Quarantine & Network Isolation (AES-256 Vault)
- Phase 5: Natural Language Security Alerts & User IPC
"""

from .event_monitor import EventMonitor, BruteForceAlert
from .file_monitor import FileMonitor, MaliciousFileAlert, calculate_shannon_entropy
from .threat_hunter import ThreatHunter, FilelessThreatAlert

__all__ = [
    "EventMonitor",
    "BruteForceAlert",
    "FileMonitor",
    "MaliciousFileAlert",
    "calculate_shannon_entropy",
    "ThreatHunter",
    "FilelessThreatAlert",
]
