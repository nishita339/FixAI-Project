"""
FixAI Security Subsystem — Endpoint Detection & Response (EDR)
==============================================================

Unified cybersecurity modules for:
- Phase 1: Security Event Harvesting (Brute-Force Detection)
- Phase 2: Real-Time Malware Detection (Shannon Entropy & YARA)
- Phase 3: Fileless Threat Hunting (WMI Persistence & LotL)
- Phase 4: Guarded Quarantine & Network Isolation (AES-256 Vault)
- Phase 5: Natural Language Security Alerts & User IPC
"""

from .event_monitor import EventMonitor, BruteForceAlert

__all__ = ["EventMonitor", "BruteForceAlert"]
