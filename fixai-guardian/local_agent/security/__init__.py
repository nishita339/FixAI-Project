"""
FixAI Security Subsystem — Endpoint Detection & Response (EDR)
==============================================================
"""

from .event_monitor import EventMonitor, BruteForceAlert
from .file_monitor import FileMonitor, MaliciousFileAlert, calculate_shannon_entropy

__all__ = [
    "EventMonitor",
    "BruteForceAlert",
    "FileMonitor",
    "MaliciousFileAlert",
    "calculate_shannon_entropy",
]
