"""
FixAI EDR — Plain-English Natural Language Generation (NLG) Engine
===================================================================

Translates cryptographic heuristics, IoC alerts, and complex forensic telemetry
into concise, plain-English security narratives for end users.

Narrative Structure:
  1. The Threat: What exact adversarial or anomalous condition occurred.
  2. The Action Taken: What autonomic defensive actions were executed.
  3. Actionable Steps: 3 prescriptive, numbered recommendations for the user.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


class SecurityNarrative:
    """Structured plain-English security alert narrative."""

    def __init__(
        self,
        title: str,
        threat: str,
        action_taken: str,
        actionable_steps: List[str],
        severity: str = "HIGH",
    ):
        self.title = title
        self.threat = threat
        self.action_taken = action_taken
        self.actionable_steps = actionable_steps
        self.severity = severity

    def to_plain_text(self) -> str:
        steps_formatted = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(self.actionable_steps))
        return (
            f"⚠️ {self.title}\n\n"
            f"The Threat:\n{self.threat}\n\n"
            f"The Action Taken:\n{self.action_taken}\n\n"
            f"Actionable Steps:\n{steps_formatted}"
        )

    def to_toast_summary(self) -> str:
        """Compact 2-line summary for desktop toast notifications."""
        return f"{self.threat[:70]}... | {self.action_taken[:70]}..."

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "threat": self.threat,
            "action_taken": self.action_taken,
            "actionable_steps": self.actionable_steps,
            "severity": self.severity,
            "plain_text": self.to_plain_text(),
        }


class NLGNarrativeEngine:
    """
    Constructs high-fidelity plain-English explanations for security events.
    """

    @staticmethod
    def generate_wmi_persistence_narrative(threat_name: str, consumer_cmd: str) -> SecurityNarrative:
        return SecurityNarrative(
            title="Fileless Malware Persistence Detected",
            threat="A hidden, persistent script attempting to execute unauthorized commands on system startup was detected via Windows Management Instrumentation (WMI).",
            action_taken="The agent has successfully suspended the associated process and encrypted the malicious configuration to prevent execution.",
            actionable_steps=[
                "Initiate a full offline antivirus scan of your operating system.",
                "Review recently installed third-party software and browser extensions in your Control Panel.",
                "Do not authorize unexpected administrative credential or User Account Control (UAC) prompts.",
            ],
            severity="CRITICAL",
        )

    @staticmethod
    def generate_brute_force_narrative(ip: str, failure_count: int, compromised: bool = False) -> SecurityNarrative:
        if compromised:
            return SecurityNarrative(
                title="Unauthorized Account Access Detected",
                threat=f"A brute-force credential attack from IP {ip} successfully compromised an active user account after {failure_count} failed attempts.",
                action_taken="The offending IP address has been immediately blocked by the host firewall and active sessions have been isolated.",
                actionable_steps=[
                    "Change your user account password immediately using a strong, unique passphrase.",
                    "Ensure Multi-Factor Authentication (MFA) is enabled on all connected enterprise accounts.",
                    "Review recent login sessions in account settings and sign out of all unrecognized devices.",
                ],
                severity="CRITICAL",
            )
        else:
            return SecurityNarrative(
                title="Active Brute-Force Intrusion Attempt",
                threat=f"A continuous hacking attempt was detected. Over {failure_count} failed login attempts to your user account were recorded from external IP address {ip}.",
                action_taken="The source IP address has been temporarily blocked by the local host firewall, and your active sessions have been secured.",
                actionable_steps=[
                    "Change your user account password immediately using a complex passphrase.",
                    "Ensure Multi-Factor Authentication (MFA) is enabled on all connected accounts.",
                    "Verify your network router's firewall settings are set to restrict unsolicited inbound traffic.",
                ],
                severity="HIGH",
            )

    @staticmethod
    def generate_malicious_file_narrative(file_name: str, entropy: float, sha256: str) -> SecurityNarrative:
        return SecurityNarrative(
            title="Malicious / Obfuscated Payload Quarantined",
            threat=f"A newly dropped file ('{file_name}') exhibited characteristics of packed/encrypted malware (Shannon Entropy: {entropy:.2f}/8.0) and posed a severe security risk.",
            action_taken="The file has been successfully intercepted, prevented from executing, and moved to a secure, AES-256 encrypted quarantine vault.",
            actionable_steps=[
                "Delete the original download source, email attachment, or USB transfer that introduced the file.",
                "Avoid launching unverified files with double extensions (e.g. .pdf.exe).",
                "If you believe this is a false positive, access the FixAI recovery console to request an administrative review.",
            ],
            severity="HIGH",
        )

    @staticmethod
    def generate_kernel_panic_narrative() -> SecurityNarrative:
        return SecurityNarrative(
            title="Unexpected System Interruption Detected",
            threat="A critical unexpected shutdown or kernel panic (Event ID 41) occurred, which may indicate a hardware fault, power loss, or denial-of-service attack.",
            action_taken="System integrity checks completed and hardware power management settings reset to nominal baseline.",
            actionable_steps=[
                "Ensure device ventilation is clear and power supply is secure.",
                "Review recent driver updates or peripheral hardware connected prior to the shutdown.",
                "Run the FixAI system diagnostics tool to verify storage and thermal health.",
            ],
            severity="MEDIUM",
        )
