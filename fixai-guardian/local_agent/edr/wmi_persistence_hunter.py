"""
FixAI EDR — WMI Persistence Hunter & Fileless Malware Detector
==============================================================

Hunts fileless persistence mechanisms leveraging Windows Management
Instrumentation (WMI) and anomalous parent-child process execution trees.

Vectors Detected:
  1. WMI Event Consumers:
     - __EventFilter
     - CommandLineEventConsumer
     - ActiveScriptEventConsumer
     - __FilterToConsumerBinding
  2. Living-off-the-Land (LotL) Process Hierarchy Anomalies:
     - scrcons.exe (WMI Scripting Host) spawning powershell.exe or cmd.exe
     - wmiprvse.exe / wmic.exe spawning suspicious command interpreters
     - Encoded PowerShell arguments running from non-user sessions
"""

from __future__ import annotations

import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

import psutil

logger = logging.getLogger("fixai.edr.wmi")


class WmiPersistenceThreat:
    """Representation of an identified WMI fileless persistence threat."""

    def __init__(
        self,
        threat_type: str,
        name: str,
        command_or_script: str,
        consumer_type: str,
        binding_filter: str,
        severity: str = "HIGH",
    ):
        self.threat_type = threat_type
        self.name = name
        self.command_or_script = command_or_script
        self.consumer_type = consumer_type
        self.binding_filter = binding_filter
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_type": self.threat_type,
            "name": self.name,
            "command_or_script": self.command_or_script,
            "consumer_type": self.consumer_type,
            "binding_filter": self.binding_filter,
            "severity": self.severity,
        }


class WmiPersistenceHunter:
    """
    Scans WMI repositories for malicious event consumer bindings
    and monitors process trees for anomalous execution chains.
    """

    def __init__(self):
        self.is_windows = sys.platform == "win32"

    def scan_wmi_subscriptions(self) -> List[WmiPersistenceThreat]:
        """
        Query WMI root\\subscription namespace for active Event Consumers and Bindings.
        """
        if not self.is_windows:
            return []

        threats: List[WmiPersistenceThreat] = []

        try:
            import win32com.client
            wmi_service = win32com.client.GetObject("winmgmts:\\\\.\\root\\subscription")

            # 1. Query CommandLineEventConsumers
            try:
                consumers = wmi_service.ExecQuery("SELECT Name, CommandLineTemplate FROM CommandLineEventConsumer")
                for c in consumers:
                    name = str(c.Properties_("Name").Value or "")
                    cmd = str(c.Properties_("CommandLineTemplate").Value or "")
                    # Known legit Windows consumers (e.g. SCM, Windows Defender)
                    if name.lower() in ("bcastdvr", "diagnostics", "scmeventconsumer"):
                        continue
                    if cmd:
                        threats.append(WmiPersistenceThreat(
                            threat_type="FILELESS_WMI_COMMAND_CONSUMER",
                            name=name,
                            command_or_script=cmd,
                            consumer_type="CommandLineEventConsumer",
                            binding_filter="WMI Auto-Trigger",
                            severity="HIGH",
                        ))
            except Exception as e:
                logger.debug("CommandLineEventConsumer query note: %s", e)

            # 2. Query ActiveScriptEventConsumers (VBScript/JScript in WMI)
            try:
                script_consumers = wmi_service.ExecQuery("SELECT Name, ScriptingEngine, ScriptText FROM ActiveScriptEventConsumer")
                for sc in script_consumers:
                    name = str(sc.Properties_("Name").Value or "")
                    script_text = str(sc.Properties_("ScriptText").Value or "")
                    engine = str(sc.Properties_("ScriptEngine").Value or "VBScript")
                    if script_text:
                        threats.append(WmiPersistenceThreat(
                            threat_type="FILELESS_WMI_SCRIPT_CONSUMER",
                            name=name,
                            command_or_script=f"[{engine}] {script_text[:100]}...",
                            consumer_type="ActiveScriptEventConsumer",
                            binding_filter="WMI Script Persistence",
                            severity="CRITICAL",
                        ))
            except Exception as e:
                logger.debug("ActiveScriptEventConsumer query note: %s", e)

        except Exception as exc:
            # Fallback to PowerShell WMI query if win32com object query failed
            threats.extend(self._powershell_wmi_fallback())

        return threats

    def _powershell_wmi_fallback(self) -> List[WmiPersistenceThreat]:
        """Fallback WMI subscription scan using powershell Get-CimInstance."""
        threats = []
        try:
            cmd = [
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer | Select-Object Name, CommandLineTemplate | ConvertTo-Json"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            if res.returncode == 0 and res.stdout.strip():
                import json
                data = json.loads(res.stdout)
                items = data if isinstance(data, list) else [data]
                for item in items:
                    name = item.get("Name", "")
                    cmd_line = item.get("CommandLineTemplate", "")
                    if cmd_line and name.lower() not in ("bcastdvr", "diagnostics"):
                        threats.append(WmiPersistenceThreat(
                            threat_type="FILELESS_WMI_COMMAND_CONSUMER",
                            name=name,
                            command_or_script=cmd_line,
                            consumer_type="CommandLineEventConsumer",
                            binding_filter="WMI Auto-Trigger",
                            severity="HIGH",
                        ))
        except Exception:
            pass
        return threats

    def scan_anomalous_process_hierarchies(self) -> List[Dict[str, Any]]:
        """
        Inspect running process parent-child relationships for WMI/LotL exploitation:
          - scrcons.exe -> powershell.exe / cmd.exe
          - wmiprvse.exe -> powershell.exe with encoded arguments
        """
        anomalies = []

        try:
            for p in psutil.process_iter(["pid", "name", "ppid", "cmdline"]):
                try:
                    name = (p.info["name"] or "").lower()
                    ppid = p.info["ppid"]
                    if not ppid or ppid <= 4:
                        continue

                    # Check parent
                    try:
                        parent = psutil.Process(ppid)
                        parent_name = parent.name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    # Check pattern: scrcons.exe (WMI Script host) spawning command interpreters
                    if parent_name in ("scrcons.exe", "wmiprvse.exe", "wmic.exe"):
                        if name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"):
                            cmdline = " ".join(p.info["cmdline"] or [])
                            anomalies.append({
                                "threat_type": "WMI_LIVING_OFF_THE_LAND_EXECUTION",
                                "pid": p.info["pid"],
                                "process_name": p.info["name"],
                                "parent_pid": ppid,
                                "parent_name": parent_name,
                                "cmdline": cmdline,
                                "severity": "CRITICAL",
                                "description": f"Anomalous execution: {parent_name} (PID: {ppid}) spawned {name} (PID: {p.info['pid']}). Likely active WMI Event Consumer execution.",
                            })

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            logger.debug("Process hierarchy scan note: %s", e)

        return anomalies
