"""
FixAI Security Subsystem — Network Socket & C2 Beaconing Monitor
================================================================

Improvement #7: Real-Time Command & Control (C2) Beacon & Socket Analyzer.
Monitors outbound and listening sockets on the host to intercept:
1. Periodic C2 Heartbeat Beacons (Cobalt Strike, Sliver, Mythic, Metasploit)
   via low-jitter inter-arrival interval analysis (MITRE ATT&CK T1071 / T1571).
2. DGA (Domain Generation Algorithm) Domains via Shannon Entropy (MITRE T1568.002).
3. Covert Tunneling & Dynamic DNS Proxies (ngrok, trycloudflare, duckdns) (MITRE T1572).
4. Direct Outbound Network Sockets spawned by Living-off-the-Land (LotL) binaries
   (powershell.exe, cmd.exe, certutil.exe, mshta.exe) (MITRE T1059 / T1105).
5. Connections to known adversary C2 & reverse-shell ports (4444, 1337, 8888, 9001, etc.).

Dual-Copy Architecture:
- Primary: fixai-guardian/local_agent/security/network_monitor.py
- Secondary: security/network_monitor.py
"""

import collections
import dataclasses
import datetime
import ipaddress
import logging
import math
import re
import socket
import sys
import threading
import time
import uuid
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

try:
    import psutil
except ImportError:
    psutil = None

logger = logging.getLogger("NetworkMonitor")

# ============================================================================
# Known Suspicious C2 & RAT Ports
# ============================================================================

SUSPICIOUS_C2_PORTS: Dict[int, str] = {
    4444: "Metasploit / Cobalt Strike Default Listener",
    1337: "Elite Backdoor / Reverse Shell",
    31337: "Back Orifice / Elite Trojan Port",
    8888: "Fiddler / Custom HTTP C2 Proxy",
    9001: "Tor Relay / Sliver Default Mutual TLS",
    9050: "Tor SOCKS Proxy",
    9051: "Tor Control Port",
    9150: "Tor Browser SOCKS Port",
    5555: "Android ADB Remote Bridge / FreeStyle RAT",
    6667: "IRC Botnet C2 Channel (Unencrypted)",
    6660: "IRC Botnet Alternate Port",
    6661: "IRC Botnet Alternate Port",
    6662: "IRC Botnet Alternate Port",
    6663: "IRC Botnet Alternate Port",
    6664: "IRC Botnet Alternate Port",
    6665: "IRC Botnet Alternate Port",
    6666: "IRC Botnet Alternate Port",
    6668: "IRC Botnet Alternate Port",
    6669: "IRC Botnet Alternate Port",
    7001: "WebLogic Exploit Callback / Miner C2",
    4443: "Alternate SSL C2 Channel",
    8088: "Radman Trojan / Alternate HTTP C2",
    8443: "Cobalt Strike Alternate Malleable HTTPS",
}

# ============================================================================
# Dynamic DNS & Adversary Reverse Tunnel Providers
# ============================================================================

SUSPICIOUS_TUNNEL_DOMAINS: Set[str] = {
    "duckdns.org",
    "ngrok.io",
    "ngrok-free.app",
    "trycloudflare.com",
    "localtunnel.me",
    "serveo.net",
    "portmap.io",
    "hopto.org",
    "no-ip.com",
    "ddns.net",
    "zapto.org",
    "sytes.net",
    "tunnelbroker.net",
    "pagekite.me",
    "packetriot.com",
    "pinggy.io",
}

# ============================================================================
# Living-off-the-Land (LotL) Executables with Suspicious Outbound Sockets
# ============================================================================

SUSPICIOUS_LOTL_NETWORK_EXES: Set[str] = {
    "powershell.exe",
    "powershell_ise.exe",
    "pwsh.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "certutil.exe",
    "bitsadmin.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "vssadmin.exe",
    "wmic.exe",
    "msiexec.exe",
    "hh.exe",
}

# ============================================================================
# Mathematical Utilities: Shannon Entropy & Beacon Jitter
# ============================================================================

def calculate_domain_entropy(domain: str) -> float:
    """
    Computes Shannon entropy for a domain or hostname label:
    H = -sum(p(x) * log2(p(x)))

    High entropy (> 3.65 on strings of length >= 8) indicates
    algorithmically generated domains (DGA) or encrypted exfiltration subdomains.
    """
    if not domain:
        return 0.0

    # Strip port if present
    clean_domain = domain.split(":")[0].strip().lower()
    # Strip common TLDs to analyze the registered label or subdomain
    parts = clean_domain.split(".")
    target_string = parts[0] if parts else clean_domain

    if not target_string:
        return 0.0

    freq: Dict[str, int] = collections.Counter(target_string)
    length = float(len(target_string))
    entropy = 0.0

    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)

    return round(entropy, 4)


def is_private_or_loopback_ip(ip_str: str) -> bool:
    """
    Returns True if the given IP address string is a loopback,
    private LAN, or link-local address.
    """
    if not ip_str or ip_str in ("0.0.0.0", "::", "*"):
        return True
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local
    except ValueError:
        # If it's a hostname like 'localhost'
        return ip_str.lower() in ("localhost", "127.0.0.1", "::1")


# ============================================================================
# Data Models
# ============================================================================

@dataclasses.dataclass
class NetworkConnection:
    """Snapshot of a single active network socket."""
    pid: int
    process_name: str
    proto: str  # "tcp" or "udp"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    status: str
    timestamp: float = dataclasses.field(default_factory=time.time)
    domain: Optional[str] = None
    entropy: float = 0.0
    is_suspicious: bool = False
    suspicious_reasons: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pid": self.pid,
            "process_name": self.process_name,
            "proto": self.proto,
            "local_ip": self.local_ip,
            "local_port": self.local_port,
            "remote_ip": self.remote_ip,
            "remote_port": self.remote_port,
            "status": self.status,
            "timestamp": self.timestamp,
            "domain": self.domain,
            "entropy": self.entropy,
            "is_suspicious": self.is_suspicious,
            "suspicious_reasons": list(self.suspicious_reasons),
        }


@dataclasses.dataclass
class C2BeaconAlert:
    """Security alert raised when beaconing or suspicious network activity is detected."""
    alert_id: str
    timestamp: str
    severity: str  # "CRITICAL", "HIGH", "MEDIUM"
    alert_type: str  # "C2_BEACONING", "SUSPICIOUS_OUTBOUND", "DGA_DOMAIN", "TUNNEL_PROXY"
    process_name: str
    pid: int
    remote_ip: str
    remote_port: int
    domain: str
    beacon_interval_seconds: float
    jitter_ratio: float
    connection_count: int
    mitre_technique: str
    description: str
    confidence: float

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


# ============================================================================
# Network Socket & C2 Beaconing Monitor
# ============================================================================

class NetworkMonitor:
    """
    Autonomous endpoint network socket observer and C2 beacon detector.
    
    Tracks temporal connection intervals per remote target to compute jitter
    and flags robotic callback intervals indicative of malware beacons.
    """

    def __init__(
        self,
        check_interval: float = 5.0,
        min_beacon_samples: int = 4,
        max_beacon_jitter: float = 0.20,
        entropy_threshold: float = 3.65,
        alert_callback: Optional[Callable[[C2BeaconAlert], None]] = None,
    ):
        """
        Args:
            check_interval: Polling frequency in seconds.
            min_beacon_samples: Minimum sequential connections needed to calculate beaconing.
            max_beacon_jitter: Coefficient of variation threshold (CV <= 0.20 => <= 20% jitter).
            entropy_threshold: Shannon entropy threshold for DGA domain flags.
            alert_callback: Optional callback invoked whenever an alert is generated.
        """
        self.check_interval = check_interval
        self.min_beacon_samples = min_beacon_samples
        self.max_beacon_jitter = max_beacon_jitter
        self.entropy_threshold = entropy_threshold
        self.alert_callback = alert_callback

        # Threading state
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.Lock()

        # Target connection history: (remote_ip, remote_port) -> list of timestamp floats
        self._connection_history: Dict[Tuple[str, int], List[float]] = collections.defaultdict(list)
        # Target process mapping: (remote_ip, remote_port) -> (process_name, pid)
        self._target_meta: Dict[Tuple[str, int], Tuple[str, int]] = {}
        # Domain resolution cache: ip -> domain
        self._domain_cache: Dict[str, str] = {}

        # Alerts recorded
        self._alerts: List[C2BeaconAlert] = []
        # Flagged targets to prevent duplicate spam: (remote_ip, remote_port) -> last_alert_time
        self._alerted_targets: Dict[Tuple[str, int], float] = {}
        # Max history keep
        self._max_samples_per_target = 50

    # ========================================================================
    # Lifecycle Management
    # ========================================================================

    def start(self) -> None:
        """Starts the background continuous network monitoring thread."""
        with self._lock:
            if self._running:
                return
            self._running = True
            self._thread = threading.Thread(
                target=self._monitor_loop,
                name="FixAI-NetworkMonitor",
                daemon=True,
            )
            self._thread.start()
            logger.info("📡 Network Socket & C2 Beaconing Monitor started.")

    def stop(self) -> None:
        """Gracefully halts the background network monitoring thread."""
        with self._lock:
            self._running = False
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)
            logger.info("🛑 Network Socket & C2 Beaconing Monitor stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    def _monitor_loop(self) -> None:
        """Background continuous evaluation loop."""
        while self._running:
            try:
                self.scan_once()
            except Exception as e:
                logger.debug(f"Error during network monitor cycle: {e}")
            time.sleep(self.check_interval)

    # ========================================================================
    # Core Inspection & Scanning
    # ========================================================================

    def scan_once(self) -> Tuple[List[NetworkConnection], List[C2BeaconAlert]]:
        """
        Executes a single observation pass across active sockets on the host.
        Returns active connections and newly generated alerts.
        """
        connections = self._collect_active_connections()
        new_alerts: List[C2BeaconAlert] = []

        for conn in connections:
            # Step 1: Static threat classification on current connection
            self.inspect_connection(conn)

            # If static inspection identified an immediate high-risk signature
            if conn.is_suspicious and not is_private_or_loopback_ip(conn.remote_ip):
                immediate_alert = self._create_immediate_threat_alert(conn)
                if immediate_alert:
                    new_alerts.append(immediate_alert)

            # Step 2: Temporal beacon tracking (outbound non-private connections)
            if not is_private_or_loopback_ip(conn.remote_ip) and conn.remote_port > 0:
                beacon_alert = self.record_connection(conn)
                if beacon_alert:
                    new_alerts.append(beacon_alert)

        return connections, new_alerts

    def _collect_active_connections(self) -> List[NetworkConnection]:
        """Harvests active sockets from the operating system via psutil."""
        if psutil is None:
            return []

        results: List[NetworkConnection] = []
        try:
            raw_conns = psutil.net_connections(kind="inet")
        except Exception as e:
            logger.debug(f"Failed to fetch net_connections: {e}")
            return []

        # Process name lookup cache to minimize psutil.Process overhead
        pname_cache: Dict[int, str] = {0: "System Idle Process", 4: "System"}

        for c in raw_conns:
            pid = c.pid or 0
            if pid not in pname_cache:
                try:
                    proc = psutil.Process(pid)
                    pname_cache[pid] = proc.name()
                except Exception:
                    pname_cache[pid] = "unknown"

            pname = pname_cache.get(pid, "unknown")
            local_ip = c.laddr.ip if c.laddr else ""
            local_port = c.laddr.port if c.laddr else 0
            remote_ip = c.raddr.ip if c.raddr else ""
            remote_port = c.raddr.port if c.raddr else 0
            proto = "tcp" if c.type == socket.SOCK_STREAM else "udp"
            status = c.status if hasattr(c, "status") else "NONE"

            conn = NetworkConnection(
                pid=pid,
                process_name=pname,
                proto=proto,
                local_ip=local_ip,
                local_port=local_port,
                remote_ip=remote_ip,
                remote_port=remote_port,
                status=status,
                timestamp=time.time(),
            )
            results.append(conn)

        return results

    # ========================================================================
    # Static Socket Inspection
    # ========================================================================

    def inspect_connection(self, conn: NetworkConnection) -> List[str]:
        """
        Evaluates a NetworkConnection against known indicators of compromise (IOCs):
        - Suspicious C2/reverse shell ports
        - Living-off-the-Land process outbound communication
        - High-entropy domains / DGA patterns
        - Dynamic DNS / reverse tunnel domains
        """
        reasons: List[str] = []

        # Ignore local/loopback for malicious destination checks
        is_external = not is_private_or_loopback_ip(conn.remote_ip)

        # 1. Suspicious Port Check
        if conn.remote_port in SUSPICIOUS_C2_PORTS and is_external:
            port_desc = SUSPICIOUS_C2_PORTS[conn.remote_port]
            reasons.append(f"Suspicious C2 port {conn.remote_port} ({port_desc}) [MITRE T1571]")

        # 2. Suspicious LotL Executable initiating external connection
        pname_lower = conn.process_name.lower()
        if pname_lower in SUSPICIOUS_LOTL_NETWORK_EXES and is_external:
            reasons.append(
                f"LotL command interpreter '{conn.process_name}' established external socket to "
                f"{conn.remote_ip}:{conn.remote_port} [MITRE T1059 / T1105]"
            )

        # 3. Dynamic DNS / Reverse Tunnel Domain Check
        domain = conn.domain or self.resolve_domain(conn.remote_ip)
        if domain:
            conn.domain = domain
            for tunnel in SUSPICIOUS_TUNNEL_DOMAINS:
                if domain.lower().endswith(tunnel):
                    reasons.append(
                        f"Connection to dynamic tunnel / reverse proxy provider '{tunnel}' [MITRE T1572]"
                    )
                    break

            # 4. Domain Entropy / DGA Check
            entropy = calculate_domain_entropy(domain)
            conn.entropy = entropy
            if entropy >= self.entropy_threshold and len(domain.split(".")[0]) >= 8:
                reasons.append(
                    f"High Shannon entropy ({entropy:.2f} >= {self.entropy_threshold}) on domain '{domain}' [MITRE T1568.002 DGA]"
                )

        if reasons:
            conn.is_suspicious = True
            conn.suspicious_reasons = reasons

        return reasons

    # ========================================================================
    # Temporal C2 Beaconing Detection Engine
    # ========================================================================

    def record_connection(
        self,
        conn: NetworkConnection,
        current_time: Optional[float] = None,
    ) -> Optional[C2BeaconAlert]:
        """
        Records a timestamped connection to a remote target and calculates
        whether consecutive connection intervals demonstrate periodic beaconing.
        """
        if is_private_or_loopback_ip(conn.remote_ip) or conn.remote_port <= 0:
            return None

        target_key = (conn.remote_ip, conn.remote_port)
        ts = current_time if current_time is not None else conn.timestamp

        with self._lock:
            timestamps = self._connection_history[target_key]
            # Avoid storing exact duplicate timestamps in close succession (< 0.1s)
            if not timestamps or (ts - timestamps[-1]) >= 0.1:
                timestamps.append(ts)
                if len(timestamps) > self._max_samples_per_target:
                    self._connection_history[target_key] = timestamps[-self._max_samples_per_target:]

            self._target_meta[target_key] = (conn.process_name, conn.pid)

            # Analyze intervals for beaconing
            alert = self._evaluate_beacon_pattern(
                target_key=target_key,
                conn=conn,
                timestamps=self._connection_history[target_key],
            )
            return alert

    def _evaluate_beacon_pattern(
        self,
        target_key: Tuple[str, int],
        conn: NetworkConnection,
        timestamps: List[float],
    ) -> Optional[C2BeaconAlert]:
        """
        Calculates inter-arrival deltas, mean interval, standard deviation,
        and jitter ratio (coefficient of variation).
        """
        if len(timestamps) < self.min_beacon_samples:
            return None

        # Calculate consecutive delta intervals
        intervals: List[float] = []
        for i in range(1, len(timestamps)):
            delta = timestamps[i] - timestamps[i - 1]
            if delta > 0.05:  # filter noise
                intervals.append(delta)

        if len(intervals) < (self.min_beacon_samples - 1):
            return None

        # Mean interval
        mean_interval = sum(intervals) / len(intervals)

        # Skip if mean interval is unrealistically small (< 0.5s is continuous streaming, not beaconing)
        if mean_interval < 0.5:
            return None

        # Standard deviation
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Jitter ratio = Coefficient of Variation (CV)
        jitter_ratio = std_dev / mean_interval if mean_interval > 0 else 1.0

        # Check beacon condition: low jitter <= threshold
        if jitter_ratio <= self.max_beacon_jitter:
            # Check cooldown to prevent duplicate alert storms (cooldown = 120s)
            now = time.time()
            last_alerted = self._alerted_targets.get(target_key, 0.0)
            if (now - last_alerted) < 120.0:
                return None

            self._alerted_targets[target_key] = now

            # Calculate confidence score
            confidence = 0.75
            if jitter_ratio <= 0.08:
                confidence += 0.15
            if conn.is_suspicious:
                confidence += 0.10
            confidence = min(1.0, round(confidence, 2))

            remote_ip, remote_port = target_key
            domain = conn.domain or self.resolve_domain(remote_ip) or remote_ip

            alert = C2BeaconAlert(
                alert_id=str(uuid.uuid4()),
                timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                severity="CRITICAL" if conn.is_suspicious or confidence >= 0.9 else "HIGH",
                alert_type="C2_BEACONING",
                process_name=conn.process_name,
                pid=conn.pid,
                remote_ip=remote_ip,
                remote_port=remote_port,
                domain=domain,
                beacon_interval_seconds=round(mean_interval, 2),
                jitter_ratio=round(jitter_ratio, 4),
                connection_count=len(timestamps),
                mitre_technique="T1071 — Application Layer Protocol (C2 Beacon)",
                description=(
                    f"Robotic beaconing detected: Process '{conn.process_name}' (PID {conn.pid}) established "
                    f"{len(timestamps)} periodic connections to {domain}:{remote_port} every "
                    f"~{mean_interval:.1f}s with minimal jitter ({jitter_ratio * 100:.1f}% <= {self.max_beacon_jitter * 100:.0f}% threshold)."
                ),
                confidence=confidence,
            )

            self._alerts.append(alert)
            if len(self._alerts) > 100:
                self._alerts = self._alerts[-50:]

            if self.alert_callback:
                try:
                    self.alert_callback(alert)
                except Exception as cb_err:
                    logger.debug(f"Alert callback error: {cb_err}")

            return alert

        return None

    def _create_immediate_threat_alert(self, conn: NetworkConnection) -> Optional[C2BeaconAlert]:
        """Creates an immediate alert for static indicators (suspicious port, tunnel, or LotL socket)."""
        target_key = (conn.remote_ip, conn.remote_port)
        now = time.time()
        last_alerted = self._alerted_targets.get(target_key, 0.0)
        if (now - last_alerted) < 120.0:
            return None

        self._alerted_targets[target_key] = now
        domain = conn.domain or self.resolve_domain(conn.remote_ip) or conn.remote_ip

        # Determine alert type and severity
        alert_type = "SUSPICIOUS_OUTBOUND"
        severity = "HIGH"
        if any("DGA" in r for r in conn.suspicious_reasons):
            alert_type = "DGA_DOMAIN"
        elif any("tunnel" in r.lower() for r in conn.suspicious_reasons):
            alert_type = "TUNNEL_PROXY"
        elif any("LotL" in r for r in conn.suspicious_reasons):
            alert_type = "SUSPICIOUS_OUTBOUND"
            severity = "CRITICAL"

        reasons_text = "; ".join(conn.suspicious_reasons)
        alert = C2BeaconAlert(
            alert_id=str(uuid.uuid4()),
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            severity=severity,
            alert_type=alert_type,
            process_name=conn.process_name,
            pid=conn.pid,
            remote_ip=conn.remote_ip,
            remote_port=conn.remote_port,
            domain=domain,
            beacon_interval_seconds=0.0,
            jitter_ratio=0.0,
            connection_count=1,
            mitre_technique="T1571 / T1059 / T1572 — Command & Control Communication",
            description=(
                f"Suspicious outbound network connection detected: '{conn.process_name}' (PID {conn.pid}) "
                f"connected to {domain}:{conn.remote_port}. Indicators: {reasons_text}"
            ),
            confidence=0.88,
        )

        self._alerts.append(alert)
        if len(self._alerts) > 100:
            self._alerts = self._alerts[-50:]

        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as cb_err:
                logger.debug(f"Immediate alert callback error: {cb_err}")

        return alert

    # ========================================================================
    # Utilities: DNS Resolution & Telemetry
    # ========================================================================

    def resolve_domain(self, ip_str: str) -> Optional[str]:
        """Performs cached reverse DNS resolution with timeout safety."""
        if not ip_str or is_private_or_loopback_ip(ip_str):
            return None

        if ip_str in self._domain_cache:
            return self._domain_cache[ip_str]

        try:
            domain, _, _ = socket.gethostbyaddr(ip_str)
            self._domain_cache[ip_str] = domain
            return domain
        except Exception:
            self._domain_cache[ip_str] = ip_str
            return ip_str

    def get_active_connections(self) -> List[Dict[str, Any]]:
        """Returns snapshot of current active sockets."""
        conns = self._collect_active_connections()
        for c in conns:
            self.inspect_connection(c)
        return [c.to_dict() for c in conns]

    def get_beacon_alerts(self) -> List[Dict[str, Any]]:
        """Returns all recorded C2 and suspicious network alerts."""
        with self._lock:
            return [a.to_dict() for a in self._alerts]

    def get_network_telemetry(self) -> Dict[str, Any]:
        """Provides compact network security telemetry for EDR ingestion."""
        with self._lock:
            active_targets = len(self._connection_history)
            alert_count = len(self._alerts)
            high_sev_count = sum(1 for a in self._alerts if a.severity in ("CRITICAL", "HIGH"))
            return {
                "active_external_targets_tracked": active_targets,
                "total_network_alerts": alert_count,
                "critical_high_alerts": high_sev_count,
                "latest_alert": self._alerts[-1].to_dict() if self._alerts else None,
            }
