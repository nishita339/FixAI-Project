"""
FixAI EDR — Improvement #1: Multi-Platform Webhook Alert Notifier
==================================================================

Dispatches real-time security alerts to external messaging platforms:
  - Telegram Bot API (via Bot Token + Chat ID)
  - Discord Webhooks (via Webhook URL)
  - Slack Incoming Webhooks (via Webhook URL)

All dispatches are non-blocking (background threads) and fault-tolerant —
a failed webhook does not block EDR operations or other notification channels.

Configuration via environment variables:
  TELEGRAM_BOT_TOKEN   — Telegram Bot API token from @BotFather
  TELEGRAM_CHAT_ID     — Target chat/group/channel ID
  DISCORD_WEBHOOK_URL  — Discord channel webhook URL
  SLACK_WEBHOOK_URL    — Slack workspace incoming webhook URL
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

logger = logging.getLogger("fixai.security.webhook_notifier")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter("[%(asctime)s] [%(levelname)s] [Webhook] %(message)s")
    )
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


# ============================================================================
# Severity → Emoji Mapping
# ============================================================================

SEVERITY_EMOJI = {
    "CRITICAL": "\U0001f6a8",  # 🚨
    "HIGH": "\u26a0\ufe0f",     # ⚠️
    "MEDIUM": "\u2139\ufe0f",   # ℹ️
    "LOW": "\u2705",            # ✅
}

ALERT_TYPE_EMOJI = {
    "BRUTE_FORCE": "\U0001f510",       # 🔐
    "MALICIOUS_FILE": "\U0001f9a0",    # 🦠
    "FILELESS_THREAT": "\U0001f47b",   # 👻
    "QUARANTINE": "\U0001f512",        # 🔒
    "FIREWALL": "\U0001f6e1\ufe0f",    # 🛡️
    "RANSOMWARE_CANARY": "\U0001f3f4", # 🏴
}


# ============================================================================
# Webhook Configuration Dataclass
# ============================================================================

@dataclass
class WebhookConfig:
    """Holds configuration for all webhook endpoints."""
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    discord_webhook_url: str = ""
    slack_webhook_url: str = ""

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)

    @property
    def discord_enabled(self) -> bool:
        return bool(self.discord_webhook_url)

    @property
    def slack_enabled(self) -> bool:
        return bool(self.slack_webhook_url)

    @property
    def any_enabled(self) -> bool:
        return self.telegram_enabled or self.discord_enabled or self.slack_enabled

    @classmethod
    def from_env(cls) -> "WebhookConfig":
        """Load webhook configuration from environment variables."""
        return cls(
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", ""),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", ""),
            discord_webhook_url=os.getenv("DISCORD_WEBHOOK_URL", ""),
            slack_webhook_url=os.getenv("SLACK_WEBHOOK_URL", ""),
        )

    def summary(self) -> str:
        """Returns a human-readable summary of enabled channels."""
        channels = []
        if self.telegram_enabled:
            channels.append("Telegram")
        if self.discord_enabled:
            channels.append("Discord")
        if self.slack_enabled:
            channels.append("Slack")
        return ", ".join(channels) if channels else "None"


# ============================================================================
# Message Formatters — Platform-Specific Rich Formatting
# ============================================================================

def format_telegram_message(alert_dict: Dict[str, Any]) -> str:
    """
    Format alert as Telegram HTML message.
    Telegram Bot API supports HTML: <b>, <i>, <code>, <pre>.
    """
    severity = alert_dict.get("severity", "HIGH")
    alert_type = alert_dict.get("alert_type", "UNKNOWN")
    sev_emoji = SEVERITY_EMOJI.get(severity, "\u26a0\ufe0f")
    type_emoji = ALERT_TYPE_EMOJI.get(alert_type, "\U0001f514")

    title = alert_dict.get("title", "Security Alert")
    threat = alert_dict.get("threat_description", "")
    action = alert_dict.get("action_taken", "")
    steps = alert_dict.get("actionable_steps", [])
    timestamp = alert_dict.get("timestamp", "")
    source = alert_dict.get("source_module", "")

    steps_text = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(steps))

    return (
        f"{sev_emoji} <b>{title}</b>\n"
        f"\n"
        f"{type_emoji} <b>Severity:</b> <code>{severity}</code>\n"
        f"\U0001f4cb <b>Type:</b> <code>{alert_type}</code>\n"
        f"\U0001f552 <b>Time:</b> {timestamp[:19]}\n"
        f"\n"
        f"<b>The Threat:</b>\n{threat}\n"
        f"\n"
        f"<b>Action Taken:</b>\n{action}\n"
        f"\n"
        f"<b>What You Should Do:</b>\n{steps_text}\n"
        f"\n"
        f"\U0001f916 <i>FixAI Guardian EDR • {source}</i>"
    )


def format_discord_embed(alert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format alert as a Discord embed object (rich embed with color sidebar).
    """
    severity = alert_dict.get("severity", "HIGH")
    alert_type = alert_dict.get("alert_type", "UNKNOWN")
    sev_emoji = SEVERITY_EMOJI.get(severity, "\u26a0\ufe0f")
    type_emoji = ALERT_TYPE_EMOJI.get(alert_type, "\U0001f514")

    # Discord embed colors (decimal)
    color_map = {
        "CRITICAL": 15158332,  # Red
        "HIGH": 15105570,      # Orange
        "MEDIUM": 16776960,    # Yellow
        "LOW": 5763719,        # Green
    }

    title = alert_dict.get("title", "Security Alert")
    threat = alert_dict.get("threat_description", "")
    action = alert_dict.get("action_taken", "")
    steps = alert_dict.get("actionable_steps", [])
    timestamp = alert_dict.get("timestamp", "")

    steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))

    return {
        "embeds": [{
            "title": f"{sev_emoji} {title}",
            "color": color_map.get(severity, 15105570),
            "fields": [
                {"name": f"{type_emoji} Severity", "value": f"`{severity}`", "inline": True},
                {"name": "\U0001f4cb Type", "value": f"`{alert_type}`", "inline": True},
                {"name": "\U0001f6a8 Threat", "value": threat[:1024], "inline": False},
                {"name": "\u2705 Action Taken", "value": action[:1024], "inline": False},
                {"name": "\U0001f4dd Recommendations", "value": steps_text[:1024], "inline": False},
            ],
            "footer": {"text": "FixAI Guardian EDR"},
            "timestamp": timestamp,
        }]
    }


def format_slack_message(alert_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format alert as a Slack Block Kit message with rich sections.
    """
    severity = alert_dict.get("severity", "HIGH")
    alert_type = alert_dict.get("alert_type", "UNKNOWN")
    sev_emoji = SEVERITY_EMOJI.get(severity, "\u26a0\ufe0f")
    type_emoji = ALERT_TYPE_EMOJI.get(alert_type, "\U0001f514")

    title = alert_dict.get("title", "Security Alert")
    threat = alert_dict.get("threat_description", "")
    action = alert_dict.get("action_taken", "")
    steps = alert_dict.get("actionable_steps", [])

    steps_text = "\n".join(f"{i+1}. {s}" for i, s in enumerate(steps))

    return {
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{sev_emoji} {title}", "emoji": True},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Severity:* `{severity}`"},
                    {"type": "mrkdwn", "text": f"*Type:* `{alert_type}`"},
                ],
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*{type_emoji} Threat:*\n{threat[:2500]}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*\u2705 Action Taken:*\n{action[:2500]}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*\U0001f4dd Recommendations:*\n{steps_text[:2500]}"},
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "\U0001f916 _FixAI Guardian EDR_"},
                ],
            },
        ],
    }


# ============================================================================
# HTTP Helper — Zero External Dependencies (stdlib only)
# ============================================================================

def _http_post_json(url: str, payload: Dict[str, Any], timeout: float = 10.0) -> int:
    """
    POST JSON payload to a URL using only Python stdlib (no requests needed).
    Returns HTTP status code, or -1 on connection error.
    """
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", "User-Agent": "FixAI-Guardian/1.0"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=timeout) as resp:
            return resp.status
    except HTTPError as e:
        logger.warning(f"Webhook HTTP error {e.code}: {e.reason} for {url[:60]}...")
        return e.code
    except (URLError, OSError, TimeoutError) as e:
        logger.debug(f"Webhook connection error for {url[:60]}...: {e}")
        return -1


# ============================================================================
# WebhookNotifier — Main Dispatcher Class
# ============================================================================

class WebhookNotifier:
    """
    Dispatches SecurityAlertMessages to configured webhook endpoints
    (Telegram, Discord, Slack) in non-blocking background threads.

    Usage:
        config = WebhookConfig.from_env()
        notifier = WebhookNotifier(config)
        notifier.send(alert)  # Non-blocking
    """

    def __init__(self, config: Optional[WebhookConfig] = None):
        self.config = config or WebhookConfig.from_env()
        self._send_count = 0
        self._error_count = 0
        self._lock = threading.Lock()

        if self.config.any_enabled:
            logger.info(
                f"\U0001f4e1 WebhookNotifier initialized — Channels: {self.config.summary()}"
            )
        else:
            logger.info(
                "\U0001f4e1 WebhookNotifier initialized — No webhook channels configured. "
                "Set TELEGRAM_BOT_TOKEN, DISCORD_WEBHOOK_URL, or SLACK_WEBHOOK_URL to enable."
            )

    def send(self, alert: Any) -> None:
        """
        Dispatch alert to all configured webhook channels.
        Non-blocking — each channel runs in its own daemon thread.

        Args:
            alert: A SecurityAlertMessage (or any object with a to_dict() method)
        """
        if not self.config.any_enabled:
            return

        alert_dict = alert.to_dict() if hasattr(alert, "to_dict") else alert

        if self.config.telegram_enabled:
            threading.Thread(
                target=self._send_telegram,
                args=(alert_dict,),
                daemon=True,
                name="FixAI-Telegram",
            ).start()

        if self.config.discord_enabled:
            threading.Thread(
                target=self._send_discord,
                args=(alert_dict,),
                daemon=True,
                name="FixAI-Discord",
            ).start()

        if self.config.slack_enabled:
            threading.Thread(
                target=self._send_slack,
                args=(alert_dict,),
                daemon=True,
                name="FixAI-Slack",
            ).start()

    def _send_telegram(self, alert_dict: Dict[str, Any]) -> bool:
        """Send alert to Telegram via Bot API."""
        url = (
            f"https://api.telegram.org/bot{self.config.telegram_bot_token}"
            f"/sendMessage"
        )
        message = format_telegram_message(alert_dict)
        payload = {
            "chat_id": self.config.telegram_chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
        status = _http_post_json(url, payload)
        success = 200 <= status < 300
        with self._lock:
            self._send_count += 1
            if not success:
                self._error_count += 1
        if success:
            logger.info("\u2705 Telegram alert sent successfully")
        else:
            logger.warning(f"\u274c Telegram alert failed (HTTP {status})")
        return success

    def _send_discord(self, alert_dict: Dict[str, Any]) -> bool:
        """Send alert to Discord via Webhook."""
        payload = format_discord_embed(alert_dict)
        status = _http_post_json(self.config.discord_webhook_url, payload)
        success = 200 <= status < 300
        with self._lock:
            self._send_count += 1
            if not success:
                self._error_count += 1
        if success:
            logger.info("\u2705 Discord alert sent successfully")
        else:
            logger.warning(f"\u274c Discord alert failed (HTTP {status})")
        return success

    def _send_slack(self, alert_dict: Dict[str, Any]) -> bool:
        """Send alert to Slack via Incoming Webhook."""
        payload = format_slack_message(alert_dict)
        status = _http_post_json(self.config.slack_webhook_url, payload)
        success = 200 <= status < 300
        with self._lock:
            self._send_count += 1
            if not success:
                self._error_count += 1
        if success:
            logger.info("\u2705 Slack alert sent successfully")
        else:
            logger.warning(f"\u274c Slack alert failed (HTTP {status})")
        return success

    # ================================================================
    # Telemetry & Stats
    # ================================================================
    @property
    def stats(self) -> Dict[str, Any]:
        """Returns webhook dispatch statistics."""
        with self._lock:
            return {
                "total_sent": self._send_count,
                "total_errors": self._error_count,
                "channels": self.config.summary(),
                "telegram_enabled": self.config.telegram_enabled,
                "discord_enabled": self.config.discord_enabled,
                "slack_enabled": self.config.slack_enabled,
            }

    # ================================================================
    # Direct Send Methods (for testing / manual dispatch)
    # ================================================================
    def send_telegram_sync(self, alert_dict: Dict[str, Any]) -> bool:
        """Synchronous Telegram send (blocking). For testing."""
        if not self.config.telegram_enabled:
            return False
        return self._send_telegram(alert_dict)

    def send_discord_sync(self, alert_dict: Dict[str, Any]) -> bool:
        """Synchronous Discord send (blocking). For testing."""
        if not self.config.discord_enabled:
            return False
        return self._send_discord(alert_dict)

    def send_slack_sync(self, alert_dict: Dict[str, Any]) -> bool:
        """Synchronous Slack send (blocking). For testing."""
        if not self.config.slack_enabled:
            return False
        return self._send_slack(alert_dict)
