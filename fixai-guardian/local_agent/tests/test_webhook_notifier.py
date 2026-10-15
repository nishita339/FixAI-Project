"""
FixAI EDR — Improvement #1: Webhook Notifier Tests
====================================================

Tests for multi-platform webhook alert dispatch:
- WebhookConfig loading & validation
- Telegram message formatting (HTML)
- Discord embed formatting (rich embed)
- Slack Block Kit message formatting
- WebhookNotifier dispatch logic & stats
- AlertBridge webhook integration
- HTTP POST helper
- Edge cases & error handling
"""

import json
import os
import sys
import threading
import time
import unittest
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

# Ensure the local_agent directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from security.webhook_notifier import (
    WebhookConfig,
    WebhookNotifier,
    format_telegram_message,
    format_discord_embed,
    format_slack_message,
    _http_post_json,
    SEVERITY_EMOJI,
    ALERT_TYPE_EMOJI,
)


# ============================================================================
# Mock SecurityAlertMessage (matches the real dataclass in alert_bridge.py)
# ============================================================================

@dataclass
class MockAlertMessage:
    """Mock SecurityAlertMessage for testing."""
    title: str = "Brute-Force Attack Blocked"
    severity: str = "HIGH"
    alert_type: str = "BRUTE_FORCE"
    threat_description: str = "5 failed login attempts from 192.168.1.100 targeting user Admin in 30 seconds."
    action_taken: str = "IP 192.168.1.100 has been blocked via Windows Defender Firewall rule."
    actionable_steps: List[str] = None
    source_module: str = "EventMonitor"
    timestamp: str = "2026-10-15T22:00:00Z"
    metadata: Dict[str, Any] = None

    def __post_init__(self):
        if self.actionable_steps is None:
            self.actionable_steps = [
                "Check Event Viewer for Event ID 4625 entries",
                "Consider enabling account lockout policies",
                "Review firewall rules for suspicious IPs",
            ]
        if self.metadata is None:
            self.metadata = {"source_ip": "192.168.1.100", "target_user": "Admin"}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "alert_type": self.alert_type,
            "threat_description": self.threat_description,
            "action_taken": self.action_taken,
            "actionable_steps": self.actionable_steps,
            "source_module": self.source_module,
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }


# ============================================================================
# Test 1: WebhookConfig
# ============================================================================

class TestWebhookConfig(unittest.TestCase):
    """Tests for WebhookConfig data class and environment loading."""

    def test_default_config_nothing_enabled(self):
        """Default config with no values should have nothing enabled."""
        config = WebhookConfig()
        self.assertFalse(config.telegram_enabled)
        self.assertFalse(config.discord_enabled)
        self.assertFalse(config.slack_enabled)
        self.assertFalse(config.any_enabled)
        self.assertEqual(config.summary(), "None")

    def test_telegram_requires_both_fields(self):
        """Telegram needs BOTH bot_token AND chat_id."""
        config = WebhookConfig(telegram_bot_token="abc")
        self.assertFalse(config.telegram_enabled)

        config = WebhookConfig(telegram_chat_id="123")
        self.assertFalse(config.telegram_enabled)

        config = WebhookConfig(telegram_bot_token="abc", telegram_chat_id="123")
        self.assertTrue(config.telegram_enabled)

    def test_discord_enabled(self):
        config = WebhookConfig(discord_webhook_url="https://discord.com/api/webhooks/123/abc")
        self.assertTrue(config.discord_enabled)
        self.assertTrue(config.any_enabled)

    def test_slack_enabled(self):
        config = WebhookConfig(slack_webhook_url="https://hooks.slack.com/services/T/B/X")
        self.assertTrue(config.slack_enabled)
        self.assertTrue(config.any_enabled)

    def test_all_channels_enabled(self):
        config = WebhookConfig(
            telegram_bot_token="bot123",
            telegram_chat_id="chat456",
            discord_webhook_url="https://discord.com/webhook",
            slack_webhook_url="https://hooks.slack.com/services/x",
        )
        self.assertTrue(config.telegram_enabled)
        self.assertTrue(config.discord_enabled)
        self.assertTrue(config.slack_enabled)
        self.assertTrue(config.any_enabled)
        self.assertIn("Telegram", config.summary())
        self.assertIn("Discord", config.summary())
        self.assertIn("Slack", config.summary())

    @patch.dict(os.environ, {
        "TELEGRAM_BOT_TOKEN": "test-token",
        "TELEGRAM_CHAT_ID": "test-chat",
        "DISCORD_WEBHOOK_URL": "https://discord.test",
        "SLACK_WEBHOOK_URL": "https://slack.test",
    })
    def test_from_env(self):
        """from_env() should load all values from environment."""
        config = WebhookConfig.from_env()
        self.assertEqual(config.telegram_bot_token, "test-token")
        self.assertEqual(config.telegram_chat_id, "test-chat")
        self.assertEqual(config.discord_webhook_url, "https://discord.test")
        self.assertEqual(config.slack_webhook_url, "https://slack.test")
        self.assertTrue(config.any_enabled)

    @patch.dict(os.environ, {}, clear=True)
    def test_from_env_empty(self):
        """from_env() with no env vars should produce empty config."""
        # Clear only the webhook-related vars
        for key in ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "DISCORD_WEBHOOK_URL", "SLACK_WEBHOOK_URL"]:
            os.environ.pop(key, None)
        config = WebhookConfig.from_env()
        self.assertFalse(config.any_enabled)


# ============================================================================
# Test 2: Telegram Message Formatting
# ============================================================================

class TestTelegramFormatting(unittest.TestCase):
    """Tests for Telegram HTML message formatting."""

    def test_basic_format(self):
        alert = MockAlertMessage()
        msg = format_telegram_message(alert.to_dict())
        self.assertIn("<b>Brute-Force Attack Blocked</b>", msg)
        self.assertIn("<code>HIGH</code>", msg)
        self.assertIn("<code>BRUTE_FORCE</code>", msg)
        self.assertIn("192.168.1.100", msg)
        self.assertIn("FixAI Guardian EDR", msg)

    def test_critical_severity_emoji(self):
        alert = MockAlertMessage(severity="CRITICAL")
        msg = format_telegram_message(alert.to_dict())
        self.assertIn(SEVERITY_EMOJI["CRITICAL"], msg)

    def test_malicious_file_type_emoji(self):
        alert = MockAlertMessage(alert_type="MALICIOUS_FILE", title="Malware Detected")
        msg = format_telegram_message(alert.to_dict())
        self.assertIn(ALERT_TYPE_EMOJI["MALICIOUS_FILE"], msg)

    def test_actionable_steps_numbered(self):
        alert = MockAlertMessage()
        msg = format_telegram_message(alert.to_dict())
        self.assertIn("1. Check Event Viewer", msg)
        self.assertIn("2. Consider enabling", msg)
        self.assertIn("3. Review firewall", msg)

    def test_empty_steps(self):
        alert = MockAlertMessage(actionable_steps=[])
        msg = format_telegram_message(alert.to_dict())
        # Should not crash with empty steps
        self.assertIn("<b>Brute-Force Attack Blocked</b>", msg)

    def test_timestamp_truncated(self):
        alert = MockAlertMessage(timestamp="2026-10-15T22:00:00.123456Z")
        msg = format_telegram_message(alert.to_dict())
        self.assertIn("2026-10-15T22:00:00", msg)


# ============================================================================
# Test 3: Discord Embed Formatting
# ============================================================================

class TestDiscordFormatting(unittest.TestCase):
    """Tests for Discord rich embed formatting."""

    def test_embed_structure(self):
        alert = MockAlertMessage()
        payload = format_discord_embed(alert.to_dict())
        self.assertIn("embeds", payload)
        self.assertEqual(len(payload["embeds"]), 1)
        embed = payload["embeds"][0]
        self.assertIn("title", embed)
        self.assertIn("color", embed)
        self.assertIn("fields", embed)
        self.assertIn("footer", embed)

    def test_severity_colors(self):
        for severity, expected_color in [
            ("CRITICAL", 15158332),
            ("HIGH", 15105570),
            ("MEDIUM", 16776960),
            ("LOW", 5763719),
        ]:
            alert = MockAlertMessage(severity=severity)
            payload = format_discord_embed(alert.to_dict())
            self.assertEqual(payload["embeds"][0]["color"], expected_color)

    def test_fields_count(self):
        alert = MockAlertMessage()
        payload = format_discord_embed(alert.to_dict())
        fields = payload["embeds"][0]["fields"]
        self.assertEqual(len(fields), 5)  # Severity, Type, Threat, Action, Recommendations

    def test_footer_text(self):
        alert = MockAlertMessage()
        payload = format_discord_embed(alert.to_dict())
        self.assertEqual(payload["embeds"][0]["footer"]["text"], "FixAI Guardian EDR")

    def test_long_threat_truncated(self):
        """Discord fields are limited to 1024 chars."""
        long_threat = "A" * 2000
        alert = MockAlertMessage(threat_description=long_threat)
        payload = format_discord_embed(alert.to_dict())
        threat_field = payload["embeds"][0]["fields"][2]
        self.assertLessEqual(len(threat_field["value"]), 1024)


# ============================================================================
# Test 4: Slack Message Formatting
# ============================================================================

class TestSlackFormatting(unittest.TestCase):
    """Tests for Slack Block Kit message formatting."""

    def test_block_structure(self):
        alert = MockAlertMessage()
        payload = format_slack_message(alert.to_dict())
        self.assertIn("blocks", payload)
        blocks = payload["blocks"]
        self.assertGreaterEqual(len(blocks), 5)

    def test_header_block(self):
        alert = MockAlertMessage()
        payload = format_slack_message(alert.to_dict())
        header = payload["blocks"][0]
        self.assertEqual(header["type"], "header")
        self.assertIn("Brute-Force Attack Blocked", header["text"]["text"])

    def test_severity_field(self):
        alert = MockAlertMessage()
        payload = format_slack_message(alert.to_dict())
        section = payload["blocks"][1]
        self.assertEqual(section["type"], "section")
        fields_text = " ".join(f["text"] for f in section["fields"])
        self.assertIn("HIGH", fields_text)

    def test_divider_present(self):
        alert = MockAlertMessage()
        payload = format_slack_message(alert.to_dict())
        types = [b["type"] for b in payload["blocks"]]
        self.assertIn("divider", types)

    def test_context_footer(self):
        alert = MockAlertMessage()
        payload = format_slack_message(alert.to_dict())
        context = payload["blocks"][-1]
        self.assertEqual(context["type"], "context")
        self.assertIn("FixAI Guardian EDR", context["elements"][0]["text"])


# ============================================================================
# Test 5: WebhookNotifier Core Logic
# ============================================================================

class TestWebhookNotifier(unittest.TestCase):
    """Tests for the WebhookNotifier dispatch class."""

    def test_no_channels_send_is_noop(self):
        """When no channels configured, send() should be a no-op."""
        notifier = WebhookNotifier(WebhookConfig())
        alert = MockAlertMessage()
        notifier.send(alert)  # Should not raise
        self.assertEqual(notifier.stats["total_sent"], 0)

    def test_stats_defaults(self):
        notifier = WebhookNotifier(WebhookConfig())
        stats = notifier.stats
        self.assertEqual(stats["total_sent"], 0)
        self.assertEqual(stats["total_errors"], 0)
        self.assertEqual(stats["channels"], "None")
        self.assertFalse(stats["telegram_enabled"])
        self.assertFalse(stats["discord_enabled"])
        self.assertFalse(stats["slack_enabled"])

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_telegram_send_sync(self, mock_post):
        """send_telegram_sync should call the API and return True on 200."""
        config = WebhookConfig(telegram_bot_token="test-bot", telegram_chat_id="12345")
        notifier = WebhookNotifier(config)
        result = notifier.send_telegram_sync(MockAlertMessage().to_dict())
        self.assertTrue(result)
        mock_post.assert_called_once()
        args = mock_post.call_args
        url = args[0][0]
        self.assertIn("api.telegram.org", url)
        self.assertIn("test-bot", url)

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_discord_send_sync(self, mock_post):
        config = WebhookConfig(discord_webhook_url="https://discord.com/api/webhooks/123/abc")
        notifier = WebhookNotifier(config)
        result = notifier.send_discord_sync(MockAlertMessage().to_dict())
        self.assertTrue(result)
        mock_post.assert_called_once()

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_slack_send_sync(self, mock_post):
        config = WebhookConfig(slack_webhook_url="https://hooks.slack.com/services/T/B/X")
        notifier = WebhookNotifier(config)
        result = notifier.send_slack_sync(MockAlertMessage().to_dict())
        self.assertTrue(result)
        mock_post.assert_called_once()

    @patch("security.webhook_notifier._http_post_json", return_value=401)
    def test_failed_send_increments_errors(self, mock_post):
        config = WebhookConfig(telegram_bot_token="bad", telegram_chat_id="bad")
        notifier = WebhookNotifier(config)
        result = notifier.send_telegram_sync(MockAlertMessage().to_dict())
        self.assertFalse(result)
        self.assertEqual(notifier.stats["total_errors"], 1)
        self.assertEqual(notifier.stats["total_sent"], 1)

    @patch("security.webhook_notifier._http_post_json", return_value=-1)
    def test_connection_error_increments_errors(self, mock_post):
        config = WebhookConfig(discord_webhook_url="https://bad.url")
        notifier = WebhookNotifier(config)
        result = notifier.send_discord_sync(MockAlertMessage().to_dict())
        self.assertFalse(result)
        self.assertEqual(notifier.stats["total_errors"], 1)

    def test_disabled_channel_sync_returns_false(self):
        """send_*_sync on a disabled channel returns False immediately."""
        notifier = WebhookNotifier(WebhookConfig())
        self.assertFalse(notifier.send_telegram_sync({}))
        self.assertFalse(notifier.send_discord_sync({}))
        self.assertFalse(notifier.send_slack_sync({}))

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_async_send_dispatches_threads(self, mock_post):
        """send() should dispatch background threads for enabled channels."""
        config = WebhookConfig(
            telegram_bot_token="bot", telegram_chat_id="chat",
            discord_webhook_url="https://discord.test",
            slack_webhook_url="https://slack.test",
        )
        notifier = WebhookNotifier(config)
        alert = MockAlertMessage()
        notifier.send(alert)
        # Give threads time to execute
        time.sleep(0.5)
        # All 3 channels should have been called
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual(notifier.stats["total_sent"], 3)

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_send_accepts_dict_directly(self, mock_post):
        """send() should accept a raw dict (no to_dict method)."""
        config = WebhookConfig(telegram_bot_token="bot", telegram_chat_id="chat")
        notifier = WebhookNotifier(config)
        notifier.send({"title": "Test", "severity": "LOW", "alert_type": "BRUTE_FORCE"})
        time.sleep(0.3)
        mock_post.assert_called_once()


# ============================================================================
# Test 6: AlertBridge Webhook Integration
# ============================================================================

class TestAlertBridgeWebhookIntegration(unittest.TestCase):
    """Tests that AlertBridge correctly wires WebhookNotifier."""

    def test_alert_bridge_has_webhook(self):
        """AlertBridge should have a webhook attribute."""
        from security.alert_bridge import AlertBridge
        bridge = AlertBridge(enable_desktop_notifications=False)
        self.assertIsNotNone(bridge.webhook)
        self.assertIsInstance(bridge.webhook, WebhookNotifier)

    def test_alert_bridge_custom_config(self):
        """AlertBridge should accept a custom WebhookConfig."""
        from security.alert_bridge import AlertBridge
        config = WebhookConfig(
            telegram_bot_token="custom-bot",
            telegram_chat_id="custom-chat",
        )
        bridge = AlertBridge(
            enable_desktop_notifications=False,
            webhook_config=config,
        )
        self.assertTrue(bridge.webhook.config.telegram_enabled)
        self.assertEqual(bridge.webhook.config.telegram_bot_token, "custom-bot")

    @patch("security.webhook_notifier._http_post_json", return_value=200)
    def test_dispatch_triggers_webhook(self, mock_post):
        """_dispatch should call webhook.send()."""
        from security.alert_bridge import AlertBridge, SecurityAlertMessage
        config = WebhookConfig(discord_webhook_url="https://discord.test")
        bridge = AlertBridge(
            enable_desktop_notifications=False,
            webhook_config=config,
        )
        alert = SecurityAlertMessage(
            alert_id="test-001",
            timestamp="2026-10-15T22:00:00Z",
            title="Test Alert",
            severity="HIGH",
            alert_type="BRUTE_FORCE",
            threat_description="Test threat",
            action_taken="Test action",
            actionable_steps=["Step 1"],
            source_module="TestModule",
        )
        bridge._dispatch(alert)
        # Give thread time
        time.sleep(0.3)
        mock_post.assert_called_once()


# ============================================================================
# Test 7: HTTP Helper
# ============================================================================

class TestHttpPostJson(unittest.TestCase):
    """Tests for the _http_post_json helper."""

    @patch("security.webhook_notifier.urlopen")
    def test_successful_post(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        status = _http_post_json("https://test.com", {"key": "value"})
        self.assertEqual(status, 200)

    def test_invalid_url_returns_negative(self):
        """An unreachable URL should return -1."""
        status = _http_post_json("https://localhost:1/nonexistent", {"key": "value"}, timeout=0.5)
        self.assertEqual(status, -1)


# ============================================================================
# Test 8: Edge Cases
# ============================================================================

class TestEdgeCases(unittest.TestCase):
    """Edge case and robustness tests."""

    def test_empty_alert_dict_formatting(self):
        """Formatters should not crash with minimal/empty dicts."""
        empty = {}
        msg = format_telegram_message(empty)
        self.assertIsInstance(msg, str)
        self.assertIn("Security Alert", msg)

        embed = format_discord_embed(empty)
        self.assertIn("embeds", embed)

        slack = format_slack_message(empty)
        self.assertIn("blocks", slack)

    def test_unknown_severity_uses_default_emoji(self):
        alert = {"severity": "UNKNOWN_LEVEL", "alert_type": "CUSTOM"}
        msg = format_telegram_message(alert)
        self.assertIn("UNKNOWN_LEVEL", msg)

    def test_all_alert_types_have_emoji(self):
        """Every defined alert type should have an emoji."""
        for atype in ["BRUTE_FORCE", "MALICIOUS_FILE", "FILELESS_THREAT", "QUARANTINE", "FIREWALL"]:
            self.assertIn(atype, ALERT_TYPE_EMOJI)

    def test_all_severities_have_emoji(self):
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            self.assertIn(sev, SEVERITY_EMOJI)

    def test_config_summary_single_channel(self):
        config = WebhookConfig(discord_webhook_url="https://test")
        self.assertEqual(config.summary(), "Discord")

    def test_config_summary_two_channels(self):
        config = WebhookConfig(
            telegram_bot_token="a", telegram_chat_id="b",
            slack_webhook_url="https://test",
        )
        summary = config.summary()
        self.assertIn("Telegram", summary)
        self.assertIn("Slack", summary)


if __name__ == "__main__":
    unittest.main()
