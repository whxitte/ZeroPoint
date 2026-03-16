"""
ZeroPoint Notifier — Async alert dispatchers for Discord and Telegram.

Both channels support the same interface:
    notifier.notify(new_assets, program_id, root_domain)

Design: fail-silently — notifications should NEVER crash the pipeline.
"""

from __future__ import annotations

import asyncio
from typing import List, Optional

import aiohttp
from loguru import logger


# ─────────────────────────────────────────────
# Discord Notifier
# ─────────────────────────────────────────────

class DiscordNotifier:
    """Sends rich embed notifications to a Discord channel via webhook."""

    # Discord embed field value limit
    FIELD_MAX_CHARS = 1024

    def __init__(self, webhook_url: str) -> None:
        self.webhook_url = webhook_url

    async def notify(
        self,
        new_assets: List[str],
        program_id: str,
        root_domain: str,
        total_found: int = 0,
    ) -> bool:
        """
        Post a Discord embed for newly discovered assets.
        Returns True on success, False on failure.
        """
        if not new_assets:
            return True

        # Build the subdomain list field value (truncate if too long)
        asset_lines = [f"`{a}`" for a in new_assets[:30]]
        if len(new_assets) > 30:
            asset_lines.append(f"*...and {len(new_assets) - 30} more*")
        assets_field_value = "\n".join(asset_lines)

        # Enforce Discord's 1024-char field limit
        if len(assets_field_value) > self.FIELD_MAX_CHARS:
            assets_field_value = assets_field_value[: self.FIELD_MAX_CHARS - 3] + "..."

        payload = {
            "username": "ZeroPoint Recon",
            "avatar_url": "https://i.imgur.com/4M34hi2.png",
            "embeds": [
                {
                    "title": f"🎯  New Assets Detected — `{root_domain}`",
                    "description": (
                        f"**Program:** `{program_id}`\n"
                        f"**New Assets:** **{len(new_assets)}**  |  "
                        f"**Total Found This Run:** {total_found}"
                    ),
                    "color": 0xFF4444,  # Red
                    "fields": [
                        {
                            "name": f"🔍 New Subdomains ({len(new_assets)})",
                            "value": assets_field_value,
                            "inline": False,
                        }
                    ],
                    "footer": {"text": "ZeroPoint v1.0 — Bug Bounty Automation"},
                    "timestamp": asyncio.get_event_loop()
                    .time()  # Placeholder — Discord accepts ISO 8601 but we keep it simple
                    and None,
                }
            ],
        }

        # Rebuild with proper timestamp
        from datetime import datetime, timezone
        payload["embeds"][0]["timestamp"] = (
            datetime.now(timezone.utc).isoformat()
        )

        return await self._post(payload)

    async def _post(self, payload: dict) -> bool:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    self.webhook_url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status in (200, 204):
                        logger.debug("[discord] Notification sent ✓")
                        return True
                    text = await resp.text()
                    logger.error(f"[discord] HTTP {resp.status}: {text[:200]}")
                    return False
        except Exception as exc:
            logger.error(f"[discord] Failed to send notification: {exc}")
            return False


# ─────────────────────────────────────────────
# Telegram Notifier
# ─────────────────────────────────────────────

class TelegramNotifier:
    """Sends Markdown messages to a Telegram chat via Bot API."""

    API_BASE = "https://api.telegram.org"

    def __init__(self, bot_token: str, chat_id: str) -> None:
        self.bot_token = bot_token
        self.chat_id   = chat_id

    async def notify(
        self,
        new_assets: List[str],
        program_id: str,
        root_domain: str,
        total_found: int = 0,
    ) -> bool:
        if not new_assets:
            return True

        asset_lines = "\n".join(f"  • `{a}`" for a in new_assets[:25])
        overflow    = f"\n  _...and {len(new_assets) - 25} more_" if len(new_assets) > 25 else ""

        message = (
            f"🎯 *ZeroPoint Alert*\n\n"
            f"*Program:* `{program_id}`\n"
            f"*Domain:*  `{root_domain}`\n"
            f"*New Assets:* *{len(new_assets)}*\n\n"
            f"*Subdomains:*\n{asset_lines}{overflow}"
        )

        url     = f"{self.API_BASE}/bot{self.bot_token}/sendMessage"
        payload = {
            "chat_id":    self.chat_id,
            "text":       message,
            "parse_mode": "Markdown",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url,
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    data = await resp.json()
                    if data.get("ok"):
                        logger.debug("[telegram] Notification sent ✓")
                        return True
                    logger.error(f"[telegram] API error: {data.get('description')}")
                    return False
        except Exception as exc:
            logger.error(f"[telegram] Failed to send notification: {exc}")
            return False


# ─────────────────────────────────────────────
# Composite Notifier
# ─────────────────────────────────────────────

class NotificationDispatcher:
    """
    Dispatches alerts to all configured channels simultaneously.
    Add a notifier with `.add()` and call `.dispatch()`.
    """

    def __init__(self) -> None:
        self._notifiers: list = []

    def add(self, notifier) -> "NotificationDispatcher":
        self._notifiers.append(notifier)
        return self

    async def dispatch(
        self,
        new_assets: List[str],
        program_id: str,
        root_domain: str,
        total_found: int = 0,
    ) -> None:
        """Fire all notifiers concurrently. Failures are logged, not raised."""
        if not new_assets or not self._notifiers:
            return

        results = await asyncio.gather(
            *[
                n.notify(new_assets, program_id, root_domain, total_found)
                for n in self._notifiers
            ],
            return_exceptions=True,
        )
        for res in results:
            if isinstance(res, Exception):
                logger.error(f"[notifier] Dispatch exception: {res}")
