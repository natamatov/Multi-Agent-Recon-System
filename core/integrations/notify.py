"""
Уведомления M.A.R.S. — Telegram Bot + Slack Webhook.

Отправляет сводку после завершения аудита:
  - Цель, профиль, время выполнения
  - Количество CVE по severity (Critical/High/Medium/Low)
  - MITRE ATT&CK тактики если есть
  - Ссылку на отчёт (если задан BASE_URL)

Переменные окружения:
  TELEGRAM_BOT_TOKEN   — токен Telegram Bot (@BotFather)
  TELEGRAM_CHAT_ID     — ID чата/канала (можно @channel_name)
  SLACK_WEBHOOK_URL    — Incoming Webhook URL от Slack App
"""

from __future__ import annotations

import json
import os
from typing import Any

from core.logger import get_logger

log = get_logger("mars.notify")

TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"
SLACK_BLOCKS_LIMIT = 50  # Slack лимит на количество блоков


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _sev_emoji(sev: str) -> str:
    return {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢"}.get(sev.lower(), "⚪")


def _build_summary_text(report: dict[str, Any], *, markdown: bool = True) -> str:
    """Строит текст сводки аудита для Telegram/Slack."""
    audit   = report.get("audit", {})
    target  = audit.get("target", "—")
    profile = audit.get("profile_label", audit.get("profile", "—"))
    ts      = str(audit.get("timestamp_utc", ""))[:19]

    sev     = report.get("severity_summary", {})
    findings = report.get("unified_findings", [])
    total_cve = len(findings)

    # CVE сводка
    crit  = sev.get("critical", 0)
    high  = sev.get("high", 0)
    med   = sev.get("medium", 0)
    low   = sev.get("low", 0)

    # MITRE тактики
    attack = report.get("attack_summary", {})
    tactics = attack.get("kill_chain_coverage", [])
    tactics_str = ", ".join(tactics[:5]) if tactics else "—"

    # Ключевые CVE
    top_cves = [
        f.get("id", "")
        for f in findings
        if str(f.get("severity", "")).lower() == "critical"
    ][:3]
    top_cves_str = ", ".join(top_cves) if top_cves else "—"

    if markdown:
        lines = [
            "🛡️ *M.A.R.S. Аудит завершён*",
            "",
            f"🎯 *Цель:* `{target}`",
            f"📋 *Профиль:* {profile}",
            f"⏰ *Время:* {ts} UTC",
            "",
            "🐛 *Найдено уязвимостей:*",
            f"  {_sev_emoji('critical')} Critical: *{crit}*   "
            f"{_sev_emoji('high')} High: *{high}*   "
            f"{_sev_emoji('medium')} Medium: *{med}*   "
            f"{_sev_emoji('low')} Low: *{low}*",
            f"  📊 Всего CVE: *{total_cve}*",
        ]
        if top_cves:
            lines += ["", f"⚠️ *Критические:* `{top_cves_str}`"]
        if tactics:
            lines += ["", f"🎯 *ATT&CK тактики:* {tactics_str}"]
    else:
        lines = [
            "M.A.R.S. Аудит завершён",
            f"Цель: {target}  |  Профиль: {profile}  |  {ts} UTC",
            f"Critical: {crit}  High: {high}  Medium: {med}  Low: {low}",
            f"Всего CVE: {total_cve}",
        ]
        if tactics:
            lines.append(f"ATT&CK: {tactics_str}")

    return "\n".join(lines)


# ─── Telegram ─────────────────────────────────────────────────────────────────

async def send_telegram(
    report: dict[str, Any],
    *,
    token: str | None = None,
    chat_id: str | None = None,
) -> bool:
    """
    Отправляет сводку в Telegram через Bot API.
    Возвращает True при успехе.
    """
    token   = token   or os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = chat_id or os.getenv("TELEGRAM_CHAT_ID", "")

    if not token or not chat_id:
        log.debug("Telegram: TELEGRAM_BOT_TOKEN или TELEGRAM_CHAT_ID не заданы — пропускаем")
        return False

    try:
        import httpx as _httpx
    except ImportError:
        log.warning("Telegram: httpx не установлен (pip install httpx)")
        return False

    text = _build_summary_text(report, markdown=True)
    url  = TELEGRAM_API.format(token=token)

    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            r = await client.post(url, json={
                "chat_id":    chat_id,
                "text":       text,
                "parse_mode": "Markdown",
            })
        if r.status_code == 200:
            log.info("Telegram: уведомление отправлено в %s", chat_id)
            return True
        log.warning("Telegram: HTTP %d — %s", r.status_code, r.text[:200])
        return False
    except Exception as exc:
        log.warning("Telegram: ошибка отправки: %s", exc)
        return False


# ─── Slack ────────────────────────────────────────────────────────────────────

async def send_slack(
    report: dict[str, Any],
    *,
    webhook_url: str | None = None,
) -> bool:
    """
    Отправляет сводку в Slack через Incoming Webhook.
    Возвращает True при успехе.
    """
    webhook_url = webhook_url or os.getenv("SLACK_WEBHOOK_URL", "")

    if not webhook_url:
        log.debug("Slack: SLACK_WEBHOOK_URL не задан — пропускаем")
        return False

    try:
        import httpx as _httpx
    except ImportError:
        log.warning("Slack: httpx не установлен (pip install httpx)")
        return False

    audit    = report.get("audit", {})
    target   = audit.get("target", "—")
    profile  = audit.get("profile_label", "—")
    sev      = report.get("severity_summary", {})
    findings = report.get("unified_findings", [])
    total    = len(findings)
    crit     = sev.get("critical", 0)
    high     = sev.get("high", 0)

    color = "#dc2626" if crit > 0 else "#ea580c" if high > 0 else "#16a34a"

    # Slack Block Kit
    payload: dict[str, Any] = {
        "attachments": [{
            "color":  color,
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🛡️ M.A.R.S. — Аудит завершён"},
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Цель:*\n`{target}`"},
                        {"type": "mrkdwn", "text": f"*Профиль:*\n{profile}"},
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": (
                            f"🔴 Critical: *{crit}*   🟠 High: *{high}*   "
                            f"🟡 Medium: *{sev.get('medium', 0)}*   "
                            f"🟢 Low: *{sev.get('low', 0)}*\n"
                            f"📊 Всего CVE: *{total}*"
                        ),
                    },
                },
                {"type": "divider"},
            ],
        }],
    }

    # Критические CVE
    top_cves = [f.get("id") for f in findings if str(f.get("severity", "")).lower() == "critical"][:5]
    if top_cves:
        payload["attachments"][0]["blocks"].append({  # type: ignore[index]
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"⚠️ *Критические:* {', '.join(f'`{c}`' for c in top_cves)}",
            },
        })

    # ATT&CK
    attack_summary = report.get("attack_summary", {})
    tactics = attack_summary.get("kill_chain_coverage", [])
    if tactics:
        payload["attachments"][0]["blocks"].append({  # type: ignore[index]
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"🎯 *ATT&CK тактики:* {', '.join(tactics[:6])}",
            },
        })

    try:
        async with _httpx.AsyncClient(timeout=15) as client:
            r = await client.post(webhook_url, content=json.dumps(payload),
                                  headers={"Content-Type": "application/json"})
        if r.status_code == 200:
            log.info("Slack: уведомление отправлено")
            return True
        log.warning("Slack: HTTP %d — %s", r.status_code, r.text[:200])
        return False
    except Exception as exc:
        log.warning("Slack: ошибка отправки: %s", exc)
        return False


# ─── Unified ──────────────────────────────────────────────────────────────────

async def notify_audit_completed(
    report: dict[str, Any],
    *,
    telegram_token: str | None = None,
    telegram_chat_id: str | None = None,
    slack_webhook: str | None = None,
) -> dict[str, bool]:
    """
    Отправляет уведомления во все настроенные каналы.

    Возвращает: {"telegram": True/False, "slack": True/False}
    """
    results: dict[str, bool] = {}

    tg_ok = await send_telegram(
        report,
        token=telegram_token,
        chat_id=telegram_chat_id,
    )
    results["telegram"] = tg_ok

    sl_ok = await send_slack(report, webhook_url=slack_webhook)
    results["slack"] = sl_ok

    if any(results.values()):
        log.info("Уведомления отправлены: %s", results)
    else:
        log.debug("Уведомления не настроены или не отправлены: %s", results)

    return results
