"""
Детектор WAF и CDN на основе сигнатур из WebCheck (X3RX3SSec).
Определяет наличие защитных слоев и предлагает варианты обхода.
"""

from __future__ import annotations

import urllib.request
from dataclasses import dataclass, field
from typing import Any


@dataclass
class WAFResult:
    """Результат проверки на наличие WAF/CDN."""

    detected: bool = False
    providers: list[str] = field(default_factory=list)
    headers_found: dict[str, str] = field(default_factory=dict)
    bypass_hints: list[str] = field(default_factory=list)


class WAFDetector:
    """
    Класс для обнаружения WAF/CDN через анализ HTTP-заголовков.
    """

    # Сигнатуры на основе WebCheck
    WAF_SIGNATURES = {
        "Cloudflare": ["cf-ray", "cf-cache-status", "cloudflare"],
        "AWS CloudFront": ["x-amz-cf-id", "x-amz-cf-pop"],
        "Akamai": ["x-check-cacheable", "akamaighost"],
        "Fastly": ["x-served-by", "x-cache-hits"],
        "Sucuri": ["x-sucuri-id", "x-sucuri-cache"],
        "Incapsula": ["x-iinfo", "incap_ses"],
        "F5 BIG-IP": ["bigipserver", "x-cnection"],
        "Varnish": ["x-varnish", "via: varnish"],
        "ModSecurity": ["mod_security", "modsecurity"],
        "Imperva": ["x-iinfo"],
    }

    BYPASS_HINTS = [
        "Попробуйте заголовки: X-Forwarded-For: 127.0.0.1",
        "Попробуйте заголовки: X-Originating-IP: 127.0.0.1",
        "Попробуйте заголовки: X-Remote-IP: 127.0.0.1",
        "Попробуйте заголовки: X-Remote-Addr: 127.0.0.1",
        "Используйте Cloudflare-подобные инструменты для поиска реального IP (например, Censys, Shodan).",
    ]

    def __init__(self, user_agent: str | None = None):
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    async def detect_async(self, url: str) -> WAFResult:
        """
        Асинхронно (через обертку) проверяет URL на наличие WAF.
        В данной версии используется синхронный urllib, обернутый в run_in_executor или просто прямой вызов,
        так как это один быстрый запрос.
        """
        import asyncio
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self.detect, url)

    def detect(self, url: str) -> WAFResult:
        """Синхронная проверка."""
        result = WAFResult()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
            with urllib.request.urlopen(req, timeout=10) as response:
                headers = {k.lower(): v.lower() for k, v in response.getheaders()}

                # Анализируем заголовки
                hdr_str = str(headers).lower()

                for provider, sigs in self.WAF_SIGNATURES.items():
                    if any(sig.lower() in hdr_str for sig in sigs):
                        result.detected = True
                        if provider not in result.providers:
                            result.providers.append(provider)

                # Сохраняем важные заголовки для отладки
                for h in ["server", "via", "x-cache", "x-powered-by"]:
                    if h in headers:
                        result.headers_found[h] = headers[h]

            if result.detected:
                result.bypass_hints = self.BYPASS_HINTS

        except Exception as e:
            # Ошибка может быть вызвана самим WAF (например, 403 Forbidden)
            # В таком случае проверяем заголовки ошибки, если это возможно
            if hasattr(e, 'headers'):
                hdr_str = str(e.headers).lower()
                for provider, sigs in self.WAF_SIGNATURES.items():
                    if any(sig.lower() in hdr_str for sig in sigs):
                        result.detected = True
                        result.providers.append(provider)
                        result.bypass_hints = self.BYPASS_HINTS

        return result

def run_waf_check(target_url: str) -> dict[str, Any]:
    """Удобная функция-обертка."""
    detector = WAFDetector()
    res = detector.detect(target_url)
    return {
        "detected": res.detected,
        "providers": res.providers,
        "hints": res.bypass_hints,
        "relevant_headers": res.headers_found
    }
