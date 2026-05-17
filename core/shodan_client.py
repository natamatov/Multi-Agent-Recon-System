import os
from typing import Any, Dict

import shodan


def run_shodan_recon(target: str, api_key: str | None = None) -> Dict[str, Any]:
    """
    Пассивный сбор информации через Shodan API.
    Не "трогает" саму цель, делает запрос только к базе Shodan.
    """
    if not api_key:
        # Пробуем достать из окружения, если не передан
        api_key = os.getenv("SHODAN_API_KEY")

    if not api_key or not api_key.strip():
        return {
            "success": False,
            "error": "SHODAN_API_KEY не задан. Пассивная разведка отключена."
        }

    try:
        api = shodan.Shodan(api_key.strip())
        # Пробуем найти информацию по IP
        # Если цель - домен, shodan search "hostname:..." или "ssl.cert.subject.cn:..."
        # Для простоты попробуем использовать функцию host() (работает с IP).
        # Но сначала надо разрезолвить IP? Shodan API имеет отдельный endpoint для доменов:
        # Однако, лучше сделать общий текстовый поиск.

        import socket
        try:
            ip = socket.gethostbyname(target)
            host = api.host(ip)

            ports = host.get("ports", [])
            vulns = host.get("vulns", [])
            org = host.get("org", "Unknown")
            os_info = host.get("os", "Unknown")

            return {
                "success": True,
                "ip": ip,
                "org": org,
                "os": os_info,
                "open_ports": ports,
                "vulns": vulns,
                "raw": host
            }
        except socket.gaierror:
            # Если это не домен, а какой-то некорректный хост
            return {
                "success": False,
                "error": f"Не удалось разрезолвить IP для {target}"
            }
        except shodan.APIError as e:
            return {
                "success": False,
                "error": f"Ошибка Shodan API: {e}"
            }

    except Exception as e:
        return {
            "success": False,
            "error": f"Внутренняя ошибка Shodan клиента: {e}"
        }
