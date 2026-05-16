"""
Интеграция с логикой Pompem: поиск эксплойтов в онлайн-базах (PacketStorm, CXSecurity).
"""

from __future__ import annotations

import re
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


@dataclass
class PompemMatch:
    """Результат поиска из базы данных эксплойтов."""

    title: str
    url: str
    date: str
    source: str


class PompemClient:
    """
    Упрощенная реализация логики Pompem для поиска эксплойтов в открытых источниках.
    """

    def __init__(self):
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36"

    def _fetch_html(self, url: str) -> str:
        """Загружает HTML-контент страницы."""
        req = urllib.request.Request(url, headers={"User-Agent": self.user_agent})
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                return response.read().decode("utf-8", errors="ignore")
        except Exception:
            return ""

    def search_packetstorm(self, query: str) -> list[PompemMatch]:
        """Поиск на PacketStorm Security."""
        encoded_query = urllib.parse.quote(query)
        url = f"https://packetstormsecurity.com/search/?q={encoded_query}"
        html = self._fetch_html(url)
        
        matches: list[PompemMatch] = []
        # Простой парсинг через регулярные выражения (аналог логики Pompem)
        # Ищем блоки с результатами
        items = re.findall(r'<dl id=".*?">.*?</dl>', html, re.DOTALL)
        for item in items[:5]:  # Берем первые 5 результатов
            title_match = re.search(r'<dt><a href="(.*?)">(.*?)</a></dt>', item)
            date_match = re.search(r'<dd class="datetime">.*?<a.*?>(\d{4}-\d{2}-\d{2})</a>', item)
            
            if title_match:
                path, title = title_match.groups()
                date = date_match.group(1) if date_match else "unknown"
                matches.append(PompemMatch(
                    title=title.strip(),
                    url=f"https://packetstormsecurity.com{path}",
                    date=date,
                    source="PacketStorm"
                ))
        return matches

    def search_cxsecurity(self, query: str) -> list[PompemMatch]:
        """Поиск на CXSecurity."""
        encoded_query = urllib.parse.quote(query)
        url = f"https://cxsecurity.com/search/wlb/ORD/DESC/1/10/search-word/{encoded_query}/"
        html = self._fetch_html(url)
        
        matches: list[PompemMatch] = []
        # Ищем ссылки на уязвимости
        items = re.findall(r'<h6><a href="(https://cxsecurity.com/issue/WLB-.*?)".*?>(.*?)</a></h6>', html)
        for url, title in items[:5]:
            matches.append(PompemMatch(
                title=title.strip(),
                url=url,
                date="unknown",
                source="CXSecurity"
            ))
        return matches

    def download_exploit(self, url: str, target_dir: str = "exploits") -> str | None:
        """
        Загружает код эксплойта по ссылке.
        """
        import os
        if not os.path.exists(target_dir):
            os.makedirs(target_dir)

        # Логика загрузки для PacketStorm
        if "packetstormsecurity.com" in url:
            file_id_match = re.search(r'/files/(\d+)/', url)
            if file_id_match:
                file_id = file_id_match.group(1)
                file_name = f"exploit_{file_id}.txt"
                download_url = f"https://packetstormsecurity.com/files/download/{file_id}/{file_name}"
                
                try:
                    req = urllib.request.Request(download_url, headers={"User-Agent": self.user_agent})
                    with urllib.request.urlopen(req, timeout=15) as response:
                        content = response.read()
                        file_path = os.path.join(target_dir, file_name)
                        with open(file_path, "wb") as f:
                            f.write(content)
                        return file_path
                except Exception:
                    return None

        elif "cxsecurity.com" in url:
            ascii_url = url.replace("/issue/", "/ascii/")
            try:
                content = self._fetch_html(ascii_url)
                if content:
                    file_name = url.split("/")[-1] + ".txt"
                    file_path = os.path.join(target_dir, file_name)
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(content)
                    return file_path
            except Exception:
                return None

        return None

    def search_all(self, query: str) -> list[dict[str, Any]]:
        """Выполняет поиск по всем доступным базам."""
        all_matches = []
        all_matches.extend(self.search_packetstorm(query))
        all_matches.extend(self.search_cxsecurity(query))
        
        return [
            {
                "title": m.title,
                "url": m.url,
                "date": m.date,
                "source": m.source
            }
            for m in all_matches
        ]


def lookup_pompem(technologies: list[dict[str, Any]], max_queries: int = 3) -> list[dict[str, Any]]:
    """
    Интерфейсная функция для использования в Swarm или основном пайплайне.
    """
    client = PompemClient()
    results = []
    
    for tech in technologies[:max_queries]:
        name = tech.get("name", "")
        version = tech.get("version", "")
        if not name:
            continue
            
        query = f"{name} {version}".strip()
        found = client.search_all(query)
        if found:
            results.append({
                "tech": query,
                "exploits": found
            })
            
    return results
