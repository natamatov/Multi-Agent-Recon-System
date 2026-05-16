"""
Инструменты для агентов CrewAI.
"""

from crewai.tools import tool
from core.pompem_client import PompemClient

@tool("pompem_exploit_search")
def pompem_exploit_search(query: str) -> str:
    """
    Выполняет поиск эксплойтов в онлайн-базах (PacketStorm, CXSecurity) через Pompem.
    Аргумент query — это название ПО и версия (например, 'OpenSSH 7.2').
    Возвращает список найденных эксплойтов с ссылками.
    """
    client = PompemClient()
    results = client.search_all(query)
    
    if not results:
        return f"По запросу '{query}' эксплойтов не найдено."
        
    output = [f"Результаты Pompem для '{query}':"]
    for res in results:
        output.append(f"- {res['title']} ({res['source']})")
        output.append(f"  URL: {res['url']}")
        output.append(f"  Дата: {res['date']}")
    
    return "\n".join(output)
