import asyncio
import sys
import os

# Добавляем путь к проекту в sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.pompem_client import PompemClient
try:
    from core.swarm.tools import pompem_exploit_search
    HAS_CREWAI = True
except (ImportError, ModuleNotFoundError):
    HAS_CREWAI = False
    print("Warning: CrewAI not found, skipping tool test.")

async def test_pompem():
    print("--- Тестирование PompemClient ---")
    client = PompemClient()
    query = "WordPress"
    print(f"Поиск для: {query}")
    results = client.search_all(query)
    
    if results:
        print(f"Найдено результатов: {len(results)}")
        for r in results:
            print(f"- [{r['source']}] {r['title']} -> {r['url']}")
    else:
        print("Результатов не найдено.")

    print("\n--- Тестирование Pompem Tool (CrewAI) ---")
    if HAS_CREWAI:
        tool_result = pompem_exploit_search(query)
        print(tool_result)
    else:
        print("Skipped tool test (CrewAI missing)")

if __name__ == "__main__":
    asyncio.run(test_pompem())
