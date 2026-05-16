import asyncio
import sys
import os

# Добавляем путь к проекту в sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.waf_detector import run_waf_check

async def test_waf():
    print("--- Тестирование WAFDetector (WebCheck logic) ---")
    
    # Список тестовых доменов
    targets = [
        "https://www.cloudflare.com",
        "https://www.akamai.com",
        "https://github.com",
        "https://google.com"
    ]
    
    for target in targets:
        print(f"\nПроверка: {target}")
        result = run_waf_check(target)
        if result["detected"]:
            print(f"[!] ОБНАРУЖЕНО: {', '.join(result['providers'])}")
            print("Советы по обходу:")
            for hint in result["hints"]:
                print(f"  - {hint}")
        else:
            print("[+] WAF/CDN не обнаружен или используется неизвестная защита.")
        
        if result["relevant_headers"]:
            print("Важные заголовки:")
            for k, v in result["relevant_headers"].items():
                print(f"  {k}: {v}")

if __name__ == "__main__":
    asyncio.run(test_waf())
