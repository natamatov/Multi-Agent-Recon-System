from crewai_tools import tool
from ..pompem_client import PompemClient

@tool
def pompem_exploit_search(query: str) -> str:
    """
    Поиск эксплойтов и PoC в онлайн-базах (PacketStorm, CXSecurity) по названию технологии и версии.
    Возвращает список заголовков и ссылок на эксплойты.
    """
    client = PompemClient()
    results = client.search_all(query)
    
    if not results:
        return f"Эксплойтов для '{query}' не найдено в базах Pompem."
    
    output = [f"Результаты поиска Pompem для '{query}':"]
    for i, res in enumerate(results, 1):
        output.append(f"{i}. {res['title']} ({res['source']}) - {res['url']}")
    
    return "\n".join(output)

@tool
def pompem_exploit_download(url: str) -> str:
    """
    Загружает код эксплойта по прямой ссылке из PacketStorm или CXSecurity.
    Возвращает путь к сохраненному файлу или сообщение об ошибке.
    """
    client = PompemClient()
    path = client.download_exploit(url)
    
    if path:
        return f"Эксплойт успешно загружен: {path}"
    else:
        return f"Не удалось загрузить эксплойт по ссылке: {url}"

@tool
def install_exploit_dependencies(command: str) -> str:
    """
    Устанавливает необходимые зависимости для эксплойта (например, pip install или apt install).
    Принимает полную команду установки.
    """
    import subprocess
    try:
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=120)
        return f"Результат установки:\nSTDOUT: {result.stdout}\nSTDERR: {result.stderr}"
    except Exception as e:
        return f"Ошибка при установке зависимостей: {str(e)}"

@tool
def execute_exploit_payload(command: str) -> str:
    """
    Автоматически запускает эксплойт против цели. 
    ВНИМАНИЕ: Используйте этот инструмент только если вы проанализировали код эксплойта 
    и уверены, что он не повредит систему и соответствует задаче верификации.
    """
    import subprocess
    try:
        # Запускаем в оболочке с таймаутом 60 секунд
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=60)
        return f"Результат выполнения эксплойта:\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
    except subprocess.TimeoutExpired:
        return "Ошибка: Превышено время ожидания выполнения эксплойта (60 сек)."
    except Exception as e:
        return f"Критическая ошибка при запуске: {str(e)}"
