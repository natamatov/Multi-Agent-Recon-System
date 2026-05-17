"""
Совместимый импорт декоратора @tool для CrewAI.
Пакет crewai-tools обязателен (ставится через pip install 'crewai[tools]').
"""

from __future__ import annotations

_INSTALL_HINT = (
    "Установите CrewAI со всеми зависимостями:\n"
    "  pip install 'crewai[tools]>=0.28.0' crewai-tools"
)


def get_tool_decorator():
    """Возвращает декоратор @tool из crewai.tools или crewai."""
    try:
        from crewai.tools import tool

        return tool
    except ImportError as first_err:
        err = first_err
        if "crewai_tools" in str(first_err):
            raise ImportError(_INSTALL_HINT) from first_err

    try:
        from crewai import tool

        return tool
    except ImportError as second_err:
        raise ImportError(_INSTALL_HINT) from second_err


tool = get_tool_decorator()
