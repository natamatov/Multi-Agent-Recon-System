import sys
from typing import Any, Dict
from crewai import Crew, Process

from .agents import SecurityAgents
from .tasks import SecurityTasks

class MARSSwarmManager:
    """Оркестратор мультиагентного анализа MARS Security Hub."""

    def __init__(self, step_callback=None):
        self.agents = SecurityAgents()
        self.tasks = SecurityTasks()
        self.step_callback = step_callback

    def _safe_callback(self, step_result):
        """Безопасный вызов коллбэка для Streamlit (информирование о статусе)."""
        if self.step_callback:
            try:
                self.step_callback(step_result)
            except Exception:
                pass

    def run_analysis(self, raw_logs: str) -> Dict[str, Any]:
        """
        Запускает рой агентов последовательно.
        Возвращает словарь с результатами работы каждого агента.
        """
        try:
            # Инициализация агентов
            parser = self.agents.parser_agent()
            threat_intel = self.agents.threat_intel_agent()
            soc_engineer = self.agents.soc_engineer_agent()

            # Инициализация задач
            task1 = self.tasks.normalize_data_task(parser, raw_logs)
            task2 = self.tasks.correlate_vulnerabilities_task(threat_intel)
            task3 = self.tasks.generate_defense_playbook_task(soc_engineer)

            # Формирование команды (Crew)
            crew = Crew(
                agents=[parser, threat_intel, soc_engineer],
                tasks=[task1, task2, task3],
                verbose=True,
                process=Process.sequential,
                step_callback=self._safe_callback
            )

            # Запуск выполнения
            result = crew.kickoff()

            # Структурируем результаты для UI
            # CrewAI >= 0.28.0 позволяет извлекать результаты задач:
            parsed_data = task1.output.raw_output if hasattr(task1, 'output') and task1.output else "Нет данных от парсера."
            cve_data = task2.output.raw_output if hasattr(task2, 'output') and task2.output else "Нет данных об уязвимостях."
            sigma_playbook = task3.output.raw_output if hasattr(task3, 'output') and task3.output else "Нет данных по защите."

            return {
                "success": True,
                "parsed_data": parsed_data,
                "cve_data": cve_data,
                "sigma_playbook": sigma_playbook,
                "final_summary": str(result)
            }

        except Exception as e:
            return {
                "success": False,
                "error": f"Ошибка выполнения роя агентов: {str(e)}"
            }
