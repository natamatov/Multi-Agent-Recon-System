from typing import Any, Callable

from crewai import Crew, Process

from core.security_mode import (
    AuditMode,
    exploit_execution_enabled,
    mode_label,
    red_team_enabled,
)
from .agents import SecurityAgents
from .tasks import SecurityTasks


class MARSSwarmManager:
    """Оркестратор мультиагентного анализа M.A.R.S. Security Hub."""

    def __init__(
        self,
        step_callback: Callable[..., None] | None = None,
        mode: AuditMode = AuditMode.ASSESSMENT,
    ):
        self.mode = mode
        self.agents_factory = SecurityAgents(mode=mode)
        self.tasks = SecurityTasks()
        self.step_callback = step_callback

    def _safe_callback(self, step_result: Any) -> None:
        if self.step_callback:
            try:
                self.step_callback(step_result)
            except Exception:
                pass

    def run_analysis(
        self,
        raw_logs: str,
        osint_data: str = "",
    ) -> dict[str, Any]:
        """
        Запускает рой агентов последовательно.
        Red Team включается только в режимах pentest_poc / pentest_exploit.
        """
        exploit_data_default = (
            "_Red Team отключён (режим Security Assessment). "
            "Включите «PoC Analysis» или «Exploit Verification» в UI._"
        )

        try:
            parser = self.agents_factory.parser_agent()
            threat_intel = self.agents_factory.threat_intel_agent()
            red_team = self.agents_factory.red_team_agent()
            soc_engineer = self.agents_factory.soc_engineer_agent()
            osint_recon = self.agents_factory.osint_recon_agent()

            task1 = self.tasks.normalize_data_task(parser, raw_logs)
            task2 = self.tasks.correlate_vulnerabilities_task(
                threat_intel, mode=self.mode
            )
            task3 = self.tasks.generate_defense_playbook_task(soc_engineer)
            task4 = self.tasks.osint_recon_task(osint_recon, osint_data)

            agents = [parser, threat_intel, soc_engineer, osint_recon]
            tasks = [task1, task2, task3, task4]
            task_exp = None

            if red_team is not None:
                agents.insert(2, red_team)
                if exploit_execution_enabled(self.mode):
                    task_exp = self.tasks.exploit_verification_task(red_team)
                else:
                    task_exp = self.tasks.poc_analysis_task(red_team)
                tasks.insert(2, task_exp)

            crew = Crew(
                agents=agents,
                tasks=tasks,
                verbose=True,
                process=Process.sequential,
                step_callback=self._safe_callback,
            )

            result = crew.kickoff()

            parsed_data = (
                task1.output.raw
                if hasattr(task1, "output") and task1.output
                else "Нет данных от парсера."
            )
            cve_data = (
                task2.output.raw
                if hasattr(task2, "output") and task2.output
                else "Нет данных об уязвимостях."
            )
            if task_exp and hasattr(task_exp, "output") and task_exp.output:
                exploit_data = task_exp.output.raw
            else:
                exploit_data = exploit_data_default

            sigma_playbook = (
                task3.output.raw
                if hasattr(task3, "output") and task3.output
                else "Нет данных по защите."
            )
            osint_result = (
                task4.output.raw
                if hasattr(task4, "output") and task4.output
                else "OSINT данные не сгенерированы."
            )

            return {
                "success": True,
                "audit_mode": self.mode.value,
                "audit_mode_label": mode_label(self.mode),
                "red_team_enabled": red_team_enabled(self.mode),
                "exploit_execution_enabled": exploit_execution_enabled(self.mode),
                "parsed_data": parsed_data,
                "cve_data": cve_data,
                "exploit_data": exploit_data,
                "sigma_playbook": sigma_playbook,
                "osint_dorking": osint_result,
                "final_summary": str(result),
            }

        except Exception as exc:
            return {
                "success": False,
                "audit_mode": self.mode.value,
                "error": f"Ошибка выполнения роя агентов: {exc}",
            }
