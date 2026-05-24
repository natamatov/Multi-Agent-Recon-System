import os

from crewai import Agent

from core.security_mode import AuditMode, exploit_execution_enabled, red_team_enabled

from .tools import (
    EXPLOIT_EXECUTION_TOOLS,
    pompem_exploit_download,
    pompem_exploit_search,
)


def _get_llm_string() -> str:
    """
    Возвращает строковый идентификатор LLM для CrewAI и настраивает ключи.
    """
    provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower()
    model = os.getenv("LLM_MODEL", "").strip()
    api_key = os.getenv("LLM_API_KEY")
    api_base = os.getenv("LLM_API_BASE")

    # Обратная совместимость
    if not api_key:
        api_key = os.getenv("CLAUDE_API_KEY")

    if not model:
        from core.llm_config import DEFAULT_MODELS
        model = DEFAULT_MODELS.get(provider, "claude-3-5-sonnet-20241022")

    if provider == "anthropic":
        if not api_key:
            raise ValueError("API-ключ для Anthropic не задан")
        os.environ["ANTHROPIC_API_KEY"] = api_key
        return f"anthropic/{model}"

    elif provider == "openai":
        if not api_key:
            raise ValueError("API-ключ для OpenAI не задан")
        os.environ["OPENAI_API_KEY"] = api_key
        if api_base:
            os.environ["OPENAI_API_BASE"] = api_base
        return f"openai/{model}"

    elif provider == "ollama":
        if api_base:
            os.environ["OLLAMA_API_BASE"] = api_base
        return f"ollama/{model}"

    else:
        # Fallback
        if api_key:
            os.environ[f"{provider.upper()}_API_KEY"] = api_key
        if api_base:
            os.environ[f"{provider.upper()}_API_BASE"] = api_base
        return f"{provider}/{model}"


class SecurityAgents:
    """Агенты мультиагентного роя с учётом режима аудита."""

    def __init__(self, mode: AuditMode = AuditMode.ASSESSMENT):
        self.llm = _get_llm_string()
        self.mode = mode

    def parser_agent(self) -> Agent:
        return Agent(
            role="Специалист по нормализации данных",
            goal="Превратить сырые логи сканеров в чистый структурированный формат.",
            backstory=(
                "Вы — педантичный аналитик данных в команде кибербезопасности. "
                "Извлекаете порты, сервисы и версии ПО только из предоставленных логов."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def threat_intel_agent(self) -> Agent:
        # VA: только поиск PoC; Pentest: поиск + загрузка для анализа
        tools = [pompem_exploit_search]
        if red_team_enabled(self.mode):
            tools.append(pompem_exploit_download)

        return Agent(
            role="Эксперт по киберразведке (Threat Intel) и уязвимостям",
            goal="Сопоставить версии ПО с CVE и оценить критичность (CVSS).",
            backstory=(
                "Вы — эксперт Threat Intelligence. Находите CVE и при необходимости "
                "ссылки на PoC. Не запускаете эксплойты — только оборонительный анализ рисков."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=tools,
        )

    def red_team_agent(self) -> Agent | None:
        """Red Team включается только в режимах pentest_poc / pentest_exploit."""
        if not red_team_enabled(self.mode):
            return None

        tools = [pompem_exploit_download]
        if exploit_execution_enabled(self.mode):
            tools.extend(EXPLOIT_EXECUTION_TOOLS)

        if exploit_execution_enabled(self.mode):
            goal = (
                "Верифицировать уязвимости: загрузить PoC, проанализировать код и "
                "при явном разрешении выполнить контролируемую проверку."
            )
        else:
            goal = (
                "Провести статический анализ PoC: загрузить, изучить код и описать "
                "гипотетические шаги верификации БЕЗ запуска против цели."
            )

        return Agent(
            role="Эксперт по эксплуатации (Red Team)",
            goal=goal,
            backstory=(
                "Вы — специалист Red Team в рамках авторизованного пентеста. "
                "В режиме PoC Analysis вы не выполняете команды на цели — только анализируете код."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
            tools=tools,
        )

    def soc_engineer_agent(self) -> Agent:
        return Agent(
            role="Архитектор защитных систем (SOC Engineer)",
            goal="Разработать план митигации и концепты Sigma-правил для CVE.",
            backstory=(
                "Вы — SOC-инженер. Разрабатываете playbook и Sigma для Blue Team."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def osint_recon_agent(self) -> Agent:
        return Agent(
            role="Специалист по пассивной разведке (OSINT)",
            goal="Профиль поверхности атаки, WAF/CDN и Google Dorks.",
            backstory=(
                "Вы — OSINT-эксперт. Анализируете Shodan, поддомены и WAF без активной атаки."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )
