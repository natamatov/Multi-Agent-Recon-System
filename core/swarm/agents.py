import os

from crewai import Agent


def _get_llm_string() -> str:
    """
    Возвращает строковый идентификатор LLM для CrewAI.
    CrewAI использует LiteLLM внутри — строка вида 'anthropic/model-name'.
    Заодно гарантируем, что ANTHROPIC_API_KEY задан (CrewAI/LiteLLM ищет именно его).
    """
    api_key = os.getenv("CLAUDE_API_KEY") or os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise ValueError("CLAUDE_API_KEY не задан в .env")
    # LiteLLM требует ANTHROPIC_API_KEY
    os.environ["ANTHROPIC_API_KEY"] = api_key
    return "anthropic/claude-3-5-sonnet-20241022"


class SecurityAgents:
    """Определяет агентов для мультиагентного анализа (Swarm)."""

    def __init__(self):
        self.llm = _get_llm_string()

    def parser_agent(self) -> Agent:
        return Agent(
            role="Специалист по нормализации данных",
            goal="Превратить сырые логи сканеров (Nmap, WhatWeb) в чистый структурированный формат JSON.",
            backstory=(
                "Вы — педантичный аналитик данных, работающий в команде кибербезопасности. "
                "Ваша задача — извлечь из сырого текстового вывода сканеров точные версии ПО, "
                "открытые порты и используемые технологии, чтобы другие эксперты могли с ними работать. "
                "Вы никогда не фантазируете и работаете только с предоставленными фактами."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def threat_intel_agent(self) -> Agent:
        return Agent(
            role="Эксперт по киберразведке (Threat Intel) и уязвимостям",
            goal="Сопоставить найденные версии ПО с базой известных CVE и оценить их критичность (CVSS).",
            backstory=(
                "Вы — эксперт Threat Intelligence, знающий наизусть базы уязвимостей. "
                "Основываясь на структурированных данных об инфраструктуре, вы находите "
                "соответствующие уязвимости (CVE). Вы оцениваете векторы атак и даете четкое "
                "понимание рисков (CVSS). Ваша работа носит строго оборонительный характер."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def soc_engineer_agent(self) -> Agent:
        return Agent(
            role="Архитектор защитных систем (SOC Engineer)",
            goal="Разработать план митигации и написать концепты Sigma-правил для выявленных CVE.",
            backstory=(
                "Вы — опытный SOC-инженер (Security Operations Center). "
                "Вы берете список уязвимостей (CVE) и разрабатываете "
                "инструкции по их устранению (патчинг, настройки). Кроме того, вы пишете "
                "Sigma-правила для SIEM, чтобы выявлять попытки эксплуатации этих уязвимостей "
                "в логах веб-серверов или систем. Вы мыслите как защитник (Blue Team)."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )

    def osint_recon_agent(self) -> Agent:
        return Agent(
            role="Специалист по пассивной разведке (OSINT) и Dorking",
            goal="Составить профиль поверхности атаки на основе поддоменов и данных Shodan, "
                 "а также сгенерировать Google Dorks для поиска утечек информации.",
            backstory=(
                "Вы — эксперт по разведке на основе открытых источников (OSINT). "
                "Вы анализируете сырые данные от Shodan (открытые порты, сертификаты) "
                "и Subfinder (список поддоменов). Ваша цель — понять, какие активы торчат "
                "в интернет, и составить мощные поисковые запросы (Google Dorks), "
                "которые помогут найти слитые PDF-документы, открытые админки (например, WordPress) "
                "или забытые файлы конфигурации (.env) на этих доменах."
            ),
            verbose=True,
            allow_delegation=False,
            llm=self.llm,
        )
