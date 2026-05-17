from crewai import Task
from textwrap import dedent

from core.security_mode import AuditMode, exploit_execution_enabled


class SecurityTasks:
    """Определяет задачи для агентов CrewAI."""

    def normalize_data_task(self, agent, raw_logs: str) -> Task:
        return Task(
            description=dedent(f"""
                Проанализируйте следующие сырые логи сканеров (Nmap, WhatWeb) и извлеките все обнаруженные
                открытые порты, сервисы и веб-технологии с их точными версиями.
                
                Сырые логи:
                {raw_logs}
                
                Ваш ответ должен быть строго структурирован (в формате Markdown), перечисляя:
                1. Открытые порты и сервисы (IP/Port/Service/Version).
                2. Веб-технологии (Технология/Версия).
            """),
            expected_output="Структурированный Markdown список портов, сервисов и технологий.",
            agent=agent,
        )

    def correlate_vulnerabilities_task(self, agent, mode: AuditMode = AuditMode.ASSESSMENT) -> Task:
        poc_line = (
            "2. Используйте Pompem для поиска ссылок на публичные PoC (без запуска)."
            if mode == AuditMode.ASSESSMENT
            else "2. Используйте Pompem для поиска и при необходимости загрузки PoC для последующего анализа."
        )
        return Task(
            description=dedent(f"""
                Используя структурированные данные о сервисах и технологиях от предыдущего агента,
                найдите потенциальные уязвимости (CVE). Для каждой технологии с известной версией:
                1. Укажите идентификаторы возможных CVE.
                {poc_line}
                3. Оцените критичность по шкале CVSS (Critical, High, Medium, Low).
                4. Дайте краткое описание вектора атаки и рекомендации по устранению.

                НЕ запускайте эксплойты и НЕ выполняйте команды на целевой системе.
                Выдайте результат в Markdown или JSON.
            """),
            expected_output="Список CVE с CVSS, описанием и рекомендациями по remediation.",
            agent=agent,
        )

    def poc_analysis_task(self, agent) -> Task:
        """Red Team: только статический разбор PoC (без execute_exploit_payload)."""
        return Task(
            description=dedent("""
                На основе CVE и ссылок от Threat Intel агента:
                1. Выберите релевантный PoC и загрузите его через pompem_exploit_download.
                2. Проанализируйте код: язык, зависимости, целевые параметры, риски для оператора.
                3. Опишите ГИПОТЕТИЧЕСКИЕ шаги верификации в лаборатории (без выполнения на TARGET).
                4. Укажите, какие признаки в логах подтвердили бы успешную эксплуатацию.

                ЗАПРЕЩЕНО: install_exploit_dependencies, execute_exploit_payload и любой запуск кода.
            """),
            expected_output="Отчёт: путь к PoC, анализ кода, гипотетические шаги проверки (без запуска).",
            agent=agent,
        )

    def exploit_verification_task(self, agent) -> Task:
        """Red Team: полная верификация — только при ALLOW_EXPLOIT_EXECUTION=true."""
        return Task(
            description=dedent("""
                Только если инструменты execute_exploit_payload доступны (режим Exploit Verification):
                1. Загрузите PoC через pompem_exploit_download.
                2. Проанализируйте код перед запуском.
                3. При необходимости установите зависимости через install_exploit_dependencies.
                4. Выполните контролируемую проверку через execute_exploit_payload.
                5. Зафиксируйте вердикт: подтверждена / не подтверждена уязвимость.

                Если инструменты заблокированы — опишите это и вернитесь к статическому анализу.
            """),
            expected_output="Отчёт верификации PoC с логами или причиной блокировки.",
            agent=agent,
        )

    def generate_defense_playbook_task(self, agent) -> Task:
        return Task(
            description=dedent("""
                Основываясь на списке найденных уязвимостей (CVE), разработайте план защиты:
                1. Для каждой критичной или высокой (High/Critical) уязвимости напишите план по устранению 
                   (митигации), например, рекомендации по обновлению или конфигурации.
                2. Напишите 1-2 концепта Sigma-правил (в формате YAML) для выявления попыток 
                   эксплуатации этих специфичных уязвимостей в логах.
                
                Финальный результат должен содержать четкий Playbook и примеры Sigma-правил.
            """),
            expected_output="План митигации (Playbook) и концепты Sigma-правил в формате YAML.",
            agent=agent,
        )

    def osint_recon_task(self, agent, osint_data: str) -> Task:
        return Task(
            description=dedent(f"""
                Изучите следующие пассивные данные (поддомены от Subfinder, результаты Shodan API и отчет WAF-детекции):
                
                Данные OSINT и WAF:
                {osint_data}
                
                Выполните:
                1. Проанализируйте поверхность атаки (какие сервисы и поддомены торчат в интернет).
                2. Если обнаружен WAF или CDN (Cloudflare, Akamai и др.), предложите 2-3 способа 
                   поиска оригинального IP-адреса и проверьте, есть ли признаки утечки реального IP в заголовках.
                3. Сгенерируйте список из 5-10 точных Google Dorks для поиска утечек, административных 
                   панелей или уязвимых файлов конфигурации для найденных доменов.
                
                Ответ должен быть структурирован в Markdown: профиль цели и список Google Dorks.
            """),
            expected_output="Markdown-профиль поверхности атаки и список Google Dorks.",
            agent=agent,
        )
