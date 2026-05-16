<div align="center">
  <img src="https://img.icons8.com/color/120/000000/security-shield.png" alt="Logo">
  <h1>M.A.R.S. (Multi-Agent Recon System)</h1>
  <p><b>Enterprise Web Security Audit Hub powered by AI Swarm (CrewAI)</b></p>
  
  <p>
    <a href="https://python.org/"><img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python Version"></a>
    <a href="#"><img src="https://img.shields.io/badge/CrewAI-Swarm-orange?style=flat-square" alt="CrewAI"></a>
    <a href="#"><img src="https://img.shields.io/badge/Claude-3.5_Sonnet-purple?style=flat-square" alt="Claude API"></a>
    <a href="#"><img src="https://img.shields.io/badge/Kali_Linux-Supported-black?style=flat-square&logo=linux" alt="Kali Linux"></a>
    <a href="#"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"></a>
  </p>
</div>

---

**M.A.R.S. (Multi-Agent Recon System)** — это передовая платформа автоматизированного аудита безопасности веб-ресурсов. Платформа запускает параллельные сканеры, собирает OSINT-данные и анализирует поверхность атаки с помощью роя интеллектуальных AI-агентов, обученных на методологиях информационной безопасности (Blue/Red Team).

> ⚠️ **ПРЕДУПРЕЖДЕНИЕ:** Используйте только на системах, где у вас есть **явное письменное разрешение** на тестирование. Проект создан в образовательных и профессиональных целях защиты (Blue Team).

---

## ✨ Ключевые возможности

🚀 **Асинхронное Сканирование**
- Запускает `nmap`, `whatweb`, `nuclei`, `subfinder` параллельно (через `asyncio.gather`), сводя время ожидания к минимуму.
- Последовательно выполняет `dirb` для перебора директорий.

🧠 **Multi-Agent Swarm (CrewAI)**
Вместо одного запроса к ИИ, логи анализирует Рой из узкоспециализированных агентов (на базе Claude 3.5 Sonnet):
1. **`Parser Agent`**: Вычищает "шум" из логов и нормализует сырые данные.
2. **`Threat Intel Agent`**: Сопоставляет выявленные версии с CVE, отбрасывая ложные срабатывания (False Positives).
3. **`SOC Engineer`**: Генерирует Playbook защиты (шаги по патчингу) и **Sigma-правила** для SIEM систем.
4. **`OSINT Recon Agent`**: Анализирует данные поддоменов и открытые порты, генерируя индивидуальные **Google Dorks** под конкретную цель.

🔍 **Обогащение Данных (Threat Intelligence)**
- Интеграция с **NVD API 2.0** для получения точного CVSS Score и описаний CVE.
- Интеграция с **SearchSploit (Exploit-DB)** для поиска PoC.
- Пассивный OSINT через **Shodan API** (не касается цели напрямую).
- **VirusTotal API v3**: проверка репутации домена/IP по 90+ антивирусным движкам.
- Специализированное сканирование **WordPress** через **WPScan** (плагины, темы, пользователи).
- **Nikto**: активное сканирование веб-сервера на опасные настройки и устаревшее ПО.
- **ffuf**: быстрый web fuzzer для обнаружения скрытых директорий и параметров.

📊 **UI и Отчетность**
- Удобный веб-интерфейс на базе **Streamlit**.
- Автоматическая генерация профессиональных отчетов: `JSON`, визуальный `HTML` и стильный `PDF` (через `wkhtmltopdf`).

---

## 🛠️ Архитектура

```text
Multi-Agent-Recon-System
├── app.py                     # Streamlit Веб-интерфейс
├── main.py                    # CLI-оркестратор (консольная версия)
├── requirements.txt           # Python зависимости
├── tests/                     # Интеграционные тесты (Pytest & Mocks)
└── core/                      # Ядро бизнес-логики
    ├── config.py              # Загрузка и валидация .env
    ├── dependency_manager.py  # Проверка системных утилит (Kali)
    ├── scanner.py             # Асинхронный запуск Nmap, WhatWeb, Subfinder, Nuclei, WPScan, Nikto, ffuf
    ├── shodan_client.py       # Клиент Shodan API
    ├── virustotal_client.py   # Клиент VirusTotal API v3
    ├── nvd_client.py          # Клиент NIST NVD API
    ├── searchsploit_client.py # Интеграция с Exploit-DB
    ├── reporter.py            # Генерация HTML и PDF отчетов
    └── swarm/                 # Модуль CrewAI
        ├── agents.py          # Инициализация ИИ-агентов
        ├── tasks.py           # Описание задач агентов
        └── orchestrator.py    # Запуск и управление роем (MARSSwarmManager)
```

---

## ⚙️ Установка (Kali Linux / Debian)

### 1. Системные зависимости

Скрипт автоматически проверит зависимости при запуске, но лучше установить их заранее:

```bash
sudo apt update
sudo apt install -y nmap whatweb dirb exploitdb subfinder wkhtmltopdf wpscan nikto ffuf
```

Установка [Nuclei](https://github.com/projectdiscovery/nuclei):
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# Или через apt: sudo apt install nuclei
nuclei -update-templates
```

### 2. Установка платформы

```bash
git clone https://github.com/natamatov/Multi-Agent-Recon-System.git
cd Multi-Agent-Recon-System

# Рекомендуется использовать виртуальное окружение
python3 -m venv venv
source venv/bin/activate

# Установка Python-пакетов
pip install -r requirements.txt
```

### 3. Конфигурация (.env)

Скопируйте пример конфига и впишите ваши API-ключи:

```bash
cp .env.example .env
```

| Переменная | Обязательно | Описание |
|------------|-------------|----------|
| `CLAUDE_API_KEY` | **Да** | Ключ Anthropic (Claude 3.5 Sonnet) для работы CrewAI агентов. |
| `TARGET` | Нет | IP, hostname или URL. Можно вводить напрямую в UI/CLI. |
| `NVD_API_KEY` | Нет | Ключ NIST (повышает лимиты API и скорость обогащения CVE). |
| `SHODAN_API_KEY` | Нет | Включает пассивный OSINT перед сканированием. |
| `WPSCAN_API_KEY` | Нет | Включает поиск CVE в плагинах/темах WordPress (25 req/day бесплатно на wpscan.com). |
| `VIRUSTOTAL_API_KEY` | Нет | Проверка репутации цели по 90+ антивирусным движкам (virustotal.com, free tier). |

---

## 🚀 Использование

### Веб-интерфейс (Streamlit)

Идеально для интерактивного анализа и просмотра результатов по вкладкам (OSINT, CVE, Sigma Rules).

```bash
streamlit run app.py
```

### Консольная версия (CLI)

Отлично подходит для автоматизации, CI/CD или запуска на сервере.

```bash
python3 main.py
```

Отчеты (`audit_report.json`, `audit_report.html`, `audit_report.pdf`) будут сохранены в корневой директории проекта.

---

## 🧪 Тестирование

Проект покрыт интеграционными тестами с использованием `unittest.mock`, что позволяет проверять работоспособность парсеров, Swarm менеджера и API-клиентов без реальных запросов и расхода токенов:

```bash
pytest tests/
```

---

## 📜 Лицензия и ответственность

Инструмент распространяется под лицензией MIT. Разработчик не несёт ответственности за несанкционированное использование. M.A.R.S. предназначен исключительно для авторизованного аудита безопасности, CTF и образовательных целей.
