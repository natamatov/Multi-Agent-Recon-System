<div align="center">
  <img src="https://img.icons8.com/color/120/000000/security-shield.png" alt="MARS Logo">
  <h1>M.A.R.S. — Multi-Agent Recon System</h1>
  <p><b>Enterprise Web Security Audit Hub powered by AI Swarm (CrewAI + Claude 3.5 Sonnet)</b></p>

  <p>
    <a href="https://python.org/"><img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python"></a>
    <a href="#"><img src="https://img.shields.io/badge/CrewAI-Multi--Agent_Swarm-orange?style=flat-square" alt="CrewAI"></a>
    <a href="#"><img src="https://img.shields.io/badge/Claude-3.5_Sonnet-purple?style=flat-square" alt="Claude"></a>
    <a href="#"><img src="https://img.shields.io/badge/Kali_Linux-Supported-black?style=flat-square&logo=linux" alt="Kali"></a>
    <a href="#"><img src="https://img.shields.io/badge/License-MIT-green?style=flat-square" alt="License"></a>
  </p>
</div>

---

**M.A.R.S.** — это платформа автоматизированного аудита безопасности с мультиагентным AI-роем. Запускает 8+ сканеров параллельно, собирает OSINT из 4 источников, а затем пропускает все данные через цепочку специализированных AI-агентов, которые выдают CVE-корреляцию, защитный Playbook и Google Dorks.

> ⚠️ **Только для авторизованного тестирования.** Использование на системах без явного письменного разрешения незаконно (ст. 272 УК РФ, CFAA и др.).

---

## ✨ Возможности

### 🔍 Сканирование (8 инструментов)

| Инструмент | Тип | Что делает |
|---|---|---|
| **nmap** | Активный | Порты, версии сервисов (`-sV`), поддержка `-e interface` и `-S source_ip` |
| **whatweb** | Активный | Fingerprint веб-стека (CMS, фреймворки, версии) |
| **nuclei** | Активный | CVE и misconfig шаблоны (`critical/high/medium`) |
| **wpscan** | Активный | WordPress: плагины, темы, пользователи + CVE (с API-токеном) |
| **nikto** | Активный | Опасные HTTP-заголовки, устаревшее ПО, дефолтные файлы |
| **subfinder** | Пассивный | Перечисление поддоменов через публичные DNS-источники |
| **ffuf** | Активный | Быстрый web-fuzzer: скрытые директории и файлы |
| **dirb** | Активный | Directory bruteforce (параллельно с ffuf) |

### 🧠 Multi-Agent Swarm (4 AI-агента на Claude 3.5 Sonnet)

```
Parser Agent  →  Threat Intel Agent  →  SOC Engineer  →  OSINT Recon Agent
(нормализация)    (CVE-корреляция)       (Sigma-правила)   (Google Dorks)
```

| Агент | Задача | Результат |
|---|---|---|
| **Parser Agent** | Очищает шум из сырых логов | Структурированный список: порты, сервисы, технологии |
| **Threat Intel Agent** | Сопоставляет версии с CVE-базой | Верифицированные CVE с CVSS, отфильтрованные False Positives |
| **SOC Engineer** | Анализирует CVE с точки зрения защиты | Playbook по патчингу + YAML Sigma-правила для SIEM |
| **OSINT Recon Agent** | Анализирует поддомены и данные API | Профиль атакуемой поверхности + 5–10 Google Dorks |

### 🌐 OSINT (4 источника)

- **Shodan API** — открытые порты и известные уязвимости без касания цели
- **VirusTotal API v3** — репутация домена/IP по 90+ антивирусным движкам
- **Subfinder** — поддомены из публичных источников (crt.sh, dnsdumpster и др.)
- **NVD API 2.0** — CVSS Score и описания CVE от NIST

### 📡 Проверка цели перед сканированием

- **ICMP ping** с измерением задержки и автоматическим определением IP
- **TCP fallback** (порты 80, 443, 22...) — если ICMP заблокирован файрволом
- Предупреждение при недоступности, но сканирование **не прерывается**

### 🌐 Сетевые настройки

- Выбор **сетевого интерфейса** для nmap (`eth0`, `wlan0`, `tun0`)
- **Source IP** для nmap (`-S`)
- **HTTP-прокси** для whatweb, nikto, ffuf, wpscan (включая Burp Suite)

### 📊 Отчётность

- **Streamlit UI** с детальным прогрессом по 4 шагам
- Вкладки: Данные / CVE / Sigma & Playbook / OSINT & Dorks / Сырые логи
- Экспорт в **HTML** и **PDF** (`wkhtmltopdf`)

---

## 🗂️ Архитектура

```text
Multi-Agent-Recon-System/
├── app.py                      # Streamlit UI (4-шаговый прогресс)
├── main.py                     # CLI-оркестратор
├── requirements.txt
├── .env.example                # Шаблон конфигурации
├── tests/                      # Pytest + mock-тесты
└── core/
    ├── config.py               # Загрузка и валидация .env
    ├── dependency_manager.py   # Проверка системных утилит
    ├── scanner.py              # Async запуск всех 8 сканеров
    ├── ping_checker.py         # ICMP + TCP ping перед сканированием
    ├── shodan_client.py        # Shodan API
    ├── virustotal_client.py    # VirusTotal API v3
    ├── nvd_client.py           # NIST NVD API 2.0
    ├── searchsploit_client.py  # Exploit-DB
    ├── reporter.py             # HTML + PDF отчёты
    └── swarm/
        ├── agents.py           # 4 AI-агента (CrewAI)
        ├── tasks.py            # Промпты и задачи агентов
        └── orchestrator.py     # MARSSwarmManager
```

---

## ⚙️ Установка (Kali Linux / Debian)

### 1. Системные зависимости

```bash
sudo apt update
sudo apt install -y nmap whatweb dirb exploitdb subfinder wkhtmltopdf wpscan nikto ffuf
```

Установка [Nuclei](https://github.com/projectdiscovery/nuclei):
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

### 2. Клонирование и установка

```bash
git clone https://github.com/natamatov/Multi-Agent-Recon-System.git
cd Multi-Agent-Recon-System
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
```

### 3. Конфигурация

```bash
cp .env.example .env
nano .env  # Вставьте ваши ключи
```

| Переменная | Обязательно | Описание | Получить |
|---|---|---|---|
| `CLAUDE_API_KEY` | **Да** | Anthropic API (Claude 3.5 Sonnet) | [console.anthropic.com](https://console.anthropic.com) |
| `TARGET` | Нет | IP/домен/URL (можно вводить в UI) | — |
| `NVD_API_KEY` | Нет | Ускоряет верификацию CVE | [nvd.nist.gov](https://nvd.nist.gov/developers/request-an-api-key) |
| `SHODAN_API_KEY` | Нет | Пассивный OSINT (порты, уязвимости) | [account.shodan.io](https://account.shodan.io) |
| `VIRUSTOTAL_API_KEY` | Нет | Репутация по 90+ AV движкам, 500 req/day | [virustotal.com](https://www.virustotal.com) |
| `WPSCAN_API_KEY` | Нет | CVE в плагинах WordPress, 25 req/day | [wpscan.com](https://wpscan.com/profile) |
| `NETWORK_INTERFACE` | Нет | Интерфейс для nmap (eth0, tun0...) | — |
| `SOURCE_IP` | Нет | Исходящий IP для nmap | — |
| `HTTP_PROXY` | Нет | Прокси для веб-сканеров (Burp, SOCKS5) | — |

---

## 🚀 Использование

### Веб-интерфейс (рекомендуется)

```bash
streamlit run app.py
```

После нажатия **«Запустить аудит»** интерфейс показывает детальный прогресс:

```
[0/4] 📡 Проверка доступности цели (ping ICMP/TCP)
[1/4] 🔍 Параллельный запуск 8 сканеров
[2/4] 🌐 OSINT: Shodan + VirusTotal + Subfinder
[3/4] 🤖 AI Swarm: 4 агента анализируют данные
[4/4] ✅ Отчёт готов — 5 вкладок с результатами
```

### CLI

```bash
python3 main.py
```

Отчёты сохраняются в `audit_report.json`, `audit_report.html`, `audit_report.pdf`.

---

## 🧪 Тестирование

```bash
pytest tests/ -v
```

Тесты используют `unittest.mock` — не требуют реальных API-ключей или сетевых запросов.

---

## ⚖️ Лицензия и ответственность

MIT License. Инструмент предназначен **исключительно** для авторизованного аудита безопасности, CTF и образовательных целей. Автор не несёт ответственности за несанкционированное использование.
