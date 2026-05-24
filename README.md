<div align="center">
  <img src="https://img.icons8.com/color/120/000000/security-shield.png" alt="MARS Logo">
  <h1>M.A.R.S. — Multi-Agent Recon System</h1>
  <p><b>Enterprise Web Security Audit Hub — CrewAI Swarm + Claude Sonnet 4.5</b></p>

  <p>
    <a href="https://python.org/"><img src="https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python" alt="Python"></a>
    <a href="#"><img src="https://img.shields.io/badge/CrewAI-Swarm-orange?style=flat-square" alt="CrewAI"></a>
    <a href="#"><img src="https://img.shields.io/badge/LiteLLM-Provider_Agnostic-purple?style=flat-square" alt="LiteLLM"></a>
    <a href="#"><img src="https://img.shields.io/badge/Ollama-Supported-green?style=flat-square" alt="Ollama"></a>
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
| **xsstrike** | Активный | Поиск и фаззинг XSS-уязвимостей |

### 🎚️ Режимы аудита (безопасность по умолчанию)

| Режим | Red Team | Запуск PoC | Когда использовать |
|--------|----------|------------|-------------------|
| **Security Assessment (VA)** | ❌ | ❌ | Отчёты CVE, compliance, bug bounty recon |
| **Full Pentest — PoC Analysis** | ✅ | ❌ | Авторизованный пентест: анализ кода PoC |
| **Exploit Verification** | ✅ | ✅* | Только lab/CTF; нужен `.env` + подтверждение в UI |

\* `ALLOW_EXPLOIT_EXECUTION=true` в `.env` и совпадение TARGET в поле подтверждения (Streamlit).

```env
ENABLE_RED_TEAM=false          # по умолчанию
ALLOW_EXPLOIT_EXECUTION=false  # по умолчанию
```

### ⚡ Профили сканирования

| Профиль | Сканеры | AI |
|---------|---------|-----|
| **Лёгкий** | nmap + whatweb | 1× запрос к LLM (без CrewAI) |
| **Полный** | 8+ инструментов | CrewAI Swarm (до 5 агентов) |

```bash
python main.py --profile light   # быстрый VA
python main.py --profile full    # по умолчанию
```

### 🧠 Multi-Agent Swarm & Локальные LLM

**M.A.R.S.** поддерживает любые модели через `litellm`: Anthropic (Claude), OpenAI (GPT-4), а также **локальные модели через Ollama** (Llama 3, Mistral и др.). Настроить их можно прямо в веб-интерфейсе!

```
Parser → Threat Intel → [Red Team*] → SOC Engineer → OSINT Recon
```

\* Red Team только при `ENABLE_RED_TEAM=true` или режиме Pentest в UI.  
`execute_exploit_payload` **заблокирован по умолчанию** (`ALLOW_EXPLOIT_EXECUTION=false`).

| # | Агент | Задача |
|---|--------|--------|
| 1 | **Parser** | Нормализация логов |
| 2 | **Threat Intel** | CVE + поиск PoC (Pompem) |
| 3 | **Red Team** *(опц.)* | Статический анализ PoC / верификация* |
| 4 | **SOC Engineer** | Playbook + Sigma |
| 5 | **OSINT Recon** | Поверхность атаки + Google Dorks |

\* Запуск эксплойтов — только в режиме Exploit Verification.

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

### 📊 Отчётность (CLI = Streamlit)

- **NVD** + **SearchSploit** в обоих интерфейсах
- Экспорт **JSON / HTML / PDF / CSV** (кнопки загрузки в Streamlit)
- **История аудитов** в `reports/` + **diff CVE** с прошлым прогоном
- **Unified findings** — единая таблица CVE (NVD + Nuclei + AI)
- **Умные сканеры** (`USE_SMART_SCANNERS=true`) — пропуск веб-инструментов без HTTP
- **Scope guardrails** — ticket ID, allowlist, блок private IP
- **Dashboard** — метрики и история в UI
- **Live progress** — авто-обновление каждые 5 с + хвост лога
- **NVD cache** 24ч в `logs/cache/nvd/`
- **Усечение логов** перед CrewAI (экономия токенов)
- Логи: `logs/mars_audit.log`
- **Docker:** `docker compose up --build`

### 🐳 Docker

```bash
cp .env.example .env
docker compose up --build
# UI: http://localhost:8501
# Health: страница Health в Streamlit multipage
```

---

## 🗂️ Архитектура

```text
├── app.py / main.py            # UI и CLI → core/audit_pipeline.py
├── core/
│   ├── audit_pipeline.py       # Единый пайплайн
│   ├── audit_state.py          # Состояние (переживает refresh)
│   ├── cancel_registry.py      # Отмена + kill PID
│   ├── light_analyzer.py       # Лёгкий Claude
│   ├── rate_limiter.py         # Очередь API
│   ├── logger.py               # logs/mars_audit.log
│   └── swarm/                  # CrewAI (5 агентов, Red Team опц.)
├── .github/workflows/ci.yml    # ruff + mypy + pytest
└── tests/
```

---

## ⚙️ Установка (Kali Linux / Debian)

### 1. Системные зависимости

```bash
sudo apt update
sudo apt install -y nmap whatweb dirb exploitdb subfinder wkhtmltopdf wpscan nikto ffuf python3-pip
```

Установка [Nuclei](https://github.com/projectdiscovery/nuclei):
```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

Установка [XSStrike](https://github.com/s0md3v/XSStrike) (опционально, нужен для XSS):
```bash
cd /opt
sudo git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike
sudo pip3 install -r requirements.txt --break-system-packages
# После установки убедитесь, что указали правильный путь в .env: XSSTRIKE_PATH=python3 /opt/XSStrike/xsstrike.py
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
```
Вы можете настроить LLM прямо через веб-интерфейс Streamlit (в боковом меню) или прописать вручную:

| Переменная | Обязательно | Описание |
|---|---|---|
| `LLM_PROVIDER` | **Да** | Провайдер LLM (`anthropic`, `openai`, `ollama`) |
| `LLM_MODEL` | **Да** | Название модели (например, `llama3`, `gpt-4o`) |
| `LLM_API_KEY` | Нет* | API-ключ (не нужен для Ollama) |
| `LLM_API_BASE` | Нет | Базовый URL (например, `http://localhost:11434` для Ollama) |
| `TARGET` | Нет | IP/домен/URL (можно вводить в UI) |
| `NVD_API_KEY` | Нет | Ускоряет верификацию CVE |
| `SHODAN_API_KEY` | Нет | Пассивный OSINT (порты, уязвимости) |
| `VIRUSTOTAL_API_KEY` | Нет | Репутация по 90+ AV движкам |
| `WPSCAN_API_KEY` | Нет | CVE в плагинах WordPress |
| `NETWORK_INTERFACE` | Нет | Интерфейс для nmap (eth0, tun0...) | — |
| `SOURCE_IP` | Нет | Исходящий IP для nmap | — |
| `HTTP_PROXY` | Нет | Прокси для веб-сканеров (Burp, SOCKS5) | — |
| `XSSTRIKE_PATH` | Нет | Путь к скрипту xsstrike.py (по умолчанию `xsstrike`) | — |

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

## 🧪 Тестирование и CI

```bash
pip install -r requirements-dev.txt
ruff check .
mypy core app.py main.py
pytest tests/ -q --ignore=tests/test_swarm.py
```

GitHub Actions: `.github/workflows/ci.yml` (ruff, mypy, pytest).

---

## ⚖️ Лицензия и ответственность

MIT License. Инструмент предназначен **исключительно** для авторизованного аудита безопасности, CTF и образовательных целей. Автор не несёт ответственности за несанкционированное использование.
