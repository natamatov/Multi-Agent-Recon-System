# PentestPlatform — Enterprise Web Security Audit

Автоматизированный аудит безопасности веб-ресурсов для **Kali Linux**: параллельное сканирование, верификация CVE через **NVD**, поиск PoC в **SearchSploit**, анализ **Claude** и HTML-отчёт.

> Используйте только на системах, где у вас есть **письменное разрешение** на тестирование.

## Возможности

| Компонент | Описание |
|-----------|----------|
| **nmap** | Порты и версии сервисов (`-sV`) |
| **whatweb** | Fingerprint веб-технологий |
| **nuclei** | CVE/misconfig шаблоны (`-jsonl`, critical/high/medium) |
| **dirb** | Перебор директорий (после параллельной фазы) |
| **NVD API** | Верификация CVE, CVSS, описания |
| **searchsploit** | Exploit-DB по технологиям |
| **Claude** | Корреляция Nuclei ↔ CVE, инструкции для разработчиков |
| **reporter** | Адаптивный HTML с цветовой кодировкой CVSS |

## Архитектура

```
main.py
  ├── config.py              # .env, валидация
  ├── dependency_manager.py  # nmap, whatweb, dirb, nuclei, searchsploit
  ├── scanner.py             # asyncio: nmap ∥ whatweb ∥ nuclei → dirb
  ├── nuclei_worker.py       # nuclei -jsonl
  ├── nvd_client.py          # NVD REST API 2.0
  ├── searchsploit_client.py # searchsploit --json
  ├── ai_analyzer.py         # Anthropic Claude
  ├── reporter.py            # audit_report.html
  └── utils.py               # PATH, CVE regex, URL helpers
```

## Установка (Kali Linux)

```bash
sudo apt update
sudo apt install -y nmap whatweb dirb exploitdb

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
# или: sudo apt install nuclei
nuclei -update-templates

# Python
cd PentestPlatform
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
# Заполните CLAUDE_API_KEY и TARGET
```

## Конфигурация (`.env`)

| Переменная | Обязательно | Описание |
|------------|-------------|----------|
| `CLAUDE_API_KEY` | Да | Ключ Anthropic |
| `TARGET` | Да | IP, hostname или URL |
| `NVD_API_KEY` | Нет | Ключ NVD (выше лимиты запросов) |

## Запуск

```bash
python3 main.py
```

**Результаты:**

- `audit_report.json` — полный машиночитаемый отчёт
- `audit_report.html` — визуальный отчёт с таблицами CVE, Nuclei и блоком для разработчиков

## Параллельное сканирование

`nmap`, `whatweb` и `nuclei` запускаются одновременно через `asyncio.gather`, что сокращает общее время ожидания. `dirb` выполняется после них (длительный перебор).

## Nuclei

Команда (формируется в `nuclei_worker.py`):

```bash
nuclei -u <TARGET> -jsonl -tags cve,misconfig -severity critical,high,medium -silent
```

## NVD

CVE извлекаются из логов (regex `CVE-YYYY-NNNNN`) и проверяются через:

`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=...`

Без API-ключа между запросами выдерживается пауза ~6.5 с (лимит NIST).

## SearchSploit

```bash
searchsploit --json "product version"
```

Выполняется по находкам Nuclei и по технологиям, определённым Claude.

## Отсутствующие утилиты

Если бинарник не найден в `PATH`, скрипт **не падает**: выводится подсказка `sudo apt install ...` и ожидание `Enter` после ручной установки.

## Требования

- Python 3.10+
- Kali Linux (или Debian с теми же пакетами)
- Доступ в интернет (Claude API, NVD, обновления Nuclei templates)

## Лицензия и ответственность

Инструмент предназначен для легального пентеста и обучения. Автор не несёт ответственности за несанкционированное использование.
