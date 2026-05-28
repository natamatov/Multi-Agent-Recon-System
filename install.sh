#!/usr/bin/env bash
# ============================================================
# M.A.R.S. v2 — Install Script
# Устанавливает все CLI-инструменты пайплайна безопасности
# Поддерживаемые дистрибутивы: Kali Linux, Ubuntu 22.04+, Debian 12+
# ============================================================
# Использование:
#   chmod +x install.sh
#   sudo ./install.sh
# ============================================================

set -euo pipefail

# ── Цвета ──────────────────────────────────────────────────────────────────────
RED='\033[0;31m';  GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m';  BOLD='\033[1m';  NC='\033[0m'

# ── Статистика ─────────────────────────────────────────────────────────────────
INSTALLED=0; SKIPPED=0; FAILED=0
FAILED_TOOLS=()

# ── Вспомогательные функции ───────────────────────────────────────────────────

log_info()    { echo -e "${BLUE}[•]${NC} $*"; }
log_ok()      { echo -e "${GREEN}[✓]${NC} $*"; ((INSTALLED++)) || true; }
log_skip()    { echo -e "${CYAN}[~]${NC} $* (уже установлен)"; ((SKIPPED++)) || true; }
log_warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
log_error()   { echo -e "${RED}[✗]${NC} $*"; ((FAILED++)) || true; FAILED_TOOLS+=("$1"); }
log_section() { echo -e "\n${BOLD}${BLUE}══ $* ══${NC}"; }

is_installed() { command -v "$1" &>/dev/null; }

install_if_missing() {
    local tool="$1" pkg="${2:-$1}"
    if is_installed "$tool"; then
        log_skip "$tool"
    else
        log_info "Устанавливаю $tool..."
        if apt-get install -y "$pkg" &>/dev/null; then
            log_ok "$tool"
        else
            log_error "$tool" "apt install $pkg завершился ошибкой"
        fi
    fi
}

install_go_tool() {
    local tool="$1" pkg="$2"
    if is_installed "$tool"; then
        log_skip "$tool"
    else
        log_info "Устанавливаю $tool (go install)..."
        if go install "$pkg" &>/dev/null 2>&1; then
            # Копируем в /usr/local/bin для системного доступа
            local bin_name
            bin_name=$(basename "${pkg%%@*}")
            if [[ -f "${GOPATH}/bin/${bin_name}" ]]; then
                cp "${GOPATH}/bin/${bin_name}" /usr/local/bin/ 2>/dev/null || true
            elif [[ -f "${HOME}/go/bin/${bin_name}" ]]; then
                cp "${HOME}/go/bin/${bin_name}" /usr/local/bin/ 2>/dev/null || true
            fi
            if is_installed "$tool"; then
                log_ok "$tool"
            else
                log_warn "$tool установлен но не в PATH — добавьте ~/go/bin в PATH"
                ((INSTALLED++)) || true
            fi
        else
            log_error "$tool" "go install $pkg завершился ошибкой"
        fi
    fi
}

install_pip_tool() {
    local tool="$1" pkg="${2:-$1}"
    if is_installed "$tool"; then
        log_skip "$tool"
    else
        log_info "Устанавливаю $tool (pip)..."
        if pip3 install "$pkg" &>/dev/null 2>&1; then
            log_ok "$tool"
        else
            log_error "$tool" "pip install $pkg завершился ошибкой"
        fi
    fi
}

# ── Проверка прав и ОС ────────────────────────────────────────────────────────

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Скрипт должен запускаться с правами root: sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${BOLD}"
echo "  ███╗   ███╗ █████╗ ██████╗ ███████╗"
echo "  ████╗ ████║██╔══██╗██╔══██╗██╔════╝"
echo "  ██╔████╔██║███████║██████╔╝███████╗"
echo "  ██║╚██╔╝██║██╔══██║██╔══██╗╚════██║"
echo "  ██║ ╚═╝ ██║██║  ██║██║  ██║███████║"
echo "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
echo -e "  Multi-Agent Recon System — Install Script v2${NC}"
echo ""

# Определяем дистрибутив
DISTRO="unknown"
if [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO="${ID:-unknown}"
fi
log_info "Дистрибутив: ${BOLD}${PRETTY_NAME:-$DISTRO}${NC}"

case "$DISTRO" in
    kali)      log_ok "Kali Linux — все инструменты доступны в репозиториях" ;;
    ubuntu)    log_warn "Ubuntu — некоторые инструменты могут потребовать PPA или ручной установки" ;;
    debian)    log_warn "Debian — рекомендуется Kali Linux для полного набора инструментов" ;;
    *)         log_warn "Неизвестный дистрибутив: $DISTRO — продолжаем, но возможны ошибки" ;;
esac

# ── Обновление репозиториев ───────────────────────────────────────────────────

log_section "Обновление пакетной базы"
log_info "apt-get update..."
apt-get update -qq 2>/dev/null || log_warn "apt-get update завершился с предупреждением"

# ── Базовые зависимости ───────────────────────────────────────────────────────

log_section "Системные зависимости"
for pkg in python3 python3-pip golang-go cargo curl wget git; do
    install_if_missing "$pkg" "$pkg"
done

# Настраиваем Go PATH
export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$PATH:$GOPATH/bin:/usr/local/go/bin"

# ── Ядро M.A.R.S. (обязательные) ─────────────────────────────────────────────

log_section "Ядро M.A.R.S. (обязательные инструменты)"

install_if_missing "nmap"        "nmap"
install_if_missing "whatweb"     "whatweb"
install_if_missing "wkhtmltopdf" "wkhtmltopdf"

# Nuclei — предпочитаем apt (Kali), иначе Go
if is_installed "nuclei"; then
    log_skip "nuclei"
elif apt-get install -y nuclei &>/dev/null 2>&1; then
    log_ok "nuclei (apt)"
else
    install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

# Обновляем шаблоны Nuclei
if is_installed "nuclei"; then
    log_info "Обновление шаблонов nuclei..."
    nuclei -update-templates &>/dev/null 2>&1 || true
    log_ok "Шаблоны nuclei обновлены"
fi

# ── Порт-сканирование ─────────────────────────────────────────────────────────

log_section "Порт-сканирование"

# RustScan — предпочитаем apt (Kali), иначе cargo
if is_installed "rustscan"; then
    log_skip "rustscan"
elif apt-get install -y rustscan &>/dev/null 2>&1; then
    log_ok "rustscan (apt)"
else
    log_info "Устанавливаю rustscan (cargo)..."
    if cargo install rustscan &>/dev/null 2>&1; then
        # cargo bin
        local_bin="${HOME}/.cargo/bin/rustscan"
        [[ -f "$local_bin" ]] && cp "$local_bin" /usr/local/bin/ 2>/dev/null || true
        log_ok "rustscan (cargo)"
    else
        # Fallback: бинарь с GitHub Releases
        log_info "Скачиваю rustscan binary..."
        RS_VER="2.3.0"
        RS_URL="https://github.com/RustScan/RustScan/releases/download/${RS_VER}/rustscan_${RS_VER}_amd64.deb"
        if wget -q "$RS_URL" -O /tmp/rustscan.deb && dpkg -i /tmp/rustscan.deb &>/dev/null; then
            log_ok "rustscan (deb)"
        else
            log_error "rustscan" "не удалось установить"
        fi
    fi
fi

# naabu
if is_installed "naabu"; then
    log_skip "naabu"
elif apt-get install -y naabu &>/dev/null 2>&1; then
    log_ok "naabu (apt)"
else
    install_go_tool "naabu" "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
fi

# ── Веб-сканирование ──────────────────────────────────────────────────────────

log_section "Веб-сканирование"

install_if_missing "nikto"  "nikto"
install_if_missing "wpscan" "wpscan"
install_if_missing "dirb"   "dirb"
install_if_missing "ffuf"   "ffuf"

# feroxbuster — предпочитаем apt (Kali)
if is_installed "feroxbuster"; then
    log_skip "feroxbuster"
elif apt-get install -y feroxbuster &>/dev/null 2>&1; then
    log_ok "feroxbuster (apt)"
else
    log_info "Скачиваю feroxbuster binary..."
    FB_VER="2.11.0"
    FB_URL="https://github.com/epi052/feroxbuster/releases/download/v${FB_VER}/x86_64-linux-feroxbuster.zip"
    if wget -q "$FB_URL" -O /tmp/feroxbuster.zip; then
        unzip -q /tmp/feroxbuster.zip -d /tmp/ferox_extract/ 2>/dev/null || true
        [[ -f /tmp/ferox_extract/feroxbuster ]] && \
            install -m 755 /tmp/ferox_extract/feroxbuster /usr/local/bin/feroxbuster
        is_installed "feroxbuster" && log_ok "feroxbuster (binary)" || \
            log_error "feroxbuster" "установка не удалась"
    else
        log_error "feroxbuster" "скачивание не удалось"
    fi
fi

# httpx (ProjectDiscovery)
if is_installed "httpx"; then
    log_skip "httpx"
elif apt-get install -y httpx &>/dev/null 2>&1; then
    log_ok "httpx (apt)"
else
    install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx@latest"
fi

# ── Уязвимости ────────────────────────────────────────────────────────────────

log_section "Сканирование уязвимостей"

install_if_missing "sqlmap" "sqlmap"
install_if_missing "testssl" "testssl.sh"

# dalfox — предпочитаем apt (Kali), иначе Go
if is_installed "dalfox"; then
    log_skip "dalfox"
elif apt-get install -y dalfox &>/dev/null 2>&1; then
    log_ok "dalfox (apt)"
else
    install_go_tool "dalfox" "github.com/hahwul/dalfox/v2@latest"
fi

# xsstrike (fallback XSS)
if is_installed "xsstrike"; then
    log_skip "xsstrike"
elif [[ -d /opt/xsstrike ]]; then
    ln -sf /opt/xsstrike/xsstrike.py /usr/local/bin/xsstrike 2>/dev/null || true
    log_skip "xsstrike (уже в /opt)"
else
    log_info "Устанавливаю xsstrike..."
    if git clone -q https://github.com/s0md3v/XSStrike /opt/xsstrike 2>/dev/null; then
        pip3 install -r /opt/xsstrike/requirements.txt &>/dev/null 2>&1 || true
        echo '#!/usr/bin/env bash' > /usr/local/bin/xsstrike
        echo 'python3 /opt/xsstrike/xsstrike.py "$@"' >> /usr/local/bin/xsstrike
        chmod +x /usr/local/bin/xsstrike
        log_ok "xsstrike"
    else
        log_error "xsstrike" "git clone не удался"
    fi
fi

# ── Разведка / OSINT ──────────────────────────────────────────────────────────

log_section "Разведка и OSINT"

# subfinder
if is_installed "subfinder"; then
    log_skip "subfinder"
elif apt-get install -y subfinder &>/dev/null 2>&1; then
    log_ok "subfinder (apt)"
else
    install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
fi

# dnsx
if is_installed "dnsx"; then
    log_skip "dnsx"
elif apt-get install -y dnsx &>/dev/null 2>&1; then
    log_ok "dnsx (apt)"
else
    install_go_tool "dnsx" "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
fi

# gau
if is_installed "gau"; then
    log_skip "gau"
elif apt-get install -y gau &>/dev/null 2>&1; then
    log_ok "gau (apt)"
else
    install_go_tool "gau" "github.com/lc/gau/v2/cmd/gau@latest"
fi

# theHarvester
if is_installed "theHarvester"; then
    log_skip "theHarvester"
elif apt-get install -y theharvester &>/dev/null 2>&1; then
    log_ok "theHarvester (apt)"
else
    log_info "Устанавливаю theHarvester из pip..."
    if pip3 install theharvester &>/dev/null 2>&1; then
        log_ok "theHarvester (pip)"
    else
        log_error "theHarvester" "установка не удалась"
    fi
fi

# ── Поиск секретов ────────────────────────────────────────────────────────────

log_section "Поиск секретов"

# trufflehog
if is_installed "trufflehog"; then
    log_skip "trufflehog"
else
    log_info "Скачиваю trufflehog binary..."
    TH_URL="https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_linux_amd64.tar.gz"
    if wget -q "$TH_URL" -O /tmp/trufflehog.tar.gz 2>/dev/null; then
        tar -xzf /tmp/trufflehog.tar.gz -C /tmp/ trufflehog 2>/dev/null || true
        [[ -f /tmp/trufflehog ]] && install -m 755 /tmp/trufflehog /usr/local/bin/trufflehog
        is_installed "trufflehog" && log_ok "trufflehog" || log_error "trufflehog" "установка не удалась"
    else
        log_error "trufflehog" "скачивание не удалось"
    fi
fi

# gitleaks (дополнение к trufflehog)
if is_installed "gitleaks"; then
    log_skip "gitleaks"
elif apt-get install -y gitleaks &>/dev/null 2>&1; then
    log_ok "gitleaks (apt)"
else
    log_info "Скачиваю gitleaks binary..."
    GL_URL="https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz"
    if wget -q "$GL_URL" -O /tmp/gitleaks.tar.gz 2>/dev/null; then
        tar -xzf /tmp/gitleaks.tar.gz -C /tmp/ gitleaks 2>/dev/null || true
        [[ -f /tmp/gitleaks ]] && install -m 755 /tmp/gitleaks /usr/local/bin/gitleaks
        is_installed "gitleaks" && log_ok "gitleaks" || log_warn "gitleaks не установлен (опционально)"
    else
        log_warn "gitleaks скачивание не удалось (опционально)"
    fi
fi

# ── Параметры и эксплойты ─────────────────────────────────────────────────────

log_section "Параметры и эксплойты"

# arjun (pip)
install_pip_tool "arjun" "arjun"

# searchsploit
install_if_missing "searchsploit" "exploitdb"

# ── SecLists (wordlists) ──────────────────────────────────────────────────────

log_section "Словари (SecLists)"
if [[ -d /usr/share/seclists ]]; then
    log_skip "SecLists (уже установлены)"
elif apt-get install -y seclists &>/dev/null 2>&1; then
    log_ok "SecLists (apt)"
else
    log_warn "SecLists не установлены — feroxbuster/ffuf будут использовать dirb wordlist"
    log_info "Установить вручную: sudo apt install seclists"
fi

# ── Python-пакеты проекта ─────────────────────────────────────────────────────

log_section "Python-зависимости M.A.R.S."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -f "$SCRIPT_DIR/requirements.txt" ]]; then
    log_info "pip install -r requirements.txt..."
    if pip3 install -r "$SCRIPT_DIR/requirements.txt" &>/dev/null 2>&1; then
        log_ok "Python-зависимости"
    else
        log_error "python-deps" "pip install -r requirements.txt завершился ошибкой"
    fi
else
    log_warn "requirements.txt не найден в $SCRIPT_DIR"
fi

# ── .env ──────────────────────────────────────────────────────────────────────

log_section "Конфигурация"
if [[ ! -f "$SCRIPT_DIR/.env" ]]; then
    if [[ -f "$SCRIPT_DIR/.env.example" ]]; then
        cp "$SCRIPT_DIR/.env.example" "$SCRIPT_DIR/.env"
        log_ok ".env создан из .env.example — заполните API ключи"
    else
        log_warn ".env.example не найден — создайте .env вручную"
    fi
else
    log_skip ".env (уже существует)"
fi

# ── Директории логов и кэша ────────────────────────────────────────────────────

mkdir -p logs/cache/nvd logs/cache/epss reports
log_ok "Директории logs/cache и reports созданы"

# ════════════════════════════════════════════════════════════════════════════════
# ── VERIFICATION CHECK ────────────────────────────────────────────────────────
# ════════════════════════════════════════════════════════════════════════════════

echo ""
echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║           POST-INSTALL VERIFICATION CHECK                ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""

# Группы для отображения
declare -A TOOL_GROUPS
TOOL_GROUPS["🔴 Ядро (обязательные)"]="nmap whatweb nuclei wkhtmltopdf python3 pip3"
TOOL_GROUPS["⚡ Порт-сканирование"]="rustscan naabu"
TOOL_GROUPS["🔬 Веб-сканирование"]="nikto ffuf feroxbuster dirb wpscan httpx"
TOOL_GROUPS["🐛 Уязвимости"]="sqlmap testssl dalfox xsstrike"
TOOL_GROUPS["🌐 Разведка / OSINT"]="subfinder dnsx gau theHarvester"
TOOL_GROUPS["🔑 Секреты"]="trufflehog gitleaks"
TOOL_GROUPS["🔍 Параметры и эксплойты"]="arjun searchsploit"

CHECK_OK=0
CHECK_FAIL=0
CHECK_WARN=0

for group in "🔴 Ядро (обязательные)" "⚡ Порт-сканирование" "🔬 Веб-сканирование" \
             "🐛 Уязвимости" "🌐 Разведка / OSINT" "🔑 Секреты" "🔍 Параметры и эксплойты"; do
    echo -e "  ${BOLD}${group}${NC}"
    for tool in ${TOOL_GROUPS[$group]}; do
        if command -v "$tool" &>/dev/null; then
            version=$(command "$tool" --version 2>/dev/null | head -1 | tr -d '\n' || echo "ok")
            printf "    ${GREEN}✓${NC} %-20s ${CYAN}%s${NC}\n" "$tool" "${version:0:40}"
            ((CHECK_OK++)) || true
        else
            if [[ "$group" == "🔴 Ядро (обязательные)" ]]; then
                printf "    ${RED}✗${NC} %-20s ${RED}НЕ УСТАНОВЛЕН — КРИТИЧНО${NC}\n" "$tool"
                ((CHECK_FAIL++)) || true
            else
                printf "    ${YELLOW}?${NC} %-20s ${YELLOW}не найден (опционально)${NC}\n" "$tool"
                ((CHECK_WARN++)) || true
            fi
        fi
    done
    echo ""
done

# Python-пакеты
echo -e "  ${BOLD}🐍 Python-пакеты${NC}"
for pkg in streamlit crewai anthropic litellm shodan httpx pandas; do
    if python3 -c "import $pkg" &>/dev/null 2>&1; then
        ver=$(python3 -c "import $pkg; print(getattr($pkg, '__version__', 'ok'))" 2>/dev/null || echo "ok")
        printf "    ${GREEN}✓${NC} %-20s ${CYAN}%s${NC}\n" "$pkg" "$ver"
        ((CHECK_OK++)) || true
    else
        printf "    ${RED}✗${NC} %-20s ${RED}не установлен${NC}\n" "$pkg"
        ((CHECK_FAIL++)) || true
    fi
done
echo ""

# ── Итоговый отчёт ────────────────────────────────────────────────────────────

echo -e "${BOLD}${BLUE}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${BLUE}║                    ИТОГ УСТАНОВКИ                       ║${NC}"
echo -e "${BOLD}${BLUE}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${GREEN}✓ Успешно установлено:${NC}  ${BOLD}${INSTALLED}${NC}"
echo -e "  ${CYAN}~ Уже было:${NC}            ${BOLD}${SKIPPED}${NC}"
echo -e "  ${RED}✗ Ошибки:${NC}              ${BOLD}${FAILED}${NC}"
echo ""
echo -e "  ${GREEN}✓ Проверка OK:${NC}         ${BOLD}${CHECK_OK}${NC}"
echo -e "  ${YELLOW}? Опциональные:${NC}        ${BOLD}${CHECK_WARN}${NC}"
echo -e "  ${RED}✗ Критические:${NC}         ${BOLD}${CHECK_FAIL}${NC}"

if [[ ${#FAILED_TOOLS[@]} -gt 0 ]]; then
    echo ""
    echo -e "  ${RED}Не установлены:${NC} ${FAILED_TOOLS[*]}"
fi

echo ""
if [[ $CHECK_FAIL -eq 0 ]]; then
    echo -e "${BOLD}${GREEN}  ✅ Все обязательные инструменты установлены!${NC}"
    echo -e "${BOLD}${GREEN}  Запуск: streamlit run app.py${NC}"
else
    echo -e "${BOLD}${RED}  ❌ Критические инструменты отсутствуют!${NC}"
    echo -e "${BOLD}${YELLOW}  Запустите: sudo apt install nmap nuclei whatweb wkhtmltopdf${NC}"
fi

if [[ $CHECK_WARN -gt 0 ]]; then
    echo ""
    echo -e "${YELLOW}  Опциональные инструменты отсутствуют — часть функций недоступна.${NC}"
    echo -e "${YELLOW}  Платформа работает, но полный профиль будет ограничен.${NC}"
fi

echo ""
echo -e "${CYAN}  Следующий шаг: заполните API ключи в файле .env${NC}"
echo -e "${CYAN}  cat .env.example  # пример конфигурации${NC}"
echo ""
