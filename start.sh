#!/usr/bin/env bash
# ============================================================
#  M.A.R.S. — скрипт запуска
#  Использование:
#    ./start.sh          — запускает Streamlit UI (по умолчанию)
#    ./start.sh ui       — то же самое
#    ./start.sh cli      — CLI режим (без UI)
#    ./start.sh cli --profile light  — CLI лёгкий профиль
# ============================================================

set -euo pipefail

# ── Цвета ───────────────────────────────────────────────────
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
NC='\033[0m'

MARS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="$MARS_DIR/.env"
PORT="${MARS_PORT:-8501}"
MODE="${1:-ui}"

echo -e "${BLU}"
echo "  ███╗   ███╗ █████╗ ██████╗ ███████╗"
echo "  ████╗ ████║██╔══██╗██╔══██╗██╔════╝"
echo "  ██╔████╔██║███████║██████╔╝███████╗"
echo "  ██║╚██╔╝██║██╔══██║██╔══██╗╚════██║"
echo "  ██║ ╚═╝ ██║██║  ██║██║  ██║███████║"
echo "  ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝"
echo -e "${NC}"
echo -e "${GRN}  Multi-Agent Recon System${NC}"
echo "  ──────────────────────────────────────"

# ── 1. Проверяем .env ────────────────────────────────────────
if [[ ! -f "$ENV_FILE" ]]; then
    echo -e "${YLW}[!] Файл .env не найден. Создаём из .env.example...${NC}"
    if [[ -f "$MARS_DIR/.env.example" ]]; then
        cp "$MARS_DIR/.env.example" "$ENV_FILE"
        echo -e "${YLW}[!] Откройте .env и заполните LLM_PROVIDER, LLM_MODEL и ключи API${NC}"
    else
        echo -e "${RED}[✗] .env.example тоже не найден. Создайте .env вручную.${NC}"
        exit 1
    fi
fi

# ── 2. Загружаем переменные окружения ───────────────────────
set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

LLM_PROVIDER="${LLM_PROVIDER:-anthropic}"
LLM_MODEL="${LLM_MODEL:-claude-3-5-sonnet-20241022}"

echo -e "  LLM провайдер : ${GRN}${LLM_PROVIDER}${NC}"
echo -e "  LLM модель    : ${GRN}${LLM_MODEL}${NC}"
echo ""

# ── 3. Проверяем Python ──────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[✗] python3 не найден. Установите Python 3.10+${NC}"
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "  Python        : ${GRN}${PY_VER}${NC}"

# ── 4. Проверяем виртуальное окружение (если есть) ──────────
VENV_DIRS=("$MARS_DIR/venv" "$MARS_DIR/.venv" "$MARS_DIR/env")
for vd in "${VENV_DIRS[@]}"; do
    if [[ -f "$vd/bin/activate" ]]; then
        echo -e "  venv          : ${GRN}${vd}${NC}"
        # shellcheck disable=SC1090
        source "$vd/bin/activate"
        break
    fi
done

# ── 5. Проверяем зависимости Python ─────────────────────────
if ! python3 -c "import streamlit" &>/dev/null; then
    echo -e "${YLW}[!] Зависимости не установлены. Запускаем pip install...${NC}"
    pip install -r "$MARS_DIR/requirements.txt" --quiet
fi

# ── 6. Ollama: запускаем если не запущен ────────────────────
if [[ "$LLM_PROVIDER" == "ollama" ]]; then
    if ! curl -sf http://localhost:11434/api/tags &>/dev/null; then
        echo -e "${YLW}[!] Ollama не запущен — запускаем в фоне...${NC}"
        ollama serve &>/tmp/ollama_mars.log &
        OLLAMA_PID=$!
        sleep 2
        if curl -sf http://localhost:11434/api/tags &>/dev/null; then
            echo -e "  Ollama        : ${GRN}запущен (PID $OLLAMA_PID)${NC}"
        else
            echo -e "${RED}[✗] Ollama не запустился. Проверьте: ollama serve${NC}"
        fi
    else
        echo -e "  Ollama        : ${GRN}уже запущен ✓${NC}"
        # Проверяем что нужная модель есть
        if ! ollama list 2>/dev/null | grep -q "$LLM_MODEL"; then
            echo -e "${YLW}[!] Модель ${LLM_MODEL} не найдена. Скачиваем...${NC}"
            ollama pull "$LLM_MODEL"
        fi
    fi
fi

echo ""
echo "  ──────────────────────────────────────"

# ── 7. Запуск ────────────────────────────────────────────────
shift || true  # убираем первый аргумент (ui/cli)

case "$MODE" in
    ui|"")
        echo -e "  ${GRN}Запуск Streamlit UI → http://localhost:${PORT}${NC}"
        echo "  ──────────────────────────────────────"
        echo ""
        exec streamlit run "$MARS_DIR/app.py" \
            --server.port "$PORT" \
            --server.address "0.0.0.0" \
            --server.headless true \
            --browser.gatherUsageStats false \
            "$@"
        ;;
    cli)
        echo -e "  ${GRN}Запуск CLI режима${NC}"
        echo "  ──────────────────────────────────────"
        echo ""
        exec python3 "$MARS_DIR/main.py" "$@"
        ;;
    *)
        echo -e "${RED}[✗] Неизвестный режим: $MODE${NC}"
        echo "  Использование: ./start.sh [ui|cli] [--profile light|full]"
        exit 1
        ;;
esac
