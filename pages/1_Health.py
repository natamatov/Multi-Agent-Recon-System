"""
M.A.R.S. — страница Health Check.
Показывает статус всех компонентов системы.
"""

from __future__ import annotations

from datetime import datetime

import streamlit as st

from core.dependency_manager import check_tools, missing_tools
from core.healthcheck import run_healthcheck

st.set_page_config(
    page_title="M.A.R.S. — Health",
    page_icon="🩺",
    layout="wide",
)

st.markdown("# 🩺 System Health")
st.caption(f"Проверка выполнена: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

with st.spinner("Проверяем компоненты..."):
    health   = run_healthcheck()
    tool_st  = check_tools()
    missing  = missing_tools(tool_st)

# ── Overall status ────────────────────────────────────────────────────────────
overall_ok = not missing and health.get("status") != "error"
if overall_ok:
    st.success("✅ Все компоненты в порядке")
else:
    st.error(f"❌ Есть проблемы: {len(missing)} инструмент(ов) отсутствует")

st.divider()

# ── Tools grid ────────────────────────────────────────────────────────────────
st.markdown("### 🔧 Инструменты")
n_cols   = 5
all_tools = list(tool_st.items())

for row_start in range(0, len(all_tools), n_cols):
    row  = all_tools[row_start : row_start + n_cols]
    cols = st.columns(n_cols)
    for i, (tool_name, available) in enumerate(row):
        icon  = "✅" if available else "❌"
        color = "#22c55e" if available else "#ef4444"
        cols[i].markdown(
            f'<div style="text-align:center; padding:10px; '
            f'background:#1e293b; border-radius:8px; '
            f'border:1px solid {"#16a34a" if available else "#dc2626"}44;">'
            f'<div style="font-size:20px">{icon}</div>'
            f'<div style="font-size:12px; color:{color}; margin-top:4px;">'
            f'<code>{tool_name}</code></div>'
            f'</div>',
            unsafe_allow_html=True,
        )

if missing:
    st.markdown("")
    st.warning(f"**Отсутствующие инструменты:** {', '.join(missing)}")
    from core.dependency_manager import _APT_PACKAGES
    apt_pkgs = " ".join(_APT_PACKAGES.get(t, t) for t in missing)
    st.code(f"sudo apt update && sudo apt install -y {apt_pkgs}", language="bash")

st.divider()

# ── Health check details ──────────────────────────────────────────────────────
st.markdown("### 📋 Детали компонентов")

sections = {
    "python":     ("🐍 Python",    health.get("python",     {})),
    "llm":        ("🤖 LLM",       health.get("llm",        {})),
    "filesystem": ("💾 Файловая система", health.get("filesystem", {})),
    "apis":       ("🌐 Внешние API",health.get("apis",       {})),
}

cols_h = st.columns(len(sections))
for i, (key, (label, data)) in enumerate(sections.items()):
    with cols_h[i]:
        if isinstance(data, dict):
            ok_count  = sum(1 for v in data.values() if v is True or v == "ok")
            all_count = len(data)
            section_ok = ok_count == all_count
            icon = "✅" if section_ok else "⚠️"
            st.markdown(
                f'<div style="padding:12px; background:#1e293b; border-radius:8px; '
                f'border:1px solid {"#16a34a" if section_ok else "#d97706"}44; margin-bottom:8px">'
                f'<b>{icon} {label}</b><br>'
                f'<small style="color:#94a3b8">{ok_count}/{all_count} OK</small>'
                f'</div>',
                unsafe_allow_html=True,
            )
            with st.expander("Подробнее"):
                for k, v in data.items():
                    is_ok = v is True or v == "ok" or (isinstance(v, str) and "error" not in v.lower())
                    st.markdown(f"{'✅' if is_ok else '❌'} **{k}**: `{v}`")
        else:
            st.markdown(f"**{label}:** `{data}`")

st.divider()

# ── Raw JSON ──────────────────────────────────────────────────────────────────
with st.expander("🔍 Raw JSON"):
    st.json(health)

if st.button("🔄 Обновить"):
    st.rerun()
