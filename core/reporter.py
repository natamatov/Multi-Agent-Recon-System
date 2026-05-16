"""
Генерация адаптивного HTML-отчёта по финальному JSON аудита.
"""

from __future__ import annotations

import html
from datetime import datetime
from pathlib import Path
from typing import Any


def _severity_class(severity: str, cvss: float | None = None) -> str:
    """CSS-класс по severity или CVSS score."""
    sev = (severity or "").lower()
    if cvss is not None:
        if cvss >= 9.0:
            return "critical"
        if cvss >= 7.0:
            return "high"
        if cvss >= 4.0:
            return "medium"
        if cvss >= 0.1:
            return "low"
    mapping = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "low": "low",
        "info": "info",
    }
    return mapping.get(sev, "info")


def _esc(value: Any) -> str:
    return html.escape(str(value)) if value is not None else ""


def _render_cve_rows(cves: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for cve in cves:
        sev = cve.get("severity", "unknown")
        cvss = cve.get("cvss_score")
        css = _severity_class(sev, cvss if isinstance(cvss, (int, float)) else None)
        rows.append(
            f"<tr class='{css}'>"
            f"<td><span class='badge {css}'>{_esc(cve.get('id', 'N/A'))}</span></td>"
            f"<td>{_esc(cvss if cvss is not None else '—')}</td>"
            f"<td><span class='badge {css}'>{_esc(sev)}</span></td>"
            f"<td>{_esc(cve.get('affected_component', cve.get('component', '—')))}</td>"
            f"<td>{_esc(cve.get('description', ''))}</td>"
            f"<td>{'✓ NVD' if cve.get('nvd_verified') or cve.get('verified') else '—'}</td>"
            f"</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='6'>CVE не обнаружены</td></tr>"


def _render_tech_rows(technologies: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for tech in technologies:
        rows.append(
            "<tr>"
            f"<td>{_esc(tech.get('name', ''))}</td>"
            f"<td>{_esc(tech.get('version', '—'))}</td>"
            f"<td>{_esc(tech.get('evidence', ''))}</td>"
            "</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='3'>—</td></tr>"


def _render_nuclei_rows(findings: list[dict[str, Any]]) -> str:
    rows: list[str] = []
    for item in findings:
        css = _severity_class(item.get("severity", "info"))
        rows.append(
            f"<tr class='{css}'>"
            f"<td><span class='badge {css}'>{_esc(item.get('severity', ''))}</span></td>"
            f"<td>{_esc(item.get('name', item.get('template_id', '')))}</td>"
            f"<td>{_esc(item.get('matched_at', ''))}</td>"
            f"<td>{_esc(', '.join(item.get('cve_ids', [])))}</td>"
            "</tr>"
        )
    return "\n".join(rows) if rows else "<tr><td colspan='4'>Находок Nuclei нет</td></tr>"
    
    
def _render_waf_info(waf: dict[str, Any] | None) -> str:
    if not waf or not waf.get("detected"):
        return "<p>Защита WAF/CDN не обнаружена.</p>"
    
    providers = ", ".join(waf.get("providers", []))
    hints = waf.get("hints", [])
    headers = waf.get("relevant_headers", {})
    
    html_output = [
        f"<p><strong>Обнаруженная защита:</strong> <span class='badge high'>{_esc(providers)}</span></p>",
        "<h4>Рекомендации по обходу (Bypass Hints):</h4>",
        "<ul>"
    ]
    for hint in hints:
        html_output.append(f"<li>{_esc(hint)}</li>")
    html_output.append("</ul>")
    
    if headers:
        html_output.append("<h4>Заголовки детекции:</h4><ul>")
        for k, v in headers.items():
            html_output.append(f"<li><code>{_esc(k)}:</code> {_esc(v)}</li>")
        html_output.append("</ul>")
        
    return "".join(html_output)


def _render_dev_instructions(instructions: list[Any]) -> str:
    if not instructions:
        return "<p>Рекомендации будут сформированы после AI-анализа.</p>"
    items = []
    for idx, instr in enumerate(instructions, 1):
        if isinstance(instr, dict):
            title = instr.get("title", f"Шаг {idx}")
            body = instr.get("action", instr.get("description", ""))
            priority = instr.get("priority", "")
            items.append(
                f"<li><strong>{_esc(title)}</strong>"
                f"{f' <span class=\"badge medium\">{_esc(priority)}</span>' if priority else ''}"
                f"<p>{_esc(body)}</p></li>"
            )
        else:
            items.append(f"<li>{_esc(instr)}</li>")
    return f"<ol class='dev-steps'>{''.join(items)}</ol>"


def generate_html_report(report: dict[str, Any]) -> str:
    """
    Строит полную HTML-страницу отчёта с встроенными CSS.

    :param report: финальный dict (audit_report.json).
    :return: строка HTML.
    """
    audit = report.get("audit", {})
    target = audit.get("target", "unknown")
    timestamp = audit.get("timestamp_utc", datetime.utcnow().isoformat())
    summary = report.get("ai_summary", report.get("summary", ""))
    technologies = report.get("technologies", [])
    cves = report.get("cves", [])
    nuclei = report.get("nuclei_findings", [])
    waf = report.get("waf")
    exploit_data = report.get("exploit_data", "")
    dev_instructions = report.get("developer_instructions", [])
    nvd_count = sum(1 for c in cves if c.get("nvd_verified") or c.get("verified"))

    return f"""<!DOCTYPE html>
<html lang="ru">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Security Audit — {_esc(target)}</title>
  <style>
    :root {{
      --bg: #0f1419;
      --card: #1a2332;
      --text: #e6edf3;
      --muted: #8b949e;
      --border: #30363d;
      --critical: #ff6b6b;
      --high: #ff922b;
      --medium: #fcc419;
      --low: #51cf66;
      --info: #74c0fc;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      font-family: 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 1.5rem;
    }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{
      background: linear-gradient(135deg, #1a2332 0%, #243044 100%);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 2rem;
      margin-bottom: 1.5rem;
    }}
    h1 {{ font-size: 1.75rem; margin-bottom: 0.5rem; }}
    .meta {{ color: var(--muted); font-size: 0.9rem; }}
    .stats {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 1rem;
      margin: 1.5rem 0;
    }}
    .stat {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      text-align: center;
    }}
    .stat .num {{ font-size: 2rem; font-weight: 700; }}
    section {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 1.5rem;
      margin-bottom: 1.5rem;
    }}
    h2 {{
      font-size: 1.25rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 1px solid var(--border);
    }}
    .summary {{ color: var(--muted); }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.9rem;
    }}
    th, td {{
      padding: 0.75rem;
      text-align: left;
      border-bottom: 1px solid var(--border);
    }}
    th {{ color: var(--muted); font-weight: 600; }}
    tr:hover {{ background: rgba(255,255,255,0.03); }}
    tr.critical {{ border-left: 4px solid var(--critical); }}
    tr.high {{ border-left: 4px solid var(--high); }}
    tr.medium {{ border-left: 4px solid var(--medium); }}
    tr.low {{ border-left: 4px solid var(--low); }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.6rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }}
    .badge.critical {{ background: var(--critical); color: #1a1a1a; }}
    .badge.high {{ background: var(--high); color: #1a1a1a; }}
    .badge.medium {{ background: var(--medium); color: #1a1a1a; }}
    .badge.low {{ background: var(--low); color: #1a1a1a; }}
    .badge.info {{ background: var(--info); color: #1a1a1a; }}
    .dev-steps {{ padding-left: 1.5rem; }}
    .dev-steps li {{ margin-bottom: 1rem; }}
    .dev-steps p {{ color: var(--muted); margin-top: 0.25rem; }}
    @media (max-width: 768px) {{
      table {{ display: block; overflow-x: auto; }}
      th, td {{ min-width: 120px; }}
    }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Отчёт аудита безопасности</h1>
      <p class="meta">Цель: <strong>{_esc(target)}</strong> · {_esc(timestamp)} UTC</p>
      <div class="stats">
        <div class="stat"><div class="num">{len(technologies)}</div>Технологий</div>
        <div class="stat"><div class="num">{len(cves)}</div>CVE</div>
        <div class="stat"><div class="num">{nvd_count}</div>NVD verified</div>
        <div class="stat"><div class="num">{len(nuclei)}</div>Nuclei</div>
      </div>
    </header>

    <section>
      <h2>Резюме</h2>
      <p class="summary">{_esc(summary)}</p>
    </section>

    <section>
      <h2>CVE (CVSS / критичность)</h2>
      <table>
        <thead>
          <tr>
            <th>CVE ID</th><th>CVSS</th><th>Severity</th>
            <th>Компонент</th><th>Описание</th><th>NVD</th>
          </tr>
        </thead>
        <tbody>{_render_cve_rows(cves)}</tbody>
      </table>
    </section>

    <section>
      <h2>Технологии</h2>
      <table>
        <thead><tr><th>Продукт</th><th>Версия</th><th>Доказательство</th></tr></thead>
        <tbody>{_render_tech_rows(technologies)}</tbody>
      </table>
    </section>

    <section>
      <h2>Nuclei — активные находки</h2>
      <table>
        <thead>
          <tr><th>Severity</th><th>Шаблон</th><th>URL</th><th>CVE</th></tr>
        </thead>
        <tbody>{_render_nuclei_rows(nuclei)}</tbody>
      </table>
    </section>

    <section>
      <h2>WAF / CDN Protection</h2>
      {_render_waf_info(waf)}
    </section>

    <section>
      <h2>Exploit Verification (PoC)</h2>
      <div style="background: #fdf2f2; padding: 15px; border-left: 5px solid #e02424; border-radius: 4px;">
        {exploit_data if exploit_data else "<p>Эксплойты не верифицированы.</p>"}
      </div>
    </section>

    <section>
      <h2>Инструкция для разработчиков</h2>
      {_render_dev_instructions(dev_instructions)}
    </section>
  </div>
</body>
</html>"""


def save_html_report(report: dict[str, Any], path: str = "audit_report.html") -> Path:
    """Записывает HTML-отчёт на диск."""
    content = generate_html_report(report)
    out = Path(path)
    out.write_text(content, encoding="utf-8")
    print(f"[OK] HTML-отчёт: {out}")
    return out

def save_pdf_report(report: dict[str, Any], path: str = "audit_report.pdf") -> Path:
    """Конвертирует HTML-отчет в PDF и сохраняет на диск."""
    import pdfkit
    
    html_content = generate_html_report(report)
    
    options = {
        'page-size': 'A4',
        'margin-top': '0.75in',
        'margin-right': '0.75in',
        'margin-bottom': '0.75in',
        'margin-left': '0.75in',
        'encoding': "UTF-8",
        'no-outline': None
    }
    
    out = Path(path)
    try:
        pdfkit.from_string(html_content, str(out), options=options)
        print(f"[OK] PDF-отчёт: {out}")
    except Exception as e:
        print(f"[ERROR] Не удалось создать PDF (убедитесь, что wkhtmltopdf установлен): {e}")
    
    return out
