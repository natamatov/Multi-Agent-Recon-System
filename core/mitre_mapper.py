"""
MITRE ATT&CK auto-mapper для M.A.R.S.

Сопоставляет найденные уязвимости, CVE и паттерны атак с техниками ATT&CK.
Работает офлайн — использует встроенную карту без внешних API.

Документация: https://attack.mitre.org/
"""

from __future__ import annotations

from typing import Any

# ── Маппинг паттернов → ATT&CK техники ───────────────────────────────────────
# Ключ: паттерн (lowercase) → список техник
# Паттерны проверяются как подстрока в (name + description + severity + tool)

_PATTERN_MAP: list[tuple[str, dict[str, str]]] = [
    # Эксплуатация приложений
    ("sql injection",      {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("sqli",               {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("remote code exec",   {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("rce",                {"id": "T1190", "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("command injection",  {"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"}),
    ("os command",         {"id": "T1059",  "name": "Command and Scripting Interpreter", "tactic": "Execution"}),

    # Веб-атаки
    ("cross-site scripting", {"id": "T1059.007", "name": "JavaScript (XSS)", "tactic": "Execution"}),
    ("xss",                  {"id": "T1059.007", "name": "JavaScript (XSS)", "tactic": "Execution"}),
    ("csrf",                 {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"}),
    ("clickjacking",         {"id": "T1185", "name": "Browser Session Hijacking", "tactic": "Collection"}),
    ("open redirect",        {"id": "T1550.001", "name": "Use Alternate Authentication Material", "tactic": "Defense Evasion"}),
    ("path traversal",       {"id": "T1083",   "name": "File and Directory Discovery", "tactic": "Discovery"}),
    ("directory traversal",  {"id": "T1083",   "name": "File and Directory Discovery", "tactic": "Discovery"}),
    ("lfi",                  {"id": "T1083",   "name": "File and Directory Discovery", "tactic": "Discovery"}),
    ("rfi",                  {"id": "T1190",   "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("ssrf",                 {"id": "T1090.001", "name": "Internal Proxy (SSRF)", "tactic": "Command and Control"}),
    ("xxe",                  {"id": "T1190",   "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("deserialization",      {"id": "T1190",   "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),

    # Аутентификация / авторизация
    ("default password",     {"id": "T1078",   "name": "Valid Accounts", "tactic": "Defense Evasion"}),
    ("default credentials",  {"id": "T1078",   "name": "Valid Accounts", "tactic": "Defense Evasion"}),
    ("brute force",          {"id": "T1110",   "name": "Brute Force", "tactic": "Credential Access"}),
    ("password spray",       {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"}),
    ("credential stuffing",  {"id": "T1110.004", "name": "Credential Stuffing", "tactic": "Credential Access"}),
    ("weak password",        {"id": "T1110",   "name": "Brute Force", "tactic": "Credential Access"}),
    ("privilege escalation", {"id": "T1068",   "name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation"}),
    ("idor",                 {"id": "T1565.001", "name": "Stored Data Manipulation", "tactic": "Impact"}),
    ("broken access",        {"id": "T1548",   "name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"}),

    # Сеть / TLS
    ("ssl",                  {"id": "T1040",   "name": "Network Sniffing (TLS downgrade)", "tactic": "Credential Access"}),
    ("tls",                  {"id": "T1040",   "name": "Network Sniffing (TLS downgrade)", "tactic": "Credential Access"}),
    ("heartbleed",           {"id": "T1040",   "name": "Network Sniffing (Heartbleed)", "tactic": "Credential Access"}),
    ("poodle",               {"id": "T1040",   "name": "Network Sniffing (POODLE)", "tactic": "Credential Access"}),
    ("beast",                {"id": "T1040",   "name": "Network Sniffing (BEAST)", "tactic": "Credential Access"}),
    ("mitm",                 {"id": "T1040",   "name": "Network Sniffing", "tactic": "Credential Access"}),
    ("dns zone transfer",    {"id": "T1590.002", "name": "DNS (Zone Transfer)", "tactic": "Reconnaissance"}),
    ("zone transfer",        {"id": "T1590.002", "name": "DNS (Zone Transfer)", "tactic": "Reconnaissance"}),

    # Разведка / утечки
    ("information disclosure", {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}),
    ("directory listing",      {"id": "T1592", "name": "Gather Victim Host Information", "tactic": "Reconnaissance"}),
    ("exposed secrets",        {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"}),
    ("api key",                {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"}),
    ("hardcoded",              {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"}),
    ("leaked",                 {"id": "T1552.001", "name": "Credentials In Files", "tactic": "Credential Access"}),
    ("sensitive data",         {"id": "T1530",   "name": "Data from Cloud Storage", "tactic": "Collection"}),

    # Конфигурация
    ("misconfiguration",     {"id": "T1562",   "name": "Impair Defenses", "tactic": "Defense Evasion"}),
    ("security header",      {"id": "T1562.001", "name": "Disable or Modify Tools", "tactic": "Defense Evasion"}),
    ("cors",                 {"id": "T1562",   "name": "Impair Defenses (CORS)", "tactic": "Defense Evasion"}),
    ("outdated",             {"id": "T1190",   "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
    ("unpatched",            {"id": "T1190",   "name": "Exploit Public-Facing Application", "tactic": "Initial Access"}),
]

# ── CVE → ATT&CK mapping для наиболее известных CVE ──────────────────────────
_CVE_MAP: dict[str, dict[str, str]] = {
    "CVE-2021-44228": {"id": "T1190", "name": "Log4Shell (Log4j RCE)",     "tactic": "Initial Access"},
    "CVE-2021-26084": {"id": "T1190", "name": "Atlassian Confluence RCE",  "tactic": "Initial Access"},
    "CVE-2022-22965": {"id": "T1190", "name": "Spring4Shell RCE",          "tactic": "Initial Access"},
    "CVE-2023-44487": {"id": "T1498", "name": "HTTP/2 Rapid Reset DoS",    "tactic": "Impact"},
    "CVE-2021-40444": {"id": "T1203", "name": "Exploitation for Client Execution", "tactic": "Execution"},
    "CVE-2021-34527": {"id": "T1547.012", "name": "PrintNightmare (Print Spooler)", "tactic": "Privilege Escalation"},
    "CVE-2020-1472":  {"id": "T1557.002", "name": "ZeroLogon (Netlogon)",  "tactic": "Lateral Movement"},
    "CVE-2019-19781": {"id": "T1190", "name": "Citrix ADC/Gateway RCE",   "tactic": "Initial Access"},
    "CVE-2021-21985": {"id": "T1190", "name": "VMware vCenter RCE",        "tactic": "Initial Access"},
    "CVE-2022-30190": {"id": "T1203", "name": "Follina (MSDT) RCE",       "tactic": "Execution"},
    "CVE-2023-23397": {"id": "T1550.002", "name": "Outlook NTLM Relay",   "tactic": "Lateral Movement"},
    "CVE-2023-20198": {"id": "T1190", "name": "Cisco IOS XE Web UI RCE",  "tactic": "Initial Access"},
}


def map_finding_to_attack(finding: dict[str, Any]) -> list[dict[str, str]]:
    """
    Возвращает список ATT&CK техник для одного finding.

    Входной finding должен содержать поля:
      id (CVE-xxx), name/description/severity, tool

    Возвращает:
    [
        {"id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "url": "https://attack.mitre.org/techniques/T1190/"}
    ]
    """
    techniques: dict[str, dict[str, str]] = {}

    # 1. Прямой CVE lookup
    cve_id = str(finding.get("id", "")).upper()
    if cve_id in _CVE_MAP:
        tech = dict(_CVE_MAP[cve_id])
        tech["url"] = f"https://attack.mitre.org/techniques/{tech['id'].replace('.', '/')}/"
        techniques[tech["id"]] = tech

    # 2. Pattern matching по тексту finding
    text = " ".join([
        str(finding.get("name",        "")),
        str(finding.get("description", "")),
        str(finding.get("evidence",    "")),
        str(finding.get("id",          "")),
        str(finding.get("tool",        "")),
    ]).lower()

    for pattern, tech_data in _PATTERN_MAP:
        if pattern in text:
            tid = tech_data["id"]
            if tid not in techniques:
                tech = dict(tech_data)
                tech["url"] = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
                techniques[tid] = tech

    return list(techniques.values())


def enrich_findings_with_attack(
    findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Добавляет поле mitre_attack[] в каждый finding dict."""
    for f in findings:
        f["mitre_attack"] = map_finding_to_attack(f)
    return findings


def build_attack_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Строит сводку по тактикам ATT&CK из всех findings.

    Возвращает:
    {
        "tactics": {"Initial Access": 3, "Execution": 1, ...},
        "techniques": [{"id": "T1190", "name": "...", "tactic": "...", "count": 3}, ...],
        "kill_chain_coverage": ["Reconnaissance", "Initial Access", ...],
    }
    """
    tactic_counts: dict[str, int] = {}
    tech_counts: dict[str, dict[str, Any]] = {}

    for f in findings:
        for tech in f.get("mitre_attack", []):
            tactic = tech.get("tactic", "Unknown")
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1

            tid = tech.get("id", "")
            if tid not in tech_counts:
                tech_counts[tid] = {**tech, "count": 0}
            tech_counts[tid]["count"] += 1

    # Порядок тактик в kill chain
    _KILL_CHAIN_ORDER = [
        "Reconnaissance", "Resource Development", "Initial Access",
        "Execution", "Persistence", "Privilege Escalation",
        "Defense Evasion", "Credential Access", "Discovery",
        "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact",
    ]

    covered = [t for t in _KILL_CHAIN_ORDER if t in tactic_counts]

    return {
        "tactics":             dict(sorted(tactic_counts.items(), key=lambda x: -x[1])),
        "techniques":          sorted(tech_counts.values(), key=lambda x: -x["count"]),
        "kill_chain_coverage": covered,
        "total_techniques":    len(tech_counts),
    }


def attack_summary_markdown(summary: dict[str, Any]) -> str:
    """Форматирует сводку ATT&CK в Markdown для отчёта."""
    lines: list[str] = []

    if not summary.get("techniques"):
        return "_MITRE ATT&CK: техники не обнаружены_"

    lines.append("## 🎯 MITRE ATT&CK Coverage\n")

    # Kill chain progress
    covered = summary.get("kill_chain_coverage", [])
    if covered:
        lines.append(f"**Покрытые тактики kill chain:** {', '.join(covered)}\n")

    # Tactics table
    tactics = summary.get("tactics", {})
    if tactics:
        lines.append("### Тактики\n")
        lines.append("| Тактика | Кол-во техник |")
        lines.append("|---------|--------------|")
        for tactic, count in tactics.items():
            lines.append(f"| {tactic} | {count} |")
        lines.append("")

    # Techniques list
    techniques = summary.get("techniques", [])[:20]  # top 20
    if techniques:
        lines.append("### Техники\n")
        for tech in techniques:
            url  = tech.get("url", "")
            tid  = tech.get("id", "")
            name = tech.get("name", "")
            tactic = tech.get("tactic", "")
            count  = tech.get("count", 0)
            link = f"[{tid}]({url})" if url else tid
            lines.append(f"- {link} **{name}** _{tactic}_ × {count}")

    return "\n".join(lines)
