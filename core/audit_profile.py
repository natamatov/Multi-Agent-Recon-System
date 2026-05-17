"""
Профиль аудита: лёгкий (nmap+whatweb+Claude) или полный (все сканеры + Swarm).
"""

from __future__ import annotations

from enum import Enum


class AuditProfile(str, Enum):
    LIGHT = "light"
    FULL = "full"


def profile_label(profile: AuditProfile) -> str:
    labels = {
        AuditProfile.LIGHT: "Лёгкий аудит (nmap + whatweb + Claude)",
        AuditProfile.FULL: "Полный аудит (все сканеры + CrewAI Swarm)",
    }
    return labels.get(profile, profile.value)
