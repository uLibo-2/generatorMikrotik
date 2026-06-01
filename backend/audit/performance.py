from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value

@registry.register
class AuditFastTrack(AuditPlugin):
    id = "BP-PRF-001"
    category = "performance"
    severity = "medium"
    confidence = 100
    title = "FastTrack Connection Acceleration"
    description = "Перевірка увімкнення механізму FastTrack для прискорення обробки транзитного IPv4 трафіку."
    impact = "Без FastTrack кожен пакет встановленого з'єднання проходить повну обробку процесором через таблицю файрволу, що обмежує продуктивність роутера та викликає 100% навантаження CPU на гігабітних швидкостях."
    best_practice = "Завжди додавати першим правилом ланцюжка forward у файрволі дію action=fasttrack-connection для established,related з'єднань."
    resolution = "Додати правило FastTrack у файрвол."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_fasttrack = False
        for rule in model.firewall_rules:
            if rule.chain == "forward" and rule.action == "fasttrack-connection":
                has_fasttrack = True
                break

        if not has_fasttrack and model.firewall_rules:
            warnings.append("⚠️ FastTrack вимкнено — транзитний трафік буде сильно навантажувати процесор (CPU)")
            fixes.append("/ip firewall filter add chain=forward action=fasttrack-connection connection-state=established,related comment=\"defconf: fasttrack\" position=0")
            fixes.append("/ip firewall filter add chain=forward action=accept connection-state=established,related comment=\"defconf: accept established,related\" position=1")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditConnectionTracking(AuditPlugin):
    id = "BP-PRF-002"
    category = "performance"
    severity = "low"
    confidence = 90
    title = "Connection Tracking State"
    description = "Перевірка налаштувань таблиці відстеження з'єднань."
    impact = "Якщо Connection Tracking вимкнено, файрвол стає stateless (нездатним аналізувати стан з'єднань established/related/invalid), що робить більшість правил безпеки та NAT недієвими."
    best_practice = "Залишати Connection Tracking у стані auto або yes."
    resolution = "Увімкнути Connection Tracking."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        conn_lines = model.raw_sections.get("/ip firewall connection tracking", [])
        for line in conn_lines:
            enabled = get_param_value(line, "enabled")
            if enabled == "no":
                warnings.append("⚠️ Connection Tracking вимкнено (enabled=no) — файрвол та NAT не зможуть коректно працювати")
                fixes.append("/ip firewall connection tracking set enabled=yes")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
