"""
Monitoring & Operations Audit Plugins for MikroTik RouterOS
Covers: SNMP monitoring, Netwatch, Logging, System resources, Health monitoring
"""
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value


@registry.register
class AuditNetwatch(AuditPlugin):
    id = "BP-MON-001"
    category = "monitoring"
    severity = "medium"
    confidence = 85
    title = "Netwatch — Моніторинг доступності вузлів"
    description = "Перевірка наявності Netwatch для моніторингу доступності критичних вузлів."
    impact = (
        "Без Netwatch адміністратор дізнається про падіння каналу або вузла "
        "тільки при надходженні скарг від користувачів. "
        "Проактивний моніторинг дозволяє реагувати до появи скарг."
    )
    best_practice = (
        "Налаштувати Netwatch для пінгу: WAN шлюзу провайдера, "
        "зовнішнього IP (8.8.8.8), DNS сервера та ключових внутрішніх хостів. "
        "У down-script — надсилати сповіщення (email/telegram) або перемикати маршрут."
    )
    resolution = "Налаштувати Netwatch для ключових хостів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        netwatch_lines = model.raw_sections.get("/tool netwatch", [])

        if not netwatch_lines:
            warnings.append(
                "⚠️ Netwatch не налаштовано — відсутній автоматичний моніторинг "
                "доступності WAN та критичних вузлів"
            )
            fixes.append(
                '/tool netwatch\n'
                'add host=8.8.8.8 interval=30s timeout=1s comment="Google DNS availability check"\n'
                'add host=1.1.1.1 interval=30s timeout=1s comment="Cloudflare DNS availability check"'
            )
        else:
            info.append(f"✅ Netwatch: {len(netwatch_lines)} хостів моніториться")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditSystemLogging(AuditPlugin):
    id = "BP-MON-002"
    category = "monitoring"
    severity = "medium"
    confidence = 90
    title = "System Logging Configuration"
    description = "Перевірка налаштувань системного логування (topics, rвіддалений syslog)."
    impact = (
        "Без налаштованого логування неможливо відстежити: "
        "спроби несанкціонованого доступу, падіння з'єднань, DHCP leases, "
        "зміни конфігурації. Відсутній syslog означає втрату логів при перезавантаженні."
    )
    best_practice = (
        "Налаштувати логування критичних топіків: critical, error, warning, firewall. "
        "Надсилати логи на віддалений syslog/Graylog сервер для збереження."
    )
    resolution = "Налаштувати logging action та topics."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        logging_lines = model.raw_sections.get("/system logging", [])
        logging_action_lines = model.raw_sections.get("/system logging action", [])

        has_remote_logging = any(
            get_param_value(l, "target") == "remote" for l in logging_action_lines
        )

        if not model.syslog_enabled and not has_remote_logging:
            warnings.append(
                "⚠️ Логування на віддалений сервер (Syslog/Graylog) не налаштовано — "
                "логи зберігаються тільки в пам'яті та втрачаються при перезавантаженні"
            )
            fixes.append(
                '/system logging action add name=remote-syslog target=remote remote=192.168.1.100 remote-port=514 bsd-syslog=yes comment="Syslog server"\n'
                '/system logging add action=remote-syslog topics=critical,error,warning comment="Log critical to syslog"\n'
                '/system logging add action=remote-syslog topics=firewall comment="Log firewall to syslog"'
            )

        # Check if firewall logging exists
        has_firewall_log = any(
            "firewall" in get_param_value(l, "topics") or ""
            for l in logging_lines
        )
        if not has_firewall_log:
            info.append(
                "ℹ️ Логування firewall подій не налаштовано — "
                "спроби вторгнення не будуть записуватись до логів"
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditEmailNotification(AuditPlugin):
    id = "BP-MON-003"
    category = "monitoring"
    severity = "low"
    confidence = 78
    title = "Email Notification (SMTP)"
    description = "Перевірка налаштування SMTP для надсилання сповіщень."
    impact = (
        "Без налаштованого SMTP неможливо отримувати автоматичні сповіщення "
        "про критичні події: падіння каналу, вичерпання місця, backup completion, "
        "підозрілу активність у мережі."
    )
    best_practice = (
        "Налаштувати /tool e-mail з SMTP сервером і перевірити за допомогою "
        "/tool e-mail send. Використовувати у Netwatch down-script та backup скриптах."
    )
    resolution = "Налаштувати SMTP для сповіщень."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        email_lines = model.raw_sections.get("/tool e-mail", [])
        smtp_configured = any(
            get_param_value(l, "server") or get_param_value(l, "smtp-server")
            for l in email_lines
        )

        if not smtp_configured:
            info.append(
                "ℹ️ Email (SMTP) сповіщення не налаштовано — "
                "неможливо надсилати алерти про критичні події автоматично"
            )
            fixes.append(
                '/tool e-mail set server=smtp.gmail.com port=587 tls=starttls user=router@example.com password="smtp-pass" from=router@example.com'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditScriptSecurity(AuditPlugin):
    id = "BP-SCR-001"
    category = "script"
    severity = "high"
    confidence = 85
    title = "Script Policy & Permissions"
    description = "Перевірка прав доступу скриптів RouterOS (надмірні дозволи)."
    impact = (
        "Скрипти з надмірними правами (policy: reboot, sensitive, write) — "
        "якщо скрипт підконтролюється ззовні або запускається від стороннього тригера, "
        "він може перезавантажити роутер або змінити критичну конфігурацію."
    )
    best_practice = (
        "Принцип мінімальних привілеїв: кожен скрипт повинен мати тільки "
        "ті права, що необхідні для його роботи. "
        "Backup скрипту потрібні: read, write, ftp. "
        "Netwatch скрипту: read, write."
    )
    resolution = "Перевірити та зменшити права скриптів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        script_lines = model.raw_sections.get("/system script", [])
        for line in script_lines:
            name = get_param_value(line, "name") or "script"
            policy = get_param_value(line, "policy") or ""
            if "reboot" in policy and "backup" not in name.lower():
                warnings.append(
                    f"⚠️ Скрипт '{name}' має право 'reboot' — "
                    "перевірте чи це необхідно, зловмисне використання може перезавантажити роутер"
                )
            if "sensitive" in policy:
                warnings.append(
                    f"⚠️ Скрипт '{name}' має право 'sensitive' — "
                    "доступ до паролів та чутливих даних"
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditSystemResources(AuditPlugin):
    id = "BP-MON-004"
    category = "monitoring"
    severity = "low"
    confidence = 75
    title = "System Resource Monitoring Scripts"
    description = "Перевірка наявності моніторингу системних ресурсів (CPU, RAM, диск)."
    impact = (
        "Без моніторингу ресурсів критичні стани (переповнення диску flash, "
        "постійне 100% CPU) виявляються тільки коли система вже нестабільна."
    )
    best_practice = (
        "Налаштувати скрипт перевірки вільного місця /system resource: "
        "при заповненні flash >80% — надсилати email або syslog alert. "
        "Особливо важливо для роутерів з активним логуванням."
    )
    resolution = "Налаштувати моніторинг ресурсів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Check if there are log-related actions that might fill disk
        logging_actions = model.raw_sections.get("/system logging action", [])
        has_disk_logging = any(
            get_param_value(l, "target") == "disk"
            for l in logging_actions
        )

        if has_disk_logging:
            info.append(
                "ℹ️ Логування на диск (target=disk) активне — "
                "налаштуйте моніторинг заповненості flash пам'яті"
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditSNMPMonitoringSetup(AuditPlugin):
    id = "BP-MON-005"
    category = "monitoring"
    severity = "low"
    confidence = 80
    title = "SNMP Monitoring Integration"
    description = "Перевірка конфігурації SNMP для інтеграції з системами моніторингу (Zabbix, PRTG, Grafana)."
    impact = (
        "Без SNMP або RouterOS API неможливо збирати метрики: "
        "завантаженість каналу, CPU/RAM роутера, стан інтерфейсів — "
        "в системи моніторингу типу Zabbix, Grafana, Prometheus."
    )
    best_practice = (
        "Налаштувати SNMP v2c або v3 з обмеженням по IP до мережі моніторингу. "
        "Або використовувати RouterOS REST API (ROS7) для Prometheus exporter."
    )
    resolution = "Налаштувати SNMP для інтеграції з моніторингом."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.snmp_enabled:
            info.append(
                "ℹ️ SNMP вимкнено — для інтеграції з Zabbix/Grafana/PRTG "
                "увімкніть SNMP або використовуйте RouterOS REST API"
            )
            fixes.append(
                '# SNMP для моніторингу (обмежити access-list до сервера моніторингу!)\n'
                '/snmp set enabled=yes trap-version=2 contact="admin@company.com" location="Server Room"\n'
                '/snmp community set [find] name=monitoring-ro read-access=yes write-access=no addresses=10.0.0.0/8'
            )
        else:
            info.append("✅ SNMP увімкнено для моніторингу")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
