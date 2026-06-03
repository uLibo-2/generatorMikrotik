from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value

@registry.register
class AuditWifiCountry(AuditPlugin):
    id = "BP-WF-001"
    category = "wifi"
    severity = "medium"
    confidence = 100
    title = "Wireless Country Code"
    description = "Перевірка встановлення коду країни для бездротових передавачів."
    impact = "Якщо регіональний код країни не встановлено (no_country_set), пристрій не може активувати DFS канали, працює на мінімальній дозволеній потужності передачі або порушує місцеві закони радіочастотного спектра."
    best_practice = "Завжди явно вказуйте країну розміщення пристрою (наприклад, Ukraine) для автоматичного застосування обмежень частот та потужності."
    resolution = "Встановити код країни для WiFi інтерфейсів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Look for country in wifi profile or interface lines
        wifi_lines = model.raw_sections.get("/interface wifi", []) or model.raw_sections.get("/interface wifiwave2", [])
        legacy_wireless = model.raw_sections.get("/interface wireless", [])

        has_country = False

        # Check v7 wifi lines for country setting
        for line in wifi_lines:
            c = get_param_value(line, "configuration.country") or get_param_value(line, "country")
            if c and c != "no_country_set":
                has_country = True

        # Also check separate wifi configuration profiles
        wifi_conf_lines = model.raw_sections.get("/interface wifi configuration", [])
        for line in wifi_conf_lines:
            c = get_param_value(line, "country")
            if c and c != "no_country_set":
                has_country = True

        for line in legacy_wireless:
            c = get_param_value(line, "country")
            if c and c != "no_country_set":
                has_country = True

        if not has_country and (wifi_lines or legacy_wireless):
            warnings.append("⚠️ Country code не встановлено на WiFi інтерфейсах — DFS та вибір частот можуть працювати некоректно")
            if wifi_lines:
                fixes.append("/interface wifi set [find] configuration.country=Ukraine")
            elif legacy_wireless:
                fixes.append("/interface wireless set [find] country=ukraine")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditWifiGuestIsolation(AuditPlugin):
    id = "BP-WF-002"
    category = "wifi"
    severity = "high"
    confidence = 95
    title = "WiFi Guest Isolation"
    description = "Перевірка ізоляції клієнтів у гостьовій бездротовій мережі."
    impact = "Якщо для гостьової мережі активовано default-forwarding=yes, клієнти зможуть обмінюватися даними між собою, що створює загрозу безпеки (наприклад, поширення вірусів або атаки типу Man-in-the-Middle)."
    best_practice = "Для гостьових бездротових мереж завжди встановлюйте default-forwarding=no."
    resolution = "Встановити default-forwarding=no для гостьових SSID/інтерфейсів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        for w in model.wifi:
            if "guest" in w.ssid.lower() or "guest" in w.name.lower():
                # Check default forwarding on this interface
                wifi_lines = model.raw_sections.get("/interface wifi", []) or model.raw_sections.get("/interface wifiwave2", []) or model.raw_sections.get("/interface wireless", [])
                for line in wifi_lines:
                    name = get_param_value(line, "name")
                    if name == w.name:
                        df = get_param_value(line, "default-forwarding") or get_param_value(line, "configuration.default-forwarding")
                        if df != "no":
                            warnings.append(f"⚠️ Гостьова мережа '{w.ssid}' на інтерфейсі '{w.name}' не має ізоляції клієнтів (default-forwarding=yes)")
                            if "wifi" in line:
                                fixes.append(f"/interface wifi set [find name={w.name}] configuration.default-forwarding=no")
                            else:
                                fixes.append(f"/interface wireless set [find name={w.name}] default-forwarding=no")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditWifiFastTransition(AuditPlugin):
    id = "BP-WF-003"
    category = "wifi"
    severity = "medium"
    confidence = 90
    title = "WiFi Fast Transition (802.11r)"
    description = "Валідація конфігурації швидкого бездротового роумінгу."
    impact = "Увімкнення Fast Transition на локаціях з однією точкою доступу (Single AP) є безглуздим та може призвести до проблем підключення застарілих клієнтських девайсів."
    best_practice = "Активувати FT (ft=yes) тільки тоді, коли в мережі розгорнуто щонайменше 2 точки доступу з однаковим SSID."
    resolution = "Вимкнути FT на одиночній точці або налаштувати супутні параметри."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Check if FT is enabled
        ft_enabled = False
        sec_lines = model.raw_sections.get("/interface wifi security", []) or model.raw_sections.get("/interface wifiwave2 security", [])
        for line in sec_lines:
            ft = get_param_value(line, "ft")
            ft_over = get_param_value(line, "ft-over-ds")
            if ft == "yes" or ft_over == "yes":
                ft_enabled = True

        # Count access points / wifi interfaces
        ap_count = len(model.wifi)

        # Check if CAPsMAN is enabled — if so, FT is expected for multi-AP roaming
        capsman_enabled = False
        caps_manager_lines = model.raw_sections.get("/interface wifi capsman", []) or model.raw_sections.get("/caps-man manager", [])
        for line in caps_manager_lines:
            if get_param_value(line, "enabled") == "yes":
                capsman_enabled = True

        if ft_enabled and ap_count <= 1 and not capsman_enabled:
            warnings.append("⚠️ Швидкий роумінг Fast Transition (802.11r) увімкнено для одиночної точки доступу без CAPsMAN. Це може викликати збої підключення старих клієнтів")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditCapsmanConfiguration(AuditPlugin):
    id = "BP-WF-004"
    category = "wifi"
    severity = "medium"
    confidence = 95
    title = "CAPsMAN Provisioning & Datapaths"
    description = "Перевірка логіки та зв'язків конфігурації CAPsMAN контролера."
    impact = "Якщо CAPsMAN активовано, але не створено правил автоматичного призначення (provisioning), нові точки доступу (CAP) підключаться, але не зможуть отримати конфігурацію частот та SSID."
    best_practice = "Для CAPsMAN завжди створювати принаймні одне загальне правило автоматичного призначення (provisioning) із вказанням master-configuration."
    resolution = "Створити provisioning rule для автоматичного налаштування CAP."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        caps_enabled = False
        caps_manager_lines = model.raw_sections.get("/interface wifi capsman", []) or model.raw_sections.get("/caps-man manager", [])
        for line in caps_manager_lines:
            enabled = get_param_value(line, "enabled") == "yes"
            if enabled:
                caps_enabled = True

        if caps_enabled:
            # Check provisioning rules
            prov_rules = model.raw_sections.get("/interface wifi provisioning", []) or model.raw_sections.get("/caps-man provisioning", [])
            if not prov_rules:
                warnings.append("⚠️ CAPsMAN увімкнено, але правила автоматичного призначення (provisioning rules) відсутні. Точки доступу не зможуть налаштуватися")
                fixes.append("/interface wifi provisioning add action=create-dynamic-enabled master-configuration=cfg-main comment=\"Auto provisioning rule\"")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
