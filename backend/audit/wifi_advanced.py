"""
Advanced WiFi & CAPsMAN Audit Plugins for MikroTik RouterOS
Covers: WPA3, PMF, PMKID, channel width, TX power, band steering, seamless roaming
"""
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value


@registry.register
class AuditWPA3Support(AuditPlugin):
    id = "BP-WF-010"
    category = "wifi"
    severity = "medium"
    confidence = 90
    title = "WPA3 / SAE Security Protocol"
    description = "Перевірка підтримки WPA3 (SAE) на точках доступу WiFiWave2."
    impact = (
        "WPA2-PSK вразливий до offline brute-force атак після перехоплення "
        "4-way handshake (Hashcat може перебирати мільярди паролів/сек офлайн). "
        "WPA3-SAE унеможливлює такі атаки завдяки Simultaneous Authentication of Equals."
    )
    best_practice = (
        "Для RouterOS v7 + WiFiWave2: налаштувати authentication-types=wpa2-psk,wpa3-psk "
        "(transition mode) для підтримки старих клієнтів при підвищеній безпеці нових."
    )
    resolution = "Увімкнути WPA3 у перехідному режимі."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        wifi_sec_lines = (
            model.raw_sections.get("/interface wifi security", []) or
            model.raw_sections.get("/interface wifiwave2 security", [])
        )

        for line in wifi_sec_lines:
            auth_types = get_param_value(line, "authentication-types") or ""
            name = get_param_value(line, "name") or "profile"

            if "wpa2" in auth_types and "wpa3" not in auth_types:
                warnings.append(
                    f"⚠️ WiFi Security '{name}': Використовується тільки WPA2 — "
                    "рекомендується додати WPA3-SAE для захисту від offline перебору паролів"
                )
                fixes.append(
                    f'/interface wifi security set [find name={name}] authentication-types=wpa2-psk,wpa3-psk'
                )

        # Also check legacy wireless security profiles
        sec_profiles = model.raw_sections.get("/interface wireless security-profiles", [])
        for line in sec_profiles:
            mode = get_param_value(line, "mode") or ""
            name = get_param_value(line, "name") or "default"
            if mode == "none" or not mode:
                issues.append(
                    f"❌ WiFi Security Profile '{name}': Шифрування відсутнє (mode=none) — "
                    "бездротова мережа повністю відкрита"
                )
                fixes.append(
                    f'/interface wireless security-profiles set [find name={name}] mode=dynamic-keys authentication-types=wpa2-psk wpa2-pre-shared-key="SecureWiFiPass123!"'
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditPMF(AuditPlugin):
    id = "BP-WF-011"
    category = "wifi"
    severity = "medium"
    confidence = 88
    title = "Protected Management Frames (802.11w / PMF)"
    description = "Перевірка увімкнення Protected Management Frames для захисту від deauth атак."
    impact = (
        "Без PMF (802.11w) зловмисники можуть надсилати підроблені Deauthentication фрейми, "
        "примушуючи WiFi клієнтів відключатися від мережі (WiFi deauth DoS атака). "
        "Це також використовується для захоплення handshake під WPA2 злому."
    )
    best_practice = (
        "Встановити management-protection=optional (для сумісності) або required (максимальний захист). "
        "При WPA3 — PMF є обов'язковим автоматично."
    )
    resolution = "Увімкнути management-protection."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        wifi_sec_lines = (
            model.raw_sections.get("/interface wifi security", []) or
            model.raw_sections.get("/interface wifiwave2 security", [])
        )

        for line in wifi_sec_lines:
            mgmt_prot = get_param_value(line, "management-protection") or ""
            name = get_param_value(line, "name") or "profile"
            auth_types = get_param_value(line, "authentication-types") or ""

            # If WPA3 is in use, PMF is implicit
            if "wpa3" in auth_types:
                info.append(f"✅ WiFi '{name}': WPA3 — PMF активний автоматично")
                continue

            if mgmt_prot == "disabled" or not mgmt_prot:
                warnings.append(
                    f"⚠️ WiFi Security '{name}': PMF (Protected Management Frames) вимкнено — "
                    "мережа вразлива до deauth DoS атак та перехоплення handshake"
                )
                fixes.append(
                    f'/interface wifi security set [find name={name}] management-protection=optional'
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditWiFiChannelConfig(AuditPlugin):
    id = "BP-WF-012"
    category = "wifi"
    severity = "medium"
    confidence = 85
    title = "WiFi Channel Width & Band Configuration"
    description = "Перевірка налаштувань ширини каналу та смуги частот WiFi."
    impact = (
        "Неоптимальні налаштування каналу знижують пропускну здатність: "
        "20MHz замість 80MHz на 5GHz дає в 4 рази менший throughput; "
        "використання 40MHz на 2.4GHz в щільній міській забудові збільшує інтерференцію."
    )
    best_practice = (
        "2.4GHz: channel-width=20mhz (менше інтерференції). "
        "5GHz: channel-width=80mhz або 160mhz (для WiFi 6/ax). "
        "6GHz (WiFi 6E): channel-width=160mhz."
    )
    resolution = "Оптимізувати ширину каналу під діапазон."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        wifi_conf_lines = (
            model.raw_sections.get("/interface wifi configuration", []) or
            model.raw_sections.get("/interface wifiwave2", []) or
            model.raw_sections.get("/interface wifi", [])
        )

        for line in wifi_conf_lines:
            band = get_param_value(line, "band") or get_param_value(line, "configuration.band") or ""
            channel_width = get_param_value(line, "channel.width") or get_param_value(line, "channel-width") or ""
            name = get_param_value(line, "name") or "wifi"

            if "5ghz" in band.lower() or "5g" in band.lower():
                if channel_width and "20" in channel_width and "80" not in channel_width:
                    warnings.append(
                        f"⚠️ WiFi '{name}' (5GHz): channel-width=20MHz — "
                        "збільшіть до 80MHz або 160MHz для кращої пропускної здатності"
                    )
                    fixes.append(
                        f'/interface wifi configuration set [find name={name}] channel.width=80mhz'
                    )

            if "2ghz" in band.lower() or "2.4" in band.lower():
                if channel_width and ("40" in channel_width or "80" in channel_width):
                    warnings.append(
                        f"⚠️ WiFi '{name}' (2.4GHz): channel-width={channel_width} — "
                        "у щільній забудові 40/80MHz підсилює інтерференцію; рекомендується 20MHz"
                    )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditCAPsMANProvisioningRules(AuditPlugin):
    id = "BP-CAP-001"
    category = "capsman"
    severity = "high"
    confidence = 90
    title = "CAPsMAN Provisioning Rules"
    description = "Перевірка наявності та правильності правил provisioning у CAPsMAN."
    impact = (
        "Без правил provisioning точки доступу CAP не отримають конфігурацію "
        "автоматично після підключення до контролера. "
        "Кожна нова AP потребуватиме ручного налаштування."
    )
    best_practice = (
        "Налаштувати provisioning правила з action=create-dynamic-enabled, "
        "вказати master-configuration та radio-configuration для кожного діапазону (2.4/5GHz)."
    )
    resolution = "Додати provisioning правила до CAPsMAN."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Check for CAPsMAN controller config
        capsman_lines = (
            model.raw_sections.get("/caps-man manager", []) or
            model.raw_sections.get("/interface wifi capsman", []) or
            model.raw_sections.get("/interface wifiwave2 capsman", [])
        )

        if not capsman_lines:
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        # Check provisioning
        prov_lines = (
            model.raw_sections.get("/caps-man provisioning", []) or
            model.raw_sections.get("/interface wifi provisioning", []) or
            model.raw_sections.get("/interface wifiwave2 provisioning", [])
        )

        capsman_enabled = any(
            get_param_value(l, "enabled") == "yes" for l in capsman_lines
        )

        if capsman_enabled and not prov_lines:
            issues.append(
                "❌ CAPsMAN увімкнено, але правила provisioning відсутні — "
                "точки доступу CAP не отримають конфігурацію автоматично"
            )
            fixes.append(
                '/interface wifi provisioning add action=create-dynamic-enabled comment="Auto-provision all CAPs"'
            )
        elif prov_lines:
            info.append(f"✅ CAPsMAN Provisioning: {len(prov_lines)} правил налаштовано")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditCAPsMANDatapath(AuditPlugin):
    id = "BP-CAP-002"
    category = "capsman"
    severity = "high"
    confidence = 90
    title = "CAPsMAN Datapath & Bridge Configuration"
    description = "Перевірка конфігурації datapath для передачі трафіку CAPsMAN."
    impact = (
        "Без правильного datapath профілю WiFi клієнти будуть підключені до "
        "точки доступу, але не матимуть доступу до LAN або Інтернету: "
        "трафік не буде переправлений до правильного bridge/VLAN."
    )
    best_practice = (
        "У CAPsMAN datapath: вказати bridge=bridge (або bridge=none з local-forwarding=yes), "
        "налаштувати vlan-id та vlan-mode для сегрегації трафіку по VLAN."
    )
    resolution = "Налаштувати datapath профіль у CAPsMAN."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        datapath_lines = (
            model.raw_sections.get("/caps-man datapath", []) or
            model.raw_sections.get("/interface wifi datapath", [])
        )

        config_lines = (
            model.raw_sections.get("/caps-man configuration", []) or
            model.raw_sections.get("/interface wifi configuration", [])
        )

        if config_lines and not datapath_lines:
            warnings.append(
                "⚠️ CAPsMAN конфігурації присутні, але datapath профілі не виявлено — "
                "трафік клієнтів може не потрапляти на LAN bridge"
            )
            fixes.append(
                '/interface wifi datapath add name=datapath-main bridge=bridge comment="Main LAN datapath"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditHiddenSSID(AuditPlugin):
    id = "BP-WF-013"
    category = "wifi"
    severity = "low"
    confidence = 80
    title = "Hidden SSID Security"
    description = "Оцінка використання прихованого SSID як заходу безпеки."
    impact = (
        "Приховування SSID (hide-ssid=yes) НЕ є заходом безпеки — "
        "будь-який WiFi сканер (Wireshark, Kismet, NetStumbler) миттєво "
        "виявить приховану мережу з probe request фреймів клієнтів. "
        "При цьому клієнти постійно транслюють SSID у probe requests."
    )
    best_practice = (
        "Не покладатися на hide-ssid як захист. "
        "Замість цього — сильний WPA2/WPA3 пароль та PMF захист."
    )
    resolution = "Не використовувати hide-ssid як єдиний захист."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        wifi_lines = (
            model.raw_sections.get("/interface wifi", []) or
            model.raw_sections.get("/interface wifiwave2", []) or
            model.raw_sections.get("/interface wireless", [])
        )

        for line in wifi_lines:
            hide_ssid = get_param_value(line, "hide-ssid") or get_param_value(line, "configuration.hide-ssid") or ""
            name = get_param_value(line, "name") or "wifi"
            if hide_ssid == "yes":
                info.append(
                    f"ℹ️ WiFi '{name}': hide-ssid=yes — прихований SSID не є надійним захистом, "
                    "будь-який WiFi аналізатор виявить мережу. Покладайтеся на WPA3/PMF."
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
