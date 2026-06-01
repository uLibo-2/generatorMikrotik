import re
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value

@registry.register
class AuditUnsafeIpServices(AuditPlugin):
    id = "BP-SEC-001"
    category = "security"
    severity = "critical"
    confidence = 100
    title = "Unsafe IP Services Detection"
    description = "Пошук та перевірка доступності незашифрованих та небезпечних служб керування роутером (telnet, ftp, www)."
    impact = "Увімкнені служби telnet та ftp передають паролі та дані в незашифрованому вигляді через мережу. Будь-хто в сегменті транзиту зможе перехопити доступ до роутера."
    best_practice = "Завжди вимикайте незашифровані служби telnet, ftp, api та www (або переведіть www на www-ssl) і використовуйте лише безпечні winbox, ssh та api-ssl."
    resolution = "Вимкнути небезпечні служби в налаштуваннях IP Services."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        unsafe_services = ["telnet", "ftp"]
        for srv in model.services:
            if srv.name in unsafe_services and not srv.disabled:
                issues.append(f"❌ Службу {srv.name} увімкнено (небезпечний незашифрований протокол)")
                fixes.append(f"/ip service disable {srv.name}")

            if srv.name == "www" and not srv.disabled:
                warnings.append("⚠️ Службу www (HTTP Webfig) увімкнено без SSL шифрування")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditIpServicesRestrictions(AuditPlugin):
    id = "BP-SEC-002"
    category = "security"
    severity = "high"
    confidence = 95
    title = "Admin Management Access Restriction"
    description = "Перевірка обмеження доступу до Winbox, SSH та Web за IP-адресами."
    impact = "Якщо доступ до служб Winbox (8291) та SSH (22) відкритий для всіх IP адрес (0.0.0.0/0), роутер піддається постійному брутфорсу (brute-force) паролів з інтернету."
    best_practice = "Явно вкажіть дозволені IP-адреси або підмережу адміністратора (параметр address) для служб winbox, ssh, www-ssl."
    resolution = "Обмежити доступ до служб управління роутером за допомогою параметра address."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        admin_services = ["winbox", "ssh", "www-ssl"]
        for srv in model.services:
            if srv.name in admin_services and not srv.disabled:
                if not srv.address or srv.address == "0.0.0.0/0":
                    warnings.append(f"⚠️ Доступ до {srv.name} відкрито для всіх IP адрес (відсутнє обмеження в полі address)")
                    fixes.append(f"/ip service set {srv.name} address=192.168.88.0/24")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditDnsOpenResolver(AuditPlugin):
    id = "BP-SEC-003"
    category = "security"
    severity = "critical"
    confidence = 98
    title = "DNS WAN Open Resolver Vulnerability"
    description = "Перевірка захисту від атак DNS Amplification, коли порт DNS 53 відкритий назовні."
    impact = "Якщо дозволено remote-requests (allow-remote-requests=yes), і порт 53 UDP/TCP не заблоковано на інтерфейсі WAN у Firewall, ваш роутер стане DNS Open Resolver. Зловмисники використовуватимуть його для здійснення потужних DDoS-атак."
    best_practice = "Завжди блокувати вхідні DNS-запити на порт 53 з боку WAN інтерфейсу або вимкнути allow-remote-requests."
    resolution = "Створити захисне правило у файрволі, яке блокує DNS запити на WAN."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if model.dns_allow_remote:
            dns_blocked_wan = False
            for rule in model.firewall_rules:
                if rule.chain == "input" and rule.action in ("drop", "reject") and not rule.disabled:
                    is_port_53 = rule.dst_port == "53" or "53" in (rule.dst_port or "")
                    is_wan = rule.in_interface_list == "WAN" or "wan" in (rule.in_interface or "").lower()
                    if is_port_53 and is_wan:
                        dns_blocked_wan = True
                        break

            if not dns_blocked_wan:
                wan_list = "WAN"
                issues.append("❌ DNS: Дозволено remote-requests, але порт 53 відкритий ззовні (WAN) — критична вразливість до DNS Amplification атак")
                fixes.append(f"/ip firewall filter add chain=input action=drop protocol=udp dst-port=53 in-interface-list={wan_list} comment=\"defconf: drop DNS requests from WAN\"")
                fixes.append(f"/ip firewall filter add chain=input action=drop protocol=tcp dst-port=53 in-interface-list={wan_list} comment=\"defconf: drop DNS requests from WAN\"")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditDiscoveryOnWan(AuditPlugin):
    id = "BP-SEC-004"
    category = "security"
    severity = "medium"
    confidence = 90
    title = "Neighbor Discovery on WAN"
    description = "Перевірка активності служб виявлення сусідів (MNDP, LLDP) на зовнішніх інтерфейсах."
    impact = "Neighbor Discovery та MAC Winbox Server, увімкнені на WAN, надсилають у зовнішню мережу інформацію про модель роутера, версію RouterOS та MAC-адресу, полегшуючи зловмисникам пошук вразливостей."
    best_practice = "Дозволяти Neighbor Discovery та MAC Winbox тільки для внутрішнього списку інтерфейсів (LAN)."
    resolution = "Обмежити Neighbor Discovery та MAC Winbox списком LAN."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        mndp_lines = model.raw_sections.get("/ip neighbor discovery-settings", [])
        mndp_only_lan = False
        for line in mndp_lines:
            iface_list = get_param_value(line, "discover-interface-list")
            if iface_list == "LAN":
                mndp_only_lan = True

        mac_winbox_lines = model.raw_sections.get("/tool mac-server mac-winbox", [])
        winbox_only_lan = False
        for line in mac_winbox_lines:
            iface_list = get_param_value(line, "allowed-interface-list")
            if iface_list == "LAN":
                winbox_only_lan = True

        if not mndp_only_lan:
            warnings.append("⚠️ Neighbor Discovery (MNDP) дозволено на всіх інтерфейсах, включаючи WAN")
            fixes.append("/ip neighbor discovery-settings set discover-interface-list=LAN")

        if not winbox_only_lan:
            warnings.append("⚠️ MAC Winbox Server дозволено для всіх інтерфейсів, включаючи WAN")
            fixes.append("/tool mac-server mac-winbox set allowed-interface-list=LAN")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditFirewallRuleOrder(AuditPlugin):
    id = "BP-SEC-005"
    category = "security"
    severity = "high"
    confidence = 95
    title = "Firewall Filter Rules Ordering"
    description = "Перевірка послідовності та пріоритету правил фільтрації у файрволі."
    impact = "RouterOS обробляє правила файрволу зверху вниз (First Match). Якщо загальне блокуюче правило розміщено вище дозволяючих правил, корисний трафік буде заблоковано."
    best_practice = "Завжди ставте правила фільтрації стану (accept established,related) першими, за ними дозволяючі правила, і тільки в кінці — блокуючі правила."
    resolution = "Перевпорядкувати чергу правил файрволу."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        drop_all_input_idx = -1
        accept_rules_after_drop = False

        for idx, rule in enumerate(model.firewall_rules):
            if rule.chain == "input" and not rule.disabled:
                is_drop_all = rule.action in ("drop", "reject") and not rule.src_address and not rule.dst_address and not rule.src_address_list and not rule.dst_address_list
                if is_drop_all:
                    drop_all_input_idx = idx
                elif drop_all_input_idx != -1 and rule.action == "accept":
                    accept_rules_after_drop = True
                    break

        if accept_rules_after_drop:
            warnings.append("⚠️ Firewall: Виявлено дозволяючі правила ланцюжка input після блокуючого правила (shadowing)")
            fixes.append("/ip firewall filter move [find action=accept chain=input] destination=0")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditNtpMonitoring(AuditPlugin):
    id = "BP-SEC-006"
    category = "security"
    severity = "medium"
    confidence = 90
    title = "System Time & Logging Audit"
    description = "Аналіз налаштувань синхронізації часу (NTP) та ведення системних логів."
    impact = "Без точного системного часу лог-файли роутера матимуть невірні мітки часу, що робить неможливим ретроспективний аналіз інцидентів безпеки та збоїв зв'язку."
    best_practice = "Завжди вмикати та налаштовувати клієнт NTP, а також налаштувати логування критичних подій на віддалений сервер логів (Syslog)."
    resolution = "Увімкнути NTP клієнт та налаштувати сервери синхронізації часу."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.ntp_enabled:
            warnings.append("⚠️ Службу синхронізації часу NTP вимкнено — лог-файли можуть мати неправильні мітки часу")
            fixes.append("/system ntp client set enabled=yes servers=0.pool.ntp.org,1.pool.ntp.org")

        if not model.syslog_enabled:
            warnings.append("⚠️ Відсутнє логування на віддалений сервер (Syslog/Graylog/Splunk)")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditFirewallDisabled(AuditPlugin):
    id = "BP-SEC-008"
    category = "security"
    severity = "critical"
    confidence = 100
    title = "IPv4 Firewall Protection Disabled"
    description = "Перевірка чи всі правила файрволу вимкнені (disabled=yes)."
    impact = "Якщо всі правила файрволу вимкнені, роутер повністю відкритий для зовнішніх атак. Служби управління (Winbox, SSH, DNS) доступні з WAN."
    best_practice = "Завжди мати активний ланцюжок input з базовою захистною конфігурацією перед підключенням роутера до Інтернету."
    resolution = "Увімкнути захисні правила файрволу або створити нові."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.firewall_rules:
            issues.append("❌ Firewall: Правила файрволу повністю відсутні — роутер не має жодного захисту від зовнішніх атак")
            fixes.append('/ip firewall filter add chain=input action=accept connection-state=established,related,untracked comment="defconf: accept established"')
            fixes.append('/ip firewall filter add chain=input action=drop connection-state=invalid comment="defconf: drop invalid"')
            fixes.append('/ip firewall filter add chain=input action=accept protocol=icmp comment="defconf: accept ICMP"')
            fixes.append('/ip firewall filter add chain=input action=accept in-interface-list=LAN comment="defconf: accept LAN"')
            fixes.append('/ip firewall filter add chain=input action=drop in-interface-list=!LAN comment="defconf: drop all not from LAN"')
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        # Count enabled vs disabled input rules
        input_rules = [r for r in model.firewall_rules if r.chain == "input"]
        enabled_input = [r for r in input_rules if not r.disabled]
        disabled_input = [r for r in input_rules if r.disabled]

        if input_rules and not enabled_input:
            issues.append(f"❌ Firewall: Усі {len(disabled_input)} правил(а) ланцюжка input вимкнені (disabled=yes) — роутер повністю незахищений від зовнішніх атак")
            fixes.append('/ip firewall filter enable [find chain=input]')
        elif len(disabled_input) > len(enabled_input) and len(disabled_input) > 3:
            warnings.append(f"⚠️ Firewall: {len(disabled_input)} з {len(input_rules)} правил input вимкнені — перевірте чи захист достатній")

        # Count enabled vs disabled forward rules
        forward_rules = [r for r in model.firewall_rules if r.chain == "forward"]
        enabled_forward = [r for r in forward_rules if not r.disabled]
        disabled_forward = [r for r in forward_rules if r.disabled]

        if forward_rules and not enabled_forward:
            warnings.append(f"⚠️ Firewall: Усі {len(disabled_forward)} правил(а) ланцюжка forward вимкнені")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditBackupScripts(AuditPlugin):
    id = "BP-SEC-007"
    category = "security"
    severity = "low"
    confidence = 95
    title = "RouterOS Backup & Export Scheduling"
    description = "Перевірка наявності автоматичних скриптів створення резервних копій."
    impact = "У разі апаратного збою або згорання роутера за відсутності актуального бекапу відновлення конфігурації офісу з нуля може тривати дні, спричиняючи простої бізнесу."
    best_practice = "Рекомендується налаштувати регулярний скрипт (наприклад, щотижня) для створення бінарного .backup та текстового .rsc експорту конфігурації з відправкою на email/FTP."
    resolution = "Створити скрипти та планувальники автоматичного резервного копіювання."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.backup_script_exists:
            warnings.append("⚠️ Відсутній скрипт створення двійкового бекапу (.backup)")
            fixes.append("/system script add name=auto_backup source=\"/system backup save name=auto_backup_file\"")
            fixes.append("/system scheduler add name=sched_backup interval=7d start-time=03:00:00 on-event=auto_backup")

        if not model.rsc_export_script_exists:
            warnings.append("⚠️ Відсутній скрипт експорту текстової конфігурації (.rsc)")
            fixes.append("/system script add name=auto_export source=\"/export file=auto_export_file\"")
            fixes.append("/system scheduler add name=sched_export interval=7d start-time=03:15:00 on-event=auto_export")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
