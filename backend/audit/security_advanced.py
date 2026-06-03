"""
Advanced Security Audit Plugins for MikroTik RouterOS
Covers: Firewall hardening, SNMP, SSH, port scanning protection,
brute-force protection, rogue DHCP, RouterOS exploit mitigations
"""
import re
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value


@registry.register
class AuditSNMPSecurity(AuditPlugin):
    id = "BP-SEC-020"
    category = "security"
    severity = "high"
    confidence = 98
    title = "SNMP Community String Security"
    description = "Перевірка захисту SNMP: дефолтне community 'public', відкритий доступ з WAN."
    impact = (
        "SNMP з community 'public' дозволяє будь-кому з мережі зчитати повну "
        "конфігурацію роутера (ARP, маршрути, інтерфейси, системну інформацію). "
        "SNMP v1/v2c передає community string у відкритому вигляді — будь-яке "
        "сніфування пакетів відкриє пароль."
    )
    best_practice = (
        "Або вимкніть SNMP, якщо не використовується. "
        "Або: змініть community 'public' на складний рядок, обмежте доступ "
        "по src-address до мереж моніторингу, та перейдіть на SNMPv3."
    )
    resolution = "Змінити community string та обмежити доступ до SNMP."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.snmp_enabled:
            info.append("✅ SNMP вимкнено")
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        # Check community name
        if model.snmp_community in ("public", "private", "", None):
            issues.append(
                f"❌ SNMP: Community string '{model.snmp_community or 'public'}' є дефолтним — "
                "зловмисники можуть зчитати всю таблицю маршрутизації, ARP та конфіг роутера"
            )
            fixes.append('/snmp community set [find name=public] name=monitoring-secure addresses=10.0.0.0/8')

        # Check SNMP access restrictions
        snmp_comm_lines = model.raw_sections.get("/snmp community", [])
        for line in snmp_comm_lines:
            addresses = get_param_value(line, "addresses")
            version = get_param_value(line, "version")
            if not addresses or addresses in ("0.0.0.0/0", "::/0", ""):
                warnings.append(
                    "⚠️ SNMP: Community без обмеження по IP-адресі — "
                    "відкритий для всіх мереж, включаючи WAN"
                )
                fixes.append('/snmp community set [find] addresses=192.168.0.0/16')
            if version in ("1", "2"):
                warnings.append(
                    f"⚠️ SNMP v{version}: Версія передає community string у відкритому вигляді — рекомендується SNMPv3"
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditBruteForceProtection(AuditPlugin):
    id = "BP-SEC-021"
    category = "security"
    severity = "high"
    confidence = 95
    title = "Brute-Force Protection (SSH/Winbox)"
    description = "Перевірка наявності захисту від перебору паролів через SSH та Winbox."
    impact = (
        "Без захисту від brute-force атак зловмисники можуть виконувати тисячі "
        "спроб входу на секунду через SSH (порт 22) або Winbox (8291). "
        "Слабкі паролі будуть зламані за лічені хвилини."
    )
    best_practice = (
        "Налаштувати blacklist за допомогою address-list та правил firewall: "
        "після N невдалих спроб — блокувати IP на певний час. "
        "Використовувати connection-limit та hashlimit для обмеження швидкості з'єднань."
    )
    resolution = "Додати правила захисту від брутфорсу у firewall filter."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_ssh_bruteforce = False
        has_winbox_bruteforce = False

        for rule in model.firewall_rules:
            line = rule.line.lower()
            comment = (rule.comment or "").lower()

            # Check for brute-force patterns
            if "brute" in comment or "bruteforce" in comment or "blacklist" in comment:
                if "22" in (rule.dst_port or "") or "ssh" in line:
                    has_ssh_bruteforce = True
                if "8291" in (rule.dst_port or "") or "winbox" in line:
                    has_winbox_bruteforce = True

            # connection-limit based
            if "connection-limit" in line and rule.action in ("add-src-to-address-list", "drop", "reject"):
                if "22" in (rule.dst_port or ""):
                    has_ssh_bruteforce = True
                if "8291" in (rule.dst_port or ""):
                    has_winbox_bruteforce = True

        if not has_ssh_bruteforce:
            warnings.append(
                "⚠️ Захист від brute-force SSH (порт 22) не виявлено — "
                "роутер відкритий для атак перебору паролів"
            )
            fixes.append(
                '# Захист SSH від брутфорсу\n'
                '/ip firewall filter\n'
                'add chain=input protocol=tcp dst-port=22 src-address-list=ssh-blacklist action=drop comment="SSH brute-force blacklist"\n'
                'add chain=input protocol=tcp dst-port=22 connection-limit=3,32 action=add-src-to-address-list address-list=ssh-blacklist address-list-timeout=1d comment="SSH brute-force: add to blacklist"\n'
                'add chain=input protocol=tcp dst-port=22 action=accept comment="SSH allow"'
            )

        if not has_winbox_bruteforce:
            warnings.append(
                "⚠️ Захист від brute-force Winbox (порт 8291) не виявлено"
            )
            fixes.append(
                '/ip firewall filter\n'
                'add chain=input protocol=tcp dst-port=8291 src-address-list=winbox-blacklist action=drop comment="Winbox brute-force blacklist"\n'
                'add chain=input protocol=tcp dst-port=8291 connection-limit=3,32 action=add-src-to-address-list address-list=winbox-blacklist address-list-timeout=1d comment="Winbox brute-force: add to blacklist"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditPortScanProtection(AuditPlugin):
    id = "BP-SEC-022"
    category = "security"
    severity = "medium"
    confidence = 90
    title = "Port Scan Detection & Protection"
    description = "Перевірка наявності захисту від сканування портів (port scan detection)."
    impact = (
        "Без захисту від port scanning зловмисники безперешкодно розвідують "
        "відкриті порти та сервіси роутера. Nmap scan покаже всі служби "
        "за кілька секунд без жодних наслідків для атакуючого."
    )
    best_practice = (
        "Додати правило detect-port-scan або NMAP-фінгерпринт блокування: "
        "TCP пакети з нестандартними комбінаціями flags (SYN+FIN, FIN без ACK, тощо) "
        "є ознакою сканування — блокувати та додавати в blacklist."
    )
    resolution = "Додати правила блокування port scan."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_port_scan_protection = False
        for rule in model.firewall_rules:
            comment = (rule.comment or "").lower()
            line = rule.line.lower()
            if "scan" in comment or "port-scan" in comment or "nmap" in comment:
                has_port_scan_protection = True
            if "tcp-flags" in line and rule.action in ("drop", "add-src-to-address-list"):
                has_port_scan_protection = True

        if not has_port_scan_protection:
            warnings.append(
                "⚠️ Захист від сканування портів (port scan) відсутній — "
                "зловмисники можуть вільно сканувати роутер без жодного блокування"
            )
            fixes.append(
                '# Захист від TCP port scanning (Nmap fingerprints)\n'
                '/ip firewall filter\n'
                'add chain=input protocol=tcp tcp-flags=fin,!syn,!rst,!psh,!ack,!urg action=add-src-to-address-list address-list=port-scanners address-list-timeout=2w comment="Port scan: NULL scan"\n'
                'add chain=input protocol=tcp tcp-flags=fin,syn action=add-src-to-address-list address-list=port-scanners address-list-timeout=2w comment="Port scan: SYN+FIN"\n'
                'add chain=input protocol=tcp tcp-flags=syn,rst action=add-src-to-address-list address-list=port-scanners address-list-timeout=2w comment="Port scan: SYN+RST"\n'
                'add chain=input protocol=tcp tcp-flags=fin,psh,urg,!syn,!rst,!ack action=add-src-to-address-list address-list=port-scanners address-list-timeout=2w comment="Port scan: Xmas scan"\n'
                'add chain=input src-address-list=port-scanners action=drop comment="Drop port scanners"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditIcmpFloodProtection(AuditPlugin):
    id = "BP-SEC-023"
    category = "security"
    severity = "medium"
    confidence = 88
    title = "ICMP Flood & Ping Protection"
    description = "Перевірка обмеження ICMP (ping) для захисту від ping flood атак."
    impact = (
        "Необмежений ICMP дозволяє flood атаки типу 'ping of death' та "
        "ICMP amplification. Також занадто відкритий ping з WAN надає "
        "зловмисникам інформацію про доступність роутера."
    )
    best_practice = (
        "Обмежити ICMP rate limit (не більше 10 pkt/s з одного джерела). "
        "Дозволити ping тільки з LAN або обмежити ICMP reply на WAN."
    )
    resolution = "Додати rate-limit для ICMP або обмежити джерела."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_icmp_limit = False
        for rule in model.firewall_rules:
            if rule.protocol == "icmp":
                if "limit" in rule.line.lower() or rule.action == "drop":
                    has_icmp_limit = True

        if not has_icmp_limit and model.firewall_rules:
            warnings.append(
                "⚠️ Відсутнє обмеження ICMP (ping) — можливий ping flood з WAN"
            )
            fixes.append(
                '/ip firewall filter\n'
                'add chain=input protocol=icmp limit=10,20:packet action=accept comment="Allow ICMP limited rate"\n'
                'add chain=input protocol=icmp action=drop comment="Drop excess ICMP (flood protection)"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditInvalidPackets(AuditPlugin):
    id = "BP-SEC-024"
    category = "security"
    severity = "high"
    confidence = 97
    title = "Drop Invalid Packets"
    description = "Перевірка наявності правила відкидання пакетів зі станом 'invalid' у connection tracking."
    impact = (
        "Пакети зі станом invalid (не відповідають жодному активному з'єднанню) "
        "є ознакою аномальних або спуфінгових пакетів. Без правила drop invalid "
        "вони можуть пропускатися через firewall та порушувати логіку файрволу."
    )
    best_practice = (
        "Перше або одне з перших правил у chain=input та chain=forward: "
        "connection-state=invalid action=drop"
    )
    resolution = "Додати drop invalid правило."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_drop_invalid_input = False
        has_drop_invalid_forward = False

        for rule in model.firewall_rules:
            state = rule.connection_state or ""
            if "invalid" in state and rule.action in ("drop", "reject"):
                if rule.chain == "input":
                    has_drop_invalid_input = True
                elif rule.chain == "forward":
                    has_drop_invalid_forward = True

        if not has_drop_invalid_input:
            warnings.append(
                "⚠️ Відсутнє правило drop invalid у chain=input — "
                "пакети без дійсного з'єднання можуть проходити"
            )
            fixes.append(
                '/ip firewall filter add chain=input connection-state=invalid action=drop comment="defconf: drop invalid"'
            )

        if not has_drop_invalid_forward:
            warnings.append(
                "⚠️ Відсутнє правило drop invalid у chain=forward — "
                "транзитні невалідні пакети не відкидаються"
            )
            fixes.append(
                '/ip firewall filter add chain=forward connection-state=invalid action=drop comment="defconf: drop invalid forwarded"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditRpFilter(AuditPlugin):
    id = "BP-SEC-025"
    category = "security"
    severity = "medium"
    confidence = 85
    title = "IP Spoofing Protection (RP Filter)"
    description = "Перевірка захисту від IP spoofing через Reverse Path Filtering або firewall-правила."
    impact = (
        "Без rp-filter або перевірки джерел зловмисники можуть підробляти "
        "вихідну IP-адресу (IP spoofing) для DDoS amplification атак "
        "через ваш роутер — роблячи вас учасником атаки."
    )
    best_practice = (
        "Увімкнути rp-filter=strict або loose на WAN інтерфейсах. "
        "Або додати правила firewall: блокувати RFC1918 адреси з WAN напрямку."
    )
    resolution = "Налаштувати захист від IP spoofing."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Check for rp-filter in raw config
        settings_lines = model.raw_sections.get("/ip settings", [])
        has_rp_filter = any("rp-filter" in l for l in settings_lines)

        # Check for bogon filtering in firewall
        has_bogon_filter = False
        rfc1918_nets = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
        for rule in model.firewall_rules:
            if rule.chain == "forward" and rule.action in ("drop", "reject"):
                src = rule.src_address or ""
                if any(net in src for net in rfc1918_nets):
                    in_if = (rule.in_interface_list or rule.in_interface or "").lower()
                    if "wan" in in_if:
                        has_bogon_filter = True

        if not has_rp_filter and not has_bogon_filter:
            warnings.append(
                "⚠️ Захист від IP spoofing (rp-filter) не виявлено — "
                "роутер може бути використаний для DDoS amplification"
            )
            fixes.append('/ip settings set rp-filter=strict')
            fixes.append(
                '# Альтернативно: блокувати RFC1918 адреси з WAN\n'
                '/ip firewall filter add chain=forward in-interface-list=WAN src-address=10.0.0.0/8 action=drop comment="Block RFC1918 from WAN"\n'
                '/ip firewall filter add chain=forward in-interface-list=WAN src-address=172.16.0.0/12 action=drop comment="Block RFC1918 from WAN"\n'
                '/ip firewall filter add chain=forward in-interface-list=WAN src-address=192.168.0.0/16 action=drop comment="Block RFC1918 from WAN"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditSSHCrypto(AuditPlugin):
    id = "BP-SEC-026"
    category = "security"
    severity = "medium"
    confidence = 95
    title = "SSH Strong Cryptography"
    description = "Перевірка увімкнення strong-crypto для SSH (сильні алгоритми шифрування)."
    impact = (
        "Без strong-crypto=yes SSH використовує старі алгоритми (DES, MD5, diffie-hellman-group1), "
        "вразливі до атак Logjam, SWEET32 та downgrade attacks."
    )
    best_practice = "Завжди встановлювати /ip ssh set strong-crypto=yes на RouterOS v6.49+/v7."
    resolution = "Увімкнути SSH strong-crypto."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        ssh_lines = model.raw_sections.get("/ip ssh", [])
        has_strong = any("strong-crypto=yes" in l for l in ssh_lines)

        if not has_strong:
            warnings.append(
                "⚠️ SSH: strong-crypto не увімкнено — можливі атаки на слабкі алгоритми шифрування"
            )
            fixes.append('/ip ssh set strong-crypto=yes')
        else:
            info.append("✅ SSH strong-crypto увімкнено")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditWinboxMACAccess(AuditPlugin):
    id = "BP-SEC-027"
    category = "security"
    severity = "medium"
    confidence = 92
    title = "MAC Telnet & MAC Server Security"
    description = "Перевірка обмеження MAC-рівневого доступу (MAC Telnet, MAC Server)."
    impact = (
        "MAC Telnet та MAC Server дозволяють підключення до роутера безпосередньо "
        "по MAC-адресі (рівень L2), обходячи IP файрвол. "
        "Якщо увімкнено для всіх інтерфейсів — будь-хто в сегменті може "
        "підключитися до роутера навіть без IP-адреси."
    )
    best_practice = "Обмежити MAC Telnet та MAC Server тільки LAN списком інтерфейсів."
    resolution = "Налаштувати allowed-interface-list=LAN."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        mac_server_lines = model.raw_sections.get("/tool mac-server", [])
        mac_telnet_lines = model.raw_sections.get("/tool mac-server telnet", [])

        for line in mac_server_lines + mac_telnet_lines:
            iface_list = get_param_value(line, "allowed-interface-list")
            if iface_list and iface_list.lower() in ("all", ""):
                warnings.append(
                    "⚠️ MAC Server/Telnet дозволено для всіх інтерфейсів — "
                    "доступ L2 без IP фільтрації відкритий навіть з WAN"
                )
                fixes.append('/tool mac-server set allowed-interface-list=LAN')
                fixes.append('/tool mac-server telnet set allowed-interface-list=LAN')
                break

        if not mac_server_lines:
            warnings.append(
                "⚠️ MAC Server не знайдено в конфігурації — "
                "за замовчуванням RouterOS дозволяє MAC Server для всіх інтерфейсів"
            )
            fixes.append('/tool mac-server set allowed-interface-list=LAN')

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditRogueDHCPProtection(AuditPlugin):
    id = "BP-SEC-028"
    category = "security"
    severity = "high"
    confidence = 85
    title = "Rogue DHCP Server Protection"
    description = "Перевірка захисту від шахрайських DHCP серверів у локальній мережі."
    impact = (
        "Без DHCP snooping (або аналога на MikroTik) будь-який пристрій у "
        "LAN-сегменті може стати DHCP сервером і видавати клієнтам підроблені "
        "шлюзи — класична атака MITM через DNS/Gateway hijacking."
    )
    best_practice = (
        "На MikroTik рекомендовано блокувати DHCP offer пакети (UDP 67→68) "
        "від не-авторизованих джерел через bridge firewall або firewall filter. "
        "Для CRS комутаторів — використовувати DHCP Snooping."
    )
    resolution = "Додати правила блокування rogue DHCP."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_dhcp_snoop = False
        for rule in model.firewall_rules:
            comment = (rule.comment or "").lower()
            line = rule.line.lower()
            if "rogue" in comment or "snooping" in comment or "dhcp" in comment:
                if "67" in (rule.dst_port or "") and rule.action in ("drop", "reject"):
                    has_dhcp_snoop = True

        # Check bridge firewall
        bridge_filter = model.raw_sections.get("/interface bridge filter", [])
        for line in bridge_filter:
            if "67" in line and "drop" in line:
                has_dhcp_snoop = True

        if not has_dhcp_snoop and model.dhcp_servers:
            warnings.append(
                "⚠️ Захист від Rogue DHCP (шахрайський DHCP сервер) не виявлено — "
                "будь-який LAN пристрій може підмінити DHCP і перехопити трафік клієнтів (MITM)"
            )
            fixes.append(
                '# Блокувати DHCP offer від незнайомих серверів (bridge firewall)\n'
                '/interface bridge filter\n'
                'add chain=forward action=drop mac-protocol=ip ip-protocol=udp dst-port=68 src-port=67 in-interface!=<dhcp_server_port> comment="Block rogue DHCP"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditIPv6Security(AuditPlugin):
    id = "BP-SEC-029"
    category = "security"
    severity = "medium"
    confidence = 90
    title = "IPv6 Firewall Configuration"
    description = "Перевірка наявності IPv6 файрволу при увімкненому IPv6."
    impact = (
        "Якщо IPv6 увімкнено, але /ipv6 firewall filter не налаштовано, "
        "всі IPv6 з'єднання проходять без фільтрації. Провайдери часто "
        "видають публічні IPv6 адреси, які напряму досяжні з інтернету — "
        "всі LAN пристрої можуть стати відкрито доступні."
    )
    best_practice = (
        "Якщо IPv6 використовується — налаштувати /ipv6 firewall filter "
        "аналогічно IPv4: drop invalid, accept established/related, "
        "drop input від WAN, drop forward від WAN до LAN."
    )
    resolution = "Налаштувати IPv6 firewall або вимкнути IPv6."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        ipv6_addr_lines = model.raw_sections.get("/ipv6 address", [])
        ipv6_firewall_lines = model.raw_sections.get("/ipv6 firewall filter", [])
        ipv6_settings = model.raw_sections.get("/ipv6 settings", [])

        ipv6_disabled = any("disable-ipv6=yes" in l for l in ipv6_settings)

        if ipv6_disabled:
            info.append("✅ IPv6 вимкнено")
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        if ipv6_addr_lines and not ipv6_firewall_lines:
            issues.append(
                "❌ IPv6 адреси налаштовано, але /ipv6 firewall filter відсутній — "
                "весь IPv6 трафік проходить без фільтрації, LAN пристрої можуть бути "
                "напряму доступні з інтернету через публічні IPv6 адреси"
            )
            fixes.append(
                '/ipv6 firewall filter\n'
                'add chain=input connection-state=invalid action=drop comment="drop invalid"\n'
                'add chain=input connection-state=established,related action=accept comment="accept established,related"\n'
                'add chain=input in-interface-list=WAN action=drop comment="drop from WAN"\n'
                'add chain=forward connection-state=invalid action=drop comment="drop invalid forward"\n'
                'add chain=forward in-interface-list=WAN action=drop comment="drop forward from WAN"'
            )
        elif not ipv6_addr_lines:
            info.append("ℹ️ IPv6 адреси не налаштовано")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditRouterIdentityDefault(AuditPlugin):
    id = "BP-SEC-030"
    category = "security"
    severity = "low"
    confidence = 98
    title = "Default Router Identity"
    description = "Перевірка зміни дефолтного імені роутера 'MikroTik'."
    impact = (
        "Роутер з іменем 'MikroTik' (за замовчуванням) легко ідентифікується "
        "зловмисниками як ненастроєний пристрій. Також MNDP broadcasts "
        "розкривають ім'я у мережі."
    )
    best_practice = "Змінити identity на унікальне ім'я, що відображає роль пристрою."
    resolution = "Встановити унікальне ім'я роутера."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        identity_lines = model.raw_sections.get("/system identity", [])
        for line in identity_lines:
            name = get_param_value(line, "name")
            if name and name.lower() in ("mikrotik", "router", ""):
                warnings.append(
                    f"⚠️ System Identity: Дефолтне ім'я '{name}' — "
                    "розкриває що пристрій може бути ненастроєним"
                )
                fixes.append('/system identity set name="Office-Router-01"')

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditUPnP(AuditPlugin):
    id = "BP-SEC-031"
    category = "security"
    severity = "high"
    confidence = 98
    title = "UPnP / NAT-PMP Security"
    description = "Перевірка стану UPnP (Universal Plug and Play) на роутері."
    impact = (
        "UPnP дозволяє будь-якій програмі в LAN автоматично відкривати порти "
        "у NAT без підтвердження адміністратора. Malware, ботнети та "
        "P2P-програми активно використовують UPnP для приховування трафіку."
    )
    best_practice = "Вимкнути UPnP якщо не потрібен, або обмежити інтерфейси тільки LAN."
    resolution = "Вимкнути або обмежити UPnP."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        upnp_lines = model.raw_sections.get("/ip upnp", [])
        for line in upnp_lines:
            enabled = get_param_value(line, "enabled")
            if enabled == "yes":
                issues.append(
                    "❌ UPnP увімкнено — будь-яка програма в LAN може автоматично "
                    "відкривати порти у NAT без відома адміністратора (небезпечно!)"
                )
                fixes.append('/ip upnp set enabled=no')

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
