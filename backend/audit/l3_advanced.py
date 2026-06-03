"""
Advanced L3/Routing Audit Plugins for MikroTik RouterOS
Covers: NAT, Masquerade, Routing policy, QoS/Queue, DNS, PPPoE, Multi-WAN
"""
import ipaddress
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value


@registry.register
class AuditMasqueradeNAT(AuditPlugin):
    id = "BP-NAT-001"
    category = "l3"
    severity = "critical"
    confidence = 100
    title = "Masquerade/srcnat NAT Rule"
    description = "Перевірка наявності правила srcnat masquerade для виходу клієнтів в Інтернет."
    impact = (
        "Без правила srcnat masquerade клієнти LAN не матимуть доступу до Інтернету: "
        "їхній трафік буде відправлений провайдеру з приватними IP-адресами, "
        "які будуть відкинуті на першому ж маршрутизаторі."
    )
    best_practice = (
        "Завжди мати правило: /ip firewall nat add chain=srcnat "
        "out-interface-list=WAN action=masquerade — або src-nat з конкретним IP "
        "якщо є статична IP-адреса провайдера (ефективніше)."
    )
    resolution = "Додати правило srcnat masquerade."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_masquerade = False
        has_src_nat = False
        masq_rule = None

        for rule in model.firewall_nat:
            if rule.chain == "srcnat":
                if rule.action == "masquerade":
                    has_masquerade = True
                    masq_rule = rule
                elif rule.action == "src-nat":
                    has_src_nat = True

        if not has_masquerade and not has_src_nat:
            issues.append(
                "❌ NAT: Відсутнє правило srcnat masquerade — "
                "клієнти LAN не зможуть вийти в Інтернет"
            )
            fixes.append(
                '/ip firewall nat add chain=srcnat out-interface-list=WAN action=masquerade comment="defconf: masquerade"'
            )
        elif has_src_nat and not has_masquerade:
            info.append("✅ NAT: Налаштовано src-nat зі статичною IP (ефективніше за masquerade)")
        elif has_masquerade:
            # Check if masquerade has out-interface or out-interface-list
            if masq_rule:
                if not masq_rule.out_interface and not masq_rule.out_interface_list:
                    warnings.append(
                        "⚠️ NAT: Masquerade без вказання out-interface або out-interface-list — "
                        "буде застосовуватись до ВСІХ вихідних інтерфейсів, включаючи LAN"
                    )
                    fixes.append(
                        '/ip firewall nat set [find action=masquerade] out-interface-list=WAN'
                    )
                else:
                    info.append("✅ NAT: Masquerade налаштовано коректно")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditDstNATHairpin(AuditPlugin):
    id = "BP-NAT-002"
    category = "l3"
    severity = "low"
    confidence = 85
    title = "Hairpin NAT (NAT Loopback)"
    description = "Перевірка налаштування Hairpin NAT для доступу до внутрішніх серверів через зовнішній IP."
    impact = (
        "Без Hairpin NAT (NAT loopback) внутрішні користувачі не можуть "
        "звернутись до внутрішнього сервера через його зовнішній IP/домен — "
        "з'єднання буде відхилено або зависне."
    )
    best_practice = (
        "При наявності dstnat правил (port forwarding) — додати відповідне "
        "srcnat правило для LAN to LAN трафіку через зовнішній IP (hairpin)."
    )
    resolution = "Налаштувати Hairpin NAT якщо є dstnat правила."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        dstnat_rules = [r for r in model.firewall_nat if r.chain == "dstnat"]
        srcnat_rules = [r for r in model.firewall_nat if r.chain == "srcnat"]

        if not dstnat_rules:
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        has_hairpin = False
        for rule in srcnat_rules:
            if rule.action in ("masquerade", "src-nat"):
                in_iface = rule.in_interface or rule.in_interface_list or ""
                if "lan" in in_iface.lower() or "bridge" in in_iface.lower():
                    has_hairpin = True

        if not has_hairpin:
            info.append(
                "ℹ️ NAT: Є dstnat правила (port forwarding), але Hairpin NAT не виявлено — "
                "клієнти LAN можуть не мати доступу до сервісів через зовнішній IP"
            )
            fixes.append(
                '# Hairpin NAT: дозволити LAN клієнтам звертатись через зовнішній IP\n'
                '/ip firewall nat add chain=srcnat action=masquerade src-address=192.168.88.0/24 out-interface=bridge comment="Hairpin NAT"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditQueueTree(AuditPlugin):
    id = "BP-QOS-001"
    category = "performance"
    severity = "medium"
    confidence = 88
    title = "QoS / Traffic Shaping (Queue)"
    description = "Перевірка наявності QoS (quality of service) для пріоритизації трафіку."
    impact = (
        "Без QoS при повному завантаженні каналу VoIP дзвінки стають нечіткими, "
        "відеоконференції зависають, а ігри лагають — бо весь трафік "
        "обробляється з однаковим пріоритетом FIFO."
    )
    best_practice = (
        "Налаштувати Simple Queue або Queue Tree для пріоритизації: "
        "VoIP (DSCP EF) > відеоконференції > загальний трафік. "
        "Обмежити bandwidth на клієнтів для справедливого розподілу."
    )
    resolution = "Налаштувати QoS черги (queue)."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        queue_lines = model.raw_sections.get("/queue simple", []) or []
        queue_tree = model.raw_sections.get("/queue tree", []) or []
        mangle_dscp = [
            r for r in getattr(model, "firewall_mangle", [])
            if hasattr(r, "action") and "dscp" in (r.action or "").lower()
        ]

        if not queue_lines and not queue_tree:
            info.append(
                "ℹ️ QoS черги не налаштовано — при повному завантаженні каналу "
                "весь трафік матиме однаковий пріоритет"
            )
            fixes.append(
                '# Базова QoS для WAN (приклад 100 Мбіт/с)\n'
                '/queue simple\n'
                'add name=wan-shaper target=192.168.88.0/24 max-limit=100M/100M priority=8 comment="WAN bandwidth shaping"'
            )
        else:
            info.append(f"✅ QoS/Queue налаштовано ({len(queue_lines)} simple, {len(queue_tree)} tree entries)")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditPPPoEMTU(AuditPlugin):
    id = "BP-L3-010"
    category = "l3"
    severity = "medium"
    confidence = 92
    title = "PPPoE MTU / MRU Configuration"
    description = "Перевірка коректності MTU/MRU для PPPoE з'єднань."
    impact = (
        "PPPoE зменшує MTU на 8 байт (1500 → 1492). Якщо MTU/MRU не виставлено "
        "явно або MSS clamping відсутній — великі TCP сегменти не проходять, "
        "що проявляється як 'сайти не відкриваються' або 'HTTPS зависає'."
    )
    best_practice = (
        "Встановити на PPPoE клієнті: mtu=1480 mru=1480 або mtu=1492 mru=1492. "
        "Додати MSS clamping mangle правило для тунелів."
    )
    resolution = "Виправити MTU/MRU або додати MSS clamping."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        pppoe_lines = model.raw_sections.get("/interface pppoe-client", [])
        for line in pppoe_lines:
            mtu = get_param_value(line, "mtu")
            mru = get_param_value(line, "mru")
            name = get_param_value(line, "name") or "pppoe-out"
            disabled = get_param_value(line, "disabled") == "yes"

            if disabled:
                continue

            if mtu and int(mtu) > 1492:
                warnings.append(
                    f"⚠️ PPPoE '{name}': MTU={mtu} завеликий для PPPoE — "
                    "рекомендується mtu=1492 або менше"
                )
                fixes.append(f'/interface pppoe-client set [find name={name}] mtu=1492 mru=1492')

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditLoopbackAddress(AuditPlugin):
    id = "BP-L3-011"
    category = "l3"
    severity = "low"
    confidence = 85
    title = "Loopback Interface for BGP/OSPF"
    description = "Перевірка наявності loopback-інтерфейсу при використанні динамічної маршрутизації."
    impact = (
        "Без loopback адреси (Lo/dummy) при BGP або OSPF — Router-ID буде "
        "автоматично обрано з фізичних інтерфейсів. Якщо цей інтерфейс впаде — "
        "Router-ID зміниться і BGP/OSPF сесії впадуть."
    )
    best_practice = (
        "При використанні BGP чи OSPF — створити loopback інтерфейс "
        "(bridge або dummy) зі стабільною IP та вказати її як router-id."
    )
    resolution = "Створити loopback інтерфейс."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_bgp = bool(model.raw_sections.get("/routing bgp", []) or model.raw_sections.get("/routing/bgp", []))
        has_ospf = bool(model.raw_sections.get("/routing ospf", []) or model.raw_sections.get("/routing/ospf", []))

        if not has_bgp and not has_ospf:
            return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

        has_loopback = any(
            "lo" in iface.name.lower() or "loopback" in iface.name.lower() or "dummy" in iface.name.lower()
            for iface in model.interfaces
        )

        if not has_loopback:
            protocol = "BGP" if has_bgp else "OSPF"
            warnings.append(
                f"⚠️ {protocol} налаштовано, але loopback інтерфейс відсутній — "
                "Router-ID нестабільний, при падінні WAN інтерфейсу {protocol} сесії перезапустяться"
            )
            fixes.append(
                '/interface bridge add name=lo comment="Loopback interface"\n'
                '/ip address add address=10.255.255.1/32 interface=lo comment="Loopback IP"'
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditStaticDNS(AuditPlugin):
    id = "BP-L3-012"
    category = "l3"
    severity = "medium"
    confidence = 95
    title = "DNS Server Configuration"
    description = "Перевірка налаштування DNS серверів та кешу."
    impact = (
        "Без явно налаштованих DNS серверів роутер може використовувати "
        "DNS провайдера, що може не підтримувати DNSSEC або уповільнювати "
        "запити. Відсутній DNS кеш збільшує latency для всіх клієнтів."
    )
    best_practice = (
        "Налаштувати надійні DNS: 1.1.1.1 (Cloudflare), 8.8.8.8 (Google), "
        "або 9.9.9.9 (Quad9 з DNSSEC). "
        "Увімкнути allow-remote-requests=yes для кешування на роутері."
    )
    resolution = "Налаштувати DNS сервери."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        if not model.dns_servers:
            warnings.append(
                "⚠️ DNS сервери не налаштовано явно — "
                "роутер може використовувати DNS провайдера без кешування"
            )
            fixes.append('/ip dns set servers=1.1.1.1,8.8.8.8 allow-remote-requests=yes')
        else:
            # Check for known bad DNS
            all_dns_text = ",".join(model.dns_servers)
            info.append(f"✅ DNS налаштовано: {all_dns_text}")

            # Check cache
            dns_lines = model.raw_sections.get("/ip dns", [])
            for line in dns_lines:
                cache_size = get_param_value(line, "cache-size")
                if cache_size and int(cache_size.replace("KiB", "").replace("MiB", "000")) < 512:
                    warnings.append(
                        f"⚠️ DNS кеш занадто малий ({cache_size}) — "
                        "збільшіть для кращої продуктивності"
                    )
                    fixes.append('/ip dns set cache-size=4096KiB')

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditMultiWANLoadBalancing(AuditPlugin):
    id = "BP-MWAN-001"
    category = "l3"
    severity = "medium"
    confidence = 82
    title = "Multi-WAN Failover/Load Balancing"
    description = "Перевірка конфігурації Multi-WAN з failover або балансуванням навантаження."
    impact = (
        "При наявності двох WAN інтерфейсів без правильного налаштування ECMP "
        "або PCC маршрутизації — один з провайдерів буде простоювати. "
        "При відмові основного провайдера без failover — мережа зупиниться."
    )
    best_practice = (
        "Для failover: налаштувати check-gateway=ping на маршрутах та "
        "резервний маршрут з більшою distance (відстанню). "
        "Для балансування: використовувати Recursive routing або Netwatch + scripts."
    )
    resolution = "Налаштувати Multi-WAN failover або балансування."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Find WAN-like interfaces
        wan_candidates = []
        for iface in model.interfaces:
            if "wan" in iface.name.lower() or "isp" in iface.name.lower() or "pppoe" in iface.name.lower():
                if not iface.disabled:
                    wan_candidates.append(iface.name)

        pppoe_clients = model.raw_sections.get("/interface pppoe-client", [])
        for line in pppoe_clients:
            name = get_param_value(line, "name")
            disabled = get_param_value(line, "disabled") == "yes"
            if name and not disabled:
                wan_candidates.append(name)

        # Deduplicate
        wan_candidates = list(set(wan_candidates))

        if len(wan_candidates) >= 2:
            route_lines = model.raw_sections.get("/ip route", [])
            has_check_gateway = any("check-gateway" in l for l in route_lines)
            has_distance_routes = len([l for l in route_lines if "distance=" in l and "0.0.0.0/0" in l]) >= 2

            if not has_check_gateway:
                warnings.append(
                    f"⚠️ Multi-WAN: Виявлено {len(wan_candidates)} WAN-подібних інтерфейси ({', '.join(wan_candidates[:3])}), "
                    "але check-gateway=ping відсутній на маршрутах — failover не буде автоматичним"
                )
                fixes.append(
                    '# Multi-WAN failover: додати check-gateway до маршрутів\n'
                    '/ip route set [find dst-address=0.0.0.0/0] check-gateway=ping\n'
                    '# Резервний маршрут з distance=2:\n'
                    '/ip route add dst-address=0.0.0.0/0 gateway=<ISP2_GW> distance=2 check-gateway=ping comment="WAN2 backup"'
                )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}


@registry.register
class AuditConnectionRateLimit(AuditPlugin):
    id = "BP-L3-013"
    category = "l3"
    severity = "low"
    confidence = 80
    title = "Connection Table Limits"
    description = "Перевірка налаштувань таблиці з'єднань та захисту від connection exhaustion."
    impact = (
        "Без обмеження на кількість з'єднань з одного джерела один заражений "
        "хост може заповнити всю connection table (128K+ entries) роутера, "
        "що призведе до відмови обслуговування для всіх інших клієнтів."
    )
    best_practice = (
        "Обмежити кількість одночасних з'єднань на клієнта через "
        "connection-limit правило у firewall filter."
    )
    resolution = "Додати connection-limit для захисту connection table."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_conn_limit = any(
            "connection-limit" in r.line.lower()
            for r in model.firewall_rules
            if r.chain == "forward"
        )

        if not has_conn_limit and model.firewall_rules:
            info.append(
                "ℹ️ Обмеження кількості з'єднань (connection-limit) для клієнтів не виявлено — "
                "один заражений вірусом хост може вичерпати connection table"
            )

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
