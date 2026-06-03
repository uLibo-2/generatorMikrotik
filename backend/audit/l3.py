import ipaddress
from typing import Dict, Any
from backend.audit.base import AuditPlugin, registry
from backend.models.network_model import NetworkModel
from backend.parsers.base import get_param_value

@registry.register
class AuditDhcpConsistency(AuditPlugin):
    id = "BP-L3-001"
    category = "l3"
    severity = "critical"
    confidence = 98
    title = "DHCP Server & Subnet Gateway Consistency"
    description = "Перевірка зв'язку DHCP сервера, IP адреси інтерфейсу та пулу адрес."
    impact = "Якщо DHCP сервер запущено на інтерфейсі без IP адреси, або гейтвей DHCP мережі не належить до підмережі інтерфейсу, клієнти не зможуть отримати IP або вийти в мережу."
    best_practice = "Інтерфейс DHCP повинен мати статичну IP адресу. Пул DHCP та гейтвей повинні повністю належати до цієї мережі."
    resolution = "Створити IP адресу на інтерфейсі або виправити DHCP налаштування."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        # Build address mapping
        iface_ips = {}
        for ip in model.ips:
            try:
                # address could be 192.168.88.1/24
                net = ipaddress.ip_network(ip.address, strict=False)
                iface_ips.setdefault(ip.interface, []).append((ip.address, net))
            except: pass

        for dhcp in model.dhcp_servers:
            if dhcp.disabled:
                continue

            # Check: Does the interface have any IP?
            if dhcp.interface not in iface_ips:
                issues.append(f"❌ DHCP: Сервер '{dhcp.name}' запущено на інтерфейсі '{dhcp.interface}', який не має жодної IP адреси")
                fixes.append(f"/ip address add address=192.168.88.1/24 interface={dhcp.interface}")
                continue

            # Check: Does the pool exist?
            pool_found = None
            for pool in model.dhcp_pools:
                if pool.name == dhcp.address_pool:
                    pool_found = pool
                    break

            if not pool_found:
                issues.append(f"❌ DHCP: Сервер '{dhcp.name}' посилається на неіснуючий пул '{dhcp.address_pool}'")
                fixes.append(f"/ip pool add name={dhcp.address_pool} ranges=192.168.88.10-192.168.88.254")
                continue

            # Find matching network network
            matching_network = None
            for net in model.dhcp_networks:
                # Match DHCP Network gateway/subnet with interface network
                try:
                    dhcp_net = ipaddress.ip_network(net.address, strict=False)
                    for ip_addr_str, ip_net in iface_ips[dhcp.interface]:
                        if ip_net.overlaps(dhcp_net):
                            matching_network = (net, ip_addr_str, ip_net)
                            break
                except: pass

            if not matching_network:
                # Only report if there are DHCP networks defined but none match
                if model.dhcp_networks:
                    warnings.append(f"⚠️ DHCP: Не вдалося зіставити мережу DHCP сервера '{dhcp.name}' з IP-адресою інтерфейсу '{dhcp.interface}' — перевірте вручну")
            else:
                dhcp_net_obj, ip_addr_str, ip_net = matching_network
                # Verify gateway ip belongs to subnet
                try:
                    gw_ip = ipaddress.ip_address(dhcp_net_obj.gateway)
                    if gw_ip not in ip_net:
                        issues.append(f"❌ DHCP: Шлюз DHCP '{dhcp_net_obj.gateway}' не належить до підмережі інтерфейсу '{ip_addr_str}'")
                except: pass

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditDefaultRoute(AuditPlugin):
    id = "BP-L3-002"
    category = "l3"
    severity = "critical"
    confidence = 100
    title = "Default Gateway Route"
    description = "Перевірка наявності дефолтного маршруту (маршруту за замовчуванням) для виходу в Інтернет."
    impact = "Без маршруту за замовчуванням (0.0.0.0/0) пристрій та його локальні клієнти не матимуть доступу до зовнішніх мереж та Інтернету."
    best_practice = "Завжди налаштовувати принаймні один активний маршрут з dst-address=0.0.0.0/0 через шлюз провайдера або увімкнути add-default-route=yes на DHCP клієнті WAN."
    resolution = "Додати дефолтний маршрут."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        has_default_route = False
        # RouterOS route parsing from raw config
        route_lines = model.raw_sections.get("/ip route", [])
        for line in route_lines:
            dst = get_param_value(line, "dst-address")
            gateway = get_param_value(line, "gateway")
            if (dst == "0.0.0.0/0" or not dst) and gateway:
                has_default_route = True

        # Also check dhcp-client default route option
        # In RouterOS, add-default-route defaults to 'yes' when not specified
        dhcp_client_lines = model.raw_sections.get("/ip dhcp-client", [])
        for line in dhcp_client_lines:
            disabled = get_param_value(line, "disabled") == "yes"
            add_default = get_param_value(line, "add-default-route")
            # Default is 'yes' if not specified
            if not disabled and add_default != "no":
                has_default_route = True
                info.append(f"ℹ️ Маршрутизація: Дефолтний маршрут буде отримано динамічно через DHCP клієнт")

        if not has_default_route:
            # Check WAN interfaces
            wan_candidate = "ether1"
            for iface in model.interfaces:
                if "wan" in iface.name.lower() or "isp" in iface.name.lower():
                    wan_candidate = iface.name
                    break
            issues.append("❌ Маршрутизація: Відсутній дефолтний маршрут (0.0.0.0/0) — немає виходу в Інтернет")
            fixes.append(f"/ip dhcp-client add interface={wan_candidate} disabled=no comment=\"defconf: WAN client\"")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditDuplicateStaticLeases(AuditPlugin):
    id = "BP-L3-003"
    category = "l3"
    severity = "high"
    confidence = 98
    title = "Duplicate DHCP Static Leases"
    description = "Пошук дублюючих записів статичної прив'язки IP та MAC адрес в DHCP сервері."
    impact = "Дублювання MAC адрес або призначення однієї IP декільком MAC адресам призведе к конфлікту адрес та періодичної втрати зв'язку в одного чи обох клієнтів."
    best_practice = "Кожен клієнт (MAC) повинен мати унікальну IP-адресу у списку статичних лізів."
    resolution = "Видалити дублюючі записи DHCP."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        seen_macs = {}
        seen_ips = {}

        for lease in model.dhcp_static_leases:
            # Check MAC
            mac = lease.mac_address.lower()
            if mac in seen_macs:
                issues.append(f"❌ DHCP: Знайдено дублювання статичного лізу для MAC '{lease.mac_address}' (IP {lease.address} та {seen_macs[mac]})")
            else:
                seen_macs[mac] = lease.address

            # Check IP
            ip = lease.address
            if ip in seen_ips:
                issues.append(f"❌ DHCP: Знайдено дублювання призначення IP '{ip}' для різних MAC ({lease.mac_address} та {seen_ips[ip]})")
            else:
                seen_ips[ip] = lease.mac_address

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}

@registry.register
class AuditSubnetOverlaps(AuditPlugin):
    id = "BP-L3-004"
    category = "l3"
    severity = "critical"
    confidence = 95
    title = "Subnet Overlap Detection"
    description = "Пошук перетинів IP підмереж на різних мережевих інтерфейсах пристрою."
    impact = "Перетин підмереж ламає таблицю маршрутизації (Connected routes). Роутер не знатиме, куди саме надсилати трафік, що призведе до непрацездатності одного з сегментів."
    best_practice = "Кожен інтерфейс / VLAN повинен використовувати свій унікальний неперетинний діапазон IP-адрес."
    resolution = "Змінити IP-адресацію на одному з інтерфейсів."

    def run(self, model: NetworkModel) -> Dict[str, Any]:
        issues, warnings, fixes, info = [], [], [], []

        networks = []
        for ip in model.ips:
            try:
                net = ipaddress.ip_network(ip.address, strict=False)
                networks.append((ip.interface, ip.address, net))
            except: pass

        for i in range(len(networks)):
            iface_a, addr_a, net_a = networks[i]
            for j in range(i + 1, len(networks)):
                iface_b, addr_b, net_b = networks[j]
                if iface_a != iface_b and net_a.overlaps(net_b):
                    issues.append(f"❌ Конфлікт IP: Підмережа '{addr_a}' на інтерфейсі '{iface_a}' перетинається з підмережею '{addr_b}' на інтерфейсі '{iface_b}'")

        return {"issues": issues, "warnings": warnings, "fixes": fixes, "info": info, "recs": []}
