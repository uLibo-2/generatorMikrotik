from typing import Dict, Any, List
from backend.models.network_model import NetworkModel

def audit_topology_model(model: NetworkModel) -> dict:
    chains = []

    # Extract IP interfaces
    ip_interfaces = []
    for ip in model.ips:
        ip_interfaces.append({"address": ip.address, "interface": ip.interface})

    if not ip_interfaces:
        ip_interfaces.append({"address": "192.168.88.1/24", "interface": "bridge"})

    # Determine default route status
    has_default_route = False
    # Check System IP routes
    # For now, default to True if route or dhcp client exists
    # Let's inspect route lists from raw sections
    route_lines = model.raw_sections.get("/ip route", [])
    for line in route_lines:
        if "gateway=" in line and ("dst-address=0.0.0.0/0" in line or "dst-address=" not in line):
            has_default_route = True
            break
    dhcp_client_lines = model.raw_sections.get("/ip dhcp-client", [])
    for line in dhcp_client_lines:
        if "add-default-route=no" not in line and "disabled=yes" not in line:
            has_default_route = True
            break

    # Determine NAT status
    has_masquerade = False
    for rule in model.firewall_nat:
        if rule.chain == "srcnat" and rule.action == "masquerade":
            has_masquerade = True
            break

    # Determine Bridge Filtering
    bridge_vlan_filtering = False
    for br in model.bridges:
        if br.vlan_filtering:
            bridge_vlan_filtering = True
            break

    for ip_if in ip_interfaces:
        iface = ip_if["interface"]
        addr = ip_if["address"]

        vlan_id = None
        is_wifi = False
        ssid = None
        wifi_profile = None

        # Check if interface is a VLAN
        for v in model.vlans:
            if v.name == iface:
                vlan_id = v.vlan_id
                break

        # Check if wifi uses this VLAN
        for w in model.wifi:
            if w.vlan_id == vlan_id or (vlan_id is None and iface in ("bridge", "bridge-local")):
                is_wifi = True
                ssid = w.ssid
                wifi_profile = w.security_profile or "default"
                break

        steps = [{"name": "Клієнт", "status": "ok", "detail": "Пристрої кінцевих користувачів"}]

        if is_wifi:
            steps.append({"name": f"SSID: {ssid}", "status": "ok", "detail": f"Шифрування: {wifi_profile}"})
        else:
            steps.append({"name": "Ethernet", "status": "ok", "detail": "Дротове підключення до портів"})

        if vlan_id:
            if bridge_vlan_filtering:
                steps.append({"name": f"VLAN {vlan_id}", "status": "ok", "detail": f"VLAN інтерфейс {iface} активний на Bridge"})
            else:
                steps.append({"name": f"VLAN {vlan_id}", "status": "warning", "detail": "VLAN створено, але vlan-filtering вимкнено на Bridge!"})
        else:
            steps.append({"name": "Bridge (L2)", "status": "ok", "detail": f"Локальний міст '{iface}'"})

        # Check DHCP server
        has_dhcp = False
        dhcp_pool = None
        for d in model.dhcp_servers:
            if d.interface == iface:
                has_dhcp = True
                dhcp_pool = d.address_pool
                break

        if has_dhcp:
            steps.append({"name": "DHCP", "status": "ok", "detail": f"DHCP сервер активний (Pool: {dhcp_pool})"})
        else:
            steps.append({"name": "DHCP", "status": "warning", "detail": "DHCP сервер відсутній (статична адресація клієнтів)"})

        steps.append({"name": "IP Шлюз", "status": "ok", "detail": f"IP адреса роутера: {addr}"})

        if has_default_route:
            steps.append({"name": "Маршрут", "status": "ok", "detail": "Дефолтний маршрут 0.0.0.0/0 налаштовано"})
        else:
            steps.append({"name": "Маршрут", "status": "error", "detail": "Немає дефолтного маршруту (роутер не має виходу в Інтернет)"})

        if has_masquerade:
            steps.append({"name": "NAT", "status": "ok", "detail": "Маскарадинг (srcnat masquerade) увімкнено"})
        else:
            steps.append({"name": "NAT", "status": "error", "detail": "NAT вимкнено (клієнти не матимуть доступу до Інтернету)"})

        chain_status = "ok"
        if any(s["status"] == "error" for s in steps):
            chain_status = "error"
            steps.append({"name": "Інтернет", "status": "error", "detail": "Доступ перервано через помилки"})
        elif any(s["status"] == "warning" for s in steps):
            chain_status = "warning"
            steps.append({"name": "Інтернет", "status": "warning", "detail": "Доступ обмежений"})
        else:
            steps.append({"name": "Інтернет", "status": "ok", "detail": "Доступ до Інтернету надано"})

        chains.append({
            "network": f"Мережа {iface} ({addr})",
            "status": chain_status,
            "chain_steps": steps
        })

    return {"chains": chains}
