# -*- coding: utf-8 -*-
"""
MikroTik RouterOS Infrastructure Migration Engine
Implements Reference Resolution, Intent Mapping, Version Translation, and Subnet Recalculation.
"""
import ipaddress
import re
from typing import List, Dict, Any, Tuple
from backend.parsers.ast_parser import RouterOS_AST, ASTNode

class ReferenceResolver:
    """Resolves names and ids of RouterOS entities into logical parent-child trees."""
    @staticmethod
    def resolve_ast_references(ast: RouterOS_AST) -> Dict[str, Any]:
        bridges = {}
        vlans = {}
        ips = []
        dhcp_servers = []
        dhcp_pools = []

        for node in ast.nodes:
            if node.action != "add":
                continue

            if node.path == "/interface bridge":
                name = node.params.get("name", "").strip('"\'')
                if name:
                    bridges[name] = {"ports": [], "vlans": [], "ips": [], "dhcp": []}

            elif node.path == "/interface vlan":
                name = node.params.get("name", "").strip('"\'')
                v_id = node.params.get("vlan-id", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                if name:
                    vlans[name] = {"vlan_id": v_id, "parent_interface": iface, "ips": [], "dhcp": []}

            elif node.path == "/ip address":
                addr = node.params.get("address", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                if addr and iface:
                    ips.append({"address": addr, "interface": iface})

            elif node.path == "/ip dhcp-server":
                name = node.params.get("name", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                pool = node.params.get("address-pool", "").strip('"\'')
                if name and iface:
                    dhcp_servers.append({"name": name, "interface": iface, "pool": pool})

            elif node.path == "/ip pool":
                name = node.params.get("name", "").strip('"\'')
                ranges = node.params.get("ranges", "").strip('"\'')
                if name and ranges:
                    dhcp_pools.append({"name": name, "ranges": ranges})

        # Resolve interfaces hierarchy
        # 1. Bind VLANs to Bridges
        for v_name, v_data in vlans.items():
            parent = v_data["parent_interface"]
            if parent in bridges:
                bridges[parent]["vlans"].append(v_name)

        # 2. Bind IP Addresses to Bridges or VLANs
        for ip in ips:
            iface = ip["interface"]
            if iface in bridges:
                bridges[iface]["ips"].append(ip["address"])
            elif iface in vlans:
                vlans[iface]["ips"].append(ip["address"])
                # propagate to parent bridge if VLAN parent is bridge
                p_iface = vlans[iface]["parent_interface"]
                if p_iface in bridges:
                    bridges[p_iface]["ips"].append(f"{ip['address']} (via {iface})")

        # 3. Bind DHCP Servers and Pools to Interfaces
        for srv in dhcp_servers:
            iface = srv["interface"]
            pool_data = next((p for p in dhcp_pools if p["name"] == srv["pool"]), None)
            pool_range = pool_data["ranges"] if pool_data else "no-pool-range"

            srv_info = {"name": srv["name"], "pool": srv["pool"], "ranges": pool_range}
            if iface in bridges:
                bridges[iface]["dhcp"].append(srv_info)
            elif iface in vlans:
                vlans[iface]["dhcp"].append(srv_info)

        return {
            "bridges": bridges,
            "vlans": vlans,
            "dhcp_pools": dhcp_pools
        }

class InterfaceIntentEngine:
    """Classifies interfaces by their logical intent (WAN, Trunk, Access)."""
    @staticmethod
    def classify_interfaces(ast: RouterOS_AST) -> Dict[str, List[str]]:
        intents = {"WAN": [], "LAN_TRUNK": [], "ACCESS": []}

        # 1. Inspect list members (WAN lists)
        for node in ast.nodes:
            if node.path == "/interface list member" and node.action == "add":
                iface = node.params.get("interface", "").strip('"\'')
                lst = node.params.get("list", "").strip('"\'')
                if iface and lst == "WAN":
                    intents["WAN"].append(iface)

        # 2. Inspect comments on ethernet interfaces
        for node in ast.nodes:
            if node.path == "/interface ethernet" and node.action == "set":
                comment = node.params.get("comment", "").strip('"\'')
                # find interface default-name or name from finder
                name_match = re.search(r'default-name=([^\s\]]+)', node.finder)
                if name_match and comment:
                    name = name_match.group(1)
                    if "ISP" in comment.upper() or "WAN" in comment.upper():
                        intents["WAN"].append(name)

        # 3. Inspect bridge ports to find trunks and access ports
        trunk_ports = set()
        access_ports = set()
        for node in ast.nodes:
            if node.path == "/interface bridge port" and node.action == "add":
                iface = node.params.get("interface", "").strip('"\'')
                pvid = node.params.get("pvid", "").strip('"\'')
                if iface:
                    if pvid and pvid != "1":
                        access_ports.add(iface)
                    else:
                        trunk_ports.add(iface)

        intents["LAN_TRUNK"] = list(trunk_ports)
        intents["ACCESS"] = list(access_ports)

        # De-duplicate WANs
        intents["WAN"] = list(set(intents["WAN"]))

        return intents

class IPRecalculator:
    """Recalculates IP networks and subnets safely using prefix offsets."""
    @staticmethod
    def shift_ip(ip_str: str, src_base: str, dst_base: str) -> str:
        """
        Translates an IP or subnet from src_base to dst_base keeping host index.
        Example: shift_ip("10.16.132.1/24", "10.16.132.0/24", "10.50.10.0/24") ➔ "10.50.10.1/24"
        """
        try:
            src_net = ipaddress.ip_network(src_base, strict=False)
            dst_net = ipaddress.ip_network(dst_base, strict=False)

            # Extract mask if present
            mask = ""
            if "/" in ip_str:
                ip_str, mask = ip_str.split("/", 1)

            clean_ip = ip_str.strip('"\'')
            ip_addr = ipaddress.ip_address(clean_ip)

            if ip_addr not in src_net:
                # Outside target subnet, leave as is
                return ip_str + (f"/{mask}" if mask else "")

            # Calculate host offset index
            offset = int(ip_addr) - int(src_net.network_address)

            # Apply to destination network address
            target_ip = dst_net.network_address + offset

            # If no custom mask was passed, default to target subnet mask
            final_mask = mask if mask else str(dst_net.prefixlen)

            return f"{target_ip}/{final_mask}"
        except Exception:
            return ip_str

    @staticmethod
    def shift_range(range_str: str, src_base: str, dst_base: str) -> str:
        """Shifts DHCP ranges: e.g. "10.16.132.50-10.16.132.250" ➔ "10.50.10.50-10.50.10.250"."""
        range_str = range_str.strip('"\'')
        if "-" not in range_str:
            return IPRecalculator.shift_ip(range_str, src_base, dst_base)

        parts = range_str.split("-")
        if len(parts) == 2:
            start = IPRecalculator.shift_ip(parts[0].strip(), src_base, dst_base).split("/")[0]
            end = IPRecalculator.shift_ip(parts[1].strip(), src_base, dst_base).split("/")[0]
            return f"{start}-{end}"
        return range_str

    @classmethod
    def recalculate_ast_ips(cls, ast: RouterOS_AST, src_base: str, dst_base: str) -> RouterOS_AST:
        """Iterates over AST nodes and shifts all IP addresses, subnets, and pools."""
        for node in ast.nodes:
            if not node.params:
                continue

            # Shift /ip address parameters
            if node.path == "/ip address":
                addr = node.params.get("address")
                net = node.params.get("network")
                if addr:
                    node.params["address"] = f'"{cls.shift_ip(addr, src_base, dst_base)}"'
                if net:
                    # network is just an IP without mask
                    node.params["network"] = cls.shift_ip(net, src_base, dst_base).split("/")[0]

            # Shift /ip pool ranges
            elif node.path == "/ip pool":
                ranges = node.params.get("ranges")
                if ranges:
                    node.params["ranges"] = f'"{cls.shift_range(ranges, src_base, dst_base)}"'

            # Shift /ip dhcp-server network subnets and gateways
            elif node.path == "/ip dhcp-server network":
                addr = node.params.get("address")
                gw = node.params.get("gateway")
                dns = node.params.get("dns-server")
                if addr:
                    node.params["address"] = f'"{cls.shift_ip(addr, src_base, dst_base)}"'
                if gw:
                    node.params["gateway"] = cls.shift_ip(gw, src_base, dst_base).split("/")[0]
                if dns:
                    dns_ips = [d.strip() for d in dns.strip('"\'').split(",")]
                    shifted_dns = [cls.shift_ip(d, src_base, dst_base).split("/")[0] for d in dns_ips]
                    node.params["dns-server"] = f'"{",".join(shifted_dns)}"'

            # Shift static routes gateway/dst-address
            elif node.path == "/ip route":
                dst = node.params.get("dst-address")
                gw = node.params.get("gateway")
                if dst:
                    node.params["dst-address"] = f'"{cls.shift_ip(dst, src_base, dst_base)}"'
                if gw and re.match(r'^\d', gw.strip('"\'')):
                    # gateway can be a interface name string, shift only if it starts with digits
                    node.params["gateway"] = cls.shift_ip(gw, src_base, dst_base).split("/")[0]

            # Shift firewall address-lists
            elif node.path == "/ip firewall address-list":
                addr = node.params.get("address")
                if addr:
                    node.params["address"] = cls.shift_ip(addr, src_base, dst_base)

        return ast

class VersionTranslator:
    """Translates obsolete RouterOS wireless nodes to modern RouterOS v7 WiFi structures."""
    @staticmethod
    def translate_v6_to_v7(ast: RouterOS_AST) -> RouterOS_AST:
        translated_nodes = []
        wifi_security_added = False

        # Accumulate legacy security profiles for conversion
        legacy_profiles = {}

        for node in ast.nodes:
            # 1. Capture old security profiles
            if node.path == "/interface wireless security-profiles" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                pwd = node.params.get("wpa2-pre-shared-key", "").strip('"\'') or node.params.get("passphrase", "").strip('"\'')
                if name and pwd:
                    legacy_profiles[name] = pwd
                # Skip legacy node from translation
                continue

            # 2. Capture old wireless settings and convert to /interface wifi configuration
            if node.path == "/interface wireless" and node.action == "set":
                # Convert wireless settings
                name_match = re.search(r'name=([^\s\]]+)', node.finder) or re.search(r'find default-name=([^\s\]]+)', node.finder)
                name = name_match.group(1).strip('"\'') if name_match else "wifi1"

                ssid = node.params.get("ssid", "").strip('"\'')
                profile = node.params.get("security-profile", "").strip('"\'')

                # Check password from mapped profiles
                pwd = legacy_profiles.get(profile, "DefaultSecurePassword123")

                # Render /interface wifi security node
                if not wifi_security_added:
                    translated_nodes.append(ASTNode(
                        path="/interface wifi security",
                        action="add",
                        params={"name": "wifi-sec-profile", "authentication-types": "wpa2-psk", "passphrase": f'"{pwd}"'}
                    ))
                    wifi_security_added = True

                # Create corresponding v7 configuration node
                translated_nodes.append(ASTNode(
                    path="/interface wifi configuration",
                    action="add",
                    params={
                        "name": f'"cfg-{name}"',
                        "ssid": f'"{ssid}"' if ssid else '"MikroTik"',
                        "security": "wifi-sec-profile",
                        "mode": "ap"
                    }
                ))

                # Update interface to bind the config
                translated_nodes.append(ASTNode(
                    path="/interface wifi",
                    action="set",
                    finder=f"[ find name={name} ]",
                    params={"configuration": f'"cfg-{name}"', "disabled": "no"}
                ))
                continue

            # 3. Handle CAPsMAN old controller setup
            if node.path == "/caps-man security" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                pwd = node.params.get("passphrase", "").strip('"\'')
                # Translate to v7 WiFi security
                translated_nodes.append(ASTNode(
                    path="/interface wifi security",
                    action="add",
                    params={"name": f'"{name}"', "authentication-types": "wpa2-psk", "passphrase": f'"{pwd}"'}
                ))
                continue

            if node.path == "/caps-man configuration" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                ssid = node.params.get("ssid", "").strip('"\'')
                sec = node.params.get("security", "").strip('"\'')
                # Translate to v7 configuration
                translated_nodes.append(ASTNode(
                    path="/interface wifi configuration",
                    action="add",
                    params={"name": f'"{name}"', "ssid": f'"{ssid}"', "security": f'"{sec}"', "mode": "ap"}
                ))
                continue

            # Filter out legacy paths
            if node.path in ["/interface wireless security-profiles", "/caps-man security", "/caps-man configuration", "/caps-man datapath"]:
                continue

            # Keep other nodes unchanged
            translated_nodes.append(node)

        ast.nodes = translated_nodes
        return ast

HARDWARE_DATABASE = {
    "RB5009": {
        "model": "RB5009UPr+S+",
        "ethernet_ports": 8,
        "sfp_plus": 1,
        "wifi": False,
        "capsman_controller": True,
        "cpu_cores": 4,
        "ram_mb": 1024
    },
    "hAP_ax3": {
        "model": "hAP ax3",
        "ethernet_ports": 5,
        "sfp_plus": 0,
        "wifi": True,
        "capsman_controller": True,
        "cpu_cores": 4,
        "ram_mb": 1024
    },
    "hAP_ac2": {
        "model": "hAP ac2",
        "ethernet_ports": 5,
        "sfp_plus": 0,
        "wifi": True,
        "capsman_controller": False,
        "cpu_cores": 4,
        "ram_mb": 128
    },
    "hEX": {
        "model": "hEX",
        "ethernet_ports": 5,
        "sfp_plus": 0,
        "wifi": False,
        "capsman_controller": False,
        "cpu_cores": 2,
        "ram_mb": 256
    },
    "hAP_lite": {
        "model": "hAP lite",
        "ethernet_ports": 4,
        "sfp_plus": 0,
        "wifi": True,
        "capsman_controller": False,
        "cpu_cores": 1,
        "ram_mb": 32
    },
    "RB4011": {
        "model": "RB4011iGS+RM",
        "ethernet_ports": 10,
        "sfp_plus": 1,
        "wifi": False,
        "capsman_controller": True,
        "cpu_cores": 4,
        "ram_mb": 1024
    }
}

try:
    import yaml
    import os
    _db_path = os.path.join(os.path.dirname(__file__), "hardware_db.yaml")
    if os.path.exists(_db_path):
        with open(_db_path, "r", encoding="utf-8") as _f:
            _yaml_data = yaml.safe_load(_f)
            if _yaml_data:
                HARDWARE_DATABASE.update(_yaml_data)
except Exception:
    pass

class MigrationRiskAnalyzer:
    """Compares source and target hardware to flag migration risks."""
    @staticmethod
    def analyze_risks(src_model_key: str, dst_model_key: str) -> List[Dict[str, Any]]:
        risks = []
        if src_model_key not in HARDWARE_DATABASE or dst_model_key not in HARDWARE_DATABASE:
            return [{"level": "info", "message": "Невідомий профіль апаратного заліза"}]

        src = HARDWARE_DATABASE[src_model_key]
        dst = HARDWARE_DATABASE[dst_model_key]

        # 1. Port count risk
        if src["ethernet_ports"] > dst["ethernet_ports"]:
            loss = src["ethernet_ports"] - dst["ethernet_ports"]
            risks.append({
                "level": "warning",
                "message": f"Помилка/втрата портів: Цільовий пристрій має на {loss} Ethernet портів менше."
            })

        # 2. SFP+ port risk
        if src["sfp_plus"] > dst["sfp_plus"]:
            risks.append({
                "level": "danger",
                "message": "Втрата SFP+ порту: Цільовий пристрій не має SFP+ інтерфейсу."
            })

        # 3. WiFi capability check
        if src["wifi"] and not dst["wifi"]:
            risks.append({
                "level": "danger",
                "message": "Втрата бездротового зв'язку: Цільовий пристрій не підтримує WiFi."
            })

        # 4. CAPsMAN capacity check
        if src["capsman_controller"] and not dst["capsman_controller"]:
            risks.append({
                "level": "warning",
                "message": "Цільовий пристрій не рекомендовано використовувати як контролер CAPsMAN."
            })

        # 5. Performance drop check (CPU/RAM drop)
        if src["cpu_cores"] > dst["cpu_cores"] or src["ram_mb"] > dst["ram_mb"]:
            risks.append({
                "level": "warning",
                "message": "Зниження продуктивності процесора або RAM: можлива нехватка ресурсів при великому трафіку."
            })

        return risks

class ValidationSandbox:
    """Validates compiled RouterOS config model to ensure no deployment failures."""
    @staticmethod
    def validate_config(ast: RouterOS_AST) -> List[Dict[str, Any]]:
        errors = []

        ips = []
        subnets = []
        bridge_names = set()
        vlan_names = set()
        all_interfaces = set()

        # Build reference directories
        for node in ast.nodes:
            if node.action != "add":
                continue

            if node.path == "/interface bridge":
                name = node.params.get("name", "").strip('"\'')
                if name:
                    bridge_names.add(name)
                    all_interfaces.add(name)

            elif node.path == "/interface vlan":
                name = node.params.get("name", "").strip('"\'')
                if name:
                    vlan_names.add(name)
                    all_interfaces.add(name)

        # Fill interface set with default ones to prevent false positives on physical ports
        for i in range(1, 24):
            all_interfaces.add(f"ether{i}")
            all_interfaces.add(f"wlan{i}")
            all_interfaces.add(f"wifi{i}")
        all_interfaces.add("sfp-sfpplus1")
        all_interfaces.add("sfp1")
        all_interfaces.add("wlan-guest")
        all_interfaces.add("wlan-work")
        all_interfaces.add("bridge")
        all_interfaces.add("bridge-work")
        all_interfaces.add("bridge-guest")
        all_interfaces.add("LEGO")
        all_interfaces.add("warcloud")

        # Core Checks
        for node in ast.nodes:
            if node.path == "/ip address" and node.action == "add":
                addr = node.params.get("address", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')

                if addr:
                    clean_addr = addr.split("/")[0]
                    # 1. Duplicate IP check
                    if clean_addr in ips:
                        errors.append({
                            "type": "error",
                            "message": f"Дублювання IP адреси: {clean_addr} вже призначено іншому інтерфейсу."
                        })
                    ips.append(clean_addr)

                    # 2. Subnet checks
                    try:
                        net = ipaddress.ip_network(addr, strict=False)
                        for existing_net in subnets:
                            if net.overlaps(existing_net) and net != existing_net:
                                errors.append({
                                    "type": "warning",
                                    "message": f"Перетин підмереж: {net} перетинається з {existing_net}."
                                })
                        subnets.append(net)
                    except:
                        pass

                # 3. Missing Interface check
                if iface and iface not in all_interfaces:
                    errors.append({
                        "type": "error",
                        "message": f"Неіснуючий інтерфейс: Адреса {addr} призначена на неіснуючий порт {iface}."
                    })

            elif node.path == "/interface bridge port" and node.action == "add":
                iface = node.params.get("interface", "").strip('"\'')
                bridge = node.params.get("bridge", "").strip('"\'')

                if bridge and bridge not in bridge_names:
                    errors.append({
                        "type": "error",
                        "message": f"Відсутній Bridge: Порт {iface} призначено на неіснуючий міст {bridge}."
                    })
                if iface and iface not in all_interfaces:
                    errors.append({
                        "type": "warning",
                        "message": f"Порт моста не знайдено: Інтерфейс {iface} призначено в міст, але він не визначений."
                    })

            elif node.path == "/interface vlan" and node.action == "add":
                parent = node.params.get("interface", "").strip('"\'')
                if parent and parent not in all_interfaces:
                    errors.append({
                        "type": "error",
                        "message": f"Помилка VLAN: VLAN {node.params.get('name')} призначено на неіснуючий батьківський порт {parent}."
                    })

        return errors

class DigitalTwin:
    """Simulates virtual packet flow routing, NAT, connection tracking, and firewall rules trace inside the configuration."""
    def __init__(self, resolved_model: Dict[str, Any], ast: RouterOS_AST):
        self.resolved = resolved_model
        self.ast = ast
        self.firewall_rules = self._parse_firewall_rules()
        self.nat_rules = self._parse_nat_rules()
        self.local_networks = self._parse_local_networks()

    def _parse_firewall_rules(self) -> List[Dict[str, Any]]:
        rules = []
        for node in self.ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                rules.append(node.params)
        return rules

    def _parse_nat_rules(self) -> List[Dict[str, Any]]:
        rules = []
        for node in self.ast.nodes:
            if node.path == "/ip firewall nat" and node.action == "add":
                rules.append(node.params)
        return rules

    def _parse_local_networks(self) -> List[Dict[str, Any]]:
        networks = []
        for node in self.ast.nodes:
            if node.path == "/ip address" and node.action == "add":
                addr = node.params.get("address", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                if addr and iface:
                    try:
                        net = ipaddress.ip_network(addr, strict=False)
                        networks.append({
                            "subnet": net,
                            "interface": iface,
                            "ip": addr.split("/")[0]
                        })
                    except:
                        pass
        return networks

    def detect_interface_by_ip(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
            for net_info in self.local_networks:
                if ip in net_info["subnet"]:
                    return net_info["interface"]
        except:
            pass
        return "WAN"  # Default to WAN for external IPs

    def simulate_path(self, src_interface: str, dst_interface: str) -> Dict[str, Any]:
        """Simple legacy interface-to-interface check (backwards compatibility)."""
        trace = [f"Початок трасування: {src_interface} ➔ {dst_interface}"]

        # Determine some mock IPs for trace
        src_ip = "192.168.88.50"
        dst_ip = "8.8.8.8" if dst_interface == "WAN" or dst_interface == "Internet" else "192.168.99.10"

        res = self.simulate_packet_trace(src_ip, dst_ip, "tcp", "80", "new")
        return {
            "allowed": res["allowed"],
            "path": trace + res["trace"],
            "reason": f"Verdict: {res['verdict']}"
        }

    def simulate_packet_trace(self, src_ip: str, dst_ip: str, protocol: str = "tcp", dst_port: str = "80", connection_state: str = "new") -> Dict[str, Any]:
        trace = []
        trace.append(f"🏁 Створення тестового пакету: {src_ip} ➔ {dst_ip} ({protocol.upper()} port:{dst_port}, state:{connection_state})")

        # 1. Detect interfaces
        src_iface = self.detect_interface_by_ip(src_ip)
        dst_iface = self.detect_interface_by_ip(dst_ip)

        # Check if dst_ip is the router itself
        is_to_router = False
        for net in self.local_networks:
            if dst_ip == net["ip"]:
                is_to_router = True
                dst_iface = "local-router"
                break

        trace.append(f" L2/L3 Вхідний інтерфейс: '{src_iface}'")
        trace.append(f" L2/L3 Вихідний інтерфейс: '{dst_iface}'")

        # 2. Connection Tracking / FastTrack Check
        has_fasttrack = False
        for node in self.ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                if node.params.get("action") == "fasttrack-connection":
                    has_fasttrack = True

        if has_fasttrack and connection_state in ["established", "related"]:
            trace.append("⚡ [FastTrack/FastPath] З'єднання перебуває у стані established/related. Пакет обходить брандмауер.")
            return {
                "allowed": True,
                "verdict": "ALLOWED (FastTrack)",
                "trace": trace
            }

        # 3. Destination NAT (DSTNAT)
        translated_dst_ip = dst_ip
        translated_dst_port = dst_port
        for idx, rule in enumerate(self.nat_rules):
            if rule.get("chain", "").strip('"\'') == "dstnat":
                action = rule.get("action", "").strip('"\'')
                proto = rule.get("protocol", "").strip('"\'')
                port = rule.get("dst-port", "").strip('"\'')

                # Check match
                match = True
                if proto and proto != protocol:
                    match = False
                if port and port != dst_port:
                    match = False
                if rule.get("in-interface", "").strip('"\'') and rule.get("in-interface", "").strip('"\'') != src_iface:
                    match = False

                if match and action == "dst-nat":
                    to_addr = rule.get("to-addresses", "").strip('"\'')
                    to_port = rule.get("to-ports", "").strip('"\'')
                    if to_addr:
                        translated_dst_ip = to_addr
                    if to_port:
                        translated_dst_port = to_port
                    trace.append(f"🔁 [DSTNAT] Правило #{idx + 1} спрацювало: Перенаправлено на {translated_dst_ip}:{translated_dst_port}")
                    # Recheck output interface after DSTNAT
                    dst_iface = self.detect_interface_by_ip(translated_dst_ip)
                    break

        # 4. Routing Decision
        trace.append(f"📍 Маршрутизація: Пошук маршруту для {translated_dst_ip} ➔ вихідний інтерфейс: '{dst_iface}'")

        # 5. Firewall Filters chain selection
        chain = "forward"
        if is_to_router or dst_iface == "local-router":
            chain = "input"
        elif src_iface == "WAN" and dst_iface == "WAN":
            chain = "forward"

        trace.append(f"🛡️ Брандмауер: Перевірка правил у ланцюжку '{chain}'...")

        # Process filter rules
        allowed = True
        matching_rule_idx = -1
        verdict_action = "accept"

        filter_rules = [r for r in self.firewall_rules if r.get("chain", "").strip('"\'') == chain]

        for idx, rule in enumerate(filter_rules):
            action = rule.get("action", "accept").strip('"\'')
            proto = rule.get("protocol", "").strip('"\'')
            port = rule.get("dst-port", "").strip('"\'')
            in_if = rule.get("in-interface", "").strip('"\'')
            out_if = rule.get("out-interface", "").strip('"\'')
            in_list = rule.get("in-interface-list", "").strip('"\'')
            out_list = rule.get("out-interface-list", "").strip('"\'')
            c_state = rule.get("connection-state", "").strip('"\'')

            # Evaluate match criteria
            match = True
            if proto and proto != protocol:
                match = False
            if port and port != translated_dst_port:
                match = False
            if in_if and in_if != src_iface:
                match = False
            if out_if and out_if != dst_iface:
                match = False
            if in_list:
                # If WAN list is checked
                if in_list == "WAN" and src_iface != "WAN":
                    match = False
                elif in_list == "LAN" and src_iface == "WAN":
                    match = False
            if out_list:
                if out_list == "WAN" and dst_iface != "WAN":
                    match = False
                elif out_list == "LAN" and dst_iface == "WAN":
                    match = False
            if c_state and connection_state not in c_state:
                match = False

            if match:
                matching_rule_idx = idx
                verdict_action = action
                break

        if matching_rule_idx != -1:
            desc = f"ланцюжок={chain}, action={verdict_action}"
            if filter_rules[matching_rule_idx].get("comment"):
                desc += f" ({filter_rules[matching_rule_idx].get('comment')})"

            if verdict_action in ["drop", "reject"]:
                allowed = False
                trace.append(f"❌ [БЛОКОВАНО] Пакет скинуто правилом #{matching_rule_idx + 1}: {desc}")
            else:
                allowed = True
                trace.append(f"✅ [ДОЗВОЛЕНО] Пакет прийнято правилом #{matching_rule_idx + 1}: {desc}")
        else:
            # Default action is accept in RouterOS if no rules block it
            allowed = True
            trace.append(f"✅ [ДОЗВОЛЕНО] Не знайдено жодного правила в ланцюжку '{chain}'. Пропущено за замовчуванням (Default Accept).")

        # 6. Source NAT (SRCNAT)
        if allowed and dst_iface == "WAN":
            for idx, rule in enumerate(self.nat_rules):
                if rule.get("chain", "").strip('"\'') == "srcnat":
                    action = rule.get("action", "").strip('"\'')
                    out_if = rule.get("out-interface", "").strip('"\'')
                    out_list = rule.get("out-interface-list", "").strip('"\'')

                    match = True
                    if out_if and out_if != dst_iface:
                        match = False
                    if out_list and out_list != "WAN":
                        match = False

                    if match and action in ["masquerade", "src-nat"]:
                        trace.append(f"🔁 [SRCNAT] Маскарадинг спрацював: адреса джерела {src_ip} замінена на публічну адресу інтерфейсу '{dst_iface}'")
                        break

        verdict = "ALLOWED" if allowed else "DENIED"
        trace.append(f"🏁 Результат симуляції: {verdict}")

        return {
            "allowed": allowed,
            "verdict": verdict,
            "trace": trace
        }


class TopologyReconstructor:
    """Builds a logical hierarchy and dependency tree representing the network topology."""
    @staticmethod
    def rebuild_tree(resolved_model: Dict[str, Any]) -> Dict[str, Any]:
        tree = {
            "name": "Router",
            "type": "device",
            "children": []
        }

        bridges = resolved_model.get("bridges", {})
        vlans = resolved_model.get("vlans", {})

        bridge_vlans = {}
        for vlan_name, vlan_info in vlans.items():
            parent = vlan_info.get("parent_interface")
            if parent not in bridge_vlans:
                bridge_vlans[parent] = []
            bridge_vlans[parent].append((vlan_name, vlan_info))

        for br_name, br_info in bridges.items():
            br_node = {
                "name": br_name,
                "type": "bridge",
                "ips": br_info.get("ips", []),
                "children": []
            }

            for v_name, v_info in bridge_vlans.get(br_name, []):
                vlan_node = {
                    "name": v_name,
                    "type": "vlan",
                    "vlan_id": v_info.get("vlan_id"),
                    "ips": v_info.get("ips", []),
                    "children": []
                }

                for dhcp in v_info.get("dhcp", []):
                    vlan_node["children"].append({
                        "name": dhcp["name"],
                        "type": "dhcp-server",
                        "pool": dhcp["pool"],
                        "ranges": dhcp["ranges"]
                    })
                br_node["children"].append(vlan_node)

            for dhcp in br_info.get("dhcp", []):
                br_node["children"].append({
                    "name": dhcp["name"],
                    "type": "dhcp-server",
                    "pool": dhcp["pool"],
                    "ranges": dhcp["ranges"]
                })

            tree["children"].append(br_node)

        return tree

    @staticmethod
    def render_ascii(tree: Dict[str, Any], prefix: str = "", is_last: bool = True) -> str:
        lines = []
        name = tree.get("name", "")
        t_type = tree.get("type", "")
        ips = tree.get("ips", [])

        ip_suffix = f" ({', '.join(ips)})" if ips else ""

        connector = "└── " if is_last else "├── "
        if name == "Router":
            lines.append("RouterOS Device")
        else:
            lines.append(f"{prefix}{connector}{name} [{t_type}]{ip_suffix}")

        next_prefix = prefix + ("    " if is_last else "│   ")
        children = tree.get("children", [])
        for idx, child in enumerate(children):
            child_is_last = (idx == len(children) - 1)
            lines.append(TopologyReconstructor.render_ascii(child, next_prefix, child_is_last))

        return "\n".join([l for l in lines if l])

class ComplianceEngine:
    """Evaluates configurations against standard MikroTik RouterOS security baselines (CIS, Best Practices)."""
    @staticmethod
    def audit_security(ast: RouterOS_AST) -> Dict[str, Any]:
        passed = []
        failed = []

        # 1. Default admin user check
        default_admin_active = True
        has_users = False

        for node in ast.nodes:
            if node.path == "/user" and node.action == "add":
                has_users = True
                name = node.params.get("name", "").strip('"\'')
                if name == "admin":
                    default_admin_active = True
            elif node.path == "/user" and node.action == "set":
                name_match = re.search(r'name=([^\s\]]+)', node.finder)
                if name_match and name_match.group(1).strip('"\'') == "admin":
                    if node.params.get("disabled") == "yes":
                        default_admin_active = False

        if not default_admin_active or has_users:
            passed.append("Безпека користувачів: Дефолтний користувач admin вимкнений або створено альтернативних адміністраторів.")
        else:
            failed.append("Безпека користувачів: Дефолтний користувач 'admin' залишається активним або єдиним у системі.")

        # 2. Service hardening
        disabled_services = set()
        for node in ast.nodes:
            if node.path == "/ip service" and node.action == "set":
                srv_name = None
                name_match = re.search(r'name=([^\s\]]+)', node.finder) or re.search(r'find name=([^\s\]]+)', node.finder)
                if name_match:
                    srv_name = name_match.group(1).strip('"\'')
                else:
                    for key in node.params.keys():
                        if key in ["telnet", "ftp", "www", "ssh", "api", "api-ssl", "winbox"]:
                            srv_name = key
                            break

                if srv_name and node.params.get("disabled") == "yes":
                    disabled_services.add(srv_name)

        dangerous_enabled = []
        for srv in ["telnet", "ftp", "api", "api-ssl"]:
            if srv not in disabled_services:
                dangerous_enabled.append(srv)

        if not dangerous_enabled:
            passed.append("Захист сервісів: Небезпечні служби керування (telnet, ftp, api) вимкнено.")
        else:
            failed.append(f"Захист сервісів: Служби {', '.join(dangerous_enabled)} увімкнені. Рекомендується їх вимкнути.")

        # 3. DNS remote request checks
        allow_remote = False
        for node in ast.nodes:
            if node.path == "/ip dns" and node.action == "set":
                if node.params.get("allow-remote-requests") == "yes":
                    allow_remote = True

        dns_blocked = False
        for node in ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                action = node.params.get("action", "").strip('"\'') or "accept"
                chain = node.params.get("chain", "").strip('"\'')
                port = node.params.get("dst-port", "").strip('"\'')
                protocol = node.params.get("protocol", "").strip('"\'')

                if chain == "input" and action in ["drop", "reject"] and "53" in port and protocol in ["udp", "tcp"]:
                    dns_blocked = True

        if not allow_remote:
            passed.append("Безпека DNS: Віддалені запити DNS (allow-remote-requests) вимкнено.")
        elif dns_blocked:
            passed.append("Безпека DNS: Запити ззовні дозволено, але захищено правилом брандмауера.")
        else:
            failed.append("Безпека DNS (УВАГА): Дозволено віддалені запити DNS (allow-remote-requests=yes) без правил блокування на зовнішньому інтерфейсі. Роутер може бути використаний для DNS Amplification атак.")

        # 4. Strict firewall forwarding baseline
        has_drop_forward = False
        has_drop_input = False
        for node in ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                action = node.params.get("action", "").strip('"\'') or "accept"
                chain = node.params.get("chain", "").strip('"\'')
                if action in ["drop", "reject"]:
                    if chain == "forward" and not node.params.get("src-address") and not node.params.get("dst-address"):
                        has_drop_forward = True
                    if chain == "input":
                        has_drop_input = True

        if has_drop_forward:
            passed.append("Захист Forwarding: Брандмауер містить загальне правило блокування (drop) для ланцюжка forward.")
        else:
            failed.append("Захист Forwarding: Відсутнє загальне правило блокування (drop forward) у кінці ланцюжка фільтрації.")

        if has_drop_input:
            passed.append("Захист Input: Брандмауер містить правило блокування (drop input) для захисту самого роутера.")
        else:
            failed.append("Захист Input: Роутер вразливий ззовні. Додайте закриваюче правило drop input у брандмауер.")

        total_rules = len(passed) + len(failed)
        score = int((len(passed) / total_rules) * 100) if total_rules > 0 else 100

        return {
            "score": score,
            "passed": passed,
            "failed": failed
        }

class SecretExtractor:
    """Extracts sensitive variables from AST nodes and replaces them with templates."""
    @staticmethod
    def extract_secrets(ast: RouterOS_AST) -> Tuple[RouterOS_AST, Dict[str, str]]:
        secrets = {}
        counter = 1

        # Keywords that indicate a sensitive parameter
        sensitive_keywords = ["passphrase", "password", "wpa2-pre-shared-key", "preshared-key", "private-key", "secret"]

        for node in ast.nodes:
            if not node.params:
                continue

            for k in list(node.params.keys()):
                # Check if key matches sensitive keywords
                is_sensitive = any(kw in k.lower() for kw in sensitive_keywords)

                val = node.params[k]
                if is_sensitive and val and not val.startswith("{{") and not val.endswith("}}"):
                    clean_val = val.strip('"\'')
                    if clean_val:
                        # Generate identifier based on node path and key name
                        path_clean = node.path.replace("/", "").replace(" ", "_").replace("-", "_")
                        secret_name = f"SECRET_{path_clean.upper()}_{k.upper().replace('-', '_')}_{counter}"
                        counter += 1

                        secrets[secret_name] = clean_val
                        # Replace in AST with placeholder
                        node.params[k] = f'"{{{{{secret_name}}}}}"'

        return ast, secrets

class RollbackGenerator:
    """Generates rollback scripts by comparing original and compiled ASTs."""
    @staticmethod
    def generate_rollback(orig_ast: RouterOS_AST, new_ast: RouterOS_AST) -> str:
        rollback_lines = []

        def get_node_key(node: ASTNode) -> str:
            if not node.params:
                return ""
            name = node.params.get("name", "").strip('"\'')
            if name:
                return name
            addr = node.params.get("address", "").strip('"\'')
            if addr:
                return addr
            return ""

        orig_keys = {}
        for node in orig_ast.nodes:
            if node.action == "add":
                key = get_node_key(node)
                if key:
                    orig_keys[(node.path, key)] = node

        removes = []
        for node in new_ast.nodes:
            if node.action == "add":
                key = get_node_key(node)
                if key and (node.path, key) not in orig_keys:
                    finder_param = ""
                    if "name" in node.params:
                        finder_param = f'name={node.params["name"]}'
                    elif "address" in node.params:
                        finder_param = f'address={node.params["address"]}'

                    if finder_param:
                        removes.append(f"{node.path} remove [ find {finder_param} ]")

        removes.reverse()

        if removes:
            rollback_lines.append("# --- Automatically Generated Rollback Script ---")
            rollback_lines.extend(removes)
        else:
            rollback_lines.append("# No new components detected to roll back.")

        return "\n".join(rollback_lines)

class BatchDeployer:
    """Compiles customized configuration profiles for multiple target sites."""
    @staticmethod
    def compile_batch(template_text: str, sites: List[Dict[str, Any]]) -> Dict[str, str]:
        from backend.generators.renderer import render_ast

        compiled_sites = {}
        base_ast = RouterOS_AST.parse_rsc(template_text)

        src_subnet = None
        for node in base_ast.nodes:
            if node.path == "/ip address" and node.action == "add":
                addr = node.params.get("address", "").strip('"\'')
                if addr and "/" in addr:
                    try:
                        net = ipaddress.ip_network(addr, strict=False)
                        src_subnet = str(net)
                        break
                    except:
                        pass

        if not src_subnet:
            src_subnet = "192.168.88.0/24"

        for site in sites:
            site_name = site.get("name", "Site")
            target_subnet = site.get("subnet")
            target_ssid = site.get("ssid")

            site_ast = deepcopy_ast(base_ast)

            if target_subnet:
                site_ast = IPRecalculator.recalculate_ast_ips(site_ast, src_subnet, target_subnet)

            if target_ssid:
                for node in site_ast.nodes:
                    if node.path in ["/interface wifi configuration", "/interface wireless", "/caps-man configuration"]:
                        if "ssid" in node.params:
                            node.params["ssid"] = f'"{target_ssid}"'

            compiled_sites[site_name] = render_ast(site_ast)

        return compiled_sites

class DisasterRecoveryPack:
    """Packages all compiled and audited products into a structured delivery model."""
    @staticmethod
    def assemble_dr_pack(orig_config_text: str, dst_model_key: str = "hAP_ax3",
                           src_subnet: str = None, target_subnet: str = None,
                           target_ssid: str = None, target_wifi_password: str = None) -> Dict[str, Any]:
        from backend.generators.renderer import render_ast

        ast = RouterOS_AST.parse_rsc(orig_config_text)

        # 1. IP / Subnet Remapping
        if target_subnet:
            if not src_subnet:
                # auto-detect first IPv4 subnet in config
                for node in ast.nodes:
                    if node.path == "/ip address" and node.action == "add":
                        addr = node.params.get("address", "").strip('"\'')
                        if addr and "/" in addr:
                            try:
                                src_subnet = str(ipaddress.ip_network(addr, strict=False))
                                break
                            except:
                                pass
                if not src_subnet:
                    src_subnet = "192.168.88.0/24"
            ast = IPRecalculator.recalculate_ast_ips(ast, src_subnet, target_subnet)

        # 2. SSID Override
        if target_ssid:
            for node in ast.nodes:
                if node.path in ["/interface wifi configuration", "/interface wireless", "/caps-man configuration"]:
                    if "ssid" in node.params:
                        node.params["ssid"] = f'"{target_ssid}"'

        # 3. Wi-Fi Password Override
        if target_wifi_password:
            for node in ast.nodes:
                if node.path == "/interface wireless security-profiles" and node.action == "add":
                    if "wpa2-pre-shared-key" in node.params:
                        node.params["wpa2-pre-shared-key"] = f'"{target_wifi_password}"'
                    if "passphrase" in node.params:
                        node.params["passphrase"] = f'"{target_wifi_password}"'
                elif node.path in ["/interface wifi security", "/caps-man security"] and node.action == "add":
                    if "passphrase" in node.params:
                        node.params["passphrase"] = f'"{target_wifi_password}"'

        resolved = ReferenceResolver.resolve_ast_references(deepcopy_ast(ast))
        compliance_report = ComplianceEngine.audit_security(deepcopy_ast(ast))
        translated_ast = VersionTranslator.translate_v6_to_v7(deepcopy_ast(ast))
        clean_ast, secrets_dict = SecretExtractor.extract_secrets(deepcopy_ast(translated_ast))

        final_config = render_ast(clean_ast)
        rollback_config = RollbackGenerator.generate_rollback(ast, translated_ast)

        tree = TopologyReconstructor.rebuild_tree(resolved)
        topology_ascii = TopologyReconstructor.render_ascii(tree)

        inventory = {
            "target_hardware": dst_model_key,
            "compliance_score": compliance_report["score"],
            "detected_bridges": list(resolved.get("bridges", {}).keys()),
            "detected_vlans": list(resolved.get("vlans", {}).keys()),
            "secrets_count": len(secrets_dict)
        }

        import yaml
        secrets_yaml = yaml.dump({"secrets": secrets_dict}, default_flow_style=False, allow_unicode=True)

        return {
            "new_config": final_config,
            "rollback_config": rollback_config,
            "secrets": secrets_yaml,
            "topology": topology_ascii,
            "inventory": inventory
        }

def deepcopy_ast(ast: RouterOS_AST) -> RouterOS_AST:
    import pickle
    return pickle.loads(pickle.dumps(ast))

class HeuristicsOptimizer:
    """Analyzes configurations and returns performance optimizations, safety alerts, and quality scores."""
    @staticmethod
    def detect_version(ast: RouterOS_AST) -> float:
        for node in ast.nodes:
            if node.comment:
                match = re.search(r'(?:version|ros)\s*=\s*([0-9.]+)', node.comment, re.IGNORECASE)
                if match:
                    try:
                        parts = match.group(1).split('.')
                        return float(f"{parts[0]}.{parts[1]}")
                    except:
                        pass
        return 7.20

    @staticmethod
    def optimize_and_score(ast: RouterOS_AST, risks: List[Dict[str, Any]], sandbox_errors: List[Dict[str, Any]], compliance: Dict[str, Any]) -> Dict[str, Any]:
        recommendations = []
        ai_review = []

        # Load semantic rules from knowledge base
        from backend.knowledgebase.kb import RouterOSKB
        rules_db = RouterOSKB.get_rules()

        # Build Semantic Graph
        from backend.dependency.graph import RouterOSSemanticGraph
        graph = RouterOSSemanticGraph.build_from_ast(ast)

        target_version = HeuristicsOptimizer.detect_version(ast)
        from backend.knowledgebase.compatibility import VersionCompatibilityEngine
        comp_warnings = VersionCompatibilityEngine.check_compatibility(ast, target_version)
        for w in comp_warnings:
            recommendations.append({
                "category": "compatibility",
                "severity": w["severity"],
                "message": w["message"]
            })
            ai_review.append({
                "issue": w["message"],
                "severity": w["severity"].upper(),
                "likelihood": "High",
                "impact": w["alternative"],
                "fix": f"# Upgrade RouterOS to support feature or replace command",
                "category": "compatibility"
            })

        # Add known issues for target version
        known_issues = RouterOSKB.get_known_issues()
        version_str = f"{target_version:.2f}".rstrip('0').rstrip('.')
        if version_str in known_issues:
            for issue in known_issues[version_str]:
                recommendations.append({
                    "category": "compatibility",
                    "severity": "warning",
                    "message": f"Відомий баг у версії {version_str}: {issue}"
                })
                ai_review.append({
                    "issue": f"Версія RouterOS {version_str} має відомий баг",
                    "severity": "WARNING",
                    "likelihood": "Medium",
                    "impact": issue,
                    "fix": f"# Рекомендується оновити RouterOS до стабільної версії 7.20.3",
                    "category": "compatibility"
                })

        # Check FastTrack
        has_fasttrack = False
        for node in ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                action = node.params.get("action", "").strip('"\'')
                if action == "fasttrack-connection":
                    has_fasttrack = True
                    break

        has_queue_tree = any(n.path == "/queue tree" for n in ast.nodes)
        has_ipsec = any(n.path == "/ip ipsec peer" or n.path == "/ip ipsec profile" for n in ast.nodes)
        has_traffic_flow = any(n.path == "/ip traffic-flow" for n in ast.nodes)

        if has_fasttrack:
            ft_rules = rules_db.get("routeros", {}).get("firewall", {}).get("fasttrack", {})
            incompatibilities = []
            if has_queue_tree:
                incompatibilities.append("Queue Tree")
            if has_ipsec:
                incompatibilities.append("IPsec")
            if has_traffic_flow:
                incompatibilities.append("Traffic Flow")

            if incompatibilities:
                msg = f"Конфлікт FastTrack: увімкнено FastTrack, але виявлено активні {', '.join(incompatibilities)}. "
                if ft_rules and ft_rules.get("risks"):
                    msg += "Ризики: " + "; ".join(ft_rules["risks"])
                recommendations.append({
                    "category": "performance",
                    "severity": "warning",
                    "message": msg
                })
                ai_review.append({
                    "issue": f"Конфлікт FastTrack з {', '.join(incompatibilities)}",
                    "severity": "WARNING",
                    "likelihood": "High",
                    "impact": "Черги QoS та тунелі IPsec будуть ігноруватися FastTrack трафіком.",
                    "fix": "/ip firewall filter remove [ find action=fasttrack-connection ]",
                    "category": "performance"
                })
        else:
            recommendations.append({
                "category": "performance",
                "severity": "info",
                "message": "Увімкніть FastTrack Connection: додайте правило fasttrack-connection в firewall filter для зниження навантаження на CPU роутера."
            })

        # DNS check
        dns_cache_size = None
        for node in ast.nodes:
            if node.path == "/ip dns" and node.action == "set":
                dns_cache_size = node.params.get("cache-size", "").strip('"\'')
        if dns_cache_size and dns_cache_size in ["1024KiB", "2048KiB"]:
            recommendations.append({
                "category": "performance",
                "severity": "info",
                "message": "Збільшіть розмір кешу DNS: поточний ліміт занадто малий, рекомендується 4096KiB або більше."
            })

        # Hardware offload check
        has_hw_offload_disabled = False
        for node in ast.nodes:
            if node.path == "/interface bridge port" and node.action == "add":
                if node.params.get("hw") == "no":
                    has_hw_offload_disabled = True
        if has_hw_offload_disabled:
            recommendations.append({
                "category": "performance",
                "severity": "warning",
                "message": "Вимкнено апаратне прискорення (hw=no): перевірте, чи дійсно необхідно обробляти трафік цього порту процесором роутера."
            })

        # STP check
        has_stp = False
        for node in ast.nodes:
            if node.path == "/interface bridge" and node.action == "add":
                name = node.params.get("name", "bridge").strip('"\'')
                protocol = node.params.get("protocol-mode", "").strip('"\'')
                if protocol in ["rstp", "mstp", "stp"]:
                    has_stp = True

                # Check bridge vlan-filtering from rules.yaml
                vf = node.params.get("vlan-filtering")
                if vf == "yes":
                    has_vlan_table = any(n.path == "/interface bridge vlan" and n.params.get("bridge", "").strip('"\'') == name for n in ast.nodes)
                    if not has_vlan_table:
                        bridge_rules = rules_db.get("routeros", {}).get("bridge", {}).get("vlan-filtering", {})
                        msg = f"Попередження L2: на Bridge '{name}' увімкнено vlan-filtering=yes, але вимога не виконана: відсутні записи у таблиці bridge vlan."
                        recommendations.append({
                            "category": "reliability",
                            "severity": "danger",
                            "message": msg
                        })
                        ai_review.append({
                            "issue": f"Bridge vlan-filtering увімкнено без VLAN таблиці",
                            "severity": "CRITICAL",
                            "likelihood": "High",
                            "impact": "Втрата зв'язку та некоректне тегування VLAN трафіку на портах моста.",
                            "fix": f"/interface bridge vlan add bridge={name} tagged=bridge,ether1 vlan-ids=10",
                            "category": "reliability"
                        })

        if not has_stp:
            recommendations.append({
                "category": "reliability",
                "severity": "warning",
                "message": "STP вимкнено на Bridge: можливе утворення мережевих петель (loops). Ввімкніть RSTP."
            })
            ai_review.append({
                "issue": "STP вимкнено на інтерфейсі Bridge",
                "severity": "WARNING",
                "likelihood": "Medium",
                "impact": "При випадковому комутаційному з'єднанні портів відбудеться повне зациклення мережі та відмова роутера.",
                "fix": "/interface bridge set [find] protocol-mode=rstp",
                "category": "reliability"
            })

        # --- 2. Best Practice Validator ---
        bp_db = RouterOSKB.get_best_practices()
        violated_bps = {}

        # BP-0001: Guest Isolation
        has_guest = False
        for node in graph.nodes.values():
            if node.type == "vlan" and "guest" in node.name.lower():
                has_guest = True
                guest_name = node.name
                # Check for drop/reject forward rules from guest VLAN interface
                has_drop_rule = False
                for r_node in graph.nodes.values():
                    if r_node.type == "firewall_rule":
                        chain = r_node.properties.get("chain")
                        action = r_node.properties.get("action")
                        # If rule drops forward traffic from this guest interface
                        if chain == "forward" and action in ["drop", "reject"]:
                            # Look at children (referenced interfaces)
                            for child in r_node.children:
                                if child.name == guest_name or child.name == "WAN":
                                    has_drop_rule = True
                if not has_drop_rule:
                    violated_bps["BP-0001"] = f"Відсутнє блокуюче правило між гостьовою VLAN '{guest_name}' та іншими підмережами."

        # BP-0002: Management VLAN Check
        has_mgmt_vlan = False
        for node in graph.nodes.values():
            if node.type == "vlan" and any(k in node.name.lower() for k in ["mgmt", "admin", "mng"]):
                has_mgmt_vlan = True

        # Check if direct bridge interface has IP address and allows SSH/Winbox (bad practice)
        direct_bridge_ip = False
        for node in graph.nodes.values():
            if node.type == "bridge":
                # If bridge has IP address children directly
                for child in node.children:
                    if child.type == "ip_address":
                        direct_bridge_ip = True
        if not has_mgmt_vlan and direct_bridge_ip:
            violated_bps["BP-0002"] = "Адміністрування роутера виконується через нетеговану IP адресу на Bridge, а не через окрему VLAN (MGMT VLAN)."

        # BP-0003: WAN Input Drop Check
        has_wan_drop = False
        for r_node in graph.nodes.values():
            if r_node.type == "firewall_rule":
                chain = r_node.properties.get("chain")
                action = r_node.properties.get("action")
                if chain == "input" and action in ["drop", "reject"]:
                    # check if drops from WAN list or drops all
                    has_wan_drop = True
        if not has_wan_drop:
            violated_bps["BP-0003"] = "Відсутнє правило закриття input (drop input з боку WAN) для захисту пристрою."

        # BP-0004: DNS Amplification Protection
        allow_dns_remote = False
        for node in ast.nodes:
            if node.path == "/ip dns" and node.action == "set":
                if node.params.get("allow-remote-requests") == "yes":
                    allow_dns_remote = True
        if allow_dns_remote:
            has_dns_block = False
            for r_node in graph.nodes.values():
                if r_node.type == "firewall_rule":
                    chain = r_node.properties.get("chain")
                    action = r_node.properties.get("action")
                    if chain == "input" and action in ["drop", "reject"]:
                        # check if drops port 53
                        ast_item = r_node.ast_node
                        if ast_item and "53" in ast_item.params.get("dst-port", ""):
                            has_dns_block = True
            if not has_dns_block:
                violated_bps["BP-0004"] = "Remote DNS requests дозволені, але порт 53 UDP/TCP не заблокований на вході з WAN."

        # BP-0005: CAPsMAN Fast Roaming Check
        has_capsman = any(n.path in ["/caps-man manager", "/interface wifi capsman"] for n in ast.nodes)
        ft_configured = False
        for node in ast.nodes:
            for k, v in node.params.items():
                if (k == "ft" or k == "ft-over-ds" or k.endswith(".ft")) and v.strip('"\'') == "yes":
                    ft_configured = True
        if has_capsman and not ft_configured:
            violated_bps["BP-0005"] = "Використовується CAPsMAN, але функція Fast Transition (802.11r) не активована."

        # Generate Best Practices Cards
        for bp_id, bp_desc in violated_bps.items():
            bp_meta = bp_db.get(bp_id, {"name": bp_id, "risk": "Вразливість безпеки або збої в роботі."})
            recommendations.append({
                "category": "security",
                "severity": "danger",
                "message": f"Порушено {bp_id} ({bp_meta['name']}): {bp_desc}"
            })
            ai_review.append({
                "issue": bp_meta["name"],
                "severity": "CRITICAL" if bp_id in ["BP-0003", "BP-0004"] else "HIGH",
                "likelihood": "High",
                "impact": bp_meta["risk"],
                "fix": f"# Дотримуйтесь Best Practice {bp_id}. Див. документацію.",
                "category": "security"
            })

        # Calculate production confidence score
        confidence_score = 100
        deductions = []
        if "BP-0001" in violated_bps:
            confidence_score -= 20
            deductions.append("Гостьова VLAN не ізольована (BP-0001): -20%")
        if "BP-0002" in violated_bps:
            confidence_score -= 15
            deductions.append("Відсутня окрема VLAN керування (BP-0002): -15%")
        if "BP-0003" in violated_bps:
            confidence_score -= 25
            deductions.append("Не захищено вхідний ланцюжок WAN (BP-0003): -25%")
        if "BP-0004" in violated_bps:
            confidence_score -= 20
            deductions.append("DNS відкритий для атак ззовні (BP-0004): -20%")
        if "BP-0005" in violated_bps:
            confidence_score -= 10
            deductions.append("Роумінг CAPsMAN не оптимізовано (BP-0005): -10%")
        if not has_stp:
            confidence_score -= 15
            deductions.append("STP вимкнено на комутаторі: -15%")

        for err in sandbox_errors:
            if err.get("type") == "error":
                confidence_score -= 15
                deductions.append(f"Критична помилка конфігурації: {err.get('message')}: -15%")
            elif err.get("type") == "warning":
                confidence_score -= 5
                deductions.append(f"Попередження валідації: {err.get('message')}: -5%")

        confidence_score = max(0, min(100, confidence_score))

        # Build quality score (clean code metrics)
        quality_score = compliance["score"]
        perf_deduction = sum(5 for r in recommendations if r["category"] == "performance")
        quality_score = max(0, min(100, quality_score - perf_deduction))

        # Calculate scorecards breakdown for categories
        # Security
        security_score = compliance.get("score", 100)
        insecure_services = ["telnet", "ftp", "www", "api"]
        for node in ast.nodes:
            if node.path == "/ip service" and node.action == "set":
                for service in insecure_services:
                    if node.finder and service in node.finder and node.params.get("disabled") == "no":
                        security_score -= 10
        security_score = max(0, min(100, security_score))

        # Reliability
        reliability_score = 100
        for node in ast.nodes:
            if node.path == "/interface bridge" and node.action == "add":
                protocol = node.params.get("protocol-mode", "").strip('"\'')
                if protocol == "none":
                    reliability_score -= 25
        for err in sandbox_errors:
            if err.get("type") == "error":
                reliability_score -= 15
            elif err.get("type") == "warning":
                reliability_score -= 5
        reliability_score = max(0, min(100, reliability_score))

        # Scalability
        scalability_score = 100
        for node in ast.nodes:
            if node.path == "/interface bridge" and node.action == "add":
                vf = node.params.get("vlan-filtering")
                if vf == "no" or not vf:
                    scalability_score -= 20
        wifi_interfaces_count = sum(1 for n in ast.nodes if n.path in ["/interface wireless", "/interface wifi"] and n.action == "add")
        if wifi_interfaces_count >= 3 and not has_capsman:
            scalability_score -= 15
        scalability_score = max(0, min(100, scalability_score))

        # Maintainability
        maintainability_score = 100
        nodes_with_comments = 0
        total_interfaces = 0
        for node in ast.nodes:
            if node.path in ["/interface bridge", "/interface vlan", "/interface ethernet", "/interface wireless", "/interface wifi"]:
                total_interfaces += 1
                if node.params.get("comment") or node.comment:
                    nodes_with_comments += 1
        if total_interfaces > 0 and (nodes_with_comments / total_interfaces) < 0.5:
            maintainability_score -= 20
        for node in ast.nodes:
            if node.path == "/ip pool" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                if name in ["pool1", "dhcp", "dhcp_pool", "pool_1"]:
                    maintainability_score -= 10
        maintainability_score = max(0, min(100, maintainability_score))

        # Populate AI Reviewer Cards for generic audit violations
        for fail in compliance.get("failed", []):
            ai_review.append({
                "issue": fail,
                "severity": "WARNING",
                "likelihood": "Medium",
                "impact": "Порушення загального стандарту безпеки MikroTik CIS Baseline.",
                "fix": "# Див. правила налаштування послуг у документації.",
                "category": "security"
            })

        return {
            "quality_score": quality_score,
            "confidence_score": confidence_score,
            "confidence_deductions": deductions,
            "recommendations": recommendations,
            "ai_review": ai_review,
            "readiness_breakdown": {
                "security": security_score,
                "reliability": reliability_score,
                "scalability": scalability_score,
                "maintainability": maintainability_score,
                "confidence": confidence_score
            }
        }

class FirewallFlowAnalyzer:
    """Analyzes the firewall security flows and builds rule tracing trees."""
    @staticmethod
    def analyze_flow(ast: RouterOS_AST) -> Dict[str, Any]:
        tree = {"input": [], "forward": [], "output": []}
        verdicts = {
            "snmp_blocked": True,
            "ssh_lan_only": True,
            "dns_lan_only": True,
            "ntp_exposed": False
        }

        has_snmp = False
        allow_remote_dns = False

        for node in ast.nodes:
            if node.path == "/snmp" and node.action == "set":
                if node.params.get("enabled") == "yes":
                    has_snmp = True
            elif node.path == "/ip dns" and node.action == "set":
                if node.params.get("allow-remote-requests") == "yes":
                    allow_remote_dns = True

        rule_num = 1
        for node in ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                chain = node.params.get("chain", "").strip('"\'')
                action = node.params.get("action", "").strip('"\'') or "accept"
                in_iface = node.params.get("in-interface", "").strip('"\'')
                out_iface = node.params.get("out-interface", "").strip('"\'')
                proto = node.params.get("protocol", "").strip('"\'')
                port = node.params.get("dst-port", "").strip('"\'')
                src_list = node.params.get("src-address-list", "").strip('"\'')
                dst_list = node.params.get("dst-address-list", "").strip('"\'')
                comment = node.params.get("comment", "").strip('"\'')

                rule_desc = f"Rule {rule_num} -> {action}"
                if proto:
                    rule_desc += f" {proto}"
                if port:
                    rule_desc += f" port:{port}"
                if in_iface:
                    rule_desc += f" in:{in_iface}"
                if out_iface:
                    rule_desc += f" out:{out_iface}"
                if comment:
                    rule_desc += f" ({comment})"

                rule_num += 1

                if chain in tree:
                    tree[chain].append(rule_desc)

                if chain == "input" and "161" in port:
                    if action in ["drop", "reject"] and in_iface in ["WAN", "ether1", "sfp-sfpplus1"]:
                        verdicts["snmp_blocked"] = True
                    elif action == "accept" and (not in_iface or in_iface in ["WAN", "ether1"]):
                        verdicts["snmp_blocked"] = False

                if chain == "input" and "22" in port:
                    if action == "accept" and (not in_iface and not src_list):
                        verdicts["ssh_lan_only"] = False

                if chain == "input" and "53" in port:
                    if action in ["drop", "reject"] and in_iface in ["WAN", "ether1", "sfp-sfpplus1"]:
                        verdicts["dns_lan_only"] = True
                    elif action == "accept" and (not in_iface or in_iface in ["WAN", "ether1"]):
                        verdicts["dns_lan_only"] = False

                if chain == "input" and "123" in port:
                    if action == "accept" and (not in_iface and not src_list):
                        verdicts["ntp_exposed"] = True

        has_drop_all_input = False
        for node in ast.nodes:
            if node.path == "/ip firewall filter" and node.action == "add":
                if node.params.get("chain", "").strip('"\'') == "input" and node.params.get("action", "").strip('"\'') in ["drop", "reject"]:
                    if not node.params.get("in-interface") and not node.params.get("src-address"):
                        has_drop_all_input = True

        if has_snmp and not has_drop_all_input:
            verdicts["snmp_blocked"] = False

        if allow_remote_dns:
            has_dns_drop = False
            for node in ast.nodes:
                if node.path == "/ip firewall filter" and node.action == "add":
                    chain = node.params.get("chain", "").strip('"\'')
                    action = node.params.get("action", "").strip('"\'') or "accept"
                    port = node.params.get("dst-port", "").strip('"\'')
                    if chain == "input" and action in ["drop", "reject"] and ("53" in port or has_drop_all_input):
                        has_dns_drop = True
            if not has_dns_drop:
                verdicts["dns_lan_only"] = False

        return {
            "tree": tree,
            "verdicts": verdicts
        }

class NATFlowAnalyzer:
    """Analyzes NAT table configuration rules and maps forwarding zones."""
    @staticmethod
    def analyze_nat(ast: RouterOS_AST) -> List[str]:
        mappings = []

        for node in ast.nodes:
            if node.path == "/ip firewall nat" and node.action == "add":
                chain = node.params.get("chain", "").strip('"\'')
                action = node.params.get("action", "").strip('"\'')
                in_iface = node.params.get("in-interface", "").strip('"\'')
                out_iface = node.params.get("out-interface", "").strip('"\'')
                dst_port = node.params.get("dst-port", "").strip('"\'')
                to_addr = node.params.get("to-addresses", "").strip('"\'')
                to_port = node.params.get("to-ports", "").strip('"\'')
                comment = node.params.get("comment", "").strip('"\'')

                comment_suffix = f" ({comment})" if comment else ""

                if chain == "srcnat":
                    if action == "masquerade":
                        out_target = out_iface if out_iface else "Any Interface"
                        mappings.append(f"LAN ➔ masquerade ➔ {out_target}{comment_suffix}")
                    elif action == "src-nat":
                        to_src = node.params.get("to-source-addresses", "").strip('"\'')
                        mappings.append(f"LAN ➔ srcnat to {to_src} ➔ {out_iface}{comment_suffix}")
                elif chain == "dstnat":
                    if action == "dst-nat":
                        in_target = in_iface if in_iface else "Any WAN"
                        t_port = f":{to_port}" if to_port else ""
                        mappings.append(f"{in_target} ➔ dstnat port {dst_port} ➔ {to_addr}{t_port}{comment_suffix}")
                    elif action == "redirect":
                        mappings.append(f"Any ➔ dstnat port {dst_port} ➔ Redirect to local port {to_port}{comment_suffix}")

        if not mappings:
            mappings.append("No NAT rules configured.")

        return mappings

class RoutingFlowAnalyzer:
    """Analyzes routing rules, PCC load balancing, and WAN gateway alignments."""
    @staticmethod
    def analyze_routing(ast: RouterOS_AST) -> Dict[str, Any]:
        wan_gateways = set()
        pcc_rules = []
        warnings = []

        for node in ast.nodes:
            if node.path == "/ip route" and node.action == "add":
                gw = node.params.get("gateway", "").strip('"\'')
                dst = node.params.get("dst-address", "").strip('"\'') or "0.0.0.0/0"
                if dst == "0.0.0.0/0" and gw:
                    wan_gateways.add(gw)
            elif node.path == "/ip dhcp-client" and node.action == "add":
                iface = node.params.get("interface", "").strip('"\'')
                disabled = node.params.get("disabled", "").strip('"\'')
                add_route = node.params.get("add-default-route", "").strip('"\'')
                if iface and disabled != "yes" and add_route != "no":
                    wan_gateways.add(iface)

        for node in ast.nodes:
            if node.path == "/ip firewall mangle" and node.action == "add":
                pcc = node.params.get("per-connection-classifier", "").strip('"\'')
                if pcc and ("both-addresses" in pcc or "src-address" in pcc):
                    match = re.search(r':(\d+)/(\d+)', pcc)
                    if match:
                        divisor = int(match.group(1))
                        remainder = int(match.group(2))
                        pcc_rules.append({"divisor": divisor, "remainder": remainder})

        if pcc_rules:
            divisors = list(set(r["divisor"] for r in pcc_rules))
            if len(divisors) == 1:
                pcc_divisor = divisors[0]
                wan_count = len(wan_gateways) if wan_gateways else 2

                if pcc_divisor != wan_count:
                    loss_percent = int(((pcc_divisor - wan_count) / pcc_divisor) * 100)
                    if loss_percent > 0:
                        warnings.append({
                            "type": "error",
                            "message": f"Конфлікт балансування PCC: PCC divisor = {pcc_divisor}, але виявлено {wan_count} WAN шлюзів. "
                                       f"Помилка: {loss_percent}% трафіку буде скинуто або втрачено (немає відповідного WAN маршруту для залишків PCC)!"
                        })
                    else:
                        warnings.append({
                            "type": "warning",
                            "message": f"Попередження PCC: PCC divisor = {pcc_divisor}, але виявлено {wan_count} WAN шлюзів."
                        })
            elif len(divisors) > 1:
                warnings.append({
                    "type": "warning",
                    "message": f"Виявлено декілька дільників PCC ({', '.join(map(str, divisors))}), що може призвести к нерівномірному розподілу трафіку."
                })

        return {
            "wan_gateways": list(wan_gateways),
            "pcc_rules_count": len(pcc_rules),
            "warnings": warnings
        }

class WiFiAuditor:
    """Audits WiFi configurations, Fast Transition, country regulatory settings, channel widths, tx-power, and roaming signal ranges."""
    @staticmethod
    def analyze_wifi(ast: RouterOS_AST) -> Dict[str, Any]:
        warnings = []
        recommendations = []
        ft_enabled = False
        country_set = False
        roaming_rules = False

        wifi_nodes = [n for n in ast.nodes if n.path in [
            "/interface wifi", "/interface wifi configuration", "/interface wifi security",
            "/interface wireless", "/interface wireless security-profiles",
            "/caps-man configuration", "/caps-man security", "/caps-man interface"
        ]]

        if not wifi_nodes:
            return {
                "warnings": [],
                "recommendations": [{"type": "info", "message": "Wi-Fi інтерфейси не налаштовані в цій конфігурації."}],
                "ft_enabled": False,
                "country_set": False,
                "roaming_rules": False
            }

        # Check for FT (Fast Transition)
        for node in ast.nodes:
            for k, v in node.params.items():
                clean_v = v.strip('"\'')
                # Matches security.ft, ft, ft-over-ds, security.ft-over-ds etc.
                if (k == "ft" or k == "ft-over-ds" or k.endswith(".ft") or k.endswith(".ft-over-ds")) and clean_v == "yes":
                    ft_enabled = True
                    break

        if not ft_enabled:
            recommendations.append({
                "type": "info",
                "message": "Рекомендується увімкнути Fast Transition (802.11r/FT) та ft-over-ds=yes для безшовного роумінгу мобільних клієнтів."
            })
        else:
            recommendations.append({
                "type": "success",
                "message": "✓ Fast Transition (802.11r) увімкнено для швидкого перемикання клієнтів."
            })

        # Check country code
        countries = set()
        for node in ast.nodes:
            for param in ["country", "country-code"]:
                if param in node.params:
                    val = node.params[param].strip('"\'').lower()
                    if val:
                        countries.add(val)
                        country_set = True

        if not country_set:
            warnings.append({
                "type": "warning",
                "message": "Попередження регулятора: Не налаштовано параметр Country. Роутер може використовувати частоти, заборонені в Україні (наприклад, DFS канали без радарного детектування)."
            })
        else:
            for country in countries:
                if country not in ["ukraine", "ukr", "ua"]:
                    warnings.append({
                        "type": "warning",
                        "message": f"Невідповідність регуляторного коду: налаштовано країну '{country}', але очікується 'ukraine' для розгортання в Україні. Частоти та обмеження потужності (EIRP) можуть не відповідати нормам."
                    })

        # Check channel width
        for node in ast.nodes:
            if "channel-width" in node.params:
                cw = node.params["channel-width"].strip('"\'')
                name = node.params.get("name", "").lower() or node.finder or ""
                if "5g" in name or "5ghz" in name:
                    if cw in ["20mhz", "20"]:
                        recommendations.append({
                            "type": "info",
                            "message": f"Оптимізація швидкості: На 5GHz інтерфейсі ({node.params.get('name', 'config')}) використовується ширина 20MHz. Рекомендується встановити 20/40/80MHz (XX) для кращої швидкості."
                        })
                elif "2g" in name or "2ghz" in name or "2.4" in name:
                    if "40" in cw:
                        warnings.append({
                            "type": "warning",
                            "message": f"Попередження частоти: На 2.4GHz інтерфейсі ({node.params.get('name', 'config')}) встановлено ширину 40MHz. Це може призвести до сильних завад у зашумленому ефірі. Рекомендується 20MHz."
                        })

        # Check access-list signal thresholds (roaming control)
        has_acl = any(n.path in ["/interface wireless access-list", "/interface wifi access-list"] for n in ast.nodes)
        if has_acl:
            roaming_rules = True
        else:
            recommendations.append({
                "type": "info",
                "message": "Рекомендується додати правила '/interface wifi access-list' з обмеженням за рівнем сигналу (наприклад, -80..-120dBm action=reject) для боротьби з ефектом 'липких' клієнтів (sticky clients)."
            })

        # Check TX Power
        for node in ast.nodes:
            if "tx-power" in node.params:
                try:
                    tp = int(node.params["tx-power"].strip('"\''))
                    if tp > 20:
                        warnings.append({
                            "type": "warning",
                            "message": f"Потужність сигналу: Встановлено високу потужність передавача tx-power={tp}dBm. Це може погіршити роумінг (клієнти не перемикатимуться вчасно)."
                        })
                except ValueError:
                    pass

        return {
            "warnings": warnings,
            "recommendations": recommendations,
            "ft_enabled": ft_enabled,
            "country_set": country_set,
            "roaming_rules": roaming_rules
        }

class MermaidGenerator:
    """Generates visual topology graphs in Mermaid JS format."""
    @staticmethod
    def generate(resolved: Dict[str, Any], intents: Dict[str, List[str]]) -> str:
        lines = ["graph TD"]

        # Add WAN nodes
        for wan in intents.get("WAN", []):
            lines.append(f'  {wan}["🌐 WAN: {wan}"]')

        # Add bridges
        for bridge, data in resolved.get("bridges", {}).items():
            lines.append(f'  {bridge}["🌉 Bridge: {bridge}"]')
            # link WAN to bridge or ports
            for port in data.get("ports", []):
                lines.append(f'  {port}["🔌 Port: {port}"]')
                lines.append(f'  {bridge} --- {port}')

            # link VLANs to bridge
            for vlan in data.get("vlans", []):
                v_info = resolved.get("vlans", {}).get(vlan, {})
                v_id = v_info.get("vlan_id", "")
                v_label = f"📶 VLAN {v_id}: {vlan}"
                lines.append(f'  {vlan}["{v_label}"]')
                lines.append(f'  {bridge} ==> {vlan}')

                # link DHCP to VLAN
                for dhcp in v_info.get("dhcp", []):
                    dhcp_name = dhcp.get("name", "dhcp")
                    dhcp_range = dhcp.get("ranges", "")
                    lines.append(f'  {dhcp_name}["📋 DHCP: {dhcp_name}\\n({dhcp_range})"]')
                    lines.append(f'  {vlan} --> {dhcp_name}')

        # Add any VLANs not under bridge
        for vlan, v_info in resolved.get("vlans", {}).items():
            parent = v_info.get("parent_interface")
            if parent not in resolved.get("bridges", {}):
                v_id = v_info.get("vlan_id", "")
                v_label = f"📶 VLAN {v_id}: {vlan}"
                lines.append(f'  {vlan}["{v_label}"]')
                if parent:
                    lines.append(f'  {parent} ==> {vlan}')

        return "\n".join(lines)

class ChangeImpactEngine:
    """Compares previous and new configuration models to predict system impact or downtime."""
    @staticmethod
    def analyze_impact(old_ast: RouterOS_AST, new_ast: RouterOS_AST) -> List[Dict[str, Any]]:
        impacts = []

        # Track bridge ports change
        old_ports = {n.params.get("interface", "").strip('"\''): n.params.get("bridge", "").strip('"\'') for n in old_ast.nodes if n.path == "/interface bridge port" and n.action == "add"}
        new_ports = {n.params.get("interface", "").strip('"\''): n.params.get("bridge", "").strip('"\'') for n in new_ast.nodes if n.path == "/interface bridge port" and n.action == "add"}

        for port, bridge in new_ports.items():
            if port not in old_ports:
                impacts.append({
                    "severity": "warning",
                    "component": "bridge",
                    "message": f"Додавання порту '{port}' до Bridge '{bridge}' спричинить тимчасове переініціалізацію лінку на цьому фізичному інтерфейсі."
                })
            elif old_ports[port] != bridge:
                impacts.append({
                    "severity": "high",
                    "component": "bridge",
                    "message": f"Перенесення порту '{port}' з Bridge '{old_ports[port]}' до '{bridge}' призведе до переініціалізації та скидання мережевого трафіку на цьому порту!"
                })

        # DHCP pools changes
        old_pools = {n.params.get("name", "").strip('"\''): n.params.get("ranges", "").strip('"\'') for n in old_ast.nodes if n.path == "/ip pool" and n.action == "add"}
        new_pools = {n.params.get("name", "").strip('"\''): n.params.get("ranges", "").strip('"\'') for n in new_ast.nodes if n.path == "/ip pool" and n.action == "add"}

        for p_name, p_range in new_pools.items():
            if p_name in old_pools and old_pools[p_name] != p_range:
                impacts.append({
                    "severity": "warning",
                    "component": "dhcp",
                    "message": f"Зміна діапазону адрес IP пулу '{p_name}' з '{old_pools[p_name]}' на '{p_range}'. Активні клієнти оновлять свої оренди (leases) поступово."
                })

        old_dhcp = {n.params.get("name", "").strip('"\''): n.params.get("address-pool", "").strip('"\'') for n in old_ast.nodes if n.path == "/ip dhcp-server" and n.action == "add"}
        new_dhcp = {n.params.get("name", "").strip('"\''): n.params.get("address-pool", "").strip('"\'') for n in new_ast.nodes if n.path == "/ip dhcp-server" and n.action == "add"}

        for name in old_dhcp:
            if name not in new_dhcp:
                impacts.append({
                    "severity": "high",
                    "component": "dhcp",
                    "message": f"Видалення DHCP сервера '{name}'. Усі клієнти цього сегмента втратять зв'язок після закінчення терміну оренди IP!"
                })

        # Routing modifications
        old_routes = {n.params.get("gateway", "").strip('"\'') for n in old_ast.nodes if n.path == "/ip route" and n.action == "add"}
        new_routes = {n.params.get("gateway", "").strip('"\'') for n in new_ast.nodes if n.path == "/ip route" and n.action == "add"}

        removed_routes = old_routes - new_routes
        if removed_routes:
            impacts.append({
                "severity": "high",
                "component": "routing",
                "message": f"Видалено або змінено шлюзи маршрутизації: {', '.join(removed_routes)}. Це може порушити зовнішній зв'язок для деяких підмереж!"
            })

        # Identity modifications
        old_id = next((n.params.get("name", "").strip('"\'') for n in old_ast.nodes if n.path == "/system identity" and n.action == "set"), "")
        new_id = next((n.params.get("name", "").strip('"\'') for n in new_ast.nodes if n.path == "/system identity" and n.action == "set"), "")
        if old_id and new_id and old_id != new_id:
            impacts.append({
                "severity": "info",
                "component": "system",
                "message": f"Зміна імені пристрою (Identity) з '{old_id}' на '{new_id}'."
            })

        if not impacts:
            impacts.append({
                "severity": "success",
                "component": "none",
                "message": "Деструктивних змін чи переривань сервісів не прогнозується."
            })

        return impacts

class AutoRepairEngine:
    """Provides smart auto-repair RouterOS CLI commands for validation failures."""
    @staticmethod
    def suggest_fixes(ast: RouterOS_AST, sandbox_errors: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        fixes = []
        for err in sandbox_errors:
            msg = err.get("message", "")
            if "vlan" in msg.lower() and "не додано" in msg.lower():
                match = re.search(r'VLAN\s+(?:ID\s+)?(\d+)', msg, re.IGNORECASE)
                if match:
                    v_id = match.group(1)
                    fixes.append({
                        "id": f"fix_vlan_{v_id}",
                        "problem": msg,
                        "command": f"/interface bridge vlan add bridge=bridge tagged=bridge,ether1 vlan-ids={v_id}",
                        "explanation": f"Додає VLAN {v_id} в таблицю bridge vlan з тегуванням на портах bridge та ether1."
                    })
            elif "dns" in msg.lower() and "wan" in msg.lower():
                fixes.append({
                    "id": "fix_dns_wan",
                    "problem": msg,
                    "command": "/ip firewall filter add chain=input action=drop protocol=udp dst-port=53 in-interface-list=WAN comment=\"Drop DNS requests from WAN\"",
                    "explanation": "Блокує зовнішні UDP DNS запити з інтерфейсів списку WAN."
                })
            elif "stp" in msg.lower() and "вимкнено" in msg.lower():
                fixes.append({
                    "id": "fix_stp",
                    "problem": msg,
                    "command": "/interface bridge set [find] protocol-mode=rstp",
                    "explanation": "Включає протокол RSTP на мосту для запобігання петель комутації."
                })
            elif "ssh" in msg.lower() and "дозволено" in msg.lower():
                fixes.append({
                    "id": "fix_ssh_sec",
                    "problem": msg,
                    "command": "/ip firewall filter add chain=input action=drop protocol=tcp dst-port=22 in-interface-list=WAN comment=\"Drop SSH from WAN\"",
                    "explanation": "Забороняє доступ до SSH (порт 22) з зовнішньої мережі WAN."
                })

        for node in ast.nodes:
            if node.path == "/interface bridge" and node.action == "add":
                name = node.params.get("name", "bridge").strip('"\'')
                vf = node.params.get("vlan-filtering")
                if vf == "no":
                    fixes.append({
                        "id": "fix_vlan_filtering",
                        "problem": f"VLAN filtering вимкнено на bridge '{name}'",
                        "command": f"/interface bridge set [find name={name}] vlan-filtering=yes",
                        "explanation": "Включає апаратну VLAN-фільтрацію на комутаторі."
                    })

        return fixes

class CapacityPlanner:
    """Estimates CPU/RAM reserve metrics for MikroTik models based on workload analysis."""
    @staticmethod
    def estimate_capacity(ast: RouterOS_AST, model_key: str, clients_count: int = 50, wan_speed_mbps: int = 1000) -> Dict[str, Any]:
        from backend.knowledgebase.kb import RouterOSKB
        models = RouterOSKB.get_models()

        model_info = models.get(model_key)
        if not model_info:
            for k, m in models.items():
                if model_key.lower().replace("_", "").replace("-", "") in k.lower().replace("_", "").replace("-", ""):
                    model_info = m
                    model_key = k
                    break

        if not model_info:
            model_info = {
                "name": model_key,
                "cpu": {"cores": 4, "frequency": 1400},
                "ram": {"size_mb": 1024},
                "throughput": {"routing_gbps": 9.8, "firewall_gbps": 4.2, "wireguard_mbps": 800, "ipsec_gbps": 0.9},
                "wiki": {"brief": "Стандартний профіль пристрою"}
            }

        cores = model_info.get("cpu", {}).get("cores", 4)
        freq = model_info.get("cpu", {}).get("frequency", 1000)
        ram_size = model_info.get("ram", {}).get("size_mb", 512)

        firewall_rules = len([n for n in ast.nodes if n.path == "/ip firewall filter" and n.action == "add"])
        nat_rules = len([n for n in ast.nodes if n.path == "/ip firewall nat" and n.action == "add"])
        mangle_rules = len([n for n in ast.nodes if n.path == "/ip firewall mangle" and n.action == "add"])
        vlans = len([n for n in ast.nodes if n.path == "/interface vlan" and n.action == "add"])

        has_pcc = any("per-connection-classifier" in n.params for n in ast.nodes if n.path == "/ip firewall mangle")
        has_capsman = any(n.path in ["/caps-man manager", "/interface wifi capsman"] for n in ast.nodes)
        has_zerotier = any(n.path == "/zerotier" for n in ast.nodes)
        has_docker = any(n.path == "/container" for n in ast.nodes)
        has_wireguard = any(n.path == "/interface wireguard" for n in ast.nodes)
        has_ipsec = any(n.path in ["/ip ipsec peer", "/ip ipsec profile"] for n in ast.nodes)

        cpu_factor = (cores * freq) / 1000.0

        cpu_load = 5.0
        cpu_load += (firewall_rules + mangle_rules) * (1.5 / cpu_factor)
        cpu_load += nat_rules * (1.0 / cpu_factor)
        cpu_load += vlans * (0.8 / cpu_factor)

        if has_pcc:
            cpu_load += 15.0 / cpu_factor
        if has_capsman:
            cpu_load += 10.0 / cpu_factor
        if has_zerotier:
            cpu_load += 8.0 / cpu_factor
        if has_docker:
            cpu_load += 12.0 / cpu_factor

        cpu_load += clients_count * (0.5 / cpu_factor)

        # Scaling cpu_load based on traffic throughput (WAN speed)
        traffic_factor = wan_speed_mbps / 1000.0
        cpu_load += traffic_factor * (15.0 / cpu_factor)

        cpu_reserve = max(5, int(100 - cpu_load))

        ram_load_mb = 120.0
        ram_load_mb += vlans * 1.5
        ram_load_mb += clients_count * 0.8
        if has_capsman:
            ram_load_mb += 40.0
        if has_zerotier:
            ram_load_mb += 30.0
        if has_docker:
            ram_load_mb += 256.0

        ram_reserve = max(2, int(((ram_size - ram_load_mb) / ram_size) * 100))

        # Determine Status
        if cpu_reserve < 15 or ram_reserve < 10:
            status_ukr = "Перевантаження системи"
            status_code = "OVERLOADED"
        elif cpu_reserve < 35 or ram_reserve < 20:
            status_ukr = "Недостатній запас ресурсів"
            status_code = "NEAR_LIMIT"
        elif cpu_reserve < 60 or ram_reserve < 40:
            status_ukr = "Оптимальний запас ресурсів"
            status_code = "OPTIMAL"
        else:
            status_ukr = "Чудовий запас ресурсів"
            status_code = "EXCELLENT"

        # Calculate expected throughput limits based on feature matrices
        th = model_info.get("throughput", {})
        routing_limit = th.get("routing_gbps", 1.0)
        firewall_limit = th.get("firewall_gbps", 0.8)
        ipsec_limit = th.get("ipsec_gbps", 0.3)
        wg_limit = th.get("wireguard_mbps", 100) / 1000.0  # convert to gbps

        # Cap based on active configurations
        expected_throughput_gbps = routing_limit
        if firewall_rules > 0 or nat_rules > 0:
            expected_throughput_gbps = min(expected_throughput_gbps, firewall_limit)
        if has_ipsec:
            expected_throughput_gbps = min(expected_throughput_gbps, ipsec_limit)
        if has_wireguard:
            expected_throughput_gbps = min(expected_throughput_gbps, wg_limit)

        # Output Expected speed in Mbps or Gbps
        expected_throughput_mbps = int(expected_throughput_gbps * 1000)

        return {
            "model_name": model_info.get("name", model_key),
            "cpu_reserve": cpu_reserve,
            "ram_reserve": ram_reserve,
            "cpu_peak": 100 - cpu_reserve,
            "ram_peak": 100 - ram_reserve,
            "status_ukr": status_ukr,
            "status_code": status_code,
            "expected_throughput_mbps": expected_throughput_mbps,
            "details": model_info.get("wiki", {}).get("brief", "")
        }
