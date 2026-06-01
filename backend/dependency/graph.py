# -*- coding: utf-8 -*-
import re
from typing import Dict, List, Any, Set
from backend.parsers.ast_parser import RouterOS_AST, ASTNode

class RouterOSSemanticNode:
    def __init__(self, name: str, node_type: str, ast_node: ASTNode = None):
        self.name = name
        self.type = node_type  # bridge, vlan, port, ip_address, dhcp_server, ip_pool, firewall_rule, interface
        self.ast_node = ast_node
        self.parents: Set['RouterOSSemanticNode'] = set()
        self.children: Set['RouterOSSemanticNode'] = set()
        self.properties: Dict[str, Any] = {}

    def add_child(self, child: 'RouterOSSemanticNode'):
        self.children.add(child)
        child.parents.add(self)

    def __repr__(self):
        return f"Node({self.name}, type={self.type})"

class RouterOSSemanticGraph:
    def __init__(self):
        self.nodes: Dict[str, RouterOSSemanticNode] = {}

    def get_or_create(self, name: str, node_type: str, ast_node: ASTNode = None) -> RouterOSSemanticNode:
        key = f"{node_type}:{name}"
        if key not in self.nodes:
            self.nodes[key] = RouterOSSemanticNode(name, node_type, ast_node)
        return self.nodes[key]

    @staticmethod
    def build_from_ast(ast: RouterOS_AST) -> 'RouterOSSemanticGraph':
        g = RouterOSSemanticGraph()

        # 1. Define physical interfaces
        for i in range(1, 25):
            g.get_or_create(f"ether{i}", "interface")
            g.get_or_create(f"sfp-sfpplus{i}", "interface")
        for w in ["wlan1", "wlan2", "wifi1", "wifi2"]:
            g.get_or_create(w, "interface")
        g.get_or_create("WAN", "interface")

        # Temporary lists to process relationships in passes
        bridges = []
        vlans = []
        ports = []
        ips = []
        dhcps = []
        pools = []
        rules = []

        for node in ast.nodes:
            if node.action not in ["add", "set"]:
                continue

            if node.path == "/interface bridge" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                if name:
                    bridges.append((name, node))
            elif node.path == "/interface vlan" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                v_id = node.params.get("vlan-id", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                if name:
                    vlans.append((name, v_id, iface, node))
            elif node.path == "/interface bridge port" and node.action == "add":
                iface = node.params.get("interface", "").strip('"\'')
                bridge = node.params.get("bridge", "").strip('"\'')
                if iface and bridge:
                    ports.append((iface, bridge, node))
            elif node.path == "/ip address" and node.action == "add":
                addr = node.params.get("address", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                if addr and iface:
                    ips.append((addr, iface, node))
            elif node.path == "/ip pool" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                ranges = node.params.get("ranges", "").strip('"\'')
                if name:
                    pools.append((name, ranges, node))
            elif node.path == "/ip dhcp-server" and node.action == "add":
                name = node.params.get("name", "").strip('"\'')
                iface = node.params.get("interface", "").strip('"\'')
                pool = node.params.get("address-pool", "").strip('"\'')
                if name:
                    dhcps.append((name, iface, pool, node))
            elif node.path == "/ip firewall filter" and node.action == "add":
                rules.append(node)

        # Build nodes and link them
        # 1. Bridges
        for name, node in bridges:
            b_node = g.get_or_create(name, "bridge", node)
            b_node.properties["vlan_filtering"] = node.params.get("vlan-filtering") == "yes"

        # 2. Bridge ports
        for iface, bridge, node in ports:
            p_node = g.get_or_create(f"{bridge}-{iface}", "port", node)
            p_node.properties["interface"] = iface
            p_node.properties["bridge"] = bridge

            b_node = g.get_or_create(bridge, "bridge")
            phy_node = g.get_or_create(iface, "interface")

            b_node.add_child(p_node)
            p_node.add_child(phy_node)

        # 3. VLANs
        for name, v_id, iface, node in vlans:
            v_node = g.get_or_create(name, "vlan", node)
            v_node.properties["vlan_id"] = v_id
            v_node.properties["parent"] = iface

            parent_node = g.get_or_create(iface, "bridge" if iface in [b[0] for b in bridges] else "interface")
            parent_node.add_child(v_node)

        # 4. IP Pools
        for name, ranges, node in pools:
            pool_node = g.get_or_create(name, "ip_pool", node)
            pool_node.properties["ranges"] = ranges

        # 5. DHCP Servers
        for name, iface, pool, node in dhcps:
            d_node = g.get_or_create(name, "dhcp_server", node)
            d_node.properties["interface"] = iface
            d_node.properties["pool"] = pool

            iface_node = g.get_or_create(iface, "vlan" if iface in [v[0] for v in vlans] else ("bridge" if iface in [b[0] for b in bridges] else "interface"))
            iface_node.add_child(d_node)

            if pool and pool != "static-only":
                pool_node = g.get_or_create(pool, "ip_pool")
                d_node.add_child(pool_node)

        # 6. IP Addresses
        for addr, iface, node in ips:
            ip_node = g.get_or_create(addr, "ip_address", node)
            iface_node = g.get_or_create(iface, "vlan" if iface in [v[0] for v in vlans] else ("bridge" if iface in [b[0] for b in bridges] else "interface"))
            iface_node.add_child(ip_node)

        # 7. Firewall Rules
        for node in rules:
            chain = node.params.get("chain", "").strip('"\'')
            action = node.params.get("action", "").strip('"\'') or "accept"
            in_iface = node.params.get("in-interface", "").strip('"\'')
            out_iface = node.params.get("out-interface", "").strip('"\'')

            r_name = f"rule-{node.line_num}"
            r_node = g.get_or_create(r_name, "firewall_rule", node)
            r_node.properties["chain"] = chain
            r_node.properties["action"] = action

            if in_iface:
                in_node = g.get_or_create(in_iface, "vlan" if in_iface in [v[0] for v in vlans] else ("bridge" if in_iface in [b[0] for b in bridges] else "interface"))
                r_node.add_child(in_node)
            if out_iface:
                out_node = g.get_or_create(out_iface, "vlan" if out_iface in [v[0] for v in vlans] else ("bridge" if out_iface in [b[0] for b in bridges] else "interface"))
                r_node.add_child(out_node)

        return g

    def get_affected_nodes(self, target_name: str) -> List[Dict[str, str]]:
        """
        Recursively trace which nodes will break or be affected if target_name is deleted.
        Returns a list of dictionaries with 'name', 'type', and 'reason'.
        """
        affected = []
        visited = set()

        # Find target node(s) across all types matching the name
        targets = []
        for key, node in self.nodes.items():
            if node.name == target_name:
                targets.append(node)

        if not targets:
            return []

        def dfs(node: RouterOSSemanticNode, reason: str):
            node_key = f"{node.type}:{node.name}"
            if node_key in visited:
                return
            visited.add(node_key)

            # Add to list (except the target itself)
            if node.name != target_name:
                affected.append({
                    "name": node.name,
                    "type": node.type,
                    "reason": reason
                })

            # 1. Any children dependent on this parent
            for child in node.children:
                child_reason = f"Батьківський об'єкт '{node.name}' ({node.type}) буде видалено."
                if node.type == "bridge" and child.type == "vlan":
                    child_reason = f"VLAN '{child.name}' залежить від мосту '{node.name}'."
                elif node.type == "vlan" and child.type == "dhcp_server":
                    child_reason = f"DHCP сервер '{child.name}' налаштовано на VLAN '{node.name}'."
                elif node.type == "ip_pool" and child.type == "dhcp_server":
                    child_reason = f"DHCP сервер '{child.name}' використовує пул '{node.name}'."
                dfs(child, child_reason)

            # 2. Any parents referencing this node (reverse link dependency)
            for parent in node.parents:
                parent_reason = f"Об'єкт залежить від '{node.name}' ({node.type})."
                if node.type == "vlan" and parent.type == "firewall_rule":
                    parent_reason = f"Правило брандмауера ({parent.name}) фільтрує трафік інтерфейсу VLAN '{node.name}'."
                elif node.type == "bridge" and parent.type == "port":
                    parent_reason = f"Порт моста '{parent.name}' прикріплено до мосту '{node.name}'."
                dfs(parent, parent_reason)

        for target in targets:
            dfs(target, f"Видалення об'єкта '{target_name}'.")

        return affected


class ConfigDependencyGraph:
    def __init__(self):
        self.nodes: List[str] = []
        self.adj: Dict[str, Set[str]] = {} # node -> set of nodes it depends on

    def add_node(self, command: str):
        self.nodes.append(command)
        self.adj[command] = set()

    def build_dependencies(self):
        # We will parse commands and match them to identify dependencies
        # Common Mikrotik resource creation patterns:
        # 1. Bridge creation: /interface bridge add name=XYZ
        # 2. VLAN creation: /interface vlan add name=VLAN_XYZ vlan-id=NUM interface=BRIDGE_XYZ
        # 3. IP address: /ip address add address=IP interface=IFACE
        # 4. DHCP Pool: /ip pool add name=POOL_XYZ
        # 5. DHCP Server: /ip dhcp-server add interface=IFACE address-pool=POOL_XYZ

        # Let's map each command to what it creates / defines
        creates_map = {} # resource_id -> command

        # First pass: identify what each command creates
        for cmd in self.nodes:
            # Normalize whitespace
            norm_cmd = " ".join(cmd.split())

            # Bridge
            if "/interface bridge add" in norm_cmd or "/interface bridge set" in norm_cmd:
                name_match = re.search(r"name=([^\s]+)", norm_cmd)
                name = name_match.group(1).replace('"', '') if name_match else "bridge"
                creates_map[f"bridge:{name}"] = cmd

            # VLAN Interface
            elif "/interface vlan add" in norm_cmd:
                name_match = re.search(r"name=([^\s]+)", norm_cmd)
                if name_match:
                    name = name_match.group(1).replace('"', '')
                    creates_map[f"interface:{name}"] = cmd
                    creates_map[f"vlan:{name}"] = cmd

            # IP Address
            elif "/ip address add" in norm_cmd:
                addr_match = re.search(r"address=([^\s]+)", norm_cmd)
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if addr_match and iface_match:
                    addr = addr_match.group(1).replace('"', '')
                    iface = iface_match.group(1).replace('"', '')
                    creates_map[f"ip:{iface}"] = cmd

            # DHCP Pool
            elif "/ip pool add" in norm_cmd:
                name_match = re.search(r"name=([^\s]+)", norm_cmd)
                if name_match:
                    name = name_match.group(1).replace('"', '')
                    creates_map[f"pool:{name}"] = cmd

            # DHCP Server
            elif "/ip dhcp-server add" in norm_cmd:
                name_match = re.search(r"name=([^\s]+)", norm_cmd)
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if name_match:
                    name = name_match.group(1).replace('"', '')
                    creates_map[f"dhcp-server:{name}"] = cmd
                if iface_match:
                    iface = iface_match.group(1).replace('"', '')
                    creates_map[f"dhcp-server-iface:{iface}"] = cmd

        # Second pass: build dependencies (edges)
        for cmd in self.nodes:
            norm_cmd = " ".join(cmd.split())

            # 1. VLAN depends on its parent interface/bridge
            if "/interface vlan add" in norm_cmd:
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if iface_match:
                    parent = iface_match.group(1).replace('"', '')
                    # Depends on bridge creation
                    if f"bridge:{parent}" in creates_map:
                        self.adj[cmd].add(creates_map[f"bridge:{parent}"])

            # 2. Bridge port depends on bridge and interface
            elif "/interface bridge port add" in norm_cmd:
                bridge_match = re.search(r"bridge=([^\s]+)", norm_cmd)
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if bridge_match:
                    br = bridge_match.group(1).replace('"', '')
                    if f"bridge:{br}" in creates_map:
                        self.adj[cmd].add(creates_map[f"bridge:{br}"])
                if iface_match:
                    iface = iface_match.group(1).replace('"', '')
                    if f"interface:{iface}" in creates_map:
                        self.adj[cmd].add(creates_map[f"interface:{iface}"])

            # 3. IP address depends on its interface (VLAN or Bridge)
            elif "/ip address add" in norm_cmd:
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if iface_match:
                    iface = iface_match.group(1).replace('"', '')
                    if f"interface:{iface}" in creates_map:
                        self.adj[cmd].add(creates_map[f"interface:{iface}"])
                    elif f"bridge:{iface}" in creates_map:
                        self.adj[cmd].add(creates_map[f"bridge:{iface}"])

            # 4. DHCP Server depends on DHCP Pool and Interface IP
            elif "/ip dhcp-server add" in norm_cmd:
                pool_match = re.search(r"address-pool=([^\s]+)", norm_cmd)
                iface_match = re.search(r"interface=([^\s]+)", norm_cmd)
                if pool_match:
                    pool = pool_match.group(1).replace('"', '')
                    if f"pool:{pool}" in creates_map:
                        self.adj[cmd].add(creates_map[f"pool:{pool}"])
                if iface_match:
                    iface = iface_match.group(1).replace('"', '')
                    # Must have IP address configured first
                    if f"ip:{iface}" in creates_map:
                        self.adj[cmd].add(creates_map[f"ip:{iface}"])
                    # Or at least the interface itself
                    elif f"interface:{iface}" in creates_map:
                        self.adj[cmd].add(creates_map[f"interface:{iface}"])

            # 5. DHCP Network depends on DHCP server/pool
            elif "/ip dhcp-server network add" in norm_cmd:
                for key, val in creates_map.items():
                    if key.startswith("pool:") or key.startswith("dhcp-server:"):
                        self.adj[cmd].add(val)

            # 6. VLAN set command in bridge vlan depends on bridge and interfaces
            elif "/interface bridge vlan add" in norm_cmd:
                bridge_match = re.search(r"bridge=([^\s]+)", norm_cmd)
                if bridge_match:
                    br = bridge_match.group(1).replace('"', '')
                    if f"bridge:{br}" in creates_map:
                        self.adj[cmd].add(creates_map[f"bridge:{br}"])

    def sort(self) -> List[str]:
        # Topological sort using DFS (Tarjan's algorithm)
        visited = {} # node -> state (0 = unvisited, 1 = visiting, 2 = visited)
        order = []

        for node in self.nodes:
            visited[node] = 0

        def dfs(node):
            visited[node] = 1 # visiting
            for dep in self.adj.get(node, []):
                if visited.get(dep, 0) == 0:
                    dfs(dep)
                elif visited.get(dep, 0) == 1:
                    # Cycle detected, ignore to prevent freeze, but break dependency
                    pass
            visited[node] = 2 # visited
            order.append(node)

        for node in self.nodes:
            if visited[node] == 0:
                dfs(node)

        return order


def sort_fixes(fixes: List[str]) -> List[str]:
    graph = ConfigDependencyGraph()
    for fix in fixes:
        graph.add_node(fix)
    graph.build_dependencies()
    return graph.sort()
