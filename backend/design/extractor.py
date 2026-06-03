# -*- coding: utf-8 -*-
"""
MikroTik Template Extraction Engine & Utilities
Allows generalized template conversion, parameter mappings, bulk cloning, and compare/sync scripts.
"""
import re
import json
import ipaddress
from typing import List, Dict, Any, Optional
from backend.parsers.base import get_param_value, clean_comment_and_join_lines
from backend.design.cloner import clone_site_config

def extract_template(config_text: str) -> dict:
    """
    Analyzes configuration text, extracts variables, and produces:
    1. generalised Template RSC with {{VARIABLES}}
    2. JSON mapping of variables
    3. YAML mapping of variables
    4. Blueprint model of the configuration
    """
    variables = {}

    sections = clean_comment_and_join_lines(config_text)

    # 1. Identity Name
    identity_match = re.search(r'/system identity\s+set name=([^\s\r\n]+)', config_text)
    if identity_match:
        site_name = identity_match.group(1).strip('"\'')
        variables["SITE_NAME"] = site_name

    # 2. WAN Interfaces
    wan_interfaces = []
    if "/interface ethernet" in sections:
        for line in sections["/interface ethernet"]:
            comment = get_param_value(line, "comment")
            def_name_match = re.search(r'default-name=([^\s\]]+)', line)
            if def_name_match and comment:
                def_name = def_name_match.group(1).strip('"\'')
                comment_val = comment.strip('"\'')
                if "ISP" in comment_val or "WAN" in comment_val:
                    wan_interfaces.append(def_name)

    if "/interface list member" in sections:
        for line in sections["/interface list member"]:
            iface = get_param_value(line, "interface")
            lst = get_param_value(line, "list")
            if iface and lst and lst.strip('"\'') == "WAN":
                wan_interfaces.append(iface.strip('"\''))

    for i, wan in enumerate(sorted(list(set(wan_interfaces)))):
        variables[f"WAN{i+1}"] = wan
    if "WAN1" not in variables:
        variables["WAN1"] = "ether1"

    # 3. IP Addresses & Subnets
    if "/ip address" in sections:
        for line in sections["/ip address"]:
            addr = get_param_value(line, "address")
            iface = get_param_value(line, "interface")
            if addr and "/" in addr and iface:
                iface = iface.strip('"\'')
                ip, mask = addr.strip('"\'').split("/", 1)

                if "guest" in iface.lower():
                    prefix = "GUEST"
                elif "work" in iface.lower() or "staff" in iface.lower():
                    prefix = "WORK"
                elif "mgmt" in iface.lower():
                    prefix = "MGMT"
                else:
                    prefix = iface.replace("bridge-", "").replace("bridge", "").replace("-", "_").upper()

                variables[f"{prefix}_GATEWAY"] = ip
                try:
                    net = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                    variables[f"{prefix}_SUBNET"] = str(net)
                    variables[f"{prefix}_NETWORK"] = str(net.network_address)
                except:
                    variables[f"{prefix}_SUBNET"] = f"{ip.rsplit('.', 1)[0]}.0/{mask}"
                    variables[f"{prefix}_NETWORK"] = f"{ip.rsplit('.', 1)[0]}.0"

    # 4. DHCP Pools
    if "/ip pool" in sections:
        for line in sections["/ip pool"]:
            name = get_param_value(line, "name")
            ranges = get_param_value(line, "ranges")
            if name and ranges:
                name = name.strip('"\'')
                rng = ranges.strip('"\'')

                if "guest" in name.lower():
                    prefix = "GUEST"
                elif "work" in name.lower() or "staff" in name.lower():
                    prefix = "WORK"
                elif "mgmt" in name.lower():
                    prefix = "MGMT"
                else:
                    prefix = name.replace("-pool", "").replace("pool", "").replace("-", "_").upper()

                variables[f"{prefix}_POOL_RANGE"] = rng

    # 5. Wireless / WiFi SSIDs
    ssid_matches = re.finditer(r'\bssid="?([^"\s\r\n]+)"?', config_text)
    for m in ssid_matches:
        ssid = m.group(1).strip('"\'')
        if "coffee" in ssid.lower() or "guest" in ssid.lower():
            variables["GUEST_SSID"] = ssid
        elif "asus" in ssid.lower() or "work" in ssid.lower() or "staff" in ssid.lower():
            variables["WORK_SSID"] = ssid

    # 6. Passphrases
    sec_sections = [
        "/interface wireless security-profiles",
        "/caps-man security",
        "/interface wifi security"
    ]
    for sec_name in sec_sections:
        if sec_name in sections:
            for line in sections[sec_name]:
                name = get_param_value(line, "name")
                pwd = get_param_value(line, "passphrase") or get_param_value(line, "wpa2-pre-shared-key")
                if name and pwd:
                    name = name.strip('"\'')
                    pwd = pwd.strip('"\'')
                    if "guest" in name.lower() or "wifi" in name.lower():
                        variables["GUEST_WIFI_PASSWORD"] = pwd
                    else:
                        variables["WORK_WIFI_PASSWORD"] = pwd

    # 7. WireGuard
    wg_match = re.search(r'/interface wireguard\s+add\s+.*?listen-port=(\d+)', config_text)
    if wg_match:
        variables["WIREGUARD_PORT"] = wg_match.group(1)

    # 8. ZeroTier
    zt_match = re.search(r'/zerotier interface\s+add\s+.*?network=([^\s\r\n]+)', config_text)
    if zt_match:
        variables["ZEROTIER_NETWORK_ID"] = zt_match.group(1).strip('"\'')

    # 9. OVPN Client
    ovpn_match = re.search(r'/interface ovpn-client\s+add\s+.*?connect-to=([^\s]+)\s+.*?password=([^\s]+)\s+.*?user=([^\s]+)', config_text)
    if ovpn_match:
        variables["OVPN_SERVER"] = ovpn_match.group(1).strip('"\'')
        variables["OVPN_USER"] = ovpn_match.group(3).strip('"\'')
        variables["OVPN_PASSWORD"] = ovpn_match.group(2).strip('"\'')

    # 10. DNS & NTP
    dns_match = re.search(r'/ip dns\s+set\s+.*?servers=([^\s\r\n]+)', config_text)
    if dns_match:
        variables["DNS_SERVERS"] = dns_match.group(1).strip('"\'')

    # Substitution list: Sort longer values first to prevent substring replacement collision
    replacements = []
    for k, v in variables.items():
        if isinstance(v, str) and v.strip():
            replacements.append((v, f"{{{{{k}}}}}"))

    replacements.sort(key=lambda x: len(x[0]), reverse=True)

    template_rsc = config_text
    for val, var in replacements:
        template_rsc = template_rsc.replace(val, var)

    # Serialization
    variables_json = json.dumps(variables, indent=2, ensure_ascii=False)

    yaml_lines = []
    for k, v in variables.items():
        if isinstance(v, str):
            escaped = v.replace('"', '\\"')
            yaml_lines.append(f'{k}: "{escaped}"')
        else:
            yaml_lines.append(f'{k}: {v}')
    variables_yaml = "\n".join(yaml_lines)

    blueprint = generate_blueprint(config_text)

    return {
        "template_rsc": template_rsc,
        "variables": variables,
        "variables_json": variables_json,
        "variables_yaml": variables_yaml,
        "blueprint": blueprint
    }

def generate_blueprint(config_text: str) -> dict:
    """Builds structural blueprint model JSON representation of the network topology."""
    from backend.parsers.network_model import parse_to_model
    model = parse_to_model(config_text)

    vlans = [{"id": v.vlan_id, "name": v.name, "interface": v.interface} for v in model.vlans]
    ips = [{"address": ip.address, "interface": ip.interface} for ip in model.ips]
    dhcp_pools = [{"name": p.name, "ranges": p.ranges} for p in model.dhcp_pools]
    dhcp_servers = [{"name": s.name, "interface": s.interface, "pool": s.address_pool} for s in model.dhcp_servers]
    dhcp_networks = [{"address": n.address, "gateway": n.gateway, "dns": n.dns_server} for n in model.dhcp_networks]

    interfaces = [{"name": i.name, "type": i.type} for i in model.interfaces]
    bridges = []
    for br in model.bridges:
        bridges.append({
            "name": br.name,
            "vlan_filtering": br.vlan_filtering,
            "ports": [{"interface": p.interface, "pvid": p.pvid} for p in br.ports]
        })

    services = [{"name": s.name, "port": s.port, "disabled": s.disabled} for s in model.services]

    identity = "Unknown"
    identity_match = re.search(r'/system identity\s+set name=([^\s\r\n]+)', config_text)
    if identity_match:
        identity = identity_match.group(1).strip('"\'')

    return {
        "hardware": model.hardware,
        "version": model.version,
        "identity": identity,
        "interfaces": interfaces,
        "bridges": bridges,
        "vlans": vlans,
        "ips": ips,
        "dhcp": {
            "pools": dhcp_pools,
            "servers": dhcp_servers,
            "networks": dhcp_networks
        },
        "services": services,
        "dns_servers": model.dns_servers
    }

def clone_site_blueprint(config_text: str, overrides: dict) -> str:
    """
    Substitutes override fields directly on the extracted template
    and returns a clean, updated output configuration.
    """
    res = extract_template(config_text)
    tpl = res["template_rsc"]
    vars_dict = res["variables"]

    # Apply override values to variables
    for k, v in overrides.items():
        if v:
            vars_dict[k] = v

    # Substitute
    cloned = tpl
    # Sort replacements by value length descending
    replacements = []
    for k, v in vars_dict.items():
        if isinstance(v, str) and v.strip():
            replacements.append((f"{{{{{k}}}}}", v))

    for placeholder, val in replacements:
        cloned = cloned.replace(placeholder, val)

    return cloned

def bulk_clone(config_text: str, sites_data: list) -> list:
    """
    Generates multiple target config scripts from a single source config
    recalculating subnet bases, SSIDs, passwords, identity overrides.
    """
    results = []
    for site in sites_data:
        site_name = site.get("site_name", "Remapped-Router")
        src_base = site.get("src_base", "10.16.132.0/24")
        dst_base = site.get("dst_base")
        ssids = site.get("ssids", {})
        passwords = site.get("passwords", {})

        # Remap IP subnets
        cloned = clone_site_config(config_text, src_base, dst_base) if dst_base else config_text

        # Update Identity
        cloned = re.sub(r'/system identity\s+set name=[^\s\r\n]+', f'/system identity set name={site_name}', cloned)

        # Swap SSIDs
        for src_ssid, dst_ssid in ssids.items():
            if src_ssid and dst_ssid:
                cloned = cloned.replace(src_ssid, dst_ssid)

        # Swap passwords
        for src_pwd, dst_pwd in passwords.items():
            if src_pwd and dst_pwd:
                cloned = cloned.replace(src_pwd, dst_pwd)

        results.append({
            "site_name": site_name,
            "config": cloned
        })
    return results

def compare_configs(config_a: str, config_b: str) -> dict:
    """
    Analyses structural differences between Config A and Config B
    and outputs a diff and a sync RSC script.
    """
    sec_a = clean_comment_and_join_lines(config_a)
    sec_b = clean_comment_and_join_lines(config_b)

    diff_added = {}
    diff_removed = {}
    sync_commands = []

    all_sections = set(sec_a.keys()).union(set(sec_b.keys()))
    for sec in all_sections:
        lines_a = sec_a.get(sec, [])
        lines_b = sec_b.get(sec, [])

        added = [l for l in lines_b if l not in lines_a]
        removed = [l for l in lines_a if l not in lines_b]

        if added:
            diff_added[sec] = added
            for line in added:
                sync_commands.append(f"{sec}\n{line}")
        if removed:
            diff_removed[sec] = removed
            for line in removed:
                # Deduce clean remove command
                params = []
                for p in ["name", "address", "vlan-id", "ssid"]:
                    val = get_param_value(line, p)
                    if val:
                        params.append(f'{p}="{val}"')
                if params:
                    sync_commands.append(f"{sec} remove [ find {' '.join(params)} ]")
                else:
                    sync_commands.append(f"{sec} remove [ find ] # Check manually: {line}")

    return {
        "added": diff_added,
        "removed": diff_removed,
        "sync_rsc": "\n".join(sync_commands)
    }
